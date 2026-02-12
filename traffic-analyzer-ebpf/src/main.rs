#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    helpers::bpf_ktime_get_ns,
    macros::{classifier, map},
    maps::{Array, HashMap, RingBuf},
    programs::TcContext,
};
use aya_ebpf_bindings::helpers::bpf_skb_load_bytes;
use traffic_analyzer_common::{
    Direction, DnsEvent, FlowKey, FlowValue, TlsEvent, COLLECTOR_STATS_MAP_ENTRIES,
    COLLECTOR_STAT_DNS_RINGBUF_DROP_IDX, COLLECTOR_STAT_FLOW_INSERT_DROP_IDX,
    COLLECTOR_STAT_TLS_RINGBUF_DROP_IDX, DNS_EVENT_PAYLOAD_LEN, FLOW_STATS_MAX_ENTRIES,
    TLS_EVENT_PAYLOAD_LEN,
};

const ETH_HDR_LEN: usize = 14;
const IPV4_ETHERTYPE: u16 = 0x0800;
const IPV6_ETHERTYPE: u16 = 0x86dd;
const IPV6_HDR_LEN: usize = 40;
const UDP_PROTO: u8 = 17;
const TCP_PROTO: u8 = 6;
const DNS_PORT: u16 = 53;
const HTTPS_PORT: u16 = 443;
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 22;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 1;

#[map]
static FLOW_STATS: HashMap<FlowKey, FlowValue> =
    HashMap::<FlowKey, FlowValue>::with_max_entries(FLOW_STATS_MAX_ENTRIES, 0);

#[map]
static DNS_EVENTS: RingBuf = RingBuf::with_byte_size(524_288, 0);

#[map]
static TLS_EVENTS: RingBuf = RingBuf::with_byte_size(2_097_152, 0);

#[map]
static COLLECTOR_STATS: Array<u64> = Array::<u64>::with_max_entries(COLLECTOR_STATS_MAP_ENTRIES, 0);

#[classifier]
pub fn ingress(ctx: TcContext) -> i32 {
    match handle_packet(&ctx, Direction::Ingress) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,
    }
}

#[classifier]
pub fn egress(ctx: TcContext) -> i32 {
    match handle_packet(&ctx, Direction::Egress) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,
    }
}

fn handle_packet(ctx: &TcContext, direction: Direction) -> Result<i32, ()> {
    let ethertype = read_u16_be(ctx, 12)?;
    let (proto, src_ip, dst_ip, l4_off) = if ethertype == IPV4_ETHERTYPE {
        let ip_off = ETH_HDR_LEN;
        let ihl = read_u8(ctx, ip_off)? & 0x0f;
        if ihl < 5 {
            return Ok(TC_ACT_OK);
        }

        let ip_hdr_len = (ihl as usize) * 4;
        let proto = read_u8(ctx, ip_off + 9)?;
        let src_ip = read_ipv4_mapped(ctx, ip_off + 12)?;
        let dst_ip = read_ipv4_mapped(ctx, ip_off + 16)?;
        (proto, src_ip, dst_ip, ip_off + ip_hdr_len)
    } else if ethertype == IPV6_ETHERTYPE {
        let ip_off = ETH_HDR_LEN;
        let proto = read_u8(ctx, ip_off + 6)?;
        let src_ip = read_ipv6(ctx, ip_off + 8)?;
        let dst_ip = read_ipv6(ctx, ip_off + 24)?;
        (proto, src_ip, dst_ip, ip_off + IPV6_HDR_LEN)
    } else {
        return Ok(TC_ACT_OK);
    };

    let (src_port, dst_port) = match proto {
        TCP_PROTO | UDP_PROTO => (read_u16_be(ctx, l4_off)?, read_u16_be(ctx, l4_off + 2)?),
        _ => (0, 0),
    };

    let key = FlowKey {
        direction: direction as u8,
        proto,
        src_port,
        dst_port,
        src_ip,
        dst_ip,
    };

    update_flow_stats(&key, packet_len(ctx) as u64);

    if proto == UDP_PROTO {
        emit_dns_event(ctx, direction, l4_off, src_port, dst_port, src_ip, dst_ip)?;
    } else if proto == TCP_PROTO {
        emit_tls_event(ctx, direction, l4_off, src_port, dst_port, src_ip, dst_ip)?;
    }

    Ok(TC_ACT_OK)
}

fn emit_dns_event(
    ctx: &TcContext,
    direction: Direction,
    udp_off: usize,
    src_port: u16,
    dst_port: u16,
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
) -> Result<(), ()> {
    if src_port != DNS_PORT && dst_port != DNS_PORT {
        return Ok(());
    }

    let udp_len = read_u16_be(ctx, udp_off + 4)? as usize;
    if udp_len <= 8 {
        return Ok(());
    }

    let dns_off = udp_off + 8;
    let dns_len = udp_len - 8;
    if dns_len < 12 {
        return Ok(());
    }

    let mut entry = match DNS_EVENTS.reserve::<DnsEvent>(0) {
        Some(v) => v,
        None => {
            inc_collector_stat(COLLECTOR_STAT_DNS_RINGBUF_DROP_IDX);
            return Ok(());
        }
    };

    let event = entry.write(DnsEvent::default());
    event.ts_ns = unsafe { bpf_ktime_get_ns() };
    event.src_ip = src_ip;
    event.dst_ip = dst_ip;
    event.src_port = src_port;
    event.dst_port = dst_port;
    event.payload_len = dns_len.min(u16::MAX as usize) as u16;
    event.direction = direction as u8;

    let captured = select_capture_len(dns_len);
    if captured == 0 {
        entry.discard(0);
        return Ok(());
    }
    event.captured_len = captured as u16;

    if load_skb_bytes_bucket(ctx, dns_off, &mut event.payload, captured).is_err() {
        entry.discard(0);
        return Ok(());
    }

    entry.submit(0);
    Ok(())
}

fn emit_tls_event(
    ctx: &TcContext,
    direction: Direction,
    tcp_off: usize,
    src_port: u16,
    dst_port: u16,
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
) -> Result<(), ()> {
    // Only client->server side can carry ClientHello and SNI.
    if dst_port != HTTPS_PORT {
        return Ok(());
    }

    let data_off_raw = read_u8(ctx, tcp_off + 12)? >> 4;
    if data_off_raw < 5 {
        return Ok(());
    }
    let tcp_hdr_len = usize::from(data_off_raw) * 4;
    let tls_off = tcp_off + tcp_hdr_len;
    let pkt_len = packet_len(ctx);
    if tls_off >= pkt_len {
        return Ok(());
    }

    let tls_len = pkt_len - tls_off;
    if tls_len < 5 {
        return Ok(());
    }
    if read_u8(ctx, tls_off)? != TLS_CONTENT_TYPE_HANDSHAKE {
        return Ok(());
    }
    if tls_len < 6 {
        return Ok(());
    }
    if read_u8(ctx, tls_off + 5)? != TLS_HANDSHAKE_CLIENT_HELLO {
        return Ok(());
    }

    let mut entry = match TLS_EVENTS.reserve::<TlsEvent>(0) {
        Some(v) => v,
        None => {
            inc_collector_stat(COLLECTOR_STAT_TLS_RINGBUF_DROP_IDX);
            return Ok(());
        }
    };

    let event = entry.write(TlsEvent::default());
    event.ts_ns = unsafe { bpf_ktime_get_ns() };
    event.src_ip = src_ip;
    event.dst_ip = dst_ip;
    event.src_port = src_port;
    event.dst_port = dst_port;
    event.payload_len = tls_len.min(u16::MAX as usize) as u16;
    event.direction = direction as u8;

    let captured = select_capture_len_tls(tls_len);
    if captured == 0 {
        entry.discard(0);
        return Ok(());
    }
    event.captured_len = captured as u16;

    if load_skb_bytes_bucket_tls(ctx, tls_off, &mut event.payload, captured).is_err() {
        entry.discard(0);
        return Ok(());
    }

    entry.submit(0);
    Ok(())
}

fn update_flow_stats(key: &FlowKey, pkt_bytes: u64) {
    let now = unsafe { bpf_ktime_get_ns() };

    if let Some(stat) = FLOW_STATS.get_ptr_mut(key) {
        unsafe {
            (*stat).bytes = (*stat).bytes.saturating_add(pkt_bytes);
            (*stat).packets = (*stat).packets.saturating_add(1);
            (*stat).last_seen_ns = now;
        }
        return;
    }

    let val = FlowValue {
        bytes: pkt_bytes,
        packets: 1,
        last_seen_ns: now,
    };
    if FLOW_STATS.insert(key, &val, 0).is_err() {
        inc_collector_stat(COLLECTOR_STAT_FLOW_INSERT_DROP_IDX);
    }
}

fn packet_len(ctx: &TcContext) -> usize {
    ctx.len() as usize
}

fn ipv4_to_mapped(ip: [u8; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[10] = 0xff;
    out[11] = 0xff;
    out[12..16].copy_from_slice(&ip);
    out
}

fn read_ipv4_mapped(ctx: &TcContext, off: usize) -> Result<[u8; 16], ()> {
    let ip = [
        read_u8(ctx, off)?,
        read_u8(ctx, off + 1)?,
        read_u8(ctx, off + 2)?,
        read_u8(ctx, off + 3)?,
    ];
    Ok(ipv4_to_mapped(ip))
}

fn read_ipv6(ctx: &TcContext, off: usize) -> Result<[u8; 16], ()> {
    let mut ip = [0u8; 16];
    let ret = unsafe {
        bpf_skb_load_bytes(
            ctx.skb.skb as *const _,
            off as u32,
            ip.as_mut_ptr() as *mut _,
            16,
        )
    };
    if ret == 0 {
        Ok(ip)
    } else {
        Err(())
    }
}

fn inc_collector_stat(idx: u32) {
    if let Some(value) = COLLECTOR_STATS.get_ptr_mut(idx) {
        unsafe {
            *value = (*value).saturating_add(1);
        }
    }
}

fn read_u8(ctx: &TcContext, off: usize) -> Result<u8, ()> {
    ctx.load::<u8>(off).map_err(|_| ())
}

fn read_u16_be(ctx: &TcContext, off: usize) -> Result<u16, ()> {
    let a = read_u8(ctx, off)? as u16;
    let b = read_u8(ctx, off + 1)? as u16;
    Ok((a << 8) | b)
}

fn select_capture_len(dns_len: usize) -> usize {
    if dns_len >= DNS_EVENT_PAYLOAD_LEN {
        DNS_EVENT_PAYLOAD_LEN
    } else if dns_len >= 64 {
        64
    } else if dns_len >= 48 {
        48
    } else if dns_len >= 32 {
        32
    } else if dns_len >= 24 {
        24
    } else if dns_len >= 16 {
        16
    } else if dns_len >= 12 {
        12
    } else {
        0
    }
}

fn select_capture_len_tls(tls_len: usize) -> usize {
    if tls_len >= TLS_EVENT_PAYLOAD_LEN {
        TLS_EVENT_PAYLOAD_LEN
    } else if tls_len >= 320 {
        320
    } else if tls_len >= 256 {
        256
    } else if tls_len >= 224 {
        224
    } else if tls_len >= 160 {
        160
    } else if tls_len >= 128 {
        128
    } else if tls_len >= 96 {
        96
    } else if tls_len >= 64 {
        64
    } else if tls_len >= 48 {
        48
    } else if tls_len >= 32 {
        32
    } else if tls_len >= 24 {
        24
    } else if tls_len >= 16 {
        16
    } else if tls_len >= 8 {
        8
    } else {
        0
    }
}

fn load_skb_bytes_bucket(
    ctx: &TcContext,
    off: usize,
    dst: &mut [u8; DNS_EVENT_PAYLOAD_LEN],
    len: usize,
) -> Result<(), ()> {
    let ret = match len {
        DNS_EVENT_PAYLOAD_LEN => unsafe {
            bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                off as u32,
                dst.as_mut_ptr() as *mut _,
                DNS_EVENT_PAYLOAD_LEN as u32,
            )
        },
        64 => unsafe {
            bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                off as u32,
                dst.as_mut_ptr() as *mut _,
                64,
            )
        },
        48 => unsafe {
            bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                off as u32,
                dst.as_mut_ptr() as *mut _,
                48,
            )
        },
        32 => unsafe {
            bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                off as u32,
                dst.as_mut_ptr() as *mut _,
                32,
            )
        },
        24 => unsafe {
            bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                off as u32,
                dst.as_mut_ptr() as *mut _,
                24,
            )
        },
        16 => unsafe {
            bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                off as u32,
                dst.as_mut_ptr() as *mut _,
                16,
            )
        },
        12 => unsafe {
            bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                off as u32,
                dst.as_mut_ptr() as *mut _,
                12,
            )
        },
        _ => return Err(()),
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(())
    }
}

fn load_skb_bytes_bucket_tls(
    ctx: &TcContext,
    off: usize,
    dst: &mut [u8; TLS_EVENT_PAYLOAD_LEN],
    len: usize,
) -> Result<(), ()> {
    let ret = match len {
        TLS_EVENT_PAYLOAD_LEN => unsafe {
            bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                off as u32,
                dst.as_mut_ptr() as *mut _,
                TLS_EVENT_PAYLOAD_LEN as u32,
            )
        },
        320 => unsafe {
            bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                off as u32,
                dst.as_mut_ptr() as *mut _,
                320,
            )
        },
        256 => unsafe {
            bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                off as u32,
                dst.as_mut_ptr() as *mut _,
                256,
            )
        },
        224 => unsafe {
            bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                off as u32,
                dst.as_mut_ptr() as *mut _,
                224,
            )
        },
        160 => unsafe {
            bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                off as u32,
                dst.as_mut_ptr() as *mut _,
                160,
            )
        },
        128 => unsafe {
            bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                off as u32,
                dst.as_mut_ptr() as *mut _,
                128,
            )
        },
        96 => unsafe {
            bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                off as u32,
                dst.as_mut_ptr() as *mut _,
                96,
            )
        },
        64 => unsafe {
            bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                off as u32,
                dst.as_mut_ptr() as *mut _,
                64,
            )
        },
        48 => unsafe {
            bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                off as u32,
                dst.as_mut_ptr() as *mut _,
                48,
            )
        },
        32 => unsafe {
            bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                off as u32,
                dst.as_mut_ptr() as *mut _,
                32,
            )
        },
        24 => unsafe {
            bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                off as u32,
                dst.as_mut_ptr() as *mut _,
                24,
            )
        },
        16 => unsafe {
            bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                off as u32,
                dst.as_mut_ptr() as *mut _,
                16,
            )
        },
        8 => unsafe {
            bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                off as u32,
                dst.as_mut_ptr() as *mut _,
                8,
            )
        },
        _ => return Err(()),
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
