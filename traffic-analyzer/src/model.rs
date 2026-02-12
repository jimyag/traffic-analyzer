use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use traffic_analyzer_common::{FlowKey, IpKey};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FlowBucketKey {
    pub direction: u8,
    pub proto: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub domain: String,
    pub attribution_status: String,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CounterDelta {
    pub bytes: u64,
    pub packets: u64,
}

#[derive(Clone, Debug)]
pub struct FlowMinuteRow {
    pub ts_minute: i64,
    pub iface: String,
    pub direction: u8,
    pub proto: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub src_ip: String,
    pub dst_ip: String,
    pub domain: String,
    pub attribution_status: String,
    pub bytes: u64,
    pub packets: u64,
}

#[derive(Clone, Debug)]
pub struct DnsMinuteRow {
    pub ts_minute: i64,
    pub iface: String,
    pub qname: String,
    pub qtype: u16,
    pub count: u64,
}

#[derive(Clone, Debug)]
pub struct TopRow {
    pub key: String,
    pub bytes: u64,
    pub packets: u64,
}

#[derive(Clone, Debug)]
pub struct DomainDetailRow {
    pub direction: u8,
    pub proto: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub attribution_status: String,
    pub bytes: u64,
    pub packets: u64,
}

#[derive(Clone, Debug)]
pub struct AttributionCoverageRow {
    pub status: String,
    pub bytes: u64,
    pub packets: u64,
}

#[derive(Clone, Debug)]
pub struct DnsCacheMinuteRow {
    pub ts_minute: i64,
    pub iface: String,
    pub cache_entries: u64,
    pub dns_answer_events: u64,
    pub sni_events: u64,
    pub new_entries: u64,
    pub refresh_entries: u64,
    pub expired_entries: u64,
}

#[derive(Clone, Debug, Default)]
pub struct CollectorStatsDelta {
    pub flow_insert_drop: u64,
    pub dns_ringbuf_drop: u64,
    pub tls_ringbuf_drop: u64,
}

#[derive(Clone, Debug)]
pub struct CollectorHealthMinuteRow {
    pub ts_minute: i64,
    pub iface: String,
    pub flow_entries: u64,
    pub flow_evicted: u64,
    pub flow_insert_drop: u64,
    pub dns_ringbuf_drop: u64,
    pub tls_ringbuf_drop: u64,
}

#[derive(Clone, Debug)]
pub struct SniMinuteRow {
    pub ts_minute: i64,
    pub iface: String,
    pub sni: String,
    pub count: u64,
}

#[derive(Clone, Debug)]
pub struct DnsCacheInspectRow {
    pub ts_minute: i64,
    pub cache_entries: u64,
    pub dns_answer_events: u64,
    pub sni_events: u64,
    pub new_entries: u64,
    pub refresh_entries: u64,
    pub expired_entries: u64,
}

#[derive(Clone, Debug)]
pub struct CollectorHealthRow {
    pub ts_minute: i64,
    pub flow_entries: u64,
    pub flow_evicted: u64,
    pub flow_insert_drop: u64,
    pub dns_ringbuf_drop: u64,
    pub tls_ringbuf_drop: u64,
}

#[derive(Clone, Debug)]
pub struct FlowTupleRow {
    pub direction: u8,
    pub proto: u8,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub bytes: u64,
    pub packets: u64,
}

impl Display for TopRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}\tbytes={}\tpackets={}",
            self.key, self.bytes, self.packets
        )
    }
}

pub fn ip_from_bytes(bytes: [u8; 16]) -> IpAddr {
    if bytes[..10] == [0; 10] && bytes[10] == 0xff && bytes[11] == 0xff {
        let v4 = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
        return IpAddr::V4(v4);
    }

    IpAddr::V6(Ipv6Addr::from(bytes))
}

pub fn ip_to_string(bytes: [u8; 16]) -> String {
    ip_from_bytes(bytes).to_string()
}

pub fn attribution_for_flow(
    key: &FlowKey,
    ip_domain_cache: &std::collections::HashMap<IpKey, String>,
) -> (String, String) {
    let remote_ip = if key.direction == 0 {
        key.src_ip
    } else {
        key.dst_ip
    };
    let ip_key = IpKey { ip: remote_ip };
    if let Some(domain) = ip_domain_cache.get(&ip_key) {
        return (domain.clone(), "exact".to_string());
    }

    (String::new(), "unknown".to_string())
}

pub fn direction_str(direction: u8) -> &'static str {
    match direction {
        0 => "ingress",
        1 => "egress",
        _ => "unknown",
    }
}

pub fn proto_str(proto: u8) -> &'static str {
    match proto {
        6 => "tcp",
        17 => "udp",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_mapped_decode() {
        let mut bytes = [0u8; 16];
        bytes[10] = 0xff;
        bytes[11] = 0xff;
        bytes[12..16].copy_from_slice(&[1, 2, 3, 4]);

        assert_eq!(ip_to_string(bytes), "1.2.3.4");
    }
}
