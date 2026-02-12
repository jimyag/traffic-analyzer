use std::collections::HashMap;
use std::mem;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use aya::maps::{Array as AyaArray, HashMap as AyaHashMap, RingBuf as AyaRingBuf};
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::Ebpf;
use tracing::{debug, info, warn};
use traffic_analyzer_common::{
    DnsEvent, FlowKey, FlowValue, IpKey, TlsEvent, COLLECTOR_STAT_DNS_RINGBUF_DROP_IDX,
    COLLECTOR_STAT_FLOW_INSERT_DROP_IDX, COLLECTOR_STAT_TLS_RINGBUF_DROP_IDX,
    DNS_EVENT_PAYLOAD_LEN, TLS_EVENT_PAYLOAD_LEN,
};

use crate::db::Database;
use crate::dns::parse_dns_payload;
use crate::model::{
    attribution_for_flow, ip_to_string, CollectorHealthMinuteRow, CollectorStatsDelta,
    CounterDelta, DnsCacheMinuteRow, DnsMinuteRow, FlowBucketKey, FlowMinuteRow, SniMinuteRow,
};
use crate::tls::parse_tls_client_hello_sni;

const DNS_DEFAULT_TTL_SEC: u64 = 300;
const SNI_DEFAULT_TTL_SEC: u64 = 300;
const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;
const SIG_ERR: usize = usize::MAX;

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" {
    fn signal(signum: i32, handler: usize) -> usize;
}

extern "C" fn handle_shutdown_signal(_sig: i32) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

pub struct RunConfig {
    pub iface: String,
    pub bpf_object: BpfObject,
    pub db_path: String,
    pub flush_interval: Duration,
    pub dns_ttl_cap_secs: u64,
    pub sni_ttl_cap_secs: u64,
    pub flow_idle_timeout_secs: u64,
}

pub enum BpfObject {
    Path(String),
    Embedded(&'static [u8]),
}

#[derive(Clone, Debug)]
struct DomainCacheEntry {
    domain: String,
    expires_at_ns: u64,
}

#[derive(Debug)]
struct WriteBatch {
    flow_rows: Vec<FlowMinuteRow>,
    dns_rows: Vec<DnsMinuteRow>,
    sni_rows: Vec<SniMinuteRow>,
    dns_cache_rows: Vec<DnsCacheMinuteRow>,
    collector_health_rows: Vec<CollectorHealthMinuteRow>,
}

#[derive(Clone, Copy, Debug, Default)]
struct CacheMetricDelta {
    cache_entries: u64,
    dns_answer_events: u64,
    sni_events: u64,
    new_entries: u64,
    refresh_entries: u64,
    expired_entries: u64,
}

struct DbWriter {
    tx: mpsc::Sender<WriteBatch>,
    handle: thread::JoinHandle<()>,
}

pub fn run(cfg: RunConfig) -> Result<()> {
    install_shutdown_handler()?;
    let db_writer = spawn_db_writer(&cfg.db_path)?;
    let mut bpf = match &cfg.bpf_object {
        BpfObject::Path(path) => {
            Ebpf::load_file(path).with_context(|| format!("failed to load bpf object: {}", path))?
        }
        BpfObject::Embedded(bytes) => {
            // include_bytes! returns a 1-byte-aligned slice; object parsing is more robust
            // on an owned buffer with allocator alignment.
            let owned = bytes.to_vec();
            Ebpf::load(&owned).context("failed to load embedded bpf object from current binary")?
        }
    };

    attach_tc_program(&mut bpf, &cfg.iface, "ingress", TcAttachType::Ingress)?;
    attach_tc_program(&mut bpf, &cfg.iface, "egress", TcAttachType::Egress)?;

    let mut flow_map = AyaHashMap::<_, FlowKey, FlowValue>::try_from(
        bpf.take_map("FLOW_STATS")
            .ok_or_else(|| anyhow!("map FLOW_STATS not found"))?,
    )?;
    let mut dns_events = AyaRingBuf::try_from(
        bpf.take_map("DNS_EVENTS")
            .ok_or_else(|| anyhow!("map DNS_EVENTS not found"))?,
    )?;
    let mut tls_events = AyaRingBuf::try_from(
        bpf.take_map("TLS_EVENTS")
            .ok_or_else(|| anyhow!("map TLS_EVENTS not found"))?,
    )?;
    let collector_stats = AyaArray::<_, u64>::try_from(
        bpf.take_map("COLLECTOR_STATS")
            .ok_or_else(|| anyhow!("map COLLECTOR_STATS not found"))?,
    )?;

    let mut flow_snapshot = HashMap::<FlowKey, FlowValue>::new();
    let mut domain_cache = HashMap::<IpKey, DomainCacheEntry>::new();
    let mut collector_stats_snapshot = [0u64; 3];

    info!(
        iface = %cfg.iface,
        db = %cfg.db_path,
        bpf_source = %bpf_source_name(&cfg.bpf_object),
        "traffic analyzer started"
    );

    let run_result = (|| -> Result<()> {
        loop {
            if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
                info!("received shutdown signal; flushing final in-memory delta");
                break;
            }

            collect_and_flush_once(
                &mut flow_map,
                &mut dns_events,
                &mut tls_events,
                &collector_stats,
                &mut collector_stats_snapshot,
                &mut flow_snapshot,
                &mut domain_cache,
                &db_writer.tx,
                &cfg.iface,
                cfg.dns_ttl_cap_secs,
                cfg.sni_ttl_cap_secs,
                cfg.flow_idle_timeout_secs,
            )?;

            sleep_with_shutdown(cfg.flush_interval);
        }

        // Final best-effort round to capture packets observed just before Ctrl+C.
        collect_and_flush_once(
            &mut flow_map,
            &mut dns_events,
            &mut tls_events,
            &collector_stats,
            &mut collector_stats_snapshot,
            &mut flow_snapshot,
            &mut domain_cache,
            &db_writer.tx,
            &cfg.iface,
            cfg.dns_ttl_cap_secs,
            cfg.sni_ttl_cap_secs,
            cfg.flow_idle_timeout_secs,
        )?;
        Ok(())
    })();

    shutdown_db_writer(db_writer);
    run_result
}

fn install_shutdown_handler() -> Result<()> {
    SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
    let handler = handle_shutdown_signal as *const () as usize;
    let sigint_ret = unsafe { signal(SIGINT, handler) };
    if sigint_ret == SIG_ERR {
        return Err(anyhow!("failed to install SIGINT handler"));
    }
    let sigterm_ret = unsafe { signal(SIGTERM, handler) };
    if sigterm_ret == SIG_ERR {
        return Err(anyhow!("failed to install SIGTERM handler"));
    }
    Ok(())
}

fn spawn_db_writer(db_path: &str) -> Result<DbWriter> {
    let (tx, rx) = mpsc::channel::<WriteBatch>();
    let db_path = db_path.to_string();

    let handle = thread::Builder::new()
        .name("traffic-db-writer".to_string())
        .spawn(move || {
            let mut db = match Database::open(&db_path) {
                Ok(v) => v,
                Err(err) => {
                    warn!(db = %db_path, error = %err, "failed to open database in writer thread");
                    return;
                }
            };

            while let Ok(batch) = rx.recv() {
                if !batch.flow_rows.is_empty() {
                    if let Err(err) = db.upsert_flow_rows(&batch.flow_rows) {
                        warn!(error = %err, rows = batch.flow_rows.len(), "failed to upsert flow rows");
                    }
                }
                if !batch.dns_rows.is_empty() {
                    if let Err(err) = db.upsert_dns_rows(&batch.dns_rows) {
                        warn!(error = %err, rows = batch.dns_rows.len(), "failed to upsert dns rows");
                    }
                }
                if !batch.sni_rows.is_empty() {
                    if let Err(err) = db.upsert_sni_rows(&batch.sni_rows) {
                        warn!(error = %err, rows = batch.sni_rows.len(), "failed to upsert sni rows");
                    }
                }
                if !batch.dns_cache_rows.is_empty() {
                    if let Err(err) = db.upsert_dns_cache_rows(&batch.dns_cache_rows) {
                        warn!(error = %err, rows = batch.dns_cache_rows.len(), "failed to upsert dns cache rows");
                    }
                }
                if !batch.collector_health_rows.is_empty() {
                    if let Err(err) = db.upsert_collector_health_rows(&batch.collector_health_rows)
                    {
                        warn!(
                            error = %err,
                            rows = batch.collector_health_rows.len(),
                            "failed to upsert collector health rows"
                        );
                    }
                }

                debug!(
                    flow_rows = batch.flow_rows.len(),
                    dns_rows = batch.dns_rows.len(),
                    sni_rows = batch.sni_rows.len(),
                    dns_cache_rows = batch.dns_cache_rows.len(),
                    collector_health_rows = batch.collector_health_rows.len(),
                    "delta batch flushed"
                );
            }

            info!("db writer thread exited");
        })
        .map_err(|err| anyhow!("failed to spawn db writer thread: {}", err))?;

    Ok(DbWriter { tx, handle })
}

fn shutdown_db_writer(db_writer: DbWriter) {
    let DbWriter { tx, handle } = db_writer;
    drop(tx);
    if handle.join().is_err() {
        warn!("db writer thread panicked");
    }
}

fn collect_and_flush_once(
    flow_map: &mut AyaHashMap<aya::maps::MapData, FlowKey, FlowValue>,
    dns_events: &mut AyaRingBuf<aya::maps::MapData>,
    tls_events: &mut AyaRingBuf<aya::maps::MapData>,
    collector_stats: &AyaArray<aya::maps::MapData, u64>,
    collector_stats_snapshot: &mut [u64; 3],
    flow_snapshot: &mut HashMap<FlowKey, FlowValue>,
    domain_cache: &mut HashMap<IpKey, DomainCacheEntry>,
    tx: &mpsc::Sender<WriteBatch>,
    iface: &str,
    dns_ttl_cap_secs: u64,
    sni_ttl_cap_secs: u64,
    flow_idle_timeout_secs: u64,
) -> Result<()> {
    let now_ns = monotonic_ns();
    let flow_evicted = prune_stale_flow_entries(
        flow_map,
        flow_snapshot,
        now_ns,
        flow_idle_timeout_secs.max(1),
    )?;
    let mut dns_delta = HashMap::<(String, u16), u64>::new();
    let mut sni_delta = HashMap::<String, u64>::new();
    let mut cache_metrics = CacheMetricDelta::default();
    collect_dns_events(
        dns_events,
        now_ns,
        dns_ttl_cap_secs,
        domain_cache,
        &mut dns_delta,
        &mut cache_metrics,
    );
    collect_tls_events(
        tls_events,
        now_ns,
        sni_ttl_cap_secs,
        domain_cache,
        &mut sni_delta,
        &mut cache_metrics,
    );

    let ip_domain_cache = build_ip_domain_cache(domain_cache, now_ns, &mut cache_metrics);
    let mut flow_delta = HashMap::<FlowBucketKey, CounterDelta>::new();
    collect_flow_delta(flow_map, flow_snapshot, &ip_domain_cache, &mut flow_delta)?;
    let flow_entries = flow_snapshot.len() as u64;
    let collector_stats_delta =
        read_collector_stats_delta(collector_stats, collector_stats_snapshot)?;
    if collector_stats_delta.flow_insert_drop > 0
        || collector_stats_delta.dns_ringbuf_drop > 0
        || collector_stats_delta.tls_ringbuf_drop > 0
    {
        warn!(
            flow_insert_drop = collector_stats_delta.flow_insert_drop,
            dns_ringbuf_drop = collector_stats_delta.dns_ringbuf_drop,
            tls_ringbuf_drop = collector_stats_delta.tls_ringbuf_drop,
            flow_entries = flow_entries,
            "collector dropped some events or flow inserts in this cycle"
        );
    }

    let ts_minute = current_minute_ts();
    flush_minute_async(
        tx,
        iface,
        ts_minute,
        &flow_delta,
        &dns_delta,
        &sni_delta,
        cache_metrics,
        flow_entries,
        flow_evicted,
        collector_stats_delta,
    )
}

fn sleep_with_shutdown(duration: Duration) {
    let step = Duration::from_millis(100);
    let start = Instant::now();
    loop {
        if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
            return;
        }
        let elapsed = start.elapsed();
        if elapsed >= duration {
            return;
        }
        let wait = (duration - elapsed).min(step);
        thread::sleep(wait);
    }
}

fn attach_tc_program(
    bpf: &mut Ebpf,
    iface: &str,
    prog_name: &str,
    attach_type: TcAttachType,
) -> Result<()> {
    if let Err(err) = tc::qdisc_add_clsact(iface) {
        debug!(iface = %iface, error = %err, "clsact exists or failed to add");
    }

    let program: &mut SchedClassifier = bpf
        .program_mut(prog_name)
        .ok_or_else(|| anyhow!("program {} not found", prog_name))?
        .try_into()?;

    program.load()?;
    program.attach(iface, attach_type)?;
    Ok(())
}

fn collect_dns_events(
    dns_events: &mut AyaRingBuf<aya::maps::MapData>,
    now_ns: u64,
    ttl_cap_secs: u64,
    domain_cache: &mut HashMap<IpKey, DomainCacheEntry>,
    dns_bucket: &mut HashMap<(String, u16), u64>,
    metrics: &mut CacheMetricDelta,
) {
    let event_size = mem::size_of::<DnsEvent>();

    while let Some(item) = dns_events.next() {
        if item.len() < event_size {
            continue;
        }

        let data = &item[..event_size];
        let event = match bytemuck::try_pod_read_unaligned::<DnsEvent>(data) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let captured_len = usize::from(event.captured_len).min(DNS_EVENT_PAYLOAD_LEN);
        if captured_len < 12 {
            continue;
        }

        let payload = &event.payload[..captured_len];
        let parsed = match parse_dns_payload(payload, event.src_port, event.dst_port) {
            Some(v) => v,
            None => continue,
        };

        if let Some((qname, qtype)) = parsed.query {
            let key = (qname, qtype);
            let item = dns_bucket.entry(key).or_default();
            *item = item.saturating_add(1);
        }

        for ans in parsed.answers {
            if ans.domain.is_empty() {
                continue;
            }
            metrics.dns_answer_events = metrics.dns_answer_events.saturating_add(1);

            let ttl = if ans.ttl_sec == 0 {
                DNS_DEFAULT_TTL_SEC
            } else {
                u64::from(ans.ttl_sec)
            };
            let capped_ttl = ttl.min(ttl_cap_secs.max(1));
            let expires_at_ns = now_ns.saturating_add(capped_ttl.saturating_mul(1_000_000_000));

            let previous = domain_cache.insert(
                ans.ip,
                DomainCacheEntry {
                    domain: ans.domain,
                    expires_at_ns,
                },
            );
            if previous.is_some() {
                metrics.refresh_entries = metrics.refresh_entries.saturating_add(1);
            } else {
                metrics.new_entries = metrics.new_entries.saturating_add(1);
            }
        }
    }
}

fn collect_tls_events(
    tls_events: &mut AyaRingBuf<aya::maps::MapData>,
    now_ns: u64,
    ttl_cap_secs: u64,
    domain_cache: &mut HashMap<IpKey, DomainCacheEntry>,
    sni_bucket: &mut HashMap<String, u64>,
    metrics: &mut CacheMetricDelta,
) {
    let event_size = mem::size_of::<TlsEvent>();

    while let Some(item) = tls_events.next() {
        if item.len() < event_size {
            continue;
        }

        let data = &item[..event_size];
        let event = match bytemuck::try_pod_read_unaligned::<TlsEvent>(data) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let captured_len = usize::from(event.captured_len).min(TLS_EVENT_PAYLOAD_LEN);
        if captured_len < 8 {
            continue;
        }

        let payload = &event.payload[..captured_len];
        let sni = match parse_tls_client_hello_sni(payload, event.src_port, event.dst_port) {
            Some(v) => v,
            None => continue,
        };
        metrics.sni_events = metrics.sni_events.saturating_add(1);
        let item = sni_bucket.entry(sni.clone()).or_default();
        *item = item.saturating_add(1);

        let ttl = SNI_DEFAULT_TTL_SEC.min(ttl_cap_secs.max(1));
        let expires_at_ns = now_ns.saturating_add(ttl.saturating_mul(1_000_000_000));
        let remote_ip = if event.dst_port == 443 {
            event.dst_ip
        } else {
            event.src_ip
        };
        let previous = domain_cache.insert(
            IpKey { ip: remote_ip },
            DomainCacheEntry {
                domain: sni,
                expires_at_ns,
            },
        );
        if previous.is_some() {
            metrics.refresh_entries = metrics.refresh_entries.saturating_add(1);
        } else {
            metrics.new_entries = metrics.new_entries.saturating_add(1);
        }
    }
}

fn prune_stale_flow_entries(
    flow_map: &mut AyaHashMap<aya::maps::MapData, FlowKey, FlowValue>,
    snapshot: &mut HashMap<FlowKey, FlowValue>,
    now_ns: u64,
    idle_timeout_secs: u64,
) -> Result<u64> {
    let idle_timeout_ns = idle_timeout_secs.saturating_mul(1_000_000_000);
    let mut stale_keys = Vec::<FlowKey>::new();
    for entry in flow_map.iter() {
        let (key, value) = entry?;
        if now_ns.saturating_sub(value.last_seen_ns) > idle_timeout_ns {
            stale_keys.push(key);
        }
    }

    let mut evicted = 0u64;
    for key in stale_keys {
        if flow_map.remove(&key).is_ok() {
            evicted = evicted.saturating_add(1);
        }
        snapshot.remove(&key);
    }
    Ok(evicted)
}

fn read_collector_stats_delta(
    collector_stats: &AyaArray<aya::maps::MapData, u64>,
    snapshot: &mut [u64; 3],
) -> Result<CollectorStatsDelta> {
    let flow_insert_abs = collector_stats
        .get(&COLLECTOR_STAT_FLOW_INSERT_DROP_IDX, 0)
        .map_err(|err| anyhow!("failed to read COLLECTOR_STATS[flow_insert_drop]: {}", err))?;
    let dns_ringbuf_abs = collector_stats
        .get(&COLLECTOR_STAT_DNS_RINGBUF_DROP_IDX, 0)
        .map_err(|err| anyhow!("failed to read COLLECTOR_STATS[dns_ringbuf_drop]: {}", err))?;
    let tls_ringbuf_abs = collector_stats
        .get(&COLLECTOR_STAT_TLS_RINGBUF_DROP_IDX, 0)
        .map_err(|err| anyhow!("failed to read COLLECTOR_STATS[tls_ringbuf_drop]: {}", err))?;

    let delta = CollectorStatsDelta {
        flow_insert_drop: flow_insert_abs.saturating_sub(snapshot[0]),
        dns_ringbuf_drop: dns_ringbuf_abs.saturating_sub(snapshot[1]),
        tls_ringbuf_drop: tls_ringbuf_abs.saturating_sub(snapshot[2]),
    };

    snapshot[0] = flow_insert_abs;
    snapshot[1] = dns_ringbuf_abs;
    snapshot[2] = tls_ringbuf_abs;
    Ok(delta)
}

fn collect_flow_delta(
    flow_map: &mut AyaHashMap<aya::maps::MapData, FlowKey, FlowValue>,
    snapshot: &mut HashMap<FlowKey, FlowValue>,
    ip_domain_cache: &HashMap<IpKey, String>,
    bucket: &mut HashMap<FlowBucketKey, CounterDelta>,
) -> Result<()> {
    for entry in flow_map.iter() {
        let (key, value) = entry?;
        let prev = snapshot.get(&key).copied().unwrap_or_default();

        let bytes = value.bytes.saturating_sub(prev.bytes);
        let packets = value.packets.saturating_sub(prev.packets);

        snapshot.insert(key, value);

        if bytes == 0 && packets == 0 {
            continue;
        }

        let (domain, attribution_status) = attribution_for_flow(&key, ip_domain_cache);
        let bucket_key = FlowBucketKey {
            direction: key.direction,
            proto: key.proto,
            src_port: key.src_port,
            dst_port: key.dst_port,
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            domain,
            attribution_status,
        };

        let item = bucket.entry(bucket_key).or_default();
        item.bytes = item.bytes.saturating_add(bytes);
        item.packets = item.packets.saturating_add(packets);
    }

    Ok(())
}

fn build_ip_domain_cache(
    domain_cache: &mut HashMap<IpKey, DomainCacheEntry>,
    now_ns: u64,
    metrics: &mut CacheMetricDelta,
) -> HashMap<IpKey, String> {
    let before = domain_cache.len();
    domain_cache.retain(|_, v| v.expires_at_ns > now_ns && !v.domain.is_empty());
    let after = domain_cache.len();
    if before > after {
        metrics.expired_entries = metrics
            .expired_entries
            .saturating_add((before - after) as u64);
    }
    metrics.cache_entries = metrics.cache_entries.max(after as u64);

    let mut out = HashMap::with_capacity(domain_cache.len());
    for (ip, v) in domain_cache.iter() {
        out.insert(*ip, v.domain.clone());
    }
    out
}

fn flush_minute_async(
    tx: &mpsc::Sender<WriteBatch>,
    iface: &str,
    ts_minute: i64,
    flow_bucket: &HashMap<FlowBucketKey, CounterDelta>,
    dns_bucket: &HashMap<(String, u16), u64>,
    sni_bucket: &HashMap<String, u64>,
    cache_metrics: CacheMetricDelta,
    flow_entries: u64,
    flow_evicted: u64,
    collector_stats_delta: CollectorStatsDelta,
) -> Result<()> {
    if flow_bucket.is_empty()
        && dns_bucket.is_empty()
        && sni_bucket.is_empty()
        && cache_metrics.cache_entries == 0
        && cache_metrics.dns_answer_events == 0
        && cache_metrics.sni_events == 0
        && cache_metrics.new_entries == 0
        && cache_metrics.refresh_entries == 0
        && cache_metrics.expired_entries == 0
        && flow_evicted == 0
        && collector_stats_delta.flow_insert_drop == 0
        && collector_stats_delta.dns_ringbuf_drop == 0
        && collector_stats_delta.tls_ringbuf_drop == 0
    {
        return Ok(());
    }

    let flow_rows = flow_bucket
        .iter()
        .map(|(k, v)| FlowMinuteRow {
            ts_minute,
            iface: iface.to_string(),
            direction: k.direction,
            proto: k.proto,
            src_port: k.src_port,
            dst_port: k.dst_port,
            src_ip: ip_to_string(k.src_ip),
            dst_ip: ip_to_string(k.dst_ip),
            domain: k.domain.clone(),
            attribution_status: k.attribution_status.clone(),
            bytes: v.bytes,
            packets: v.packets,
        })
        .collect::<Vec<_>>();

    let dns_rows = dns_bucket
        .iter()
        .map(|((qname, qtype), count)| DnsMinuteRow {
            ts_minute,
            iface: iface.to_string(),
            qname: qname.clone(),
            qtype: *qtype,
            count: *count,
        })
        .collect::<Vec<_>>();

    let sni_rows = sni_bucket
        .iter()
        .map(|(sni, count)| SniMinuteRow {
            ts_minute,
            iface: iface.to_string(),
            sni: sni.clone(),
            count: *count,
        })
        .collect::<Vec<_>>();

    let dns_cache_rows = vec![DnsCacheMinuteRow {
        ts_minute,
        iface: iface.to_string(),
        cache_entries: cache_metrics.cache_entries,
        dns_answer_events: cache_metrics.dns_answer_events,
        sni_events: cache_metrics.sni_events,
        new_entries: cache_metrics.new_entries,
        refresh_entries: cache_metrics.refresh_entries,
        expired_entries: cache_metrics.expired_entries,
    }];

    let collector_health_rows = vec![CollectorHealthMinuteRow {
        ts_minute,
        iface: iface.to_string(),
        flow_entries,
        flow_evicted,
        flow_insert_drop: collector_stats_delta.flow_insert_drop,
        dns_ringbuf_drop: collector_stats_delta.dns_ringbuf_drop,
        tls_ringbuf_drop: collector_stats_delta.tls_ringbuf_drop,
    }];

    tx.send(WriteBatch {
        flow_rows,
        dns_rows,
        sni_rows,
        dns_cache_rows,
        collector_health_rows,
    })
    .map_err(|err| anyhow!("failed to send write batch: {}", err))?;

    Ok(())
}

fn current_minute_ts() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs() as i64;
    (now / 60) * 60
}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts as *mut _) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        warn!(error = %err, "clock_gettime(CLOCK_MONOTONIC) failed");
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

fn bpf_source_name(obj: &BpfObject) -> &str {
    match obj {
        BpfObject::Path(_) => "path",
        BpfObject::Embedded(_) => "embedded",
    }
}
