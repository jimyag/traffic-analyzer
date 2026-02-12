use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use traffic_analyzer_common::FLOW_STATS_MAX_ENTRIES;

use crate::db::Database;
use crate::model::{direction_str, proto_str, CollectorHealthRow, TopRow};

pub struct UiConfig {
    pub iface: String,
    pub db_path: String,
    pub lookback_minutes: i64,
    pub limit: i64,
    pub refresh: Duration,
}

pub fn run(cfg: UiConfig) -> Result<()> {
    let db = Database::open_for_query(&cfg.db_path)?;

    loop {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();

        let top_domain = db.top_domain(&cfg.iface, cfg.lookback_minutes, cfg.limit)?;
        let top_ip = db.top_ip(&cfg.iface, cfg.lookback_minutes, cfg.limit)?;
        let top_lan_ip = db.top_lan_ip(&cfg.iface, cfg.lookback_minutes, cfg.limit)?;
        let top_dns = db.top_dns_query(&cfg.iface, cfg.lookback_minutes, cfg.limit)?;
        let top_sni = db.top_sni(&cfg.iface, cfg.lookback_minutes, cfg.limit)?;
        let top_quic = db.top_quic(&cfg.iface, cfg.lookback_minutes, cfg.limit)?;
        let top_doh = db.top_doh(&cfg.iface, cfg.lookback_minutes, cfg.limit)?;
        let top_dot = db.top_dot(&cfg.iface, cfg.lookback_minutes, cfg.limit)?;
        let top_flow = db.top_flow(&cfg.iface, cfg.lookback_minutes, cfg.limit)?;
        let coverage = db.attribution_coverage(&cfg.iface, cfg.lookback_minutes)?;
        let unknown_detail = db.domain_detail(
            &cfg.iface,
            "(unknown)",
            cfg.lookback_minutes,
            cfg.limit.max(5),
        )?;
        let collector_health =
            db.collector_health(&cfg.iface, cfg.lookback_minutes, cfg.limit.max(5))?;

        print!("\x1B[2J\x1B[H");
        println!(
            "LAS Traffic Dashboard  iface={}  db={}  lookback={}m  now={}  refresh={}s",
            cfg.iface,
            cfg.db_path,
            cfg.lookback_minutes,
            now,
            cfg.refresh.as_secs()
        );
        println!("Ctrl+C 退出");
        println!();

        println!("== Coverage ==");
        let total_bytes = coverage.iter().map(|v| v.bytes).sum::<u64>().max(1);
        for row in coverage {
            let ratio = (row.bytes as f64) * 100.0 / (total_bytes as f64);
            println!(
                "status={:<8} bytes={} packets={} ratio={:.2}%",
                row.status,
                human_bytes(row.bytes),
                row.packets,
                ratio
            );
        }
        println!();
        render_collector_health(&collector_health);

        render_top_rows("Top Domain", &top_domain, false);
        render_top_rows("Top IP", &top_ip, false);
        render_top_rows("Top LAN IP", &top_lan_ip, false);
        render_top_rows("Top DNS", &top_dns, true);
        render_top_rows("Top SNI", &top_sni, true);
        println!("== Top Flow (5-tuple) ==");
        if top_flow.is_empty() {
            println!("(empty)");
        } else {
            for row in top_flow {
                println!(
                    "direction={} proto={} {}:{} -> {}:{} bytes={} packets={}",
                    direction_str(row.direction),
                    proto_str(row.proto),
                    row.src_ip,
                    row.src_port,
                    row.dst_ip,
                    row.dst_port,
                    human_bytes(row.bytes),
                    row.packets
                );
            }
        }
        println!();
        render_top_rows("Top QUIC(udp/443)", &top_quic, false);
        render_top_rows("Top DoH (suspected)", &top_doh, false);
        render_top_rows("Top DoT (853)", &top_dot, false);

        println!("== Unknown Detail (direction/proto/port) ==");
        if unknown_detail.is_empty() {
            println!("(empty)");
        } else {
            for row in unknown_detail {
                println!(
                    "direction={} proto={} sport={} dport={} status={} bytes={} packets={}",
                    direction_str(row.direction),
                    proto_str(row.proto),
                    row.src_port,
                    row.dst_port,
                    row.attribution_status,
                    human_bytes(row.bytes),
                    row.packets
                );
            }
        }
        println!();

        std::thread::sleep(cfg.refresh);
    }
}

fn render_top_rows(title: &str, rows: &[TopRow], count_only: bool) {
    println!("== {} ==", title);
    if rows.is_empty() {
        println!("(empty)");
        println!();
        return;
    }

    for row in rows {
        if count_only {
            println!("{}\tcount={}", row.key, row.bytes);
        } else {
            println!(
                "{}\tbytes={}\tpackets={}",
                row.key,
                human_bytes(row.bytes),
                row.packets
            );
        }
    }
    println!();
}

fn render_collector_health(rows: &[CollectorHealthRow]) {
    println!("== Collector Health ==");
    if rows.is_empty() {
        println!("(empty)");
        println!();
        return;
    }

    for row in rows {
        let usage = if FLOW_STATS_MAX_ENTRIES == 0 {
            0.0
        } else {
            row.flow_entries as f64 * 100.0 / FLOW_STATS_MAX_ENTRIES as f64
        };
        println!(
            "ts_minute={} flow_entries={} ({:.2}%) flow_evicted={} flow_insert_drop={} dns_ringbuf_drop={} tls_ringbuf_drop={}",
            row.ts_minute,
            row.flow_entries,
            usage,
            row.flow_evicted,
            row.flow_insert_drop,
            row.dns_ringbuf_drop,
            row.tls_ringbuf_drop
        );
    }
    println!();
}

fn human_bytes(v: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let x = v as f64;
    if x >= GB {
        format!("{:.2} GiB", x / GB)
    } else if x >= MB {
        format!("{:.2} MiB", x / MB)
    } else if x >= KB {
        format!("{:.2} KiB", x / KB)
    } else {
        format!("{} B", v)
    }
}
