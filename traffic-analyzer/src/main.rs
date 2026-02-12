mod collector;
mod db;
mod dns;
mod model;
mod tls;
mod ui;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use collector::{BpfObject, RunConfig};
use db::Database;
use model::{direction_str, proto_str};
use tracing::debug;
use ui::UiConfig;

#[cfg(embedded_bpf)]
static EMBEDDED_BPF_OBJECT: &[u8] = include_bytes!(env!("TRAFFIC_ANALYZER_EMBED_BPF_PATH"));

#[derive(Parser, Debug)]
#[command(name = "traffic-analyzer")]
#[command(about = "Analyze per-interface traffic and DNS attribution with eBPF + aya")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Start collection loop and persist into SQLite.
    Run {
        #[arg(long)]
        iface: String,

        /// Optional eBPF object path. If omitted, auto-detect local build artifact, then fallback to embedded object.
        #[arg(long)]
        bpf_object: Option<String>,

        #[arg(long, default_value = "./traffic-analyzer.db")]
        db: String,

        #[arg(long, default_value_t = 1)]
        flush_interval_secs: u64,

        #[arg(long, default_value_t = 600)]
        dns_ttl_cap_secs: u64,

        #[arg(long, default_value_t = 300)]
        sni_ttl_cap_secs: u64,

        #[arg(long, default_value_t = 900)]
        flow_idle_timeout_secs: u64,
    },

    /// Show top peer IP by bytes in lookback window.
    TopIp {
        #[arg(long)]
        iface: String,

        #[arg(long, default_value = "./traffic-analyzer.db")]
        db: String,

        #[arg(long, default_value_t = 60)]
        lookback_minutes: i64,

        #[arg(long, default_value_t = 20)]
        limit: i64,
    },

    /// Show top LAN/local IP by bytes in lookback window.
    TopLan {
        #[arg(long)]
        iface: String,

        #[arg(long, default_value = "./traffic-analyzer.db")]
        db: String,

        #[arg(long, default_value_t = 60)]
        lookback_minutes: i64,

        #[arg(long, default_value_t = 20)]
        limit: i64,
    },

    /// Show top 5-tuple flow by bytes in lookback window.
    TopFlow {
        #[arg(long)]
        iface: String,

        #[arg(long, default_value = "./traffic-analyzer.db")]
        db: String,

        #[arg(long, default_value_t = 60)]
        lookback_minutes: i64,

        #[arg(long, default_value_t = 20)]
        limit: i64,
    },

    /// Show top domain by bytes in lookback window.
    TopDomain {
        #[arg(long)]
        iface: String,

        #[arg(long, default_value = "./traffic-analyzer.db")]
        db: String,

        #[arg(long, default_value_t = 60)]
        lookback_minutes: i64,

        #[arg(long, default_value_t = 20)]
        limit: i64,
    },

    /// Show top DNS query domains by count in lookback window.
    TopDns {
        #[arg(long)]
        iface: String,

        #[arg(long, default_value = "./traffic-analyzer.db")]
        db: String,

        #[arg(long, default_value_t = 60)]
        lookback_minutes: i64,

        #[arg(long, default_value_t = 20)]
        limit: i64,
    },

    /// Show top TLS SNI by count in lookback window.
    TopSni {
        #[arg(long)]
        iface: String,

        #[arg(long, default_value = "./traffic-analyzer.db")]
        db: String,

        #[arg(long, default_value_t = 60)]
        lookback_minutes: i64,

        #[arg(long, default_value_t = 20)]
        limit: i64,
    },

    /// Show top QUIC(udp/443) traffic in lookback window.
    TopQuic {
        #[arg(long)]
        iface: String,

        #[arg(long, default_value = "./traffic-analyzer.db")]
        db: String,

        #[arg(long, default_value_t = 60)]
        lookback_minutes: i64,

        #[arg(long, default_value_t = 20)]
        limit: i64,
    },

    /// Show per-domain detail split by direction/proto/port.
    DomainDetail {
        #[arg(long)]
        iface: String,

        #[arg(long)]
        domain: String,

        #[arg(long, default_value = "./traffic-analyzer.db")]
        db: String,

        #[arg(long, default_value_t = 60)]
        lookback_minutes: i64,

        #[arg(long, default_value_t = 50)]
        limit: i64,
    },

    /// Show attribution coverage (exact/unknown) in lookback window.
    AttributionCoverage {
        #[arg(long)]
        iface: String,

        #[arg(long, default_value = "./traffic-analyzer.db")]
        db: String,

        #[arg(long, default_value_t = 60)]
        lookback_minutes: i64,
    },

    /// Show DNS cache behavior metrics in lookback window.
    DnsCacheInspect {
        #[arg(long)]
        iface: String,

        #[arg(long, default_value = "./traffic-analyzer.db")]
        db: String,

        #[arg(long, default_value_t = 60)]
        lookback_minutes: i64,

        #[arg(long, default_value_t = 20)]
        limit: i64,
    },

    /// Show collector health metrics (flow map pressure and ringbuf drops).
    CollectorHealth {
        #[arg(long)]
        iface: String,

        #[arg(long, default_value = "./traffic-analyzer.db")]
        db: String,

        #[arg(long, default_value_t = 60)]
        lookback_minutes: i64,

        #[arg(long, default_value_t = 20)]
        limit: i64,
    },

    /// Show suspected DoH/DoT traffic in lookback window.
    TopDohdot {
        #[arg(long)]
        iface: String,

        #[arg(long, default_value = "./traffic-analyzer.db")]
        db: String,

        #[arg(long, default_value_t = 60)]
        lookback_minutes: i64,

        #[arg(long, default_value_t = 20)]
        limit: i64,
    },

    /// Live dashboard in terminal.
    Ui {
        #[arg(long)]
        iface: String,

        #[arg(long, default_value = "./traffic-analyzer.db")]
        db: String,

        #[arg(long, default_value_t = 60)]
        lookback_minutes: i64,

        #[arg(long, default_value_t = 10)]
        limit: i64,

        #[arg(long, default_value_t = 2)]
        refresh_secs: u64,
    },

    /// Delete historical rows older than retention days.
    Prune {
        #[arg(long, default_value = "./traffic-analyzer.db")]
        db: String,

        #[arg(long, default_value_t = 30)]
        retention_days: i64,
    },
}

fn main() -> Result<()> {
    init_log();

    let cli = Cli::parse();
    match cli.command {
        Command::Run {
            iface,
            bpf_object,
            db,
            flush_interval_secs,
            dns_ttl_cap_secs,
            sni_ttl_cap_secs,
            flow_idle_timeout_secs,
        } => collector::run(RunConfig {
            iface,
            bpf_object: resolve_bpf_object(bpf_object)?,
            db_path: db,
            flush_interval: Duration::from_secs(flush_interval_secs),
            dns_ttl_cap_secs,
            sni_ttl_cap_secs,
            flow_idle_timeout_secs,
        }),
        Command::TopIp {
            iface,
            db,
            lookback_minutes,
            limit,
        } => {
            let db = Database::open_for_query(&db)?;
            let rows = db.top_ip(&iface, lookback_minutes, limit)?;
            print_rows_or_empty(&rows, |row| println!("{}", row));
            Ok(())
        }
        Command::TopLan {
            iface,
            db,
            lookback_minutes,
            limit,
        } => {
            let db = Database::open_for_query(&db)?;
            let rows = db.top_lan_ip(&iface, lookback_minutes, limit)?;
            print_rows_or_empty(&rows, |row| println!("{}", row));
            Ok(())
        }
        Command::TopFlow {
            iface,
            db,
            lookback_minutes,
            limit,
        } => {
            let db = Database::open_for_query(&db)?;
            let rows = db.top_flow(&iface, lookback_minutes, limit)?;
            print_rows_or_empty(&rows, |row| {
                println!(
                    "direction={}\tproto={}\t{}:{} -> {}:{}\tbytes={}\tpackets={}",
                    direction_str(row.direction),
                    proto_str(row.proto),
                    row.src_ip,
                    row.src_port,
                    row.dst_ip,
                    row.dst_port,
                    row.bytes,
                    row.packets
                );
            });
            Ok(())
        }
        Command::TopDomain {
            iface,
            db,
            lookback_minutes,
            limit,
        } => {
            let db = Database::open_for_query(&db)?;
            let rows = db.top_domain(&iface, lookback_minutes, limit)?;
            print_rows_or_empty(&rows, |row| println!("{}", row));
            Ok(())
        }
        Command::TopDns {
            iface,
            db,
            lookback_minutes,
            limit,
        } => {
            let db = Database::open_for_query(&db)?;
            let rows = db.top_dns_query(&iface, lookback_minutes, limit)?;
            print_rows_or_empty(&rows, |row| println!("{}\tcount={}", row.key, row.bytes));
            Ok(())
        }
        Command::TopSni {
            iface,
            db,
            lookback_minutes,
            limit,
        } => {
            let db = Database::open_for_query(&db)?;
            let rows = db.top_sni(&iface, lookback_minutes, limit)?;
            print_rows_or_empty(&rows, |row| println!("{}\tcount={}", row.key, row.bytes));
            Ok(())
        }
        Command::TopQuic {
            iface,
            db,
            lookback_minutes,
            limit,
        } => {
            let db = Database::open_for_query(&db)?;
            let rows = db.top_quic(&iface, lookback_minutes, limit)?;
            print_rows_or_empty(&rows, |row| println!("{}", row));
            Ok(())
        }
        Command::DomainDetail {
            iface,
            domain,
            db,
            lookback_minutes,
            limit,
        } => {
            let db = Database::open_for_query(&db)?;
            let rows = db.domain_detail(&iface, &domain, lookback_minutes, limit)?;
            print_rows_or_empty(&rows, |row| {
                println!(
                    "direction={}\tproto={}\tsport={}\tdport={}\tstatus={}\tbytes={}\tpackets={}",
                    direction_str(row.direction),
                    proto_str(row.proto),
                    row.src_port,
                    row.dst_port,
                    row.attribution_status,
                    row.bytes,
                    row.packets
                );
            });
            Ok(())
        }
        Command::AttributionCoverage {
            iface,
            db,
            lookback_minutes,
        } => {
            let db = Database::open_for_query(&db)?;
            let rows = db.attribution_coverage(&iface, lookback_minutes)?;
            if rows.is_empty() {
                println!("(empty)");
                return Ok(());
            }
            let total_bytes = rows.iter().map(|v| v.bytes).sum::<u64>().max(1);
            for row in rows {
                let ratio = (row.bytes as f64) * 100.0 / (total_bytes as f64);
                println!(
                    "status={}\tbytes={}\tpackets={}\tratio={:.2}%",
                    row.status, row.bytes, row.packets, ratio
                );
            }
            Ok(())
        }
        Command::DnsCacheInspect {
            iface,
            db,
            lookback_minutes,
            limit,
        } => {
            let db = Database::open_for_query(&db)?;
            let rows = db.dns_cache_inspect(&iface, lookback_minutes, limit)?;
            print_rows_or_empty(&rows, |row| {
                println!(
                    "ts_minute={}\tcache_entries={}\tdns_answers={}\tsni_events={}\tnew={}\trefresh={}\texpired={}",
                    row.ts_minute,
                    row.cache_entries,
                    row.dns_answer_events,
                    row.sni_events,
                    row.new_entries,
                    row.refresh_entries,
                    row.expired_entries
                );
            });
            Ok(())
        }
        Command::CollectorHealth {
            iface,
            db,
            lookback_minutes,
            limit,
        } => {
            let db = Database::open_for_query(&db)?;
            let rows = db.collector_health(&iface, lookback_minutes, limit)?;
            print_rows_or_empty(&rows, |row| {
                println!(
                    "ts_minute={}\tflow_entries={}\tflow_evicted={}\tflow_insert_drop={}\tdns_ringbuf_drop={}\ttls_ringbuf_drop={}",
                    row.ts_minute,
                    row.flow_entries,
                    row.flow_evicted,
                    row.flow_insert_drop,
                    row.dns_ringbuf_drop,
                    row.tls_ringbuf_drop
                );
            });
            Ok(())
        }
        Command::TopDohdot {
            iface,
            db,
            lookback_minutes,
            limit,
        } => {
            let db = Database::open_for_query(&db)?;
            println!("## DoH (suspected)");
            let doh_rows = db.top_doh(&iface, lookback_minutes, limit)?;
            print_rows_or_empty(&doh_rows, |row| println!("{}", row));
            println!("## DoT");
            let dot_rows = db.top_dot(&iface, lookback_minutes, limit)?;
            print_rows_or_empty(&dot_rows, |row| println!("{}", row));
            Ok(())
        }
        Command::Ui {
            iface,
            db,
            lookback_minutes,
            limit,
            refresh_secs,
        } => ui::run(UiConfig {
            iface,
            db_path: db,
            lookback_minutes,
            limit,
            refresh: Duration::from_secs(refresh_secs.max(1)),
        }),
        Command::Prune { db, retention_days } => {
            let db = Database::open(&db)?;
            db.prune(retention_days)?;
            println!("prune complete: retention_days={}", retention_days);
            Ok(())
        }
    }
}

fn init_log() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,aya=warn".into()),
        )
        .with_target(true)
        .try_init();
}

fn resolve_bpf_object(input: Option<String>) -> Result<BpfObject> {
    if let Some(path) = input {
        return Ok(BpfObject::Path(path));
    }

    let candidates = [
        "./traffic-analyzer-ebpf.o",
        "./target/bpfel-unknown-none/release/traffic-analyzer-ebpf",
        "./target/bpfel-unknown-none/debug/traffic-analyzer-ebpf",
        "./target/bpfel-unknown-none/release/traffic_analyzer_ebpf",
        "./target/bpfel-unknown-none/debug/traffic_analyzer_ebpf",
        "./target/bpfel-unknown-none/release/libtraffic_analyzer_ebpf.so",
        "./target/bpfel-unknown-none/debug/libtraffic_analyzer_ebpf.so",
    ];

    for candidate in candidates {
        if PathBuf::from(candidate).exists() {
            return Ok(BpfObject::Path(candidate.to_string()));
        }
    }

    #[cfg(embedded_bpf)]
    {
        let magic = if EMBEDDED_BPF_OBJECT.len() >= 4 {
            Some([
                EMBEDDED_BPF_OBJECT[0],
                EMBEDDED_BPF_OBJECT[1],
                EMBEDDED_BPF_OBJECT[2],
                EMBEDDED_BPF_OBJECT[3],
            ])
        } else {
            None
        };
        debug!(
            embedded_len = EMBEDDED_BPF_OBJECT.len(),
            embedded_magic = ?magic,
            "fallback to embedded bpf object"
        );
        Ok(BpfObject::Embedded(EMBEDDED_BPF_OBJECT))
    }
    #[cfg(not(embedded_bpf))]
    {
        anyhow::bail!(
            "cannot find eBPF object automatically; pass --bpf-object <path>, or build a single-binary release with embedded eBPF"
        )
    }
}

fn print_rows_or_empty<T, F>(rows: &[T], mut render: F)
where
    F: FnMut(&T),
{
    if rows.is_empty() {
        println!("(empty)");
        return;
    }
    for row in rows {
        render(row);
    }
}
