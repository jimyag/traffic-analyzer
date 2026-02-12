use std::io::{self, Read, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use traffic_analyzer_common::FLOW_STATS_MAX_ENTRIES;

use crate::db::Database;
use crate::model::{direction_str, proto_str, CollectorHealthRow, TopRow};

const PANEL_GAP: usize = 2;
const MAX_PANEL_ROWS: usize = 8;
const MIN_SINGLE_PANEL_WIDTH: usize = 52;
const MIN_DOUBLE_PANEL_WIDTH: usize = 120;
const INPUT_POLL_INTERVAL: Duration = Duration::from_millis(120);
const PAGE_TITLES: [&str; 3] = ["Overview", "Signals", "Flow"];

pub struct UiConfig {
    pub iface: String,
    pub db_path: String,
    pub lookback_minutes: i64,
    pub limit: i64,
    pub refresh: Duration,
}

#[derive(Clone, Debug)]
struct Panel {
    title: String,
    lines: Vec<String>,
}

#[derive(Clone, Debug)]
struct DashboardData {
    coverage: Vec<crate::model::AttributionCoverageRow>,
    collector_health: Vec<CollectorHealthRow>,
    top_domain: Vec<TopRow>,
    top_ip: Vec<TopRow>,
    top_lan_ip: Vec<TopRow>,
    top_dns: Vec<TopRow>,
    top_sni: Vec<TopRow>,
    top_quic: Vec<TopRow>,
    top_doh: Vec<TopRow>,
    top_dot: Vec<TopRow>,
    top_flow: Vec<crate::model::FlowTupleRow>,
    unknown_detail: Vec<crate::model::DomainDetailRow>,
}

#[derive(Clone, Copy, Debug)]
enum UiKey {
    NextTab,
    PrevTab,
    SelectPage(usize),
    Quit,
}

#[derive(Clone, Copy, Debug)]
struct UiState {
    active_page: usize,
}

impl UiState {
    fn new() -> Self {
        Self { active_page: 0 }
    }

    fn next_page(&mut self) {
        self.active_page = (self.active_page + 1) % PAGE_TITLES.len();
    }

    fn prev_page(&mut self) {
        self.active_page = if self.active_page == 0 {
            PAGE_TITLES.len() - 1
        } else {
            self.active_page - 1
        };
    }

    fn set_page(&mut self, idx: usize) {
        if idx < PAGE_TITLES.len() {
            self.active_page = idx;
        }
    }
}

struct TerminalModeGuard {
    restore: Option<(libc::termios, i32)>,
}

impl TerminalModeGuard {
    fn enter() -> io::Result<Self> {
        if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
            return Ok(Self { restore: None });
        }

        let mut term = libc::termios {
            c_iflag: 0,
            c_oflag: 0,
            c_cflag: 0,
            c_lflag: 0,
            c_line: 0,
            c_cc: [0; 32],
            c_ispeed: 0,
            c_ospeed: 0,
        };
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut term as *mut _) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let original = term;

        term.c_lflag &= !(libc::ICANON | libc::ECHO);
        term.c_cc[libc::VMIN] = 0;
        term.c_cc[libc::VTIME] = 0;
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &term as *const _) } != 0 {
            return Err(io::Error::last_os_error());
        }

        let flags = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0
        {
            return Err(io::Error::last_os_error());
        }

        print!("\x1B[?25l");
        let _ = io::stdout().flush();

        Ok(Self {
            restore: Some((original, flags)),
        })
    }
}

impl Drop for TerminalModeGuard {
    fn drop(&mut self) {
        if let Some((orig_term, orig_flags)) = self.restore {
            let _ = unsafe {
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &orig_term as *const _)
            };
            let _ = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_SETFL, orig_flags) };
        }
        print!("\x1B[?25h\n");
        let _ = io::stdout().flush();
    }
}

pub fn run(cfg: UiConfig) -> Result<()> {
    let db = Database::open_for_query(&cfg.db_path)?;
    let _guard = TerminalModeGuard::enter()?;

    let mut state = UiState::new();
    let mut data = fetch_dashboard_data(&db, &cfg)?;
    let mut last_fetch = Instant::now();
    draw_dashboard(&cfg, &state, &data, last_fetch.elapsed())?;

    loop {
        let mut need_redraw = false;
        for key in read_keys()? {
            match key {
                UiKey::NextTab => {
                    state.next_page();
                    need_redraw = true;
                }
                UiKey::PrevTab => {
                    state.prev_page();
                    need_redraw = true;
                }
                UiKey::SelectPage(idx) => {
                    state.set_page(idx);
                    need_redraw = true;
                }
                UiKey::Quit => return Ok(()),
            }
        }

        if last_fetch.elapsed() >= cfg.refresh {
            data = fetch_dashboard_data(&db, &cfg)?;
            last_fetch = Instant::now();
            need_redraw = true;
        }

        if need_redraw {
            draw_dashboard(&cfg, &state, &data, last_fetch.elapsed())?;
        }

        std::thread::sleep(INPUT_POLL_INTERVAL);
    }
}

fn fetch_dashboard_data(db: &Database, cfg: &UiConfig) -> Result<DashboardData> {
    Ok(DashboardData {
        coverage: db.attribution_coverage(&cfg.iface, cfg.lookback_minutes)?,
        collector_health: db.collector_health(
            &cfg.iface,
            cfg.lookback_minutes,
            cfg.limit.max(5),
        )?,
        top_domain: db.top_domain(&cfg.iface, cfg.lookback_minutes, cfg.limit)?,
        top_ip: db.top_ip(&cfg.iface, cfg.lookback_minutes, cfg.limit)?,
        top_lan_ip: db.top_lan_ip(&cfg.iface, cfg.lookback_minutes, cfg.limit)?,
        top_dns: db.top_dns_query(&cfg.iface, cfg.lookback_minutes, cfg.limit)?,
        top_sni: db.top_sni(&cfg.iface, cfg.lookback_minutes, cfg.limit)?,
        top_quic: db.top_quic(&cfg.iface, cfg.lookback_minutes, cfg.limit)?,
        top_doh: db.top_doh(&cfg.iface, cfg.lookback_minutes, cfg.limit)?,
        top_dot: db.top_dot(&cfg.iface, cfg.lookback_minutes, cfg.limit)?,
        top_flow: db.top_flow(&cfg.iface, cfg.lookback_minutes, cfg.limit)?,
        unknown_detail: db.domain_detail(
            &cfg.iface,
            "(unknown)",
            cfg.lookback_minutes,
            cfg.limit.max(5),
        )?,
    })
}

fn draw_dashboard(
    cfg: &UiConfig,
    state: &UiState,
    data: &DashboardData,
    data_age: Duration,
) -> io::Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs();
    let (term_w, _) = terminal_size();
    let width = term_w.max(MIN_SINGLE_PANEL_WIDTH);

    let mut out = String::new();
    out.push_str("\x1B[2J\x1B[H");
    out.push_str(&format!(
        "LAS Traffic Dashboard | iface={} | lookback={}m | refresh={}s | now={}\n",
        cfg.iface,
        cfg.lookback_minutes,
        cfg.refresh.as_secs(),
        now
    ));
    out.push_str(&format!(
        "db={} | flow_map_capacity={} | data_age={}s\n",
        cfg.db_path,
        FLOW_STATS_MAX_ENTRIES,
        data_age.as_secs()
    ));
    out.push_str(&format!(
        "{}\n\n",
        truncate_str(
            &render_tabs_line(state.active_page),
            width.saturating_sub(1).max(1)
        )
    ));

    match state.active_page {
        0 => render_overview_page(data, width, &mut out),
        1 => render_signals_page(data, width, &mut out),
        _ => render_flow_page(data, width, &mut out),
    }

    print!("{}", out);
    io::stdout().flush()
}

fn render_tabs_line(active_page: usize) -> String {
    let mut parts = Vec::new();
    for (idx, title) in PAGE_TITLES.iter().enumerate() {
        let tag = if idx == active_page {
            format!("[{}:{}*]", idx + 1, title)
        } else {
            format!("[{}:{}]", idx + 1, title)
        };
        parts.push(tag);
    }
    format!(
        "Tabs {} | Tab/Shift+Tab or Left/Right switch | q quit",
        parts.join(" ")
    )
}

fn render_overview_page(data: &DashboardData, width: usize, out: &mut String) {
    let summary_lines = build_summary_lines(&data.coverage, &data.collector_health);
    render_panel(
        &Panel {
            title: "Summary".to_string(),
            lines: summary_lines,
        },
        width,
        out,
    );

    if width >= MIN_DOUBLE_PANEL_WIDTH {
        render_panel_pair(
            &Panel {
                title: "Top Domain".to_string(),
                lines: top_row_lines(&data.top_domain, false),
            },
            &Panel {
                title: "Top Peer IP".to_string(),
                lines: top_row_lines(&data.top_ip, false),
            },
            width,
            out,
        );
        render_panel_pair(
            &Panel {
                title: "Top LAN IP".to_string(),
                lines: top_row_lines(&data.top_lan_ip, false),
            },
            &Panel {
                title: "Top Flow (preview)".to_string(),
                lines: top_flow_lines(&data.top_flow),
            },
            width,
            out,
        );
    } else {
        render_panel(
            &Panel {
                title: "Top Domain".to_string(),
                lines: top_row_lines(&data.top_domain, false),
            },
            width,
            out,
        );
        render_panel(
            &Panel {
                title: "Top Peer IP".to_string(),
                lines: top_row_lines(&data.top_ip, false),
            },
            width,
            out,
        );
        render_panel(
            &Panel {
                title: "Top LAN IP".to_string(),
                lines: top_row_lines(&data.top_lan_ip, false),
            },
            width,
            out,
        );
    }
}

fn render_signals_page(data: &DashboardData, width: usize, out: &mut String) {
    if width >= MIN_DOUBLE_PANEL_WIDTH {
        render_panel_pair(
            &Panel {
                title: "Top DNS".to_string(),
                lines: top_row_lines(&data.top_dns, true),
            },
            &Panel {
                title: "Top SNI".to_string(),
                lines: top_row_lines(&data.top_sni, true),
            },
            width,
            out,
        );
        render_panel_pair(
            &Panel {
                title: "Top QUIC (udp/443)".to_string(),
                lines: top_row_lines(&data.top_quic, false),
            },
            &Panel {
                title: "Top DoH (suspected)".to_string(),
                lines: top_row_lines(&data.top_doh, false),
            },
            width,
            out,
        );
        render_panel_pair(
            &Panel {
                title: "Top DoT (853)".to_string(),
                lines: top_row_lines(&data.top_dot, false),
            },
            &Panel {
                title: "Top Domain".to_string(),
                lines: top_row_lines(&data.top_domain, false),
            },
            width,
            out,
        );
    } else {
        render_panel(
            &Panel {
                title: "Top DNS".to_string(),
                lines: top_row_lines(&data.top_dns, true),
            },
            width,
            out,
        );
        render_panel(
            &Panel {
                title: "Top SNI".to_string(),
                lines: top_row_lines(&data.top_sni, true),
            },
            width,
            out,
        );
        render_panel(
            &Panel {
                title: "Top QUIC (udp/443)".to_string(),
                lines: top_row_lines(&data.top_quic, false),
            },
            width,
            out,
        );
        render_panel(
            &Panel {
                title: "Top DoH (suspected)".to_string(),
                lines: top_row_lines(&data.top_doh, false),
            },
            width,
            out,
        );
        render_panel(
            &Panel {
                title: "Top DoT (853)".to_string(),
                lines: top_row_lines(&data.top_dot, false),
            },
            width,
            out,
        );
    }
}

fn render_flow_page(data: &DashboardData, width: usize, out: &mut String) {
    render_panel(
        &Panel {
            title: "Top Flow (5-tuple)".to_string(),
            lines: top_flow_lines(&data.top_flow),
        },
        width,
        out,
    );
    render_panel(
        &Panel {
            title: "Unknown Detail".to_string(),
            lines: unknown_detail_lines(&data.unknown_detail),
        },
        width,
        out,
    );
}

fn build_summary_lines(
    coverage: &[crate::model::AttributionCoverageRow],
    collector_health: &[CollectorHealthRow],
) -> Vec<String> {
    let mut lines = Vec::new();

    if coverage.is_empty() {
        lines.push("coverage: (empty)".to_string());
    } else {
        let total_bytes = coverage.iter().map(|v| v.bytes).sum::<u64>().max(1);
        for row in coverage.iter().take(MAX_PANEL_ROWS) {
            let ratio = row.bytes as f64 * 100.0 / total_bytes as f64;
            lines.push(format!(
                "coverage status={} bytes={} packets={} ratio={:.2}%",
                row.status,
                human_bytes(row.bytes),
                row.packets,
                ratio
            ));
        }
    }

    if collector_health.is_empty() {
        lines.push("collector: (empty)".to_string());
    } else {
        let latest = &collector_health[0];
        let usage = if FLOW_STATS_MAX_ENTRIES == 0 {
            0.0
        } else {
            latest.flow_entries as f64 * 100.0 / FLOW_STATS_MAX_ENTRIES as f64
        };
        let sum_flow_drop = collector_health
            .iter()
            .map(|v| v.flow_insert_drop)
            .sum::<u64>();
        let sum_dns_drop = collector_health
            .iter()
            .map(|v| v.dns_ringbuf_drop)
            .sum::<u64>();
        let sum_tls_drop = collector_health
            .iter()
            .map(|v| v.tls_ringbuf_drop)
            .sum::<u64>();
        lines.push(format!(
            "collector ts_minute={} flow_entries={} ({:.2}%) evicted={} flow_drop={} dns_drop={} tls_drop={}",
            latest.ts_minute,
            latest.flow_entries,
            usage,
            latest.flow_evicted,
            sum_flow_drop,
            sum_dns_drop,
            sum_tls_drop
        ));
    }

    lines
}

fn top_row_lines(rows: &[TopRow], count_only: bool) -> Vec<String> {
    if rows.is_empty() {
        return vec!["(empty)".to_string()];
    }
    rows.iter()
        .take(MAX_PANEL_ROWS)
        .map(|row| {
            if count_only {
                format!("{} | count={}", row.key, row.bytes)
            } else {
                format!(
                    "{} | bytes={} packets={}",
                    row.key,
                    human_bytes(row.bytes),
                    row.packets
                )
            }
        })
        .collect()
}

fn top_flow_lines(rows: &[crate::model::FlowTupleRow]) -> Vec<String> {
    if rows.is_empty() {
        return vec!["(empty)".to_string()];
    }
    rows.iter()
        .take(MAX_PANEL_ROWS)
        .map(|row| {
            format!(
                "{} {} {}:{} -> {}:{} | bytes={} packets={}",
                direction_str(row.direction),
                proto_str(row.proto),
                row.src_ip,
                row.src_port,
                row.dst_ip,
                row.dst_port,
                human_bytes(row.bytes),
                row.packets
            )
        })
        .collect()
}

fn unknown_detail_lines(rows: &[crate::model::DomainDetailRow]) -> Vec<String> {
    if rows.is_empty() {
        return vec!["(empty)".to_string()];
    }
    rows.iter()
        .take(MAX_PANEL_ROWS)
        .map(|row| {
            format!(
                "{} {} sport={} dport={} status={} | bytes={} packets={}",
                direction_str(row.direction),
                proto_str(row.proto),
                row.src_port,
                row.dst_port,
                row.attribution_status,
                human_bytes(row.bytes),
                row.packets
            )
        })
        .collect()
}

fn render_panel_pair(left: &Panel, right: &Panel, total_width: usize, out: &mut String) {
    let col_width = (total_width.saturating_sub(PANEL_GAP)) / 2;
    let left_lines = panel_lines(left, col_width);
    let right_lines = panel_lines(right, col_width);
    let max_len = left_lines.len().max(right_lines.len());

    for idx in 0..max_len {
        let l = left_lines
            .get(idx)
            .cloned()
            .unwrap_or_else(|| " ".repeat(col_width));
        let r = right_lines
            .get(idx)
            .cloned()
            .unwrap_or_else(|| " ".repeat(col_width));
        out.push_str(&l);
        out.push_str(&" ".repeat(PANEL_GAP));
        out.push_str(&r);
        out.push('\n');
    }
    out.push('\n');
}

fn render_panel(panel: &Panel, width: usize, out: &mut String) {
    for line in panel_lines(panel, width) {
        out.push_str(&line);
        out.push('\n');
    }
    out.push('\n');
}

fn panel_lines(panel: &Panel, width: usize) -> Vec<String> {
    let width = width.max(MIN_SINGLE_PANEL_WIDTH);
    let inner = width.saturating_sub(2);
    let mut lines = Vec::new();
    lines.push(format!("+{}+", "-".repeat(inner)));
    lines.push(format!(
        "|{}|",
        pad_str(&truncate_str(&panel.title, inner), inner)
    ));
    lines.push(format!("+{}+", "-".repeat(inner)));

    if panel.lines.is_empty() {
        lines.push(format!("|{}|", pad_str("(empty)", inner)));
    } else {
        for line in panel.lines.iter().take(MAX_PANEL_ROWS) {
            lines.push(format!("|{}|", pad_str(&truncate_str(line, inner), inner)));
        }
    }
    lines.push(format!("+{}+", "-".repeat(inner)));
    lines
}

fn read_keys() -> io::Result<Vec<UiKey>> {
    let mut keys = Vec::new();
    let mut stdin = io::stdin();
    loop {
        let mut buf = [0u8; 64];
        match stdin.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => parse_keys(&buf[..n], &mut keys),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(err) => return Err(err),
        }
    }
    Ok(keys)
}

fn parse_keys(bytes: &[u8], out: &mut Vec<UiKey>) {
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\t' {
            out.push(UiKey::NextTab);
            i += 1;
            continue;
        }
        if b == 3 || b == b'q' || b == b'Q' {
            out.push(UiKey::Quit);
            i += 1;
            continue;
        }
        if (b'1'..=b'9').contains(&b) {
            out.push(UiKey::SelectPage((b - b'1') as usize));
            i += 1;
            continue;
        }
        if b == 27 && i + 2 < bytes.len() && bytes[i + 1] == b'[' {
            match bytes[i + 2] {
                b'C' => out.push(UiKey::NextTab), // Right arrow
                b'D' => out.push(UiKey::PrevTab), // Left arrow
                b'Z' => out.push(UiKey::PrevTab), // Shift+Tab
                _ => {}
            }
            i += 3;
            continue;
        }
        i += 1;
    }
}

fn truncate_str(input: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let count = input.chars().count();
    if count <= max_chars {
        return input.to_string();
    }
    if max_chars <= 3 {
        return ".".repeat(max_chars);
    }
    let kept = max_chars.saturating_sub(3);
    let mut out = input.chars().take(kept).collect::<String>();
    out.push_str("...");
    out
}

fn pad_str(input: &str, width: usize) -> String {
    let mut out = input.to_string();
    let chars = out.chars().count();
    if chars < width {
        out.push_str(&" ".repeat(width - chars));
    }
    out
}

fn terminal_size() -> (usize, usize) {
    let mut ws = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    let ok = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws as *mut _) } == 0;
    if ok && ws.ws_col > 0 && ws.ws_row > 0 {
        return (ws.ws_col as usize, ws.ws_row as usize);
    }

    let width = std::env::var("COLUMNS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(140);
    let height = std::env::var("LINES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(40);
    (width, height)
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
