use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use anyhow::Result;
use rusqlite::{params, Connection, ErrorCode, OpenFlags, OptionalExtension};

use crate::model::{
    AttributionCoverageRow, CollectorHealthMinuteRow, CollectorHealthRow, DnsCacheInspectRow,
    DnsCacheMinuteRow, DnsMinuteRow, DomainDetailRow, FlowMinuteRow, FlowTupleRow, SniMinuteRow,
    TopRow,
};

pub struct Database {
    conn: Connection,
}

const LEGACY_FLOW_MIGRATION_KEY: &str = "flow_1m_migrated_to_5t_v1";

impl Database {
    pub fn open(path: &str) -> Result<Self> {
        ensure_db_parent_dir(path)?;
        let conn = Connection::open(path)?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;

            CREATE TABLE IF NOT EXISTS flow_1m_5t (
                ts_minute INTEGER NOT NULL,
                iface TEXT NOT NULL,
                direction INTEGER NOT NULL,
                proto INTEGER NOT NULL,
                src_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                dst_ip TEXT NOT NULL,
                dst_port INTEGER NOT NULL,
                domain TEXT NOT NULL,
                attribution_status TEXT NOT NULL,
                bytes INTEGER NOT NULL,
                packets INTEGER NOT NULL,
                PRIMARY KEY (
                    ts_minute,
                    iface,
                    direction,
                    proto,
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    domain,
                    attribution_status
                )
            );

            CREATE INDEX IF NOT EXISTS idx_flow_1m_5t_ts_iface_dir
                ON flow_1m_5t(ts_minute, iface, direction);
            CREATE INDEX IF NOT EXISTS idx_flow_1m_5t_domain_ts
                ON flow_1m_5t(domain, ts_minute);
            CREATE INDEX IF NOT EXISTS idx_flow_1m_5t_src_ip_ts
                ON flow_1m_5t(src_ip, ts_minute);
            CREATE INDEX IF NOT EXISTS idx_flow_1m_5t_dst_ip_ts
                ON flow_1m_5t(dst_ip, ts_minute);

            CREATE TABLE IF NOT EXISTS dns_1m (
                ts_minute INTEGER NOT NULL,
                iface TEXT NOT NULL,
                qname TEXT NOT NULL,
                qtype INTEGER NOT NULL,
                count INTEGER NOT NULL,
                PRIMARY KEY (ts_minute, iface, qname, qtype)
            );

            CREATE INDEX IF NOT EXISTS idx_dns_1m_qname_ts
                ON dns_1m(qname, ts_minute);

            CREATE TABLE IF NOT EXISTS sni_1m (
                ts_minute INTEGER NOT NULL,
                iface TEXT NOT NULL,
                sni TEXT NOT NULL,
                count INTEGER NOT NULL,
                PRIMARY KEY (ts_minute, iface, sni)
            );

            CREATE INDEX IF NOT EXISTS idx_sni_1m_sni_ts
                ON sni_1m(sni, ts_minute);

            CREATE TABLE IF NOT EXISTS dns_cache_1m (
                ts_minute INTEGER NOT NULL,
                iface TEXT NOT NULL,
                cache_entries INTEGER NOT NULL,
                dns_answer_events INTEGER NOT NULL,
                sni_events INTEGER NOT NULL,
                new_entries INTEGER NOT NULL,
                refresh_entries INTEGER NOT NULL,
                expired_entries INTEGER NOT NULL,
                PRIMARY KEY (ts_minute, iface)
            );

            CREATE INDEX IF NOT EXISTS idx_dns_cache_1m_ts_iface
                ON dns_cache_1m(ts_minute, iface);

            CREATE TABLE IF NOT EXISTS collector_health_1m (
                ts_minute INTEGER NOT NULL,
                iface TEXT NOT NULL,
                flow_entries INTEGER NOT NULL,
                flow_evicted INTEGER NOT NULL,
                flow_insert_drop INTEGER NOT NULL,
                dns_ringbuf_drop INTEGER NOT NULL,
                tls_ringbuf_drop INTEGER NOT NULL,
                PRIMARY KEY (ts_minute, iface)
            );

            CREATE INDEX IF NOT EXISTS idx_collector_health_1m_ts_iface
                ON collector_health_1m(ts_minute, iface);

            CREATE TABLE IF NOT EXISTS meta_kv (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            "#,
        )?;
        migrate_legacy_flow_table(&conn)?;

        Ok(Self { conn })
    }

    pub fn open_readonly(path: &str) -> Result<Self> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        Ok(Self { conn })
    }

    pub fn open_for_query(path: &str) -> Result<Self> {
        match Self::open(path) {
            Ok(db) => Ok(db),
            Err(err) if is_sqlite_readonly_error(&err) => {
                let db = Self::open_readonly(path)?;
                if !table_exists(&db.conn, "flow_1m_5t")? {
                    anyhow::bail!(
                        "database is readonly and schema flow_1m_5t is missing; run one writable command first (for example with sudo) to initialize/migrate this DB"
                    );
                }
                Ok(db)
            }
            Err(err) => Err(err),
        }
    }

    pub fn upsert_flow_rows(&mut self, rows: &[FlowMinuteRow]) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                r#"
                INSERT INTO flow_1m_5t (
                    ts_minute, iface, direction, proto,
                    src_ip, src_port, dst_ip, dst_port,
                    domain, attribution_status, bytes, packets
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                ON CONFLICT (
                    ts_minute, iface, direction, proto,
                    src_ip, src_port, dst_ip, dst_port,
                    domain, attribution_status
                ) DO UPDATE SET
                    bytes = flow_1m_5t.bytes + excluded.bytes,
                    packets = flow_1m_5t.packets + excluded.packets
                "#,
            )?;

            for row in rows {
                stmt.execute(params![
                    row.ts_minute,
                    row.iface,
                    row.direction,
                    row.proto,
                    row.src_ip,
                    row.src_port,
                    row.dst_ip,
                    row.dst_port,
                    row.domain,
                    row.attribution_status,
                    row.bytes,
                    row.packets,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn upsert_dns_rows(&mut self, rows: &[DnsMinuteRow]) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                r#"
                INSERT INTO dns_1m (ts_minute, iface, qname, qtype, count)
                VALUES (?1, ?2, ?3, ?4, ?5)
                ON CONFLICT (ts_minute, iface, qname, qtype) DO UPDATE SET
                    count = dns_1m.count + excluded.count
                "#,
            )?;

            for row in rows {
                stmt.execute(params![
                    row.ts_minute,
                    row.iface,
                    row.qname,
                    row.qtype,
                    row.count
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn upsert_sni_rows(&mut self, rows: &[SniMinuteRow]) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                r#"
                INSERT INTO sni_1m (ts_minute, iface, sni, count)
                VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT (ts_minute, iface, sni) DO UPDATE SET
                    count = sni_1m.count + excluded.count
                "#,
            )?;

            for row in rows {
                stmt.execute(params![row.ts_minute, row.iface, row.sni, row.count])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn upsert_dns_cache_rows(&mut self, rows: &[DnsCacheMinuteRow]) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                r#"
                INSERT INTO dns_cache_1m (
                    ts_minute, iface, cache_entries, dns_answer_events, sni_events,
                    new_entries, refresh_entries, expired_entries
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                ON CONFLICT (ts_minute, iface) DO UPDATE SET
                    cache_entries = MAX(dns_cache_1m.cache_entries, excluded.cache_entries),
                    dns_answer_events = dns_cache_1m.dns_answer_events + excluded.dns_answer_events,
                    sni_events = dns_cache_1m.sni_events + excluded.sni_events,
                    new_entries = dns_cache_1m.new_entries + excluded.new_entries,
                    refresh_entries = dns_cache_1m.refresh_entries + excluded.refresh_entries,
                    expired_entries = dns_cache_1m.expired_entries + excluded.expired_entries
                "#,
            )?;

            for row in rows {
                stmt.execute(params![
                    row.ts_minute,
                    row.iface,
                    row.cache_entries,
                    row.dns_answer_events,
                    row.sni_events,
                    row.new_entries,
                    row.refresh_entries,
                    row.expired_entries
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn upsert_collector_health_rows(
        &mut self,
        rows: &[CollectorHealthMinuteRow],
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                r#"
                INSERT INTO collector_health_1m (
                    ts_minute, iface, flow_entries, flow_evicted,
                    flow_insert_drop, dns_ringbuf_drop, tls_ringbuf_drop
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                ON CONFLICT (ts_minute, iface) DO UPDATE SET
                    flow_entries = MAX(collector_health_1m.flow_entries, excluded.flow_entries),
                    flow_evicted = collector_health_1m.flow_evicted + excluded.flow_evicted,
                    flow_insert_drop = collector_health_1m.flow_insert_drop + excluded.flow_insert_drop,
                    dns_ringbuf_drop = collector_health_1m.dns_ringbuf_drop + excluded.dns_ringbuf_drop,
                    tls_ringbuf_drop = collector_health_1m.tls_ringbuf_drop + excluded.tls_ringbuf_drop
                "#,
            )?;

            for row in rows {
                stmt.execute(params![
                    row.ts_minute,
                    row.iface,
                    row.flow_entries,
                    row.flow_evicted,
                    row.flow_insert_drop,
                    row.dns_ringbuf_drop,
                    row.tls_ringbuf_drop
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn top_ip(&self, iface: &str, lookback_minutes: i64, limit: i64) -> Result<Vec<TopRow>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                CASE WHEN direction = 0 THEN src_ip ELSE dst_ip END AS peer_ip,
                SUM(bytes) AS total_bytes,
                SUM(packets) AS total_packets
            FROM flow_1m_5t
            WHERE iface = ?1
              AND ts_minute >= strftime('%s','now') - (?2 * 60)
            GROUP BY peer_ip
            ORDER BY total_bytes DESC
            LIMIT ?3
            "#,
        )?;

        let rows = stmt
            .query_map(params![iface, lookback_minutes, limit], |row| {
                Ok(TopRow {
                    key: row.get(0)?,
                    bytes: row.get(1)?,
                    packets: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(rows)
    }

    pub fn top_lan_ip(
        &self,
        iface: &str,
        lookback_minutes: i64,
        limit: i64,
    ) -> Result<Vec<TopRow>> {
        let fetch_limit = limit.max(1).saturating_mul(10).max(100);
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                CASE WHEN direction = 0 THEN dst_ip ELSE src_ip END AS local_ip,
                SUM(bytes) AS total_bytes,
                SUM(packets) AS total_packets
            FROM flow_1m_5t
            WHERE iface = ?1
              AND ts_minute >= strftime('%s','now') - (?2 * 60)
              AND (CASE WHEN direction = 0 THEN dst_ip ELSE src_ip END) NOT IN ('0.0.0.0', '::')
            GROUP BY local_ip
            ORDER BY total_bytes DESC
            LIMIT ?3
            "#,
        )?;

        let rows = stmt
            .query_map(params![iface, lookback_minutes, fetch_limit], |row| {
                Ok(TopRow {
                    key: row.get(0)?,
                    bytes: row.get(1)?,
                    packets: row.get(2)?,
                })
            })?
            .filter_map(|row| match row {
                Ok(v) if is_lan_ip(&v.key) => Some(Ok(v)),
                Ok(_) => None,
                Err(err) => Some(Err(err)),
            })
            .take(limit.max(1) as usize)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(rows)
    }

    pub fn top_flow(
        &self,
        iface: &str,
        lookback_minutes: i64,
        limit: i64,
    ) -> Result<Vec<FlowTupleRow>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                direction, proto, src_ip, src_port, dst_ip, dst_port,
                SUM(bytes) AS total_bytes,
                SUM(packets) AS total_packets
            FROM flow_1m_5t
            WHERE iface = ?1
              AND ts_minute >= strftime('%s','now') - (?2 * 60)
            GROUP BY direction, proto, src_ip, src_port, dst_ip, dst_port
            ORDER BY total_bytes DESC
            LIMIT ?3
            "#,
        )?;

        let rows = stmt
            .query_map(params![iface, lookback_minutes, limit], |row| {
                Ok(FlowTupleRow {
                    direction: row.get(0)?,
                    proto: row.get(1)?,
                    src_ip: row.get(2)?,
                    src_port: row.get(3)?,
                    dst_ip: row.get(4)?,
                    dst_port: row.get(5)?,
                    bytes: row.get(6)?,
                    packets: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(rows)
    }

    pub fn top_domain(
        &self,
        iface: &str,
        lookback_minutes: i64,
        limit: i64,
    ) -> Result<Vec<TopRow>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                CASE WHEN domain = '' THEN '(unknown)' ELSE domain END AS d,
                SUM(bytes) AS total_bytes,
                SUM(packets) AS total_packets
            FROM flow_1m_5t
            WHERE iface = ?1
              AND ts_minute >= strftime('%s','now') - (?2 * 60)
            GROUP BY d
            ORDER BY total_bytes DESC
            LIMIT ?3
            "#,
        )?;

        let rows = stmt
            .query_map(params![iface, lookback_minutes, limit], |row| {
                Ok(TopRow {
                    key: row.get(0)?,
                    bytes: row.get(1)?,
                    packets: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(rows)
    }

    pub fn top_dns_query(
        &self,
        iface: &str,
        lookback_minutes: i64,
        limit: i64,
    ) -> Result<Vec<TopRow>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT qname, SUM(count) AS total_count
            FROM dns_1m
            WHERE iface = ?1
              AND ts_minute >= strftime('%s','now') - (?2 * 60)
            GROUP BY qname
            ORDER BY total_count DESC
            LIMIT ?3
            "#,
        )?;

        let rows = stmt
            .query_map(params![iface, lookback_minutes, limit], |row| {
                let count: u64 = row.get(1)?;
                Ok(TopRow {
                    key: row.get(0)?,
                    bytes: count,
                    packets: 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(rows)
    }

    pub fn top_sni(&self, iface: &str, lookback_minutes: i64, limit: i64) -> Result<Vec<TopRow>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT sni, SUM(count) AS total_count
            FROM sni_1m
            WHERE iface = ?1
              AND ts_minute >= strftime('%s','now') - (?2 * 60)
            GROUP BY sni
            ORDER BY total_count DESC
            LIMIT ?3
            "#,
        )?;

        let rows = stmt
            .query_map(params![iface, lookback_minutes, limit], |row| {
                let count: u64 = row.get(1)?;
                Ok(TopRow {
                    key: row.get(0)?,
                    bytes: count,
                    packets: 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn domain_detail(
        &self,
        iface: &str,
        domain: &str,
        lookback_minutes: i64,
        limit: i64,
    ) -> Result<Vec<DomainDetailRow>> {
        let domain_match = if domain == "(unknown)" { "" } else { domain };
        let mut stmt = self.conn.prepare(
            r#"
            SELECT direction, proto, src_port, dst_port, attribution_status, SUM(bytes), SUM(packets)
            FROM flow_1m_5t
            WHERE iface = ?1
              AND domain = ?2
              AND ts_minute >= strftime('%s','now') - (?3 * 60)
            GROUP BY direction, proto, src_port, dst_port, attribution_status
            ORDER BY SUM(bytes) DESC
            LIMIT ?4
            "#,
        )?;

        let rows = stmt
            .query_map(
                params![iface, domain_match, lookback_minutes, limit],
                |row| {
                    Ok(DomainDetailRow {
                        direction: row.get(0)?,
                        proto: row.get(1)?,
                        src_port: row.get(2)?,
                        dst_port: row.get(3)?,
                        attribution_status: row.get(4)?,
                        bytes: row.get(5)?,
                        packets: row.get(6)?,
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn attribution_coverage(
        &self,
        iface: &str,
        lookback_minutes: i64,
    ) -> Result<Vec<AttributionCoverageRow>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT attribution_status, SUM(bytes), SUM(packets)
            FROM flow_1m_5t
            WHERE iface = ?1
              AND ts_minute >= strftime('%s','now') - (?2 * 60)
            GROUP BY attribution_status
            ORDER BY SUM(bytes) DESC
            "#,
        )?;

        let rows = stmt
            .query_map(params![iface, lookback_minutes], |row| {
                Ok(AttributionCoverageRow {
                    status: row.get(0)?,
                    bytes: row.get(1)?,
                    packets: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn dns_cache_inspect(
        &self,
        iface: &str,
        lookback_minutes: i64,
        limit: i64,
    ) -> Result<Vec<DnsCacheInspectRow>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                ts_minute, cache_entries, dns_answer_events, sni_events,
                new_entries, refresh_entries, expired_entries
            FROM dns_cache_1m
            WHERE iface = ?1
              AND ts_minute >= strftime('%s','now') - (?2 * 60)
            ORDER BY ts_minute DESC
            LIMIT ?3
            "#,
        )?;

        let rows = stmt
            .query_map(params![iface, lookback_minutes, limit], |row| {
                Ok(DnsCacheInspectRow {
                    ts_minute: row.get(0)?,
                    cache_entries: row.get(1)?,
                    dns_answer_events: row.get(2)?,
                    sni_events: row.get(3)?,
                    new_entries: row.get(4)?,
                    refresh_entries: row.get(5)?,
                    expired_entries: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn collector_health(
        &self,
        iface: &str,
        lookback_minutes: i64,
        limit: i64,
    ) -> Result<Vec<CollectorHealthRow>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                ts_minute,
                MAX(flow_entries) AS flow_entries,
                SUM(flow_evicted) AS flow_evicted,
                SUM(flow_insert_drop) AS flow_insert_drop,
                SUM(dns_ringbuf_drop) AS dns_ringbuf_drop,
                SUM(tls_ringbuf_drop) AS tls_ringbuf_drop
            FROM collector_health_1m
            WHERE iface = ?1
              AND ts_minute >= strftime('%s','now') - (?2 * 60)
            GROUP BY ts_minute
            ORDER BY ts_minute DESC
            LIMIT ?3
            "#,
        )?;

        let rows = stmt
            .query_map(params![iface, lookback_minutes, limit], |row| {
                Ok(CollectorHealthRow {
                    ts_minute: row.get(0)?,
                    flow_entries: row.get(1)?,
                    flow_evicted: row.get(2)?,
                    flow_insert_drop: row.get(3)?,
                    dns_ringbuf_drop: row.get(4)?,
                    tls_ringbuf_drop: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn top_dot(&self, iface: &str, lookback_minutes: i64, limit: i64) -> Result<Vec<TopRow>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                CASE WHEN domain = '' THEN CASE WHEN direction = 0 THEN src_ip ELSE dst_ip END ELSE domain END AS target,
                SUM(bytes) AS total_bytes,
                SUM(packets) AS total_packets
            FROM flow_1m_5t
            WHERE iface = ?1
              AND (CASE WHEN direction = 0 THEN src_port ELSE dst_port END) = 853
              AND ts_minute >= strftime('%s','now') - (?2 * 60)
            GROUP BY target
            ORDER BY total_bytes DESC
            LIMIT ?3
            "#,
        )?;

        let rows = stmt
            .query_map(params![iface, lookback_minutes, limit], |row| {
                Ok(TopRow {
                    key: row.get(0)?,
                    bytes: row.get(1)?,
                    packets: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn top_doh(&self, iface: &str, lookback_minutes: i64, limit: i64) -> Result<Vec<TopRow>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT domain, SUM(bytes) AS total_bytes, SUM(packets) AS total_packets
            FROM flow_1m_5t
            WHERE iface = ?1
              AND (CASE WHEN direction = 0 THEN src_port ELSE dst_port END) = 443
              AND domain != ''
              AND (
                    lower(domain) = 'dns.google'
                 OR lower(domain) = 'cloudflare-dns.com'
                 OR lower(domain) = 'one.one.one.one'
                 OR lower(domain) = 'dns.alidns.com'
                 OR lower(domain) = 'doh.pub'
                 OR lower(domain) = 'dns.quad9.net'
                 OR lower(domain) LIKE '%.dns.google'
                 OR lower(domain) LIKE '%.cloudflare-dns.com'
              )
              AND ts_minute >= strftime('%s','now') - (?2 * 60)
            GROUP BY domain
            ORDER BY total_bytes DESC
            LIMIT ?3
            "#,
        )?;

        let rows = stmt
            .query_map(params![iface, lookback_minutes, limit], |row| {
                Ok(TopRow {
                    key: row.get(0)?,
                    bytes: row.get(1)?,
                    packets: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn top_quic(&self, iface: &str, lookback_minutes: i64, limit: i64) -> Result<Vec<TopRow>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                CASE WHEN domain = '' THEN CASE WHEN direction = 0 THEN src_ip ELSE dst_ip END ELSE domain END AS target,
                SUM(bytes) AS total_bytes,
                SUM(packets) AS total_packets
            FROM flow_1m_5t
            WHERE iface = ?1
              AND proto = 17
              AND (CASE WHEN direction = 0 THEN src_port ELSE dst_port END) = 443
              AND ts_minute >= strftime('%s','now') - (?2 * 60)
            GROUP BY target
            ORDER BY total_bytes DESC
            LIMIT ?3
            "#,
        )?;

        let rows = stmt
            .query_map(params![iface, lookback_minutes, limit], |row| {
                Ok(TopRow {
                    key: row.get(0)?,
                    bytes: row.get(1)?,
                    packets: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn prune(&self, retention_days: i64) -> Result<()> {
        self.conn.execute(
            "DELETE FROM flow_1m_5t WHERE ts_minute < strftime('%s','now') - (?1 * 86400)",
            params![retention_days],
        )?;
        self.conn.execute(
            "DELETE FROM dns_1m WHERE ts_minute < strftime('%s','now') - (?1 * 86400)",
            params![retention_days],
        )?;
        self.conn.execute(
            "DELETE FROM sni_1m WHERE ts_minute < strftime('%s','now') - (?1 * 86400)",
            params![retention_days],
        )?;
        self.conn.execute(
            "DELETE FROM dns_cache_1m WHERE ts_minute < strftime('%s','now') - (?1 * 86400)",
            params![retention_days],
        )?;
        self.conn.execute(
            "DELETE FROM collector_health_1m WHERE ts_minute < strftime('%s','now') - (?1 * 86400)",
            params![retention_days],
        )?;
        self.conn.execute_batch("VACUUM;")?;
        Ok(())
    }
}

fn ensure_db_parent_dir(path: &str) -> Result<()> {
    if path == ":memory:" || path.starts_with("file:") {
        return Ok(());
    }
    let parent = match Path::new(path).parent() {
        Some(v) if !v.as_os_str().is_empty() => v,
        _ => return Ok(()),
    };
    std::fs::create_dir_all(parent)?;
    Ok(())
}

fn migrate_legacy_flow_table(conn: &Connection) -> Result<()> {
    if !table_exists(conn, "flow_1m")? {
        return Ok(());
    }
    if meta_key_exists(conn, LEGACY_FLOW_MIGRATION_KEY)? {
        return Ok(());
    }
    if !legacy_flow_table_compatible(conn)? {
        return Ok(());
    }

    conn.execute_batch(
        r#"
        INSERT INTO flow_1m_5t (
            ts_minute, iface, direction, proto,
            src_ip, src_port, dst_ip, dst_port,
            domain, attribution_status, bytes, packets
        )
        SELECT
            ts_minute,
            iface,
            direction,
            proto,
            CASE WHEN direction = 0 THEN peer_ip ELSE '0.0.0.0' END AS src_ip,
            CASE WHEN direction = 0 THEN peer_port ELSE 0 END AS src_port,
            CASE WHEN direction = 1 THEN peer_ip ELSE '0.0.0.0' END AS dst_ip,
            CASE WHEN direction = 1 THEN peer_port ELSE 0 END AS dst_port,
            domain,
            attribution_status,
            SUM(bytes) AS bytes,
            SUM(packets) AS packets
        FROM flow_1m
        GROUP BY
            ts_minute, iface, direction, proto,
            peer_ip, peer_port, domain, attribution_status
        ON CONFLICT (
            ts_minute, iface, direction, proto,
            src_ip, src_port, dst_ip, dst_port,
            domain, attribution_status
        ) DO UPDATE SET
            bytes = flow_1m_5t.bytes + excluded.bytes,
            packets = flow_1m_5t.packets + excluded.packets;
        "#,
    )?;

    conn.execute(
        r#"
        INSERT INTO meta_kv(key, value)
        VALUES (?1, strftime('%s','now'))
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        "#,
        params![LEGACY_FLOW_MIGRATION_KEY],
    )?;
    Ok(())
}

fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    let found = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?1 LIMIT 1",
            params![name],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    Ok(found)
}

fn meta_key_exists(conn: &Connection, key: &str) -> Result<bool> {
    let found = conn
        .query_row(
            "SELECT 1 FROM meta_kv WHERE key = ?1 LIMIT 1",
            params![key],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    Ok(found)
}

fn legacy_flow_table_compatible(conn: &Connection) -> Result<bool> {
    let mut stmt = conn.prepare("PRAGMA table_info(flow_1m)")?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    let has_peer_ip = columns.iter().any(|c| c == "peer_ip");
    let has_peer_port = columns.iter().any(|c| c == "peer_port");
    Ok(has_peer_ip && has_peer_port)
}

fn is_lan_ip(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => is_lan_ipv4(v4),
        Ok(IpAddr::V6(v6)) => {
            v6.is_unique_local() || v6.is_unicast_link_local() || v6.is_loopback()
        }
        Err(_) => false,
    }
}

fn is_lan_ipv4(ip: Ipv4Addr) -> bool {
    if ip.is_private() || ip.is_link_local() || ip.is_loopback() {
        return true;
    }
    let [a, b, _, _] = ip.octets();
    a == 100 && (64..=127).contains(&b)
}

fn is_sqlite_readonly_error(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(sqlite_err) = cause.downcast_ref::<rusqlite::Error>() {
            if let rusqlite::Error::SqliteFailure(inner, _) = sqlite_err {
                return matches!(inner.code, ErrorCode::ReadOnly);
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_db_bootstrap() {
        let db = Database::open(":memory:");
        assert!(db.is_ok());
    }

    #[test]
    fn test_open_migrates_legacy_flow_table_once() -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let ts_minute = (now / 60) * 60;
        let db_path =
            std::env::temp_dir().join(format!("ta-migration-{}-{}.db", std::process::id(), now));
        let db_path_str = db_path.to_string_lossy().to_string();

        {
            let conn = Connection::open(&db_path_str)?;
            conn.execute_batch(
                r#"
                CREATE TABLE flow_1m (
                    ts_minute INTEGER NOT NULL,
                    iface TEXT NOT NULL,
                    direction INTEGER NOT NULL,
                    proto INTEGER NOT NULL,
                    peer_ip TEXT NOT NULL,
                    peer_port INTEGER NOT NULL,
                    domain TEXT NOT NULL,
                    attribution_status TEXT NOT NULL,
                    bytes INTEGER NOT NULL,
                    packets INTEGER NOT NULL
                );
                "#,
            )?;
            conn.execute(
                r#"
                INSERT INTO flow_1m (
                    ts_minute, iface, direction, proto, peer_ip, peer_port,
                    domain, attribution_status, bytes, packets
                ) VALUES (?1, 'eth0', 1, 6, '1.1.1.1', 443, 'cloudflare-dns.com', 'exact', 1000, 10)
                "#,
                params![ts_minute],
            )?;
        }

        let db1 = Database::open(&db_path_str)?;
        let first = db1.top_flow("eth0", 10, 10)?;
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].src_ip, "0.0.0.0");
        assert_eq!(first[0].dst_ip, "1.1.1.1");
        assert_eq!(first[0].bytes, 1000);

        let db2 = Database::open(&db_path_str)?;
        let second = db2.top_flow("eth0", 10, 10)?;
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].bytes, 1000);

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        Ok(())
    }

    #[test]
    fn test_lan_ip_filter() {
        assert!(is_lan_ip("192.168.1.10"));
        assert!(is_lan_ip("10.0.0.1"));
        assert!(is_lan_ip("100.100.34.201"));
        assert!(is_lan_ip("fd00::1"));
        assert!(!is_lan_ip("8.8.8.8"));
        assert!(!is_lan_ip("1.1.1.1"));
    }
}
