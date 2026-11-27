//! SQLite persistence: traffic history, per-flow usage, alerts, devices, known apps.

use crate::event::{Alert, AlertLevel, Event};
use rusqlite::{params, Connection as Db};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Storage {
    db: Db,
}

pub fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq)]
pub struct AlertRow {
    pub id: i64,
    pub ts: i64,
    pub alert: Alert,
    pub read: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeviceRow {
    pub mac: String,
    pub ip: String,
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HostUsage {
    pub ip: String,
    pub rx: u64,
    pub tx: u64,
    pub top_app: String,
}

/// Row of the per-minute flow table (what ETW attributes to a process/remote/port).
pub struct Flow<'a> {
    pub minute: i64,
    pub app: &'a str,
    pub ip: &'a str,
    pub port: u16,
    pub udp: bool,
    pub rx: u64,
    pub tx: u64,
    pub lan: bool,
}

impl Storage {
    pub fn open(path: &Path) -> Result<Self, String> {
        Self::init(Db::open(path).map_err(|e| e.to_string())?)
    }

    pub fn open_memory() -> Result<Self, String> {
        Self::init(Db::open_in_memory().map_err(|e| e.to_string())?)
    }

    fn init(db: Db) -> Result<Self, String> {
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS traffic(ts INTEGER NOT NULL, rx INTEGER NOT NULL, tx INTEGER NOT NULL, ms INTEGER NOT NULL);
             CREATE INDEX IF NOT EXISTS traffic_ts ON traffic(ts);
             CREATE TABLE IF NOT EXISTS flows(
                 minute INTEGER NOT NULL, app TEXT NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL, udp INTEGER NOT NULL,
                 rx INTEGER NOT NULL, tx INTEGER NOT NULL, lan INTEGER NOT NULL,
                 PRIMARY KEY(minute, app, ip, port, udp));
             CREATE TABLE IF NOT EXISTS app_exes(app TEXT PRIMARY KEY, exe TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS known_apps(app TEXT PRIMARY KEY, first_seen INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS devices(mac TEXT PRIMARY KEY, ip TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS alerts(ts INTEGER NOT NULL, level TEXT NOT NULL, source TEXT NOT NULL, message TEXT NOT NULL);",
        )
        .map_err(|e| e.to_string())?;
        // Migration: alerts.read (ignore the error if the column already exists).
        let _ = db.execute("ALTER TABLE alerts ADD COLUMN read INTEGER NOT NULL DEFAULT 0", []);
        Ok(Self { db })
    }

    /// Persist the events worth keeping (traffic samples and alerts).
    pub fn record(&self, ev: &Event) -> Result<(), String> {
        let ts = now_secs();
        match ev {
            Event::TrafficSample { rx_bytes, tx_bytes, interval_ms } => self.db.execute(
                "INSERT INTO traffic VALUES(?,?,?,?)",
                params![ts, *rx_bytes as i64, *tx_bytes as i64, *interval_ms as i64],
            ),
            Event::Alert(a) => self.db.execute(
                "INSERT INTO alerts(ts, level, source, message) VALUES(?,?,?,?)",
                params![ts, format!("{:?}", a.level).to_lowercase(), a.source, a.message],
            ),
            _ => return Ok(()),
        }
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    // ---- known applications -------------------------------------------------

    /// Remember an application permanently. Returns true only the first time it is ever seen.
    pub fn mark_known(&self, app: &str) -> bool {
        self.db
            .execute("INSERT OR IGNORE INTO known_apps VALUES(?,?)", params![app.to_lowercase(), now_secs()])
            .map(|n| n == 1)
            .unwrap_or(false)
    }

    // ---- application executables --------------------------------------------

    /// Remember which executable a process name belongs to (lower-cased name).
    pub fn set_exes(&self, pairs: &[(String, String)]) -> Result<(), String> {
        if pairs.is_empty() {
            return Ok(());
        }
        self.db.execute_batch("BEGIN").map_err(|e| e.to_string())?;
        for (app, exe) in pairs {
            let _ = self.db.execute("INSERT OR REPLACE INTO app_exes VALUES(?,?)", params![app.to_lowercase(), exe]);
        }
        self.db.execute_batch("COMMIT").map_err(|e| e.to_string())
    }

    pub fn exe_of(&self, app: &str) -> Option<String> {
        self.db.query_row("SELECT exe FROM app_exes WHERE app=?", [app.to_lowercase()], |r| r.get(0)).ok()
    }

    pub fn exe_known(&self, exe: &str) -> bool {
        self.db.query_row("SELECT 1 FROM app_exes WHERE exe=? LIMIT 1", [exe], |r| r.get::<_, i64>(0)).is_ok()
    }

    // ---- flows --------------------------------------------------------------

    /// Add bytes to a per-minute flow row.
    pub fn add_flow(&self, f: &Flow) -> Result<(), String> {
        self.db
            .execute(
                "INSERT INTO flows VALUES(?,?,?,?,?,?,?,?)
                 ON CONFLICT(minute, app, ip, port, udp) DO UPDATE SET rx = rx + excluded.rx, tx = tx + excluded.tx",
                params![f.minute, f.app, f.ip, f.port as i64, f.udp as i64, f.rx as i64, f.tx as i64, f.lan as i64],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Add many flow rows in one transaction.
    pub fn add_flows(&self, rows: &[Flow]) -> Result<(), String> {
        if rows.is_empty() {
            return Ok(());
        }
        self.db.execute_batch("BEGIN").map_err(|e| e.to_string())?;
        let mut res = Ok(());
        for f in rows {
            res = res.and(self.add_flow(f));
        }
        self.db.execute_batch(if res.is_ok() { "COMMIT" } else { "ROLLBACK" }).map_err(|e| e.to_string())?;
        res
    }

    /// Top applications by total bytes since `since`: (app, rx, tx).
    pub fn app_usage_since(&self, since: i64, limit: usize) -> Result<Vec<(String, u64, u64)>, String> {
        let mut st = self
            .db
            .prepare("SELECT app, SUM(rx), SUM(tx) FROM flows WHERE minute>=? AND lan=0 GROUP BY app ORDER BY SUM(rx)+SUM(tx) DESC LIMIT ?")
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map(params![since, limit as i64], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64, r.get::<_, i64>(2)? as u64)))
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
    }

    /// Remote hosts by total bytes (WAN only) with the application that used them most.
    pub fn host_usage_since(&self, since: i64, limit: usize) -> Result<Vec<HostUsage>, String> {
        let mut st = self
            .db
            .prepare(
                "SELECT ip, SUM(rx), SUM(tx),
                        (SELECT app FROM flows f2 WHERE f2.ip = flows.ip AND f2.minute >= ?1 GROUP BY app ORDER BY SUM(rx+tx) DESC LIMIT 1)
                 FROM flows WHERE minute >= ?1 AND lan = 0
                 GROUP BY ip ORDER BY SUM(rx)+SUM(tx) DESC LIMIT ?2",
            )
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map(params![since, limit as i64], |r| {
                Ok(HostUsage { ip: r.get(0)?, rx: r.get::<_, i64>(1)? as u64, tx: r.get::<_, i64>(2)? as u64, top_app: r.get::<_, Option<String>>(3)?.unwrap_or_default() })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
    }

    /// Usage by (port, udp): (port, udp, rx, tx), WAN only.
    pub fn port_usage_since(&self, since: i64) -> Result<Vec<(u16, bool, u64, u64)>, String> {
        let mut st = self
            .db
            .prepare("SELECT port, udp, SUM(rx), SUM(tx) FROM flows WHERE minute>=? AND lan=0 GROUP BY port, udp ORDER BY SUM(rx)+SUM(tx) DESC LIMIT 200")
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map([since], |r| Ok((r.get::<_, i64>(0)? as u16, r.get::<_, i64>(1)? != 0, r.get::<_, i64>(2)? as u64, r.get::<_, i64>(3)? as u64)))
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
    }

    /// ((lan_rx, lan_tx), (wan_rx, wan_tx)) since `since`.
    pub fn lan_wan_since(&self, since: i64) -> Result<((u64, u64), (u64, u64)), String> {
        let q = |lan: i64| -> Result<(u64, u64), String> {
            self.db
                .query_row("SELECT COALESCE(SUM(rx),0), COALESCE(SUM(tx),0) FROM flows WHERE minute>=? AND lan=?", params![since, lan], |r| {
                    Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64))
                })
                .map_err(|e| e.to_string())
        };
        Ok((q(1)?, q(0)?))
    }

    // ---- traffic ------------------------------------------------------------

    /// (bucket_ts, rx_bytes_per_sec, tx_bytes_per_sec) averaged per bucket, oldest first.
    pub fn traffic_buckets(&self, since: i64, bucket_secs: i64) -> Result<Vec<(i64, u64, u64)>, String> {
        let b = bucket_secs.max(1);
        let mut st = self
            .db
            .prepare(
                "SELECT (ts/?1)*?1, SUM(rx)*1000.0/SUM(ms), SUM(tx)*1000.0/SUM(ms)
                 FROM traffic WHERE ts>=?2 GROUP BY (ts/?1) ORDER BY 1",
            )
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map(params![b, since], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, f64>(1)? as u64, r.get::<_, f64>(2)? as u64)))
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
    }

    /// Total (rx, tx) bytes since `since`.
    pub fn usage_since(&self, since: i64) -> Result<(u64, u64), String> {
        self.db
            .query_row("SELECT COALESCE(SUM(rx),0), COALESCE(SUM(tx),0) FROM traffic WHERE ts>=?", [since], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64))
            })
            .map_err(|e| e.to_string())
    }

    // ---- alerts -------------------------------------------------------------

    pub fn recent_alerts(&self, limit: usize, important_only: bool, since: i64) -> Result<Vec<AlertRow>, String> {
        let sql = if important_only {
            "SELECT rowid, ts, level, source, message, read FROM alerts WHERE ts>=? AND level != 'info' ORDER BY ts DESC, rowid DESC LIMIT ?"
        } else {
            "SELECT rowid, ts, level, source, message, read FROM alerts WHERE ts>=? ORDER BY ts DESC, rowid DESC LIMIT ?"
        };
        let mut st = self.db.prepare(sql).map_err(|e| e.to_string())?;
        let rows = st
            .query_map(params![since, limit as i64], |r| {
                let lvl: String = r.get(2)?;
                let level = match lvl.as_str() {
                    "critical" => AlertLevel::Critical,
                    "warning" => AlertLevel::Warning,
                    _ => AlertLevel::Info,
                };
                Ok(AlertRow {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    alert: Alert { level, source: r.get(3)?, message: r.get(4)? },
                    read: r.get::<_, i64>(5)? != 0,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
    }

    pub fn unread_alerts(&self) -> usize {
        self.db.query_row("SELECT COUNT(*) FROM alerts WHERE read=0", [], |r| r.get::<_, i64>(0)).unwrap_or(0) as usize
    }

    pub fn mark_alerts_read(&self) -> Result<(), String> {
        self.db.execute("UPDATE alerts SET read=1 WHERE read=0", []).map(|_| ()).map_err(|e| e.to_string())
    }

    // ---- devices ------------------------------------------------------------

    /// Insert or refresh a device. Returns true if the MAC is new.
    pub fn upsert_device(&self, mac: &str, ip: &str) -> bool {
        let now = now_secs();
        let new = self
            .db
            .execute("INSERT OR IGNORE INTO devices VALUES(?,?,?,?)", params![mac, ip, now, now])
            .map(|n| n == 1)
            .unwrap_or(false);
        if !new {
            let _ = self.db.execute("UPDATE devices SET ip=?, last_seen=? WHERE mac=?", params![ip, now, mac]);
        }
        new
    }

    pub fn devices(&self) -> Result<Vec<DeviceRow>, String> {
        let mut st = self.db.prepare("SELECT mac, ip, first_seen, last_seen FROM devices ORDER BY last_seen DESC, ip").map_err(|e| e.to_string())?;
        let rows = st
            .query_map([], |r| Ok(DeviceRow { mac: r.get(0)?, ip: r.get(1)?, first_seen: r.get(2)?, last_seen: r.get(3)? }))
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
    }

    // ---- retention ----------------------------------------------------------

    /// Delete history older than `days` (flows are kept at most 90 days).
    pub fn prune(&self, days: i64) -> Result<(), String> {
        let cut = now_secs() - days * 86400;
        self.db
            .execute_batch(&format!("DELETE FROM traffic WHERE ts<{cut}; DELETE FROM flows WHERE minute<{cut};"))
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(minute: i64, app: &'static str, ip: &'static str, port: u16, rx: u64, tx: u64, lan: bool) -> Flow<'static> {
        Flow { minute, app, ip, port, udp: false, rx, tx, lan }
    }

    #[test]
    fn traffic_and_alerts() {
        let s = Storage::open_memory().unwrap();
        s.record(&Event::TrafficSample { rx_bytes: 2000, tx_bytes: 1000, interval_ms: 1000 }).unwrap();
        s.record(&Event::Alert(Alert { level: AlertLevel::Warning, source: "t".into(), message: "m".into() })).unwrap();
        s.record(&Event::Alert(Alert { level: AlertLevel::Info, source: "t".into(), message: "i".into() })).unwrap();
        assert_eq!(s.traffic_buckets(0, 60).unwrap()[0].1, 2000);
        assert_eq!(s.usage_since(0).unwrap(), (2000, 1000));
        assert_eq!(s.recent_alerts(5, false, 0).unwrap().len(), 2);
        assert_eq!(s.recent_alerts(5, true, 0).unwrap().len(), 1);
        assert_eq!(s.unread_alerts(), 2);
        s.mark_alerts_read().unwrap();
        assert_eq!(s.unread_alerts(), 0);
    }

    #[test]
    fn flows_aggregate() {
        let s = Storage::open_memory().unwrap();
        s.add_flow(&flow(60, "a.exe", "1.1.1.1", 443, 10, 5, false)).unwrap();
        s.add_flow(&flow(60, "a.exe", "1.1.1.1", 443, 10, 5, false)).unwrap();
        s.add_flow(&flow(60, "b.exe", "1.1.1.1", 443, 1, 1, false)).unwrap();
        s.add_flow(&flow(60, "a.exe", "192.168.1.2", 445, 100, 0, true)).unwrap();
        assert_eq!(s.app_usage_since(0, 5).unwrap()[0], ("a.exe".to_string(), 20, 10));
        let h = s.host_usage_since(0, 5).unwrap();
        assert_eq!((h.len(), h[0].top_app.as_str(), h[0].rx), (1, "a.exe", 21));
        assert_eq!(s.port_usage_since(0).unwrap()[0].0, 443);
        assert_eq!(s.lan_wan_since(0).unwrap(), ((100, 0), (21, 11)));
    }

    #[test]
    fn known_apps_and_devices() {
        let s = Storage::open_memory().unwrap();
        assert!(s.mark_known("C:\\A.exe"));
        assert!(!s.mark_known("c:\\a.exe"));
        s.set_exes(&[("A.exe".into(), "C:\\x\\A.exe".into())]).unwrap();
        assert_eq!(s.exe_of("a.EXE").as_deref(), Some("C:\\x\\A.exe"));
        assert!(s.exe_known("C:\\x\\A.exe") && !s.exe_known("C:\\nope.exe"));
        assert!(s.upsert_device("aa:bb", "1.2.3.4"));
        assert!(!s.upsert_device("aa:bb", "1.2.3.5"));
        assert_eq!(s.devices().unwrap()[0].ip, "1.2.3.5");
        s.prune(1).unwrap();
    }
}
