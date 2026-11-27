//! SQLite persistence: traffic history and alerts.

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
             CREATE TABLE IF NOT EXISTS alerts(ts INTEGER NOT NULL, level TEXT NOT NULL, source TEXT NOT NULL, message TEXT NOT NULL);",
        )
        .map_err(|e| e.to_string())?;
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
                "INSERT INTO alerts VALUES(?,?,?,?)",
                params![ts, format!("{:?}", a.level).to_lowercase(), a.source, a.message],
            ),
            _ => return Ok(()),
        }
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    /// (ts, rx_bytes_per_sec, tx_bytes_per_sec) since `since`, oldest first.
    pub fn traffic_since(&self, since: i64) -> Result<Vec<(i64, u64, u64)>, String> {
        let mut st = self
            .db
            .prepare("SELECT ts, rx*1000/ms, tx*1000/ms FROM traffic WHERE ts>=? ORDER BY ts")
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map([since], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)? as u64, r.get::<_, i64>(2)? as u64)))
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

    pub fn recent_alerts(&self, limit: usize) -> Result<Vec<(i64, Alert)>, String> {
        let mut st = self
            .db
            .prepare("SELECT ts, level, source, message FROM alerts ORDER BY ts DESC, rowid DESC LIMIT ?")
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map([limit as i64], |r| {
                let lvl: String = r.get(1)?;
                let level = match lvl.as_str() {
                    "critical" => AlertLevel::Critical,
                    "warning" => AlertLevel::Warning,
                    _ => AlertLevel::Info,
                };
                Ok((r.get(0)?, Alert { level, source: r.get(2)?, message: r.get(3)? }))
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
    }

    /// Retention: delete traffic rows older than `days`.
    pub fn prune(&self, days: i64) -> Result<(), String> {
        self.db
            .execute("DELETE FROM traffic WHERE ts<?", [now_secs() - days * 86400])
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let s = Storage::open_memory().unwrap();
        s.record(&Event::TrafficSample { rx_bytes: 2000, tx_bytes: 1000, interval_ms: 1000 }).unwrap();
        s.record(&Event::Alert(Alert { level: AlertLevel::Warning, source: "t".into(), message: "m".into() })).unwrap();
        assert_eq!(s.traffic_since(0).unwrap()[0].1, 2000);
        assert_eq!(s.usage_since(0).unwrap(), (2000, 1000));
        assert_eq!(s.recent_alerts(5).unwrap().len(), 1);
    }
}
