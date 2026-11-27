//! Per-process network byte counters.
//!
//! Windows: ETW provider `Microsoft-Windows-Kernel-Network` (requires Administrator).
//! Other platforms: not implemented yet (`start` returns an error).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Cumulative (rx, tx) bytes per PID since the monitor started.
#[derive(Clone, Default)]
pub struct ProcCounters(Arc<Mutex<HashMap<u32, (u64, u64)>>>);

impl ProcCounters {
    pub fn add(&self, pid: u32, rx: u64, tx: u64) {
        let mut m = self.0.lock().unwrap();
        let e = m.entry(pid).or_insert((0, 0));
        e.0 += rx;
        e.1 += tx;
    }

    pub fn snapshot(&self) -> HashMap<u32, (u64, u64)> {
        self.0.lock().unwrap().clone()
    }
}

/// Tracks per-process deltas between calls.
#[derive(Default)]
pub struct DeltaTracker {
    last: HashMap<u32, (u64, u64)>,
}

impl DeltaTracker {
    /// Returns pid -> (rx, tx) bytes moved since the previous call (non-zero only).
    pub fn delta(&mut self, now: HashMap<u32, (u64, u64)>) -> HashMap<u32, (u64, u64)> {
        let mut out = HashMap::new();
        for (pid, (rx, tx)) in &now {
            let (lrx, ltx) = self.last.get(pid).copied().unwrap_or((0, 0));
            let (drx, dtx) = (rx.saturating_sub(lrx), tx.saturating_sub(ltx));
            if drx > 0 || dtx > 0 {
                out.insert(*pid, (drx, dtx));
            }
        }
        self.last = now;
        out
    }
}

/// Keeps the ETW session alive; dropping it stops tracing.
pub struct ProcNetSession {
    #[cfg(windows)]
    _trace: ferrisetw::trace::UserTrace,
}

#[cfg(windows)]
const SESSION_PREFIX: &str = "ConWatchNet-";

/// Stop ETW sessions left behind by ConWatch processes that no longer exist (e.g. killed).
#[cfg(windows)]
fn cleanup_stale_sessions() {
    let mut q = std::process::Command::new("logman");
    q.args(["query", "-ets"]);
    let Ok(out) = crate::no_window(&mut q).output() else { return };
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let mut sys = sysinfo::System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    for line in text.lines() {
        let Some(name) = line.split_whitespace().next() else { continue };
        let Some(pid) = name.strip_prefix(SESSION_PREFIX).and_then(|p| p.parse::<u32>().ok()) else { continue };
        if pid != std::process::id() && sys.process(sysinfo::Pid::from_u32(pid)).is_none() {
            let mut c = std::process::Command::new("logman");
            c.args(["stop", name, "-ets"]);
            let _ = crate::no_window(&mut c).output();
        }
    }
}

#[cfg(windows)]
pub fn start(counters: ProcCounters) -> Result<ProcNetSession, String> {
    use ferrisetw::parser::Parser;
    use ferrisetw::provider::Provider;
    use ferrisetw::schema_locator::SchemaLocator;
    use ferrisetw::trace::UserTrace;
    use ferrisetw::EventRecord;

    cleanup_stale_sessions();
    // Microsoft-Windows-Kernel-Network. Event ids: 10/26 TCP send (v4/v6), 11/27 TCP recv,
    // 42/58 UDP send, 43/59 UDP recv. Fields: PID, size.
    let provider = Provider::by_guid("7DD42A49-5329-4832-8DFD-43D979153A88")
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let (rx, tx) = match record.event_id() {
                10 | 26 | 42 | 58 => (false, true),
                11 | 27 | 43 | 59 => (true, false),
                _ => return,
            };
            let Ok(schema) = locator.event_schema(record) else { return };
            let parser = Parser::create(record, &schema);
            let pid: Result<u32, _> = parser.try_parse("PID");
            let size: Result<u32, _> = parser.try_parse("size");
            if let (Ok(pid), Ok(size)) = (pid, size) {
                let s = size as u64;
                counters.add(pid, if rx { s } else { 0 }, if tx { s } else { 0 });
            }
        })
        .build();
    let trace = UserTrace::new()
        .named(format!("{SESSION_PREFIX}{}", std::process::id()))
        .enable(provider)
        .start_and_process()
        .map_err(|e| format!("cannot start ETW session (run as Administrator): {e:?}"))?;
    Ok(ProcNetSession { _trace: trace })
}

#[cfg(not(windows))]
pub fn start(_counters: ProcCounters) -> Result<ProcNetSession, String> {
    Err("per-application traffic is not implemented on this platform yet".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deltas() {
        let c = ProcCounters::default();
        let mut d = DeltaTracker::default();
        c.add(1, 100, 10);
        assert_eq!(d.delta(c.snapshot())[&1], (100, 10));
        c.add(1, 50, 0);
        assert_eq!(d.delta(c.snapshot())[&1], (50, 0));
        assert!(d.delta(c.snapshot()).is_empty());
    }
}
