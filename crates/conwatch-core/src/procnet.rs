//! Per-process, per-remote-endpoint network byte counters.
//!
//! Windows: ETW provider `Microsoft-Windows-Kernel-Network` (requires Administrator).
//! Other platforms: not implemented yet (`start` returns an error).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

/// One traffic flow: a process talking to a remote address/port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub pid: u32,
    pub remote: IpAddr,
    pub port: u16,
    pub udp: bool,
}

/// Accumulates (rx, tx) bytes per flow until drained.
#[derive(Clone, Default)]
pub struct ProcCounters(Arc<Mutex<HashMap<FlowKey, (u64, u64)>>>);

impl ProcCounters {
    pub fn add(&self, key: FlowKey, rx: u64, tx: u64) {
        let mut m = self.0.lock().unwrap();
        // Bound memory if nobody drains for a long time.
        if m.len() > 200_000 && !m.contains_key(&key) {
            return;
        }
        let e = m.entry(key).or_insert((0, 0));
        e.0 += rx;
        e.1 += tx;
    }

    /// Take everything accumulated since the last call.
    pub fn take(&self) -> HashMap<FlowKey, (u64, u64)> {
        std::mem::take(&mut *self.0.lock().unwrap())
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
    // 42/58 UDP send, 43/59 UDP recv. Verified layout: for TCP events `daddr`/`dport` is always the
    // remote endpoint; for UDP the remote is `daddr` on send and `saddr` on receive.
    // Ports are in network byte order.
    let provider = Provider::by_guid("7DD42A49-5329-4832-8DFD-43D979153A88")
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let id = record.event_id();
            let (rx, udp) = match id {
                10 | 26 => (false, false),
                11 | 27 => (true, false),
                42 | 58 => (false, true),
                43 | 59 => (true, true),
                _ => return,
            };
            let Ok(schema) = locator.event_schema(record) else { return };
            let parser = Parser::create(record, &schema);
            let pid: Result<u32, _> = parser.try_parse("PID");
            let size: Result<u32, _> = parser.try_parse("size");
            let (addr_field, port_field) = if udp && rx { ("saddr", "sport") } else { ("daddr", "dport") };
            let remote: Result<IpAddr, _> = parser.try_parse(addr_field);
            let port: Result<u16, _> = parser.try_parse(port_field);
            if let (Ok(pid), Ok(size), Ok(remote), Ok(port)) = (pid, size, remote, port) {
                let s = size as u64;
                let key = FlowKey { pid, remote, port: port.swap_bytes(), udp };
                counters.add(key, if rx { s } else { 0 }, if rx { 0 } else { s });
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
    fn take_drains() {
        let c = ProcCounters::default();
        let k = FlowKey { pid: 1, remote: "1.2.3.4".parse().unwrap(), port: 443, udp: false };
        c.add(k, 100, 10);
        c.add(k, 50, 0);
        let m = c.take();
        assert_eq!(m[&k], (150, 10));
        assert!(c.take().is_empty());
    }
}
