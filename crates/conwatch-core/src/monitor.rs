//! Connection monitor: polls the OS socket table and emits open/close events.

use crate::event::{Connection, Event, Proto};
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use sysinfo::{Pid, ProcessesToUpdate, System};

pub struct ConnectionMonitor {
    sys: System,
    known: HashSet<Connection>,
    seen_apps: HashSet<String>,
    primed: bool,
}

impl Default for ConnectionMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionMonitor {
    pub fn new() -> Self {
        Self {
            sys: System::new(),
            known: HashSet::new(),
            seen_apps: HashSet::new(),
            primed: false,
        }
    }

    /// Current established TCP connections (and bound UDP sockets).
    pub fn snapshot(&mut self) -> Result<Vec<Connection>, String> {
        self.sys.refresh_processes(ProcessesToUpdate::All, true);
        let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let pf = ProtocolFlags::TCP | ProtocolFlags::UDP;
        let sockets = get_sockets_info(af, pf).map_err(|e| e.to_string())?;

        let mut cache: HashMap<u32, (String, Option<String>)> = HashMap::new();
        let mut out = Vec::new();
        for s in sockets {
            let pid = s.associated_pids.first().copied().unwrap_or(0);
            let (process, exe) = cache
                .entry(pid)
                .or_insert_with(|| {
                    match self.sys.process(Pid::from_u32(pid)) {
                        Some(p) => (
                            p.name().to_string_lossy().into_owned(),
                            p.exe().map(|e| e.to_string_lossy().into_owned()),
                        ),
                        None if pid == 0 => ("System Idle".into(), None),
                        None => (format!("pid {pid}"), None),
                    }
                })
                .clone();
            match s.protocol_socket_info {
                ProtocolSocketInfo::Tcp(t) => {
                    if t.state != TcpState::Established {
                        continue;
                    }
                    out.push(Connection {
                        proto: Proto::Tcp,
                        local_addr: t.local_addr,
                        local_port: t.local_port,
                        remote_addr: t.remote_addr,
                        remote_port: t.remote_port,
                        pid,
                        process,
                        exe,
                    });
                }
                ProtocolSocketInfo::Udp(u) => out.push(Connection {
                    proto: Proto::Udp,
                    local_addr: u.local_addr,
                    local_port: u.local_port,
                    remote_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    remote_port: 0,
                    pid,
                    process,
                    exe,
                }),
            }
        }
        Ok(out)
    }

    /// Poll once and return events describing what changed since last call.
    /// The first call only primes the state (no events), so existing
    /// connections are not reported as "new".
    pub fn poll(&mut self) -> Result<Vec<Event>, String> {
        let now: HashSet<Connection> = self.snapshot()?.into_iter().collect();
        let mut events = Vec::new();
        if self.primed {
            let mut opened: Vec<_> = now.difference(&self.known).cloned().collect();
            opened.sort_by(|a, b| a.process.cmp(&b.process));
            for c in opened {
                if self.seen_apps.insert(c.process.clone()) {
                    events.push(Event::AppFirstSeen {
                        process: c.process.clone(),
                        exe: c.exe.clone(),
                    });
                }
                events.push(Event::ConnectionOpened(c));
            }
            for c in self.known.difference(&now) {
                events.push(Event::ConnectionClosed(c.clone()));
            }
        } else {
            self.seen_apps.extend(now.iter().map(|c| c.process.clone()));
            self.primed = true;
        }
        self.known = now;
        Ok(events)
    }
}
