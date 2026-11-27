//! "Network scanner": devices on the local network, from the ARP cache plus an optional ping sweep.
//! Works on Windows (`arp -a`) and macOS (`arp -an`).

use crate::event::Event;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;

/// Parse `arp` output into (ip, mac) pairs. Skips broadcast/multicast/incomplete.
pub fn parse_arp(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut ip = None;
        let mut mac = None;
        for tok in line.split(|c: char| c.is_whitespace() || c == '(' || c == ')') {
            if ip.is_none() && tok.parse::<Ipv4Addr>().is_ok() {
                ip = Some(tok.to_string());
            } else if mac.is_none() && is_mac(tok) {
                mac = Some(normalize_mac(tok));
            }
        }
        if let (Some(ip), Some(mac)) = (ip, mac) {
            let first: u8 = ip.split('.').next().and_then(|x| x.parse().ok()).unwrap_or(0);
            if mac != "ff:ff:ff:ff:ff:ff" && !mac.starts_with("01:00:5e") && first < 224 {
                out.push((ip, mac));
            }
        }
    }
    out
}

fn is_mac(t: &str) -> bool {
    let sep = if t.contains('-') { '-' } else { ':' };
    let parts: Vec<_> = t.split(sep).collect();
    parts.len() == 6 && parts.iter().all(|p| !p.is_empty() && p.len() <= 2 && u8::from_str_radix(p, 16).is_ok())
}

/// `a:b:c:d:e:f` / `AA-BB-...` -> `aa:bb:cc:dd:ee:ff` (macOS prints single digits without leading zeros).
fn normalize_mac(t: &str) -> String {
    let sep = if t.contains('-') { '-' } else { ':' };
    t.split(sep).map(|p| format!("{:0>2}", p.to_lowercase())).collect::<Vec<_>>().join(":")
}

/// This machine's primary IPv4 address (no packets are sent; used to find the local /24).
pub fn local_ipv4() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(v) => Some(v),
        _ => None,
    }
}

fn arp_table() -> Vec<(String, String)> {
    let args: &[&str] = if cfg!(windows) { &["-a"] } else { &["-an"] };
    crate::no_window(Command::new("arp").args(args))
        .output()
        .map(|o| parse_arp(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default()
}

/// Ping every address of the local /24 (so that the ARP cache is complete), then read the ARP table.
/// Blocks for a few seconds; call from a background thread.
pub fn scan() -> Vec<(String, String)> {
    if let Some(me) = local_ipv4() {
        let o = me.octets();
        let hosts: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new((1..255u8).filter(|h| *h != o[3]).collect()));
        let workers: Vec<_> = (0..48)
            .map(|_| {
                let hosts = hosts.clone();
                thread::spawn(move || loop {
                    let Some(h) = hosts.lock().unwrap().pop() else { break };
                    let ip = format!("{}.{}.{}.{}", o[0], o[1], o[2], h);
                    let mut c = Command::new("ping");
                    if cfg!(windows) {
                        c.args(["-n", "1", "-w", "300", &ip]);
                    } else {
                        c.args(["-c", "1", "-W", "1", &ip]);
                    }
                    let _ = crate::no_window(&mut c).stdout(std::process::Stdio::null()).status();
                })
            })
            .collect();
        for w in workers {
            let _ = w.join();
        }
    }
    arp_table()
}

#[derive(Default)]
pub struct LanScanner {
    known: HashSet<String>,
    primed: bool,
}

impl LanScanner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devices(&self) -> Vec<(String, String)> {
        arp_table()
    }

    /// Emits `DeviceSeen` for MAC addresses not seen before (first call only primes).
    pub fn poll(&mut self) -> Vec<Event> {
        let mut ev = Vec::new();
        for (ip, mac) in self.devices() {
            if self.known.insert(mac.clone()) && self.primed {
                ev.push(Event::DeviceSeen { ip, mac });
            }
        }
        self.primed = true;
        ev
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_windows_and_mac() {
        let w = "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic\n  224.0.0.22  01-00-5e-00-00-16  static\n";
        assert_eq!(parse_arp(w), vec![("192.168.1.1".into(), "aa:bb:cc:dd:ee:ff".into())]);
        let m = "? (192.168.1.5) at a:b:c:d:e:f on en0 ifscope [ethernet]\n";
        assert_eq!(parse_arp(m), vec![("192.168.1.5".into(), "0a:0b:0c:0d:0e:0f".into())]);
    }
}
