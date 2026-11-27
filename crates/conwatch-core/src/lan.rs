//! "Things": devices on the local network, discovered from the ARP cache.
//! Works on Windows (`arp -a`) and macOS (`arp -an`).

use crate::event::Event;
use std::collections::HashSet;
use std::process::Command;

/// Parse `arp` output into (ip, mac) pairs. Skips broadcast/multicast/incomplete.
pub fn parse_arp(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut ip = None;
        let mut mac = None;
        for tok in line.split(|c: char| c.is_whitespace() || c == '(' || c == ')') {
            if ip.is_none() && tok.parse::<std::net::Ipv4Addr>().is_ok() {
                ip = Some(tok.to_string());
            } else if mac.is_none() && is_mac(tok) {
                mac = Some(tok.replace('-', ":").to_lowercase());
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
        let args: &[&str] = if cfg!(windows) { &["-a"] } else { &["-an"] };
        Command::new("arp")
            .args(args)
            .output()
            .map(|o| parse_arp(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default()
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
        assert_eq!(parse_arp(m).len(), 1);
    }
}
