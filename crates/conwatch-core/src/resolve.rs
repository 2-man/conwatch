//! Host names (reverse DNS, resolved in the background) and countries (optional GeoIP database).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !(v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified() || v.is_broadcast() || v.is_multicast())
        }
        IpAddr::V6(v) => {
            !(v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || (v.segments()[0] & 0xfe00) == 0xfc00
                || (v.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// Non-blocking reverse-DNS cache: `lookup` returns what is known and queues the rest.
#[derive(Clone)]
pub struct HostResolver {
    cache: Arc<Mutex<HashMap<IpAddr, Option<String>>>>,
    tx: Sender<IpAddr>,
}

impl Default for HostResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl HostResolver {
    pub fn new() -> Self {
        let cache: Arc<Mutex<HashMap<IpAddr, Option<String>>>> = Arc::default();
        let (tx, rx) = channel::<IpAddr>();
        // A small pool: single reverse lookups can block for seconds on unresponsive DNS.
        let rx = Arc::new(Mutex::new(rx));
        for _ in 0..8 {
            let (c, rx) = (cache.clone(), rx.clone());
            thread::spawn(move || loop {
                let ip = match rx.lock().unwrap().recv() {
                    Ok(ip) => ip,
                    Err(_) => break,
                };
                let name = dns_lookup::lookup_addr(&ip).ok().filter(|n| n != &ip.to_string());
                c.lock().unwrap().insert(ip, name);
            });
        }
        Self { cache, tx }
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        if !is_public(&ip) {
            return None;
        }
        let mut c = self.cache.lock().unwrap();
        match c.get(&ip) {
            Some(v) => v.clone(),
            None => {
                if c.len() < 10_000 {
                    c.insert(ip, None); // mark as pending so it is queued once
                    let _ = self.tx.send(ip);
                }
                None
            }
        }
    }
}

/// Country lookup from a user-supplied MaxMind-format database (e.g. GeoLite2-Country.mmdb).
pub struct Geo(maxminddb::Reader<Vec<u8>>);

impl Geo {
    pub fn open(path: &Path) -> Option<Self> {
        maxminddb::Reader::open_readfile(path).ok().map(Geo)
    }

    /// ISO 3166-1 alpha-2 code.
    pub fn country(&self, ip: IpAddr) -> Option<String> {
        if !is_public(&ip) {
            return None;
        }
        let c: maxminddb::geoip2::Country = self.0.lookup(ip).ok()?;
        c.country?.iso_code.map(String::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_ranges_are_skipped() {
        assert!(!is_public(&"192.168.1.1".parse().unwrap()));
        assert!(!is_public(&"127.0.0.1".parse().unwrap()));
        assert!(!is_public(&"fe80::1".parse().unwrap()));
        assert!(is_public(&"8.8.8.8".parse().unwrap()));
        assert_eq!(HostResolver::new().lookup("10.0.0.1".parse().unwrap()), None);
    }
}
