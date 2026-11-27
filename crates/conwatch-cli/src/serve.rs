//! Local dashboard server. Binds to 127.0.0.1 only.

use crate::{build_engine, data_dir};
use conwatch_core::event::{Alert, AlertLevel, Event};
use conwatch_core::firewall::{self, Blocked, Dir};
use conwatch_core::icons;
use conwatch_core::lan::{self, LanScanner};
use conwatch_core::monitor::ConnectionMonitor;
use conwatch_core::procnet::{self, ProcCounters};
use conwatch_core::resolve::{is_public, Geo, HostResolver};
use conwatch_core::settings::Settings;
use conwatch_core::storage::{now_secs, Flow, Storage};
use conwatch_core::system::{SystemSample, SystemSampler};
use conwatch_core::traffic::TrafficSampler;
use conwatch_core::{vendor, Connection, Proto};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::{thread, time::Duration};
use tiny_http::{Header, Method, Request, Response, Server};

const INDEX: &str = include_str!("../ui/index.html");
const WORLD_SVG: &str = include_str!("../ui/world.svg");

#[derive(Default)]
struct State {
    conns: Vec<Connection>,
    /// lower-case process name -> executable path (from live connections)
    exe_by_app: HashMap<String, String>,
    sys_hist: VecDeque<SystemSample>,
    /// bytes during the last second per application (rx, tx)
    app_rates: HashMap<String, (u64, u64)>,
    spark: HashMap<String, VecDeque<u64>>,
    online: HashSet<String>,
    scanning: bool,
    blocked: Vec<Blocked>,
    /// None = per-app tracking active; Some(reason) = unavailable.
    procnet_error: Option<String>,
    settings: Settings,
    spike_bps: Arc<AtomicU64>,
    new_app_alerts: Arc<AtomicBool>,
    resolver: HostResolver,
    geo: Option<Geo>,
    modules: Vec<String>,
    module_errors: Vec<String>,
    /// Events produced outside the collector loop (e.g. by a manual scan).
    extra: Vec<Event>,
    /// PNG icons by lower-case exe path (None = extraction failed; do not retry).
    icons: HashMap<String, Option<Arc<Vec<u8>>>>,
}

type Shared = Arc<Mutex<State>>;
type Store = Arc<Mutex<Storage>>;

fn settings_path() -> std::path::PathBuf {
    data_dir().join("settings.json")
}

/// Never auto-block Windows components or ConWatch itself.
fn is_protected(exe: &str) -> bool {
    let norm = |s: &str| s.replace('/', "\\").to_lowercase();
    let e = norm(exe);
    let windir = std::env::var("SystemRoot").map(|w| norm(&w)).unwrap_or_else(|_| "c:\\windows".into());
    if e.starts_with(&format!("{windir}\\")) {
        return true;
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| norm(&d.to_string_lossy())))
        .map(|dir| e.starts_with(&format!("{dir}\\")))
        .unwrap_or(false)
}

/// Bind the dashboard, start background collection and serving threads, return immediately.
pub fn start(port: u16) -> Result<String, String> {
    let server = Server::http(("127.0.0.1", port)).map_err(|e| format!("cannot listen on 127.0.0.1:{port}: {e}"))?;
    let db_path = data_dir().join("conwatch.db");
    let store: Store = Arc::new(Mutex::new(Storage::open(&db_path)?));
    let state: Shared = Arc::new(Mutex::new(State::default()));
    {
        let mut s = state.lock().unwrap();
        s.settings = Settings::load(&settings_path());
        s.spike_bps.store(s.settings.spike_mb_s as u64 * 1024 * 1024, Ordering::Relaxed);
        s.new_app_alerts.store(s.settings.alert_new_apps, Ordering::Relaxed);
        s.geo = Geo::open(&data_dir().join("GeoLite2-Country.mmdb")).or_else(|| Geo::open(&data_dir().join("dbip-country-lite.mmdb")));
    }
    {
        let (state, store) = (state.clone(), store.clone());
        thread::spawn(move || collector(state, store));
    }
    thread::spawn(move || {
        for req in server.incoming_requests() {
            handle(req, &state, &store);
        }
    });
    Ok(format!("http://127.0.0.1:{port}"))
}

pub fn run(port: u16, open: bool) {
    let url = match start(port) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    println!("ConWatch dashboard: {url}  (data: {})", data_dir().join("conwatch.db").display());
    if open {
        let _ = if cfg!(windows) {
            std::process::Command::new("cmd").args(["/C", "start", "", &url]).spawn()
        } else {
            std::process::Command::new("open").arg(&url).spawn()
        };
    }
    loop {
        thread::park();
    }
}

fn process_stem(exe: &str) -> String {
    std::path::Path::new(exe).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| exe.to_string())
}

fn collector(state: Shared, store: Store) {
    let (spike, newapp) = {
        let s = state.lock().unwrap();
        (s.spike_bps.clone(), s.new_app_alerts.clone())
    };
    let (mut engine, names, errors) = build_engine(spike, newapp);
    {
        let mut s = state.lock().unwrap();
        s.modules = names;
        s.module_errors = errors;
    }
    let counters = ProcCounters::default();
    let session = match procnet::start(counters.clone()) {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("per-application traffic disabled: {e}");
            state.lock().unwrap().procnet_error = Some(e);
            None
        }
    };
    let mut names: HashMap<u32, String> = HashMap::new();
    let mut mon = ConnectionMonitor::new();
    // Everything already talking to the network at startup counts as known.
    if let Ok(snap) = mon.snapshot() {
        let st = store.lock().unwrap();
        for c in &snap {
            st.mark_known(c.exe.as_deref().unwrap_or(&c.process));
        }
    }
    let lan_scanner = LanScanner::new();
    let mut traffic = TrafficSampler::new();
    let mut sysmon = SystemSampler::new();
    let mut lan_primed = store.lock().unwrap().devices().map(|d| !d.is_empty()).unwrap_or(false);
    let mut tick = 0u64;
    loop {
        thread::sleep(Duration::from_secs(1));
        let mut events = mon.poll().unwrap_or_default();
        // "New application" means never seen before, across restarts.
        {
            let st = store.lock().unwrap();
            events.retain(|e| match e {
                Event::AppFirstSeen { process, exe, .. } => st.mark_known(exe.as_deref().unwrap_or(process)),
                _ => true,
            });
        }
        events.push(traffic.sample());
        if tick % 10 == 0 {
            let devs = lan_scanner.devices();
            let st = store.lock().unwrap();
            let mut online = HashSet::new();
            for (ip, mac) in devs {
                online.insert(mac.clone());
                if st.upsert_device(&mac, &ip) && lan_primed {
                    events.push(Event::DeviceSeen { ip, mac });
                }
            }
            lan_primed = true;
            drop(st);
            state.lock().unwrap().online = online;
        }
        {
            let mut s = state.lock().unwrap();
            events.append(&mut s.extra);
            // Periodic active scan (opt-in), every 5 minutes.
            if s.settings.auto_scan && tick % 300 == 150 && !s.scanning {
                s.scanning = true;
                spawn_scan(state.clone(), store.clone());
            }
        }

        let mut all = engine.dispatch(events);
        if state.lock().unwrap().settings.auto_block_new_apps {
            let mut extra = Vec::new();
            for ev in &all {
                if let Event::AppFirstSeen { process, exe: Some(exe), .. } = ev {
                    if is_protected(exe) {
                        continue;
                    }
                    let (level, msg) = match firewall::block(exe) {
                        Ok(()) => (AlertLevel::Warning, format!("Automatically blocked new application: {process}")),
                        Err(e) => (AlertLevel::Critical, format!("Could not block {process}: {e}")),
                    };
                    extra.push(Event::Alert(Alert { level, source: "auto-block".into(), message: msg }));
                }
            }
            all.extend(extra);
        }

        // Per-flow bytes from ETW -> per-minute rows and per-app rates.
        let mut rates: HashMap<String, (u64, u64)> = HashMap::new();
        if session.is_some() {
            let drained = counters.take();
            let minute = now_secs() / 60 * 60;
            let mut rows: Vec<(String, String, u16, bool, u64, u64, bool)> = Vec::new();
            for (k, (rx, tx)) in drained {
                if k.remote.is_loopback() || k.remote.is_unspecified() {
                    continue;
                }
                let app = match mon.name_of(k.pid) {
                    Some(n) => {
                        names.insert(k.pid, n.clone());
                        n
                    }
                    None => names.get(&k.pid).cloned().unwrap_or_else(|| format!("pid {}", k.pid)),
                };
                let e = rates.entry(app.clone()).or_insert((0, 0));
                e.0 += rx;
                e.1 += tx;
                rows.push((app, k.remote.to_string(), k.port, k.udp, rx, tx, !is_public(&k.remote)));
            }
            let flows: Vec<Flow> = rows
                .iter()
                .map(|(a, ip, p, u, rx, tx, lan)| Flow { minute, app: a, ip, port: *p, udp: *u, rx: *rx, tx: *tx, lan: *lan })
                .collect();
            let _ = store.lock().unwrap().add_flows(&flows);
        }
        {
            let st = store.lock().unwrap();
            for ev in &all {
                let _ = st.record(ev);
            }
            if tick % 3600 == 0 {
                let days = state.lock().unwrap().settings.retention_days as i64;
                let _ = st.prune(days);
            }
        }

        let sample = sysmon.sample(now_secs());
        let mut s = state.lock().unwrap();
        s.sys_hist.push_back(sample);
        if s.sys_hist.len() > 3600 {
            s.sys_hist.pop_front();
        }
        // sparkline history per application (last 40 seconds)
        let tracked: HashSet<String> = s.spark.keys().cloned().chain(rates.keys().cloned()).collect();
        for app in tracked {
            let v = rates.get(&app).map(|(r, t)| r + t).unwrap_or(0);
            let h = s.spark.entry(app).or_default();
            h.push_back(v);
            if h.len() > 40 {
                h.pop_front();
            }
        }
        s.spark.retain(|_, h| h.iter().any(|v| *v > 0));
        s.app_rates = rates;
        let pairs: Vec<(String, String)> = if tick % 20 == 5 { s.exe_by_app.iter().map(|(a, e)| (a.clone(), e.clone())).collect() } else { Vec::new() };

        if tick % 2 == 0 {
            if let Ok(mut c) = mon.snapshot() {
                c.sort_by_key(|c| c.process.to_lowercase());
                for c in &c {
                    if let Some(e) = &c.exe {
                        s.exe_by_app.insert(c.process.to_lowercase(), e.clone());
                    }
                }
                s.conns = c;
            }
        }
        if tick % 30 == 0 {
            // netsh is slow; refresh the cached list rarely (and right after changes).
            drop(s);
            let b = firewall::blocked();
            s = state.lock().unwrap();
            s.blocked = b;
        }
        drop(s);
        let _ = store.lock().unwrap().set_exes(&pairs);
        tick += 1;
    }
}

/// Active scan in a background thread; new devices raise alerts via the collector.
fn spawn_scan(state: Shared, store: Store) {
    thread::spawn(move || {
        let found = lan::scan();
        let mut new_events = Vec::new();
        let mut online = HashSet::new();
        {
            let st = store.lock().unwrap();
            for (ip, mac) in found {
                online.insert(mac.clone());
                if st.upsert_device(&mac, &ip) {
                    new_events.push(Event::DeviceSeen { ip, mac });
                }
            }
        }
        let mut s = state.lock().unwrap();
        s.online = online;
        s.extra.extend(new_events);
        s.scanning = false;
    });
}

// ---------------------------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------------------------

fn json_resp(v: Value, code: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(v.to_string())
        .with_status_code(code)
        .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
        .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap())
}

fn bytes_resp(data: Vec<u8>, mime: &str, cache: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_data(data)
        .with_header(Header::from_bytes("Content-Type", mime).unwrap())
        .with_header(Header::from_bytes("Cache-Control", cache).unwrap())
}

fn query(url: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    if let Some((_, q)) = url.split_once('?') {
        for kv in q.split('&') {
            if let Some((k, v)) = kv.split_once('=') {
                m.insert(k.to_string(), url_decode(v));
            }
        }
    }
    m
}

fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn read_body(req: &mut Request) -> Value {
    let mut body = String::new();
    let _ = std::io::Read::read_to_string(&mut std::io::Read::take(req.as_reader(), 16384), &mut body);
    serde_json::from_str(&body).unwrap_or(Value::Null)
}

/// Well-known service for a remote port ("Other" for everything else).
fn service_name(port: u16, udp: bool) -> &'static str {
    match (port, udp) {
        (443, true) => "QUIC (HTTP/3)",
        (443, false) => "HTTPS (TLS/SSL)",
        (80, _) | (8080, _) => "HTTP",
        (8443, _) => "HTTPS (alt)",
        (53, _) => "DNS",
        (853, _) => "DNS over TLS",
        (123, _) => "NTP",
        (5353, _) => "mDNS",
        (1900, _) => "SSDP / UPnP",
        (22, _) => "SSH",
        (21, _) => "FTP",
        (25, _) | (465, _) | (587, _) => "SMTP (mail)",
        (993, _) => "IMAP over SSL",
        (143, _) => "IMAP",
        (995, _) | (110, _) => "POP3",
        (3389, _) => "Remote Desktop",
        (445, _) | (139, _) => "SMB (file sharing)",
        (51820, true) => "WireGuard",
        (1194, _) => "OpenVPN",
        (3478, _) | (3479, _) => "STUN / VoIP",
        (5228, _) => "Google push",
        (5222, _) => "XMPP",
        (1883, _) | (8883, _) => "MQTT",
        _ => "Other",
    }
}

fn handle(mut req: Request, state: &Shared, store: &Store) {
    // Reject DNS-rebinding: only accept requests addressed to the loopback host.
    let host_ok = req.headers().iter().any(|h| {
        h.field.equiv("Host") && {
            let v = h.value.as_str();
            v.starts_with("127.0.0.1:") || v.starts_with("localhost:") || v == "127.0.0.1" || v == "localhost"
        }
    });
    if !host_ok {
        let _ = req.respond(json_resp(json!({"error": "bad host"}), 403));
        return;
    }
    let full = req.url().to_string();
    let path = full.split('?').next().unwrap_or("/").to_string();
    let q = query(&full);
    let method = req.method().clone();
    // Custom header forces a CORS preflight, which we never answer: blocks cross-site writes.
    let csrf_ok = req.headers().iter().any(|h| h.field.equiv("X-ConWatch"));
    if method == Method::Post && !csrf_ok {
        let _ = req.respond(json_resp(json!({"error": "forbidden"}), 403));
        return;
    }
    let range = q.get("range").and_then(|r| r.parse::<i64>().ok()).unwrap_or(300).clamp(60, 31 * 86400);

    let resp = match (&method, path.as_str()) {
        (Method::Get, "/") => {
            let r = Response::from_string(INDEX).with_header(Header::from_bytes("Content-Type", "text/html; charset=utf-8").unwrap());
            let _ = req.respond(r);
            return;
        }
        (Method::Get, "/world.svg") => bytes_resp(WORLD_SVG.as_bytes().to_vec(), "image/svg+xml", "public, max-age=86400"),
        (Method::Get, p) if p.starts_with("/flags/") && p.ends_with(".png") => {
            let code = p["/flags/".len()..p.len() - 4].to_lowercase();
            match (code.len() == 2 && code.bytes().all(|b| b.is_ascii_lowercase()))
                .then(|| crate::flags::flag(&code))
                .flatten()
            {
                Some(png) => bytes_resp(png.to_vec(), "image/png", "public, max-age=86400"),
                None => json_resp(json!({"error": "no such flag"}), 404),
            }
        }
        (Method::Get, "/api/icon") => {
            // Resolve to an executable we already know about (never an arbitrary path from the URL).
            let exe: Option<String> = if let Some(app) = q.get("app") {
                let key = app.to_lowercase();
                let mem = state.lock().unwrap().exe_by_app.get(&key).cloned();
                mem.or_else(|| store.lock().unwrap().exe_of(&key))
            } else if let Some(exe) = q.get("exe") {
                let in_rules = state.lock().unwrap().blocked.iter().any(|b| b.exe.eq_ignore_ascii_case(exe));
                (in_rules || store.lock().unwrap().exe_known(exe)).then(|| exe.clone())
            } else {
                None
            };
            match exe {
                None => json_resp(json!({"error": "unknown application"}), 404),
                Some(exe) => {
                    let key = exe.to_lowercase();
                    let cached = state.lock().unwrap().icons.get(&key).cloned();
                    let png = match cached {
                        Some(v) => v,
                        None => {
                            let v = icons::exe_icon_png(&exe).map(Arc::new);
                            state.lock().unwrap().icons.insert(key, v.clone());
                            v
                        }
                    };
                    match png {
                        Some(p) => bytes_resp(p.as_ref().clone(), "image/png", "public, max-age=600"),
                        None => json_resp(json!({"error": "no icon"}), 404),
                    }
                }
            }
        }
        (Method::Get, "/api/meta") => {
            let unread = store.lock().unwrap().unread_alerts();
            let s = state.lock().unwrap();
            json_resp(
                json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "settings": s.settings,
                    "procnet_error": s.procnet_error,
                    "geo": s.geo.is_some(),
                    "modules": s.modules,
                    "module_errors": s.module_errors,
                    "unread": unread,
                    "can_elevate": cfg!(windows) && s.procnet_error.is_some(),
                }),
                200,
            )
        }
        (Method::Get, "/api/overview") => {
            let now = now_secs();
            let since = now - range;
            let bucket = (range / 300).max(1);
            let st = store.lock().unwrap();
            let series: Vec<Value> = st.traffic_buckets(since, bucket).unwrap_or_default().into_iter().map(|(t, r, x)| json!([t, r, x])).collect();
            let (rx, tx) = st.usage_since(since).unwrap_or((0, 0));
            let now_rate = st.traffic_buckets(now - 3, 3).unwrap_or_default().last().map(|(_, r, x)| (*r, *x)).unwrap_or((0, 0));
            let (lan, wan) = st.lan_wan_since(since / 60 * 60).unwrap_or(((0, 0), (0, 0)));
            drop(st);
            let procnet_error = state.lock().unwrap().procnet_error.clone();
            json_resp(
                json!({
                    "range": range, "bucket": bucket, "now": now, "series": series,
                    "totals": {"rx": rx, "tx": tx}, "rate": {"rx": now_rate.0, "tx": now_rate.1},
                    "lan": {"rx": lan.0, "tx": lan.1}, "wan": {"rx": wan.0, "tx": wan.1},
                    "flows_available": procnet_error.is_none(),
                }),
                200,
            )
        }
        (Method::Get, "/api/breakdown") => {
            let since = (now_secs() - range) / 60 * 60;
            let st = store.lock().unwrap();
            let s = state.lock().unwrap();
            let apps: Vec<Value> = st.app_usage_since(since, 15).unwrap_or_default().into_iter().map(|(a, r, x)| json!({"name": a, "rx": r, "tx": x})).collect();
            let all_hosts = st.host_usage_since(since, 3000).unwrap_or_default();
            let mut countries: HashMap<String, (u64, u64)> = HashMap::new();
            let mut country_apps: HashMap<String, HashMap<String, u64>> = HashMap::new();
            let mut hosts = Vec::new();
            for h in &all_hosts {
                let ip: Option<IpAddr> = h.ip.parse().ok();
                let cc = ip.and_then(|ip| s.geo.as_ref().and_then(|g| g.country(ip)));
                if let Some(cc) = &cc {
                    let e = countries.entry(cc.clone()).or_insert((0, 0));
                    e.0 += h.rx;
                    e.1 += h.tx;
                    *country_apps.entry(cc.clone()).or_default().entry(h.top_app.clone()).or_insert(0) += h.rx + h.tx;
                }
                if hosts.len() < 25 {
                    let name = ip.and_then(|ip| s.resolver.lookup(ip));
                    hosts.push(json!({"name": name.unwrap_or_else(|| h.ip.clone()), "ip": h.ip, "rx": h.rx, "tx": h.tx, "app": h.top_app, "country": cc}));
                }
            }
            let mut types: HashMap<&'static str, (u64, u64)> = HashMap::new();
            for (port, udp, rx, tx) in st.port_usage_since(since).unwrap_or_default() {
                let e = types.entry(service_name(port, udp)).or_insert((0, 0));
                e.0 += rx;
                e.1 += tx;
            }
            let mut types: Vec<_> = types.into_iter().collect();
            types.sort_by_key(|(n, (r, x))| (*n == "Other", std::cmp::Reverse(r + x)));
            let mut countries: Vec<_> = countries.into_iter().collect();
            countries.sort_by_key(|(_, (r, x))| std::cmp::Reverse(r + x));
            let (lan, _) = st.lan_wan_since(since).unwrap_or(((0, 0), (0, 0)));
            json_resp(
                json!({
                    "apps": apps, "hosts": hosts,
                    "types": types.iter().take(15).map(|(n, (r, x))| json!({"name": n, "rx": r, "tx": x})).collect::<Vec<_>>(),
                    "countries": countries.iter().map(|(c, (r, x))| {
                        let mut apps: Vec<(&String, &u64)> = country_apps.get(c).map(|m| m.iter().collect()).unwrap_or_default();
                        apps.sort_by_key(|(_, b)| std::cmp::Reverse(**b));
                        json!({"code": c, "rx": r, "tx": x, "apps": apps.iter().take(3).map(|(a, _)| a).collect::<Vec<_>>()})
                    }).collect::<Vec<_>>(),
                    "local": {"rx": lan.0, "tx": lan.1},
                    "flows_available": s.procnet_error.is_none(),
                    "geo": s.geo.is_some(),
                }),
                200,
            )
        }
        (Method::Get, "/api/firewall") => {
            let s = state.lock().unwrap();
            let mut apps: HashMap<String, Value> = HashMap::new();
            // Active applications (live connections).
            let mut by_app: HashMap<String, Vec<&Connection>> = HashMap::new();
            for c in s.conns.iter().filter(|c| c.proto == Proto::Tcp && !c.remote_addr.is_loopback()) {
                by_app.entry(c.process.to_lowercase()).or_default().push(c);
            }
            let find_block = |exe: &str| s.blocked.iter().find(|b| b.exe.eq_ignore_ascii_case(exe)).cloned();
            for (key, conns) in &by_app {
                let exe = conns[0].exe.clone().unwrap_or_default();
                let b = find_block(&exe);
                let mut seen = HashSet::new();
                let mut hosts: Vec<Value> = Vec::new();
                for c in conns {
                    if seen.insert(c.remote_addr) && hosts.len() < 40 {
                        let name = s.resolver.lookup(c.remote_addr);
                        let cc = s.geo.as_ref().and_then(|g| g.country(c.remote_addr));
                        hosts.push(json!({"name": name.unwrap_or_else(|| c.remote_addr.to_string()), "country": cc}));
                    }
                }
                let rate = s.app_rates.get(&conns[0].process).copied().unwrap_or((0, 0));
                apps.insert(
                    key.clone(),
                    json!({"name": conns[0].process, "exe": exe, "active": true, "in_blocked": b.as_ref().map(|b| b.inbound).unwrap_or(false),
                           "out_blocked": b.as_ref().map(|b| b.outbound).unwrap_or(false), "hosts": hosts, "rx": rate.0, "tx": rate.1,
                           "spark": s.spark.get(&conns[0].process).map(|h| h.iter().copied().collect::<Vec<_>>()).unwrap_or_default(),
                           "protected": is_protected(&exe)}),
                );
            }
            // Blocked applications that are not active right now.
            for b in &s.blocked {
                let key = process_stem(&b.exe).to_lowercase();
                apps.entry(key).or_insert_with(|| {
                    json!({"name": process_stem(&b.exe), "exe": b.exe, "active": false, "in_blocked": b.inbound, "out_blocked": b.outbound,
                           "hosts": [], "rx": 0, "tx": 0, "spark": [], "protected": is_protected(&b.exe)})
                });
            }
            let mut list: Vec<Value> = apps.into_values().collect();
            list.sort_by_key(|a| (!a["active"].as_bool().unwrap_or(false), a["name"].as_str().unwrap_or("").to_lowercase()));
            json_resp(json!({"apps": list, "auto_block": s.settings.auto_block_new_apps, "can_block": cfg!(windows)}), 200)
        }
        (Method::Post, "/api/firewall") => {
            let b = read_body(&mut req);
            let (exe, dir, blocked) = (b["exe"].as_str().map(String::from), b["dir"].as_str().unwrap_or("both").to_string(), b["blocked"].as_bool());
            match (exe, blocked) {
                (Some(exe), Some(blocked)) => {
                    let dirs: Vec<Dir> = match dir.as_str() {
                        "in" => vec![Dir::In],
                        "out" => vec![Dir::Out],
                        _ => vec![Dir::Out, Dir::In],
                    };
                    let mut res = Ok(());
                    for d in dirs {
                        let r = if blocked { firewall::block_dir(&exe, d) } else { firewall::unblock_dir(&exe, d) };
                        res = res.and(r);
                    }
                    let nb = firewall::blocked();
                    state.lock().unwrap().blocked = nb;
                    match res {
                        Ok(()) => json_resp(json!({"ok": true}), 200),
                        Err(e) => json_resp(json!({"error": e}), 500),
                    }
                }
                _ => json_resp(json!({"error": "missing exe/blocked"}), 400),
            }
        }
        (Method::Get, "/api/alerts") => {
            let important = q.get("filter").map(|f| f != "all").unwrap_or(true);
            let since = if range >= 31 * 86400 { 0 } else { now_secs() - range };
            let needle = q.get("q").map(|s| s.to_lowercase()).unwrap_or_default();
            let rows = store.lock().unwrap().recent_alerts(500, important, since).unwrap_or_default();
            let s = state.lock().unwrap();
            let items: Vec<Value> = rows
                .into_iter()
                .filter(|r| needle.is_empty() || r.alert.message.to_lowercase().contains(&needle) || r.alert.source.to_lowercase().contains(&needle))
                .map(|r| {
                    // "... first network connection to <ip>" -> attach a host name when known.
                    let host = r.alert.message.rsplit_once(" to ").and_then(|(_, ip)| ip.parse::<IpAddr>().ok()).and_then(|ip| s.resolver.lookup(ip));
                    json!({"id": r.id, "ts": r.ts, "level": r.alert.level, "source": r.alert.source, "message": r.alert.message, "read": r.read, "host": host})
                })
                .collect();
            json_resp(json!({"alerts": items, "now": now_secs()}), 200)
        }
        (Method::Post, "/api/alerts/read") => {
            let _ = store.lock().unwrap().mark_alerts_read();
            json_resp(json!({"ok": true}), 200)
        }
        (Method::Get, "/api/network") => {
            let devs = store.lock().unwrap().devices().unwrap_or_default();
            let s = state.lock().unwrap();
            let me = lan::local_ipv4().map(|i| i.to_string());
            let list: Vec<Value> = devs
                .into_iter()
                .map(|d| {
                    let v = vendor::vendor(&d.mac);
                    let is_me = me.as_deref() == Some(d.ip.as_str());
                    let gateway = d.ip.ends_with(".1");
                    let kind = if is_me { "computer" } else { vendor::kind(v, gateway) };
                    json!({"ip": d.ip, "mac": d.mac, "vendor": v, "kind": kind, "me": is_me, "online": s.online.contains(&d.mac), "first_seen": d.first_seen, "last_seen": d.last_seen})
                })
                .collect();
            json_resp(json!({"devices": list, "scanning": s.scanning, "auto_scan": s.settings.auto_scan}), 200)
        }
        (Method::Post, "/api/network/scan") => {
            let mut s = state.lock().unwrap();
            if !s.scanning {
                s.scanning = true;
                spawn_scan(state.clone(), store.clone());
            }
            json_resp(json!({"ok": true}), 200)
        }
        (Method::Get, "/api/system") => {
            let s = state.lock().unwrap();
            let since = now_secs() - range.min(3600);
            let v: Vec<Value> = s.sys_hist.iter().filter(|x| x.ts >= since).map(|x| json!([x.ts, x.cpu, x.mem_used, x.mem_total, x.disk_read, x.disk_write])).collect();
            json_resp(json!({"samples": v}), 200)
        }
        (Method::Post, "/api/settings") => {
            let body = read_body(&mut req);
            match serde_json::from_value::<Settings>(body) {
                Err(e) => json_resp(json!({"error": e.to_string()}), 400),
                Ok(new) => {
                    let new = new.sanitized();
                    let mut s = state.lock().unwrap();
                    s.spike_bps.store(new.spike_mb_s as u64 * 1024 * 1024, Ordering::Relaxed);
                    s.new_app_alerts.store(new.alert_new_apps, Ordering::Relaxed);
                    s.settings = new.clone();
                    match new.save(&settings_path()) {
                        Ok(()) => json_resp(json!({"ok": true}), 200),
                        Err(e) => json_resp(json!({"error": e}), 500),
                    }
                }
            }
        }
        (Method::Post, "/api/geo/download") => {
            let dest = data_dir().join("dbip-country-lite.mmdb");
            match conwatch_core::geodb::download(&dest) {
                Ok(()) => {
                    state.lock().unwrap().geo = Geo::open(&dest);
                    json_resp(json!({"ok": true}), 200)
                }
                Err(e) => json_resp(json!({"error": e}), 500),
            }
        }
        (Method::Post, "/api/elevate") => json_resp(elevate(), 200),
        _ => json_resp(json!({"error": "not found"}), 404),
    };
    let _ = req.respond(resp);
}

/// Relaunch this program elevated (UAC prompt). On success the current instance exits shortly after.
fn elevate() -> Value {
    if !cfg!(windows) {
        return json!({"error": "only available on Windows"});
    }
    let Ok(exe) = std::env::current_exe() else { return json!({"error": "cannot locate executable"}) };
    let q = |s: &str| format!("'{}'", s.replace('\'', "''"));
    let args: Vec<String> = std::env::args().skip(1).map(|a| q(&a)).collect();
    let mut cmd = format!("Start-Process -FilePath {} -Verb RunAs", q(&exe.to_string_lossy()));
    if !args.is_empty() {
        cmd.push_str(&format!(" -ArgumentList {}", args.join(",")));
    }
    let mut c = std::process::Command::new("powershell");
    c.args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &cmd]);
    match conwatch_core::no_window(&mut c).status() {
        Ok(s) if s.success() => {
            thread::spawn(|| {
                thread::sleep(Duration::from_millis(800));
                std::process::exit(0);
            });
            json!({"ok": true})
        }
        _ => json!({"error": "elevation was cancelled or failed"}),
    }
}
