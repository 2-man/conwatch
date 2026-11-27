//! Local dashboard server. Binds to 127.0.0.1 only.

use crate::{build_engine, data_dir};
use conwatch_core::event::{Alert, AlertLevel, Event};
use conwatch_core::lan::LanScanner;
use conwatch_core::monitor::ConnectionMonitor;
use conwatch_core::procnet::{self, DeltaTracker, ProcCounters};
use conwatch_core::resolve::{Geo, HostResolver};
use conwatch_core::settings::Settings;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use conwatch_core::storage::{now_secs, Storage};
use conwatch_core::traffic::TrafficSampler;
use conwatch_core::{firewall, Connection};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::{thread, time::Duration};
use tiny_http::{Header, Method, Request, Response, Server};

const INDEX: &str = include_str!("../ui/index.html");

#[derive(Default)]
struct State {
    conns: Vec<Connection>,
    devices: Vec<(String, String)>,
    traffic: VecDeque<(i64, u64, u64)>,
    modules: Vec<String>,
    module_errors: Vec<String>,
    /// None = per-app tracking active; Some(reason) = unavailable.
    procnet_error: Option<String>,
    settings: Settings,
    blocked: Vec<String>,
    spike_bps: Arc<AtomicU64>,
    new_app_alerts: Arc<AtomicBool>,
    resolver: HostResolver,
    geo: Option<Geo>,
}

fn settings_path() -> std::path::PathBuf {
    data_dir().join("settings.json")
}

/// Bind the dashboard, start background collection and serving threads, return immediately.
pub fn start(port: u16) -> Result<String, String> {
    let server = Server::http(("127.0.0.1", port)).map_err(|e| format!("cannot listen on 127.0.0.1:{port}: {e}"))?;
    let db_path = data_dir().join("conwatch.db");
    let store = Arc::new(Mutex::new(Storage::open(&db_path)?));
    let state = Arc::new(Mutex::new(State::default()));
    {
        let mut s = state.lock().unwrap();
        s.settings = Settings::load(&settings_path());
        s.spike_bps.store(s.settings.spike_mb_s as u64 * 1024 * 1024, Ordering::Relaxed);
        s.new_app_alerts.store(s.settings.alert_new_apps, Ordering::Relaxed);
        s.geo = Geo::open(&data_dir().join("GeoLite2-Country.mmdb"));
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

fn collector(state: Arc<Mutex<State>>, store: Arc<Mutex<Storage>>) {
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
    let _session = match procnet::start(counters.clone()) {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("per-application traffic disabled: {e}");
            state.lock().unwrap().procnet_error = Some(e);
            None
        }
    };
    let mut deltas = DeltaTracker::default();
    let mut names: std::collections::HashMap<u32, String> = Default::default();
    let mut mon = ConnectionMonitor::new();
    let mut lan = LanScanner::new();
    let mut traffic = TrafficSampler::new();
    let mut tick = 0u64;
    loop {
        thread::sleep(Duration::from_secs(1));
        let mut events = mon.poll().unwrap_or_default();
        events.push(traffic.sample());
        if tick % 10 == 0 {
            events.extend(lan.poll());
        }
        let mut all = engine.dispatch(events);
        if state.lock().unwrap().settings.auto_block_new_apps {
            let mut extra = Vec::new();
            for ev in &all {
                if let Event::AppFirstSeen { process, exe: Some(exe) } = ev {
                    let (level, msg) = match firewall::block(exe) {
                        Ok(()) => (AlertLevel::Warning, format!("Automatically blocked new application: {process}")),
                        Err(e) => (AlertLevel::Critical, format!("Could not block {process}: {e}")),
                    };
                    extra.push(Event::Alert(Alert { level, source: "auto-block".into(), message: msg }));
                }
            }
            all.extend(extra);
        }
        if _session.is_some() {
            let d = deltas.delta(counters.snapshot());
            let st = store.lock().unwrap();
            for (pid, (rx, tx)) in d {
                let name = match mon.name_of(pid) {
                    Some(n) => {
                        names.insert(pid, n.clone());
                        n
                    }
                    None => names.get(&pid).cloned().unwrap_or_else(|| format!("pid {pid}")),
                };
                let _ = st.record_app(&name, rx, tx);
            }
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
        let mut s = state.lock().unwrap();
        for ev in &all {
            if let Event::TrafficSample { rx_bytes, tx_bytes, interval_ms } = ev {
                s.traffic.push_back((now_secs(), rx_bytes * 1000 / interval_ms, tx_bytes * 1000 / interval_ms));
                if s.traffic.len() > 600 {
                    s.traffic.pop_front();
                }
            }
        }
        if tick % 2 == 0 {
            if let Ok(mut c) = mon.snapshot() {
                c.sort_by_key(|c| c.process.to_lowercase());
                s.conns = c;
            }
        }
        if tick % 10 == 0 {
            s.devices = lan.devices();
        }
        if tick % 30 == 0 {
            // netsh is slow; refresh the cached list rarely (and right after block/unblock).
            drop(s);
            let b = firewall::blocked();
            s = state.lock().unwrap();
            s.blocked = b;
        }
        tick += 1;
    }
}

fn json_resp(v: Value, code: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(v.to_string())
        .with_status_code(code)
        .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
}

fn handle(mut req: Request, state: &Arc<Mutex<State>>, store: &Arc<Mutex<Storage>>) {
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
    let url = req.url().split('?').next().unwrap_or("/").to_string();
    let method = req.method().clone();
    let resp = match (&method, url.as_str()) {
        (Method::Get, "/") => {
            let r = Response::from_string(INDEX).with_header(Header::from_bytes("Content-Type", "text/html; charset=utf-8").unwrap());
            let _ = req.respond(r);
            return;
        }
        (Method::Get, "/api/state") => {
            let s = state.lock().unwrap();
            let st = store.lock().unwrap();
            let now = now_secs();
            let day = st.usage_since(now - 86400).unwrap_or((0, 0));
            let week = st.usage_since(now - 7 * 86400).unwrap_or((0, 0));
            let month = st.usage_since(now - 30 * 86400).unwrap_or((0, 0));
            let alerts: Vec<Value> = st
                .recent_alerts(100)
                .unwrap_or_default()
                .into_iter()
                .map(|(ts, a)| json!({"ts": ts, "level": a.level, "source": a.source, "message": a.message}))
                .collect();
            json_resp(
                json!({
                    "traffic": s.traffic.iter().map(|(t, r, x)| json!([t, r, x])).collect::<Vec<_>>(),
                    "connections": s.conns.iter().map(|c| {
                        let mut v = serde_json::to_value(c).unwrap_or(Value::Null);
                        if c.proto == conwatch_core::Proto::Tcp {
                            v["host"] = json!(s.resolver.lookup(c.remote_addr));
                            v["country"] = json!(s.geo.as_ref().and_then(|g| g.country(c.remote_addr)));
                        }
                        v
                    }).collect::<Vec<_>>(),
                    "settings": s.settings,
                    "geo": s.geo.is_some(),
                    "devices": s.devices.iter().map(|(ip, mac)| json!({"ip": ip, "mac": mac})).collect::<Vec<_>>(),
                    "usage": {"day": day, "week": week, "month": month},
                    "alerts": alerts,
                    "modules": s.modules,
                    "module_errors": s.module_errors,
                    "blocked": s.blocked,
                    "apps": st.app_usage_since(now - 86400, 30).unwrap_or_default().into_iter().map(|(a, r, x)| json!({"app": a, "rx": r, "tx": x})).collect::<Vec<_>>(),
                    "apps_error": s.procnet_error,
                }),
                200,
            )
        }
        (Method::Post, "/api/settings") => {
            let has_hdr = req.headers().iter().any(|h| h.field.equiv("X-ConWatch"));
            let mut body = String::new();
            let _ = std::io::Read::read_to_string(&mut req.as_reader().take(4096), &mut body);
            match (has_hdr, serde_json::from_str::<Settings>(&body)) {
                (false, _) => json_resp(json!({"error": "forbidden"}), 403),
                (_, Err(e)) => json_resp(json!({"error": e.to_string()}), 400),
                (_, Ok(new)) => {
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
        (Method::Post, "/api/block") | (Method::Post, "/api/unblock") => {
            // Custom header forces a CORS preflight, which we never answer: blocks cross-site requests.
            let has_hdr = req.headers().iter().any(|h| h.field.equiv("X-ConWatch"));
            let mut body = String::new();
            let _ = std::io::Read::read_to_string(&mut req.as_reader().take(4096), &mut body);
            let exe = serde_json::from_str::<Value>(&body).ok().and_then(|v| v["exe"].as_str().map(String::from));
            match (has_hdr, exe) {
                (false, _) => json_resp(json!({"error": "forbidden"}), 403),
                (_, None) => json_resp(json!({"error": "missing exe"}), 400),
                (_, Some(exe)) => {
                    let r = if url == "/api/block" { firewall::block(&exe) } else { firewall::unblock(&exe) };
                    match r {
                        Ok(()) => {
                            let b = firewall::blocked();
                            state.lock().unwrap().blocked = b;
                            json_resp(json!({"ok": true}), 200)
                        }
                        Err(e) => json_resp(json!({"error": e}), 500),
                    }
                }
            }
        }
        _ => json_resp(json!({"error": "not found"}), 404),
    };
    let _ = req.respond(resp);
}

use std::io::Read as _;
