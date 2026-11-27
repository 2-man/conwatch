//! Local dashboard server. Binds to 127.0.0.1 only.

use crate::{build_engine, data_dir};
use conwatch_core::event::Event;
use conwatch_core::lan::LanScanner;
use conwatch_core::monitor::ConnectionMonitor;
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
}

pub fn run(port: u16, open: bool) {
    let server = match Server::http(("127.0.0.1", port)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot listen on 127.0.0.1:{port}: {e}");
            std::process::exit(1);
        }
    };
    let db_path = data_dir().join("conwatch.db");
    let store = Arc::new(Mutex::new(Storage::open(&db_path).expect("open database")));
    let state = Arc::new(Mutex::new(State::default()));

    {
        let (state, store) = (state.clone(), store.clone());
        thread::spawn(move || collector(state, store));
    }
    let url = format!("http://127.0.0.1:{port}");
    println!("ConWatch dashboard: {url}  (data: {})", db_path.display());
    if open {
        let _ = if cfg!(windows) {
            std::process::Command::new("cmd").args(["/C", "start", "", &url]).spawn()
        } else {
            std::process::Command::new("open").arg(&url).spawn()
        };
    }
    for req in server.incoming_requests() {
        handle(req, &state, &store);
    }
}

fn collector(state: Arc<Mutex<State>>, store: Arc<Mutex<Storage>>) {
    let (mut engine, names, errors) = build_engine();
    {
        let mut s = state.lock().unwrap();
        s.modules = names;
        s.module_errors = errors;
    }
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
        let all = engine.dispatch(events);
        {
            let st = store.lock().unwrap();
            for ev in &all {
                let _ = st.record(ev);
            }
            if tick % 3600 == 0 {
                let _ = st.prune(90);
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
                    "connections": s.conns,
                    "devices": s.devices.iter().map(|(ip, mac)| json!({"ip": ip, "mac": mac})).collect::<Vec<_>>(),
                    "usage": {"day": day, "week": week, "month": month},
                    "alerts": alerts,
                    "modules": s.modules,
                    "module_errors": s.module_errors,
                    "blocked": firewall::blocked(),
                }),
                200,
            )
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
                        Ok(()) => json_resp(json!({"ok": true}), 200),
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
