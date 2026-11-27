use conwatch_cli::{default_engine, serve};
use conwatch_core::event::{Event, Proto};
use conwatch_core::monitor::ConnectionMonitor;
use conwatch_core::{firewall, lan::LanScanner};
use std::{env, thread, time::Duration};

fn proto(p: Proto) -> &'static str {
    match p {
        Proto::Tcp => "TCP",
        Proto::Udp => "UDP",
    }
}

fn usage() {
    eprintln!("conwatch {}\n", env!("CARGO_PKG_VERSION"));
    eprintln!("USAGE:");
    eprintln!("  conwatch serve [--port N] [--open]  start the dashboard (default http://127.0.0.1:8650)");
    eprintln!("  conwatch list                       current connections per process");
    eprintln!("  conwatch watch [--json]             stream events (Ctrl+C to stop)");
    eprintln!("  conwatch devices                    devices on the local network");
    eprintln!("  conwatch modules                    list loaded modules");
    eprintln!("  conwatch block <exe-path>           block an application (Administrator)");
    eprintln!("  conwatch unblock <exe-path>         remove the block");
    eprintln!("  conwatch autostart on|off           start conwatch-app at login (Windows)");
    eprintln!("  conwatch blocked                    list blocked applications");
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let flag = |f: &str| args.iter().any(|a| a == f);
    match args.first().map(String::as_str) {
        Some("serve") => {
            let port = args.iter().position(|a| a == "--port").and_then(|i| args.get(i + 1)).and_then(|p| p.parse().ok()).unwrap_or(8650);
            serve::run(port, flag("--open"));
        }
        Some("list") => list(),
        Some("watch") => watch(flag("--json")),
        Some("devices") => {
            for (ip, mac) in LanScanner::new().devices() {
                println!("{ip:<16} {mac}");
            }
        }
        Some("modules") => {
            let (_e, names, errors) = default_engine();
            names.iter().for_each(|n| println!("{n}"));
            errors.iter().for_each(|e| eprintln!("error: {e}"));
        }
        Some("block") => report(args.get(1).map(|e| firewall::block(e)).unwrap_or(Err("missing <exe-path>".into())), "blocked"),
        Some("unblock") => report(args.get(1).map(|e| firewall::unblock(e)).unwrap_or(Err("missing <exe-path>".into())), "unblocked"),
        #[cfg(all(windows, feature = "wfp"))]
        Some("wfp-block") => report(args.get(1).map(|e| conwatch_core::wfp::block_app(e)).unwrap_or(Err("missing <exe-path>".into())), "blocked (WFP)"),
        #[cfg(all(windows, feature = "wfp"))]
        Some("wfp-unblock") => report(args.get(1).map(|e| conwatch_core::wfp::unblock_app(e)).unwrap_or(Err("missing <exe-path>".into())), "unblocked (WFP)"),
        Some("autostart") => autostart(args.get(1).map(String::as_str)),
        Some("blocked") => firewall::blocked().iter().for_each(|b| {
            let dirs = match (b.inbound, b.outbound) {
                (true, true) => "in+out",
                (true, false) => "in",
                _ => "out",
            };
            println!("{}	{dirs}", b.exe)
        }),
        _ => usage(),
    }
}

fn report(r: Result<(), String>, ok: &str) {
    match r {
        Ok(()) => println!("{ok}"),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

fn list() {
    let mut mon = ConnectionMonitor::new();
    let mut conns = mon.snapshot().unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });
    conns.retain(|c| c.proto == Proto::Tcp);
    conns.sort_by_key(|c| c.process.to_lowercase());
    println!("{:<28} {:>6}  {:<5} REMOTE", "PROCESS", "PID", "PROTO");
    for c in conns {
        println!("{:<28} {:>6}  {:<5} {}:{}", c.process, c.pid, proto(c.proto), c.remote_addr, c.remote_port);
    }
}

fn watch(json: bool) {
    let (mut engine, _, errors) = default_engine();
    errors.iter().for_each(|e| eprintln!("module error: {e}"));
    let mut mon = ConnectionMonitor::new();
    let mut lan = LanScanner::new();
    let mut tick = 0u64;
    loop {
        let mut events = mon.poll().unwrap_or_else(|e| {
            eprintln!("error: {e}");
            vec![]
        });
        if tick.is_multiple_of(10) {
            events.extend(lan.poll());
        }
        tick += 1;
        for ev in engine.dispatch(events) {
            if json {
                println!("{}", serde_json::to_string(&ev).unwrap());
            } else {
                print_event(&ev);
            }
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn print_event(ev: &Event) {
    match ev {
        Event::ConnectionOpened(c) => println!("+ {} [{}] -> {}:{}", c.process, proto(c.proto), c.remote_addr, c.remote_port),
        Event::ConnectionClosed(c) => println!("- {} [{}] -> {}:{}", c.process, proto(c.proto), c.remote_addr, c.remote_port),
        Event::AppFirstSeen { process, .. } => println!("* first seen: {process}"),
        Event::DeviceSeen { ip, mac } => println!("* device: {ip} {mac}"),
        Event::TrafficSample { .. } => {}
        Event::Alert(a) => println!("! [{:?}] {}: {}", a.level, a.source, a.message),
    }
}

/// Windows: toggle `HKCU\...\Run` entry pointing to `conwatch-app.exe` next to this binary.
fn autostart(mode: Option<&str>) {
    if !cfg!(windows) {
        eprintln!("autostart is only implemented on Windows");
        return;
    }
    let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
    let res = match mode {
        Some("on") => {
            let app = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("conwatch-app.exe")));
            match app.filter(|p| p.is_file()) {
                Some(p) => std::process::Command::new("reg")
                    .args(["add", key, "/v", "ConWatch", "/t", "REG_SZ", "/d", &format!("\"{}\"", p.display()), "/f"])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false),
                None => {
                    eprintln!("conwatch-app.exe not found next to conwatch.exe");
                    false
                }
            }
        }
        Some("off") => std::process::Command::new("reg").args(["delete", key, "/v", "ConWatch", "/f"]).status().map(|s| s.success()).unwrap_or(false),
        _ => {
            eprintln!("usage: conwatch autostart on|off");
            return;
        }
    };
    println!("{}", if res { "ok" } else { "failed" });
}
