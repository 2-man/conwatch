use conwatch_core::event::{AlertLevel, Event, Proto};
use conwatch_core::monitor::ConnectionMonitor;
use conwatch_core::{Context, Engine, Module};
use std::{env, thread, time::Duration};

/// Built-in example module: warns when an application is seen for the first time.
struct NewAppAlert;

impl Module for NewAppAlert {
    fn name(&self) -> &str {
        "new-app-alert"
    }
    fn on_event(&mut self, event: &Event, ctx: &mut Context) {
        if let Event::AppFirstSeen { process, .. } = event {
            ctx.alert(
                AlertLevel::Warning,
                self.name(),
                format!("New application is using the network: {process}"),
            );
        }
    }
}

fn proto(p: Proto) -> &'static str {
    match p {
        Proto::Tcp => "TCP",
        Proto::Udp => "UDP",
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("list") => list(),
        Some("watch") => watch(args.iter().any(|a| a == "--json")),
        _ => {
            eprintln!("conwatch {}\n", env!("CARGO_PKG_VERSION"));
            eprintln!("USAGE:\n  conwatch list            show current connections per process");
            eprintln!("  conwatch watch [--json]  stream connection events (Ctrl+C to stop)");
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
    conns.sort_by(|a, b| a.process.to_lowercase().cmp(&b.process.to_lowercase()));
    println!("{:<28} {:>6}  {:<5} REMOTE", "PROCESS", "PID", "PROTO");
    for c in conns {
        println!(
            "{:<28} {:>6}  {:<5} {}:{}",
            c.process,
            c.pid,
            proto(c.proto),
            c.remote_addr,
            c.remote_port
        );
    }
}

fn watch(json: bool) {
    let mut engine = Engine::new();
    engine.register(Box::new(NewAppAlert));
    let mut mon = ConnectionMonitor::new();
    loop {
        match mon.poll() {
            Ok(events) => {
                for ev in engine.dispatch(events) {
                    if json {
                        println!("{}", serde_json::to_string(&ev).unwrap());
                    } else {
                        print_event(&ev);
                    }
                }
            }
            Err(e) => eprintln!("error: {e}"),
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn print_event(ev: &Event) {
    match ev {
        Event::ConnectionOpened(c) => println!(
            "+ {} [{}] -> {}:{}",
            c.process,
            proto(c.proto),
            c.remote_addr,
            c.remote_port
        ),
        Event::ConnectionClosed(c) => println!(
            "- {} [{}] -> {}:{}",
            c.process,
            proto(c.proto),
            c.remote_addr,
            c.remote_port
        ),
        Event::AppFirstSeen { process, .. } => println!("* first seen: {process}"),
        Event::Alert(a) => println!("! [{:?}] {}: {}", a.level, a.source, a.message),
    }
}
