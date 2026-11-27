use conwatch_core::external::{Manifest, ExternalModule};
use conwatch_core::event::{Connection, Event, Proto};
use conwatch_core::Engine;
use std::path::PathBuf;
use std::time::Duration;

fn python_available() -> bool {
    std::process::Command::new("python").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
}

#[test]
fn example_module_raises_alert_over_stdio() {
    if !python_available() {
        eprintln!("python not found, skipping");
        return;
    }
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../modules/example-telnet-alert");
    let manifest: Manifest = toml_parse(&std::fs::read_to_string(dir.join("module.toml")).unwrap());
    let module = ExternalModule::spawn(&dir, manifest).unwrap();
    let mut engine = Engine::new();
    engine.register(Box::new(module));

    let conn = Connection {
        proto: Proto::Tcp,
        local_addr: "10.0.0.2".parse().unwrap(),
        local_port: 50000,
        remote_addr: "10.0.0.9".parse().unwrap(),
        remote_port: 23,
        pid: 1,
        process: "telnet.exe".into(),
        exe: None,
    };
    // The module replies asynchronously: dispatch a few rounds until its alert arrives.
    let mut got = false;
    for _ in 0..50 {
        let out = engine.dispatch(vec![Event::ConnectionOpened(conn.clone())]);
        if out.iter().any(|e| matches!(e, Event::Alert(a) if a.source == "example-telnet-alert")) {
            got = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(got, "module alert not received");
}

fn toml_parse(s: &str) -> Manifest {
    // Manifest is Deserialize; parse via the toml crate re-exported through serde_json-free path.
    toml::from_str(s).unwrap()
}
