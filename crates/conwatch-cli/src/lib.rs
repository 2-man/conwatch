//! ConWatch application library: dashboard server and engine assembly.
pub mod flags;
pub mod serve;

use conwatch_core::builtin::{NewAppAlert, NewDeviceAlert, SpikeAlert};
use conwatch_core::{external, Engine};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;

/// Engine with default settings (CLI use).
pub fn default_engine() -> (Engine, Vec<String>, Vec<String>) {
    build_engine(Arc::new(AtomicU64::new(50 * 1024 * 1024)), Arc::new(AtomicBool::new(true)))
}

pub fn data_dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."));
    let d = base.join("ConWatch");
    let _ = std::fs::create_dir_all(&d);
    d
}

/// Engine with built-in modules plus user modules from `<data>/modules` and `./modules`.
pub fn build_engine(spike_bps: Arc<AtomicU64>, new_app_alerts: Arc<AtomicBool>) -> (Engine, Vec<String>, Vec<String>) {
    let mut engine = Engine::new();
    engine.register(Box::new(NewAppAlert { enabled: new_app_alerts }));
    engine.register(Box::new(NewDeviceAlert));
    engine.register(Box::new(SpikeAlert::shared(spike_bps)));
    let mut names = vec!["new-app-alert".to_string(), "new-device-alert".into(), "spike-alert".into()];
    let mut errors = Vec::new();
    for dir in [data_dir().join("modules"), PathBuf::from("modules")] {
        let (mods, errs) = external::load_dir(&dir);
        errors.extend(errs);
        for m in mods {
            names.push(m.manifest().name.clone());
            engine.register(Box::new(m));
        }
    }
    (engine, names, errors)
}

