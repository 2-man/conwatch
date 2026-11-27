//! ConWatch application library: dashboard server and engine assembly.
pub mod serve;

use conwatch_core::builtin::{NewAppAlert, NewDeviceAlert, SpikeAlert};
use conwatch_core::{external, Engine};
use std::path::PathBuf;

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
pub fn build_engine() -> (Engine, Vec<String>, Vec<String>) {
    let mut engine = Engine::new();
    engine.register(Box::new(NewAppAlert));
    engine.register(Box::new(NewDeviceAlert));
    engine.register(Box::new(SpikeAlert::default()));
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

