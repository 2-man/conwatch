//! User modules: external processes speaking JSON lines over stdio.
//!
//! `module.toml`:
//! ```toml
//! name = "my-module"
//! version = "0.1.0"
//! description = "..."
//! command = "python"
//! args = ["main.py"]
//! permissions = ["events:read", "alerts:emit"]
//! ```
//! ConWatch writes each [`Event`] as one JSON line to the module's stdin
//! (requires `events:read`). The module may print action lines to stdout, e.g.
//! `{"action":"alert","level":"warning","message":"text"}` (requires `alerts:emit`).

use crate::event::{AlertLevel, Event};
use crate::module::{Context, Module};
use serde::Deserialize;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::thread;

#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum Action {
    Alert {
        #[serde(default = "default_level")]
        level: AlertLevel,
        message: String,
    },
    Log {
        message: String,
    },
}

fn default_level() -> AlertLevel {
    AlertLevel::Info
}

pub struct ExternalModule {
    manifest: Manifest,
    child: Child,
    stdin: Option<ChildStdin>,
    actions: Receiver<Action>,
}

impl ExternalModule {
    fn can(&self, perm: &str) -> bool {
        self.manifest.permissions.iter().any(|p| p == perm)
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn spawn(dir: &Path, manifest: Manifest) -> Result<Self, String> {
        let mut child = Command::new(&manifest.command)
            .args(&manifest.args)
            .current_dir(dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("{}: cannot start '{}': {e}", manifest.name, manifest.command))?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().ok_or("no stdout")?;
        let (tx, rx) = channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Ok(a) = serde_json::from_str::<Action>(&line) {
                    if tx.send(a).is_err() {
                        break;
                    }
                }
            }
        });
        Ok(Self { manifest, child, stdin, actions: rx })
    }
}

impl Drop for ExternalModule {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Module for ExternalModule {
    fn name(&self) -> &str {
        &self.manifest.name
    }

    fn on_event(&mut self, event: &Event, ctx: &mut Context) {
        // Never feed a module its own alerts back (avoid loops).
        if let Event::Alert(a) = event {
            if a.source == self.manifest.name {
                return;
            }
        }
        if self.can("events:read") {
            if let (Some(stdin), Ok(line)) = (self.stdin.as_mut(), serde_json::to_string(event)) {
                if writeln!(stdin, "{line}").and_then(|_| stdin.flush()).is_err() {
                    self.stdin = None; // module exited
                }
            }
        }
        while let Ok(action) = self.actions.try_recv() {
            match action {
                Action::Alert { level, message } if self.can("alerts:emit") => {
                    let name = self.manifest.name.clone();
                    ctx.alert(level, &name, message)
                }
                Action::Log { message } => eprintln!("[{}] {message}", self.manifest.name),
                _ => {}
            }
        }
    }
}

/// Load every `<dir>/*/module.toml`. Returns modules and human-readable errors.
pub fn load_dir(dir: &Path) -> (Vec<ExternalModule>, Vec<String>) {
    let (mut mods, mut errs) = (Vec::new(), Vec::new());
    let Ok(rd) = std::fs::read_dir(dir) else { return (mods, errs) };
    let mut dirs: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.join("module.toml").is_file()).collect();
    dirs.sort();
    for d in dirs {
        let res = std::fs::read_to_string(d.join("module.toml"))
            .map_err(|e| e.to_string())
            .and_then(|t| toml::from_str::<Manifest>(&t).map_err(|e| e.to_string()))
            .and_then(|m| ExternalModule::spawn(&d, m));
        match res {
            Ok(m) => mods.push(m),
            Err(e) => errs.push(format!("{}: {e}", d.display())),
        }
    }
    (mods, errs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_parses() {
        let m: Manifest = toml::from_str("name='x'\ncommand='python'\npermissions=['events:read']").unwrap();
        assert_eq!(m.name, "x");
        assert!(m.args.is_empty());
    }

    #[test]
    fn action_parses() {
        let a: Action = serde_json::from_str(r#"{"action":"alert","level":"critical","message":"m"}"#).unwrap();
        assert!(matches!(a, Action::Alert { level: AlertLevel::Critical, .. }));
    }
}
