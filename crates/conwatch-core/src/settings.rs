//! User settings persisted as JSON.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// "auto" | "light" | "dark"
    pub theme: String,
    /// How long traffic history is kept.
    pub retention_days: u32,
    /// Spike alert threshold in MB/s.
    pub spike_mb_s: u32,
    /// Alert when a new application uses the network.
    pub alert_new_apps: bool,
    /// Automatically add a firewall block for every newly seen application (needs Administrator).
    pub auto_block_new_apps: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self { theme: "auto".into(), retention_days: 90, spike_mb_s: 50, alert_new_apps: true, auto_block_new_apps: false }
    }
}

impl Settings {
    /// Clamp/normalize untrusted values.
    pub fn sanitized(mut self) -> Self {
        if !["auto", "light", "dark"].contains(&self.theme.as_str()) {
            self.theme = "auto".into();
        }
        self.retention_days = self.retention_days.clamp(1, 3650);
        self.spike_mb_s = self.spike_mb_s.clamp(1, 10_000);
        self
    }

    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str::<Settings>(&t).ok())
            .unwrap_or_default()
            .sanitized()
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let t = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, t).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sanitizes() {
        let s = Settings { theme: "neon".into(), retention_days: 0, spike_mb_s: 999_999, alert_new_apps: true, auto_block_new_apps: false }.sanitized();
        assert_eq!((s.theme.as_str(), s.retention_days, s.spike_mb_s), ("auto", 1, 10_000));
        let p: Settings = serde_json::from_str(r#"{"theme":"dark"}"#).unwrap();
        assert_eq!(p.retention_days, 90);
    }
}
