//! Built-in modules.

use crate::event::{AlertLevel, Event};
use crate::module::{Context, Module};

/// Warns when an application uses the network for the first time.
pub struct NewAppAlert;

impl Module for NewAppAlert {
    fn name(&self) -> &str {
        "new-app-alert"
    }
    fn on_event(&mut self, event: &Event, ctx: &mut Context) {
        if let Event::AppFirstSeen { process, .. } = event {
            ctx.alert(AlertLevel::Warning, self.name(), format!("New application is using the network: {process}"));
        }
    }
}

/// Warns when a new device appears on the local network.
pub struct NewDeviceAlert;

impl Module for NewDeviceAlert {
    fn name(&self) -> &str {
        "new-device-alert"
    }
    fn on_event(&mut self, event: &Event, ctx: &mut Context) {
        if let Event::DeviceSeen { ip, mac } = event {
            ctx.alert(AlertLevel::Warning, self.name(), format!("New device on the network: {ip} ({mac})"));
        }
    }
}

/// Warns on sustained high download/upload (default threshold 50 MB/s) – a simple spike detector.
pub struct SpikeAlert {
    pub threshold_bps: u64,
    cooling: u32,
}

impl SpikeAlert {
    pub fn new(threshold_bps: u64) -> Self {
        Self { threshold_bps, cooling: 0 }
    }
}

impl Default for SpikeAlert {
    fn default() -> Self {
        Self::new(50 * 1024 * 1024)
    }
}

impl Module for SpikeAlert {
    fn name(&self) -> &str {
        "spike-alert"
    }
    fn on_event(&mut self, event: &Event, ctx: &mut Context) {
        if let Event::TrafficSample { rx_bytes, tx_bytes, interval_ms } = event {
            self.cooling = self.cooling.saturating_sub(1);
            let bps = (rx_bytes + tx_bytes) * 1000 / interval_ms.max(&1);
            if bps > self.threshold_bps && self.cooling == 0 {
                self.cooling = 60;
                ctx.alert(AlertLevel::Warning, self.name(), format!("Traffic spike: {:.1} MB/s", bps as f64 / 1_048_576.0));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn spike_triggers_once() {
        let mut m = SpikeAlert::new(1000);
        let mut c = Context::default();
        let ev = Event::TrafficSample { rx_bytes: 5000, tx_bytes: 0, interval_ms: 1000 };
        m.on_event(&ev, &mut c);
        m.on_event(&ev, &mut c);
        assert_eq!(c.out.len(), 1);
    }
}
