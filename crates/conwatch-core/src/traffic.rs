//! Total network throughput sampler (all interfaces, no admin rights needed).

use crate::event::Event;
use std::time::Instant;
use sysinfo::Networks;

pub struct TrafficSampler {
    nets: Networks,
    last: Instant,
}

impl Default for TrafficSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficSampler {
    pub fn new() -> Self {
        let mut nets = Networks::new_with_refreshed_list();
        nets.refresh(true);
        Self { nets, last: Instant::now() }
    }

    /// Bytes moved since the previous call.
    pub fn sample(&mut self) -> Event {
        self.nets.refresh(true);
        let (mut rx, mut tx) = (0, 0);
        for n in self.nets.values() {
            rx += n.received();
            tx += n.transmitted();
        }
        let now = Instant::now();
        let ms = now.duration_since(self.last).as_millis() as u64;
        self.last = now;
        Event::TrafficSample { rx_bytes: rx, tx_bytes: tx, interval_ms: ms.max(1) }
    }
}
