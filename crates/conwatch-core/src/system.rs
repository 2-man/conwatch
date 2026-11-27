//! Hardware resource sampler (CPU, memory, disk throughput) for the System tab.

use sysinfo::{DiskRefreshKind, Disks, MemoryRefreshKind, System};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SystemSample {
    pub ts: i64,
    /// Percent, 0..100.
    pub cpu: f32,
    pub mem_used: u64,
    pub mem_total: u64,
    /// Bytes during the last sampling interval.
    pub disk_read: u64,
    pub disk_write: u64,
}

pub struct SystemSampler {
    sys: System,
    disks: Disks,
}

impl Default for SystemSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemSampler {
    pub fn new() -> Self {
        let mut sys = System::new();
        sys.refresh_cpu_usage();
        let mut disks = Disks::new_with_refreshed_list();
        disks.refresh_specifics(true, DiskRefreshKind::nothing().with_io_usage());
        Self { sys, disks }
    }

    pub fn sample(&mut self, ts: i64) -> SystemSample {
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory_specifics(MemoryRefreshKind::nothing().with_ram());
        self.disks.refresh_specifics(true, DiskRefreshKind::nothing().with_io_usage());
        let (mut r, mut w) = (0, 0);
        for d in self.disks.list() {
            let u = d.usage();
            r += u.read_bytes;
            w += u.written_bytes;
        }
        SystemSample {
            ts,
            cpu: self.sys.global_cpu_usage(),
            mem_used: self.sys.used_memory(),
            mem_total: self.sys.total_memory(),
            disk_read: r,
            disk_write: w,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn samples_are_sane() {
        let mut s = SystemSampler::new();
        std::thread::sleep(std::time::Duration::from_millis(300));
        let x = s.sample(1);
        assert!(x.mem_total > 0 && x.mem_used <= x.mem_total);
        assert!((0.0..=100.0).contains(&x.cpu));
    }
}
