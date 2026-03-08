use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug)]
pub struct ActivityTracker {
    started_at: Instant,
    last_active_ms: AtomicU64,
}

impl ActivityTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            started_at: Instant::now(),
            last_active_ms: AtomicU64::new(0),
        })
    }

    pub fn record(&self) {
        let elapsed_ms = self
            .started_at
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        self.last_active_ms.store(elapsed_ms, Ordering::Relaxed);
    }

    pub fn idle_for(&self) -> Duration {
        let now_ms = self
            .started_at
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        let last_active_ms = self.last_active_ms.load(Ordering::Relaxed);
        Duration::from_millis(now_ms.saturating_sub(last_active_ms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resets_idle_when_recorded() {
        let tracker = ActivityTracker::new();
        assert!(tracker.idle_for() <= Duration::from_secs(1));
        tracker.record();
        assert!(tracker.idle_for() <= Duration::from_secs(1));
    }
}
