use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct SharedRateLimiter {
    state: Mutex<BucketState>,
}

#[derive(Debug)]
struct BucketState {
    bytes_per_second: u64,
    burst_bytes: u64,
    available_at: Instant,
}

impl SharedRateLimiter {
    pub fn new(bytes_per_second: u64) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(BucketState {
                bytes_per_second,
                burst_bytes: bucket_capacity(bytes_per_second),
                available_at: Instant::now(),
            }),
        })
    }

    pub fn set_rate(&self, bytes_per_second: u64) {
        let mut state = self.state.lock().expect("rate limiter poisoned");
        state.bytes_per_second = bytes_per_second;
        state.burst_bytes = bucket_capacity(bytes_per_second);
        state.available_at = Instant::now();
    }

    pub async fn consume(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let wait = {
            let mut state = self.state.lock().expect("rate limiter poisoned");
            if state.bytes_per_second == 0 {
                return;
            }

            let now = Instant::now();
            let burst_window = burst_window(state.bytes_per_second, state.burst_bytes);
            let earliest = now.checked_sub(burst_window).unwrap_or(now);
            if state.available_at < earliest {
                state.available_at = earliest;
            }

            let start = state.available_at.max(now);
            let wait = start.saturating_duration_since(now);
            state.available_at = start + reserve_duration(bytes, state.bytes_per_second);
            wait
        };

        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

fn reserve_duration(bytes: usize, bytes_per_second: u64) -> Duration {
    Duration::from_secs_f64(bytes as f64 / bytes_per_second as f64)
}

fn burst_window(bytes_per_second: u64, burst_bytes: u64) -> Duration {
    if bytes_per_second == 0 || burst_bytes == 0 {
        Duration::ZERO
    } else {
        Duration::from_secs_f64(burst_bytes as f64 / bytes_per_second as f64)
    }
}

fn bucket_capacity(bytes_per_second: u64) -> u64 {
    if bytes_per_second == 0 {
        0
    } else {
        bytes_per_second.max(64 * 1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updates_rate() {
        let limiter = SharedRateLimiter::new(1024);
        limiter.set_rate(2048);
        let state = limiter.state.lock().expect("rate limiter poisoned");
        assert_eq!(state.bytes_per_second, 2048);
        assert_eq!(state.burst_bytes, 64 * 1024);
    }
}
