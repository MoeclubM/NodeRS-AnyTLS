use crate::panel::StatusPayload;

pub fn collect_status() -> StatusPayload {
    #[cfg(target_os = "linux")]
    {
        linux::collect_status()
    }

    #[cfg(not(target_os = "linux"))]
    {
        StatusPayload::default()
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use libc::statvfs;
    use std::ffi::CString;
    use std::fs;
    use std::sync::{Mutex, OnceLock};

    use crate::panel::MemoryStat;

    static CPU_SAMPLER: OnceLock<Mutex<CpuSampler>> = OnceLock::new();

    pub fn collect_status() -> StatusPayload {
        StatusPayload {
            cpu: cpu_usage(),
            mem: memory(),
            swap: swap(),
            disk: disk(),
        }
    }

    fn cpu_usage() -> f64 {
        let sampler = CPU_SAMPLER.get_or_init(|| Mutex::new(CpuSampler::default()));
        let mut sampler = sampler.lock().expect("cpu sampler poisoned");
        read_proc_stat()
            .map(|sample| sampler.sample(sample))
            .unwrap_or_default()
    }

    fn memory() -> MemoryStat {
        let meminfo = read_meminfo();
        let total = meminfo.get("MemTotal").copied().unwrap_or(0);
        let available = meminfo
            .get("MemAvailable")
            .copied()
            .or_else(|| {
                Some(
                    meminfo.get("MemFree").copied().unwrap_or(0)
                        + meminfo.get("Buffers").copied().unwrap_or(0)
                        + meminfo.get("Cached").copied().unwrap_or(0),
                )
            })
            .unwrap_or(0);
        MemoryStat {
            total,
            used: total.saturating_sub(available),
        }
    }

    fn swap() -> MemoryStat {
        let meminfo = read_meminfo();
        let total = meminfo.get("SwapTotal").copied().unwrap_or(0);
        let free = meminfo.get("SwapFree").copied().unwrap_or(0);
        MemoryStat {
            total,
            used: total.saturating_sub(free),
        }
    }

    fn disk() -> MemoryStat {
        let path = match CString::new("/") {
            Ok(path) => path,
            Err(_) => return MemoryStat::default(),
        };
        let mut stats = std::mem::MaybeUninit::uninit();
        let result = unsafe { statvfs(path.as_ptr(), stats.as_mut_ptr()) };
        if result != 0 {
            return MemoryStat::default();
        }
        let stats = unsafe { stats.assume_init() };
        let block_size = stats.f_frsize.max(1);
        let total = stats.f_blocks.saturating_mul(block_size);
        let free = stats.f_bavail.saturating_mul(block_size);
        MemoryStat {
            total,
            used: total.saturating_sub(free),
        }
    }

    fn read_meminfo() -> std::collections::HashMap<&'static str, u64> {
        fs::read_to_string("/proc/meminfo")
            .ok()
            .map(|contents| parse_meminfo(&contents))
            .unwrap_or_default()
    }

    fn read_proc_stat() -> Option<CpuSample> {
        let contents = fs::read_to_string("/proc/stat").ok()?;
        parse_proc_stat(&contents)
    }

    fn parse_proc_stat(contents: &str) -> Option<CpuSample> {
        let line = contents.lines().find(|line| line.starts_with("cpu "))?;
        let mut parts = line.split_whitespace().skip(1);
        let user = parts.next()?.parse::<u64>().ok()?;
        let nice = parts.next()?.parse::<u64>().ok()?;
        let system = parts.next()?.parse::<u64>().ok()?;
        let idle = parts.next()?.parse::<u64>().ok()?;
        let iowait = parts
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let irq = parts
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let softirq = parts
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let steal = parts
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let idle_all = idle.saturating_add(iowait);
        let total = user
            .saturating_add(nice)
            .saturating_add(system)
            .saturating_add(idle_all)
            .saturating_add(irq)
            .saturating_add(softirq)
            .saturating_add(steal);
        Some(CpuSample {
            idle: idle_all,
            total,
        })
    }

    fn parse_meminfo(contents: &str) -> std::collections::HashMap<&'static str, u64> {
        let mut parsed = std::collections::HashMap::new();
        for line in contents.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let bytes = value
                .split_whitespace()
                .next()
                .and_then(|number| number.parse::<u64>().ok())
                .map(|kilobytes| kilobytes.saturating_mul(1024))
                .unwrap_or(0);
            match key {
                "MemTotal" => {
                    parsed.insert("MemTotal", bytes);
                }
                "MemAvailable" => {
                    parsed.insert("MemAvailable", bytes);
                }
                "MemFree" => {
                    parsed.insert("MemFree", bytes);
                }
                "Buffers" => {
                    parsed.insert("Buffers", bytes);
                }
                "Cached" => {
                    parsed.insert("Cached", bytes);
                }
                "SwapTotal" => {
                    parsed.insert("SwapTotal", bytes);
                }
                "SwapFree" => {
                    parsed.insert("SwapFree", bytes);
                }
                _ => {}
            }
        }
        parsed
    }

    #[derive(Debug, Clone, Copy)]
    struct CpuSample {
        idle: u64,
        total: u64,
    }

    #[derive(Debug, Default)]
    struct CpuSampler {
        previous: Option<CpuSample>,
    }

    impl CpuSampler {
        fn sample(&mut self, next: CpuSample) -> f64 {
            let Some(previous) = self.previous.replace(next) else {
                return 0.0;
            };
            let idle_delta = next.idle.saturating_sub(previous.idle);
            let total_delta = next.total.saturating_sub(previous.total);
            if total_delta == 0 {
                return 0.0;
            }
            let busy_delta = total_delta.saturating_sub(idle_delta);
            (busy_delta as f64 / total_delta as f64) * 100.0
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_proc_stat_sample() {
            let sample = parse_proc_stat("cpu  100 5 20 200 10 1 2 3\n").expect("cpu sample");
            assert_eq!(sample.idle, 210);
            assert_eq!(sample.total, 341);
        }

        #[test]
        fn parses_meminfo_values() {
            let info = parse_meminfo(
                "MemTotal:       1024 kB\nMemAvailable:    256 kB\nSwapTotal:       128 kB\nSwapFree:        64 kB\n",
            );
            assert_eq!(info.get("MemTotal"), Some(&(1024 * 1024)));
            assert_eq!(info.get("MemAvailable"), Some(&(256 * 1024)));
            assert_eq!(info.get("SwapTotal"), Some(&(128 * 1024)));
            assert_eq!(info.get("SwapFree"), Some(&(64 * 1024)));
        }
    }
}
