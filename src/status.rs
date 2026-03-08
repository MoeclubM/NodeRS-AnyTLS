use crate::panel::{MemoryStat, StatusPayload};

pub fn collect_status() -> StatusPayload {
    #[cfg(windows)]
    {
        windows::collect_status()
    }

    #[cfg(not(windows))]
    {
        StatusPayload::default()
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::mem::{size_of, zeroed};
    use std::sync::OnceLock;
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::Storage::FileSystem::{GetDiskFreeSpaceExW, GetLogicalDrives};
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    use windows_sys::Win32::System::Threading::GetSystemTimes;

    static CPU_SAMPLER: OnceLock<std::sync::Mutex<CpuSampler>> = OnceLock::new();

    pub fn collect_status() -> StatusPayload {
        let mem = memory();
        let swap = swap();
        let disk = disk();
        let cpu = cpu();
        StatusPayload {
            cpu,
            mem,
            swap,
            disk,
        }
    }

    fn cpu() -> f64 {
        let sampler = CPU_SAMPLER.get_or_init(|| std::sync::Mutex::new(CpuSampler::default()));
        sampler.lock().expect("cpu sampler poisoned").sample()
    }

    fn memory() -> MemoryStat {
        unsafe {
            let mut status: MEMORYSTATUSEX = zeroed();
            status.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
            if GlobalMemoryStatusEx(&mut status) == 0 {
                return MemoryStat::default();
            }
            MemoryStat {
                total: status.ullTotalPhys,
                used: status.ullTotalPhys.saturating_sub(status.ullAvailPhys),
            }
        }
    }

    fn swap() -> MemoryStat {
        unsafe {
            let mut status: MEMORYSTATUSEX = zeroed();
            status.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
            if GlobalMemoryStatusEx(&mut status) == 0 {
                return MemoryStat::default();
            }
            MemoryStat {
                total: status.ullTotalPageFile,
                used: status
                    .ullTotalPageFile
                    .saturating_sub(status.ullAvailPageFile),
            }
        }
    }

    fn disk() -> MemoryStat {
        let root = system_root_drive();
        let wide = root
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        unsafe {
            let mut free_available = 0u64;
            let mut total = 0u64;
            let mut total_free = 0u64;
            if GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &mut free_available,
                &mut total,
                &mut total_free,
            ) == 0
            {
                return MemoryStat::default();
            }
            MemoryStat {
                total,
                used: total.saturating_sub(total_free),
            }
        }
    }

    fn system_root_drive() -> String {
        std::env::var("SystemDrive")
            .map(|value| format!("{value}\\"))
            .unwrap_or_else(|_| {
                let mask = unsafe { GetLogicalDrives() };
                for index in 0..26 {
                    if (mask & (1 << index)) != 0 {
                        return format!("{}:\\", (b'A' + index as u8) as char);
                    }
                }
                "C:\\".to_string()
            })
    }

    #[derive(Debug, Default)]
    struct CpuSampler {
        previous_idle: u64,
        previous_kernel: u64,
        previous_user: u64,
        primed: bool,
    }

    impl CpuSampler {
        fn sample(&mut self) -> f64 {
            let (idle, kernel, user) = unsafe {
                let mut idle = FILETIME::default();
                let mut kernel = FILETIME::default();
                let mut user = FILETIME::default();
                if GetSystemTimes(&mut idle, &mut kernel, &mut user) == 0 {
                    return 0.0;
                }
                (as_u64(idle), as_u64(kernel), as_u64(user))
            };

            if !self.primed {
                self.previous_idle = idle;
                self.previous_kernel = kernel;
                self.previous_user = user;
                self.primed = true;
                return 0.0;
            }

            let idle_delta = idle.saturating_sub(self.previous_idle);
            let kernel_delta = kernel.saturating_sub(self.previous_kernel);
            let user_delta = user.saturating_sub(self.previous_user);
            self.previous_idle = idle;
            self.previous_kernel = kernel;
            self.previous_user = user;

            let total = kernel_delta.saturating_add(user_delta);
            if total == 0 {
                return 0.0;
            }
            let busy = total.saturating_sub(idle_delta);
            (busy as f64 / total as f64) * 100.0
        }
    }

    fn as_u64(time: FILETIME) -> u64 {
        ((time.dwHighDateTime as u64) << 32) | time.dwLowDateTime as u64
    }
}
