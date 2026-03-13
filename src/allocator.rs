// Linux binaries use the system allocator by default. `linux-mimalloc` is only
// enabled for controlled benchmark variants where we explicitly want to compare it.
#[cfg(all(target_os = "linux", feature = "linux-mimalloc"))]
use mimalloc::MiMalloc;

#[cfg(all(target_os = "linux", feature = "linux-mimalloc"))]
#[global_allocator]
static GLOBAL_ALLOCATOR: MiMalloc = MiMalloc;
