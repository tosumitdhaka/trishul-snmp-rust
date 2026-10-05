//! Clock + Rng traits, System impls (seams)
//!
//! Two tiny traits, `Arc<dyn _>`-injected and defaulted in every config,
//! replacing the monkeypatch surfaces of the Python test suite
//! (docs/architecture.md §7).

use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A monotonic/unix time source. Consumed where monotonic values fold into
/// protocol state (engine-time anchors, replay windows, drop-log rate limits).
pub trait Clock: Send + Sync {
    /// Seconds elapsed since an arbitrary, monotonic anchor.
    fn monotonic(&self) -> Duration;
    /// Unix seconds.
    fn unix(&self) -> u64;
}

/// The production clock: real monotonic time (anchored at first use) and the
/// system wall clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn monotonic(&self) -> Duration {
        static START: OnceLock<Instant> = OnceLock::new();
        START.get_or_init(Instant::now).elapsed()
    }

    fn unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// A random-byte source. Consumed for request ids, USM salts, and simulation
/// rules.
pub trait Rng: Send + Sync {
    /// Fills `buf` with random bytes.
    fn fill_bytes(&self, buf: &mut [u8]);
}

/// The production RNG: the OS CSPRNG (`/dev/urandom`), std-only dependency
/// surface.
pub struct SystemRng;

impl Rng for SystemRng {
    fn fill_bytes(&self, buf: &mut [u8]) {
        use std::io::Read;
        let mut file =
            std::fs::File::open("/dev/urandom").expect("SystemRng: /dev/urandom must be readable");
        file.read_exact(buf)
            .expect("SystemRng: short read from /dev/urandom");
    }
}
