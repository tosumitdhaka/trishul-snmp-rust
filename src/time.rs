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

/// The production RNG: the OS CSPRNG.
///
/// On unix that is `/dev/urandom` (std-only). Other platforms (Windows) have
/// no std CSPRNG and no new dependency is allowed here, so the bytes are
/// derived from `std::collections::hash_map::RandomState`'s OS-seeded SipHash
/// keys: a fresh OS-CSPRNG seed per 8-byte chunk, expanded through the
/// secret-keyed `DefaultHasher` (a PRF), so the output stream is
/// cryptographically pseudorandom. A future maintenance pass may swap in the
/// `getrandom` crate for a single-call CSPRNG on every platform.
pub struct SystemRng;

impl Rng for SystemRng {
    fn fill_bytes(&self, buf: &mut [u8]) {
        fill_system_random(buf);
    }
}

/// OS CSPRNG bytes via `/dev/urandom` (unix).
#[cfg(unix)]
fn fill_system_random(buf: &mut [u8]) {
    use std::io::Read;
    let mut file =
        std::fs::File::open("/dev/urandom").expect("SystemRng: /dev/urandom must be readable");
    file.read_exact(buf)
        .expect("SystemRng: short read from /dev/urandom");
}

/// OS-seeded pseudorandom bytes on platforms without a std CSPRNG (see
/// [`SystemRng`] for the security note).
#[cfg(not(unix))]
fn fill_system_random(buf: &mut [u8]) {
    use std::hash::{BuildHasher, Hasher};
    let mut index = 0u64;
    for chunk in buf.chunks_mut(8) {
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(index);
        index += 1;
        let bits = hasher.finish().to_le_bytes();
        let len = chunk.len();
        chunk.copy_from_slice(&bits[..len]);
    }
}
