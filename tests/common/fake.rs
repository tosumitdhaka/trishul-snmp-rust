//! FakeClock and FakeRng for deterministic tests.

use std::sync::Mutex;
use std::time::Duration;

use trishul_snmp::time::{Clock, Rng};

/// A controllable clock.
pub struct FakeClock {
    monotonic: Mutex<Duration>,
    unix: Mutex<u64>,
}

impl FakeClock {
    /// Creates a clock frozen at the given times.
    #[must_use]
    pub fn new(monotonic: Duration, unix: u64) -> Self {
        Self {
            monotonic: Mutex::new(monotonic),
            unix: Mutex::new(unix),
        }
    }

    /// Sets the monotonic reading.
    pub fn set_monotonic(&self, value: Duration) {
        *self.monotonic.lock().unwrap() = value;
    }

    /// Sets the unix reading.
    pub fn set_unix(&self, value: u64) {
        *self.unix.lock().unwrap() = value;
    }
}

impl Clock for FakeClock {
    fn monotonic(&self) -> Duration {
        *self.monotonic.lock().unwrap()
    }

    fn unix(&self) -> u64 {
        *self.unix.lock().unwrap()
    }
}

/// A deterministic byte source replaying a fixed byte stream (repeats the
/// final byte once exhausted).
pub struct FakeRng {
    bytes: Mutex<std::collections::VecDeque<u8>>,
}

impl FakeRng {
    /// Creates an RNG seeded with `bytes`.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: Mutex::new(bytes.iter().copied().collect()),
        }
    }

    /// Appends more bytes to the stream.
    pub fn push(&self, bytes: &[u8]) {
        self.bytes.lock().unwrap().extend(bytes.iter().copied());
    }
}

impl Rng for FakeRng {
    fn fill_bytes(&self, buf: &mut [u8]) {
        let mut stream = self.bytes.lock().unwrap();
        for slot in buf.iter_mut() {
            *slot = stream.pop_front().unwrap_or(0);
        }
    }
}
