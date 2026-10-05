//! V3ReplayGuard, salt LRU, shared drop taxonomy, verdicts (← notify/v3.py:90–285)
//!
//! The RFC 3414 §3.2.7 receive-side replay and time-window checks live here,
//! together with the nine-member drop taxonomy shared by both notification
//! listeners (`DropReason`) and the verdict→reason mapping.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use crate::time::Clock;

/// Receive-side time-window half-width in seconds (notify/v3.py:71).
const TIME_WINDOW_SECONDS: f64 = 150.0;
/// Bounded per-(engine, username) salt cache size (notify/v3.py:72).
const SALT_CACHE_SIZE: usize = 64;

/// Shared drop taxonomy for the v2c and v3 notification listeners
/// (notify/v3.py:90–107).
///
/// One member per reason a received datagram is discarded instead of being
/// surfaced as a notification event. The replay/time-window members map
/// one-to-one onto [`V3ReceiveVerdict`]; the remaining members cover the v2c
/// and v3 decode paths. The discriminant order doubles as the
/// `crate::notify::listener::DropCounts` index order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(usize)]
pub enum DropReason {
    /// The datagram is not decodable BER for its version's message envelope.
    UndecodableBer = 0,
    /// v2c: the community is not allow-listed.
    WrongCommunity = 1,
    /// v1/v2c: the version INTEGER names an unsupported version.
    UnsupportedVersion = 2,
    /// v3: the message names a user other than the configured one.
    WrongUser = 3,
    /// The message decoded but its PDU is not a notification.
    NotNotification = 4,
    /// v3: the HMAC did not verify.
    AuthenticationFailed = 5,
    /// v3: engine boots went backwards (replay).
    EngineBootsReplay = 6,
    /// v3: engine time outside the ±150 s window.
    OutsideTimeWindow = 7,
    /// v3: an identical (boots, time, salt) tuple was seen before.
    DuplicateSalt = 8,
}

impl DropReason {
    /// The wire/log label (the reference's `reason.value`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UndecodableBer => "undecodable-ber",
            Self::WrongCommunity => "wrong-community",
            Self::UnsupportedVersion => "unsupported-version",
            Self::WrongUser => "wrong-user",
            Self::NotNotification => "not-notification",
            Self::AuthenticationFailed => "authentication-failed",
            Self::EngineBootsReplay => "engine-boots-replay",
            Self::OutsideTimeWindow => "outside-time-window",
            Self::DuplicateSalt => "duplicate-salt",
        }
    }
}

impl std::fmt::Display for DropReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Receive-side disposition for an inbound SNMPv3 notification
/// (notify/v3.py:75–87).
///
/// `Accept` is the only pass verdict; every other member names the reason an
/// RFC 3414 §3.2.7 receive-side check rejected the datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V3ReceiveVerdict {
    /// Fresh message: pass.
    Accept,
    /// Engine boots went backwards for a known engine.
    EngineBootsReplay,
    /// Engine time outside the lag/lead acceptance window.
    OutsideTimeWindow,
    /// The exact (boots, time, salt) tuple was seen before.
    DuplicateSalt,
}

/// Maps a non-`Accept` verdict onto the shared drop taxonomy
/// (notify/v3.py:110–118).
#[must_use]
pub fn drop_reason_from_verdict(verdict: V3ReceiveVerdict) -> DropReason {
    match verdict {
        V3ReceiveVerdict::EngineBootsReplay => DropReason::EngineBootsReplay,
        V3ReceiveVerdict::OutsideTimeWindow => DropReason::OutsideTimeWindow,
        V3ReceiveVerdict::DuplicateSalt => DropReason::DuplicateSalt,
        V3ReceiveVerdict::Accept => panic!("ACCEPT is not a drop reason"),
    }
}

/// Snapshot of an authoritative engine's boots/time and its monotonic anchor
/// (notify/v3.py:145–152).
#[derive(Clone, Debug)]
struct EngineBaseline {
    engine_boots: i64,
    engine_time: i64,
    monotonic: Duration,
}

/// Bounded LRU of recently seen (engine_boots, engine_time, salt) tuples
/// (notify/v3.py:154–185).
///
/// Mirrors the RFC 3414 §3.2.7 privacy salt cache. Entries are keyed by the
/// full (boots, time, salt) tuple so a salt may be legitimately reused once
/// either boots or time advances.
#[derive(Default)]
struct SaltCache {
    entries: HashMap<(i64, i64, Vec<u8>), ()>,
    order: VecDeque<(i64, i64, Vec<u8>)>,
    capacity: usize,
}

impl SaltCache {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    /// Records `salt` unless already seen for the same boots/time.
    ///
    /// Returns `true` when the salt is fresh, `false` when the exact
    /// (engine_boots, engine_time, salt) tuple was seen before (replay).
    fn check_and_record(&mut self, engine_boots: i64, engine_time: i64, salt: &[u8]) -> bool {
        let key = (engine_boots, engine_time, salt.to_vec());
        if self.entries.contains_key(&key) {
            return false;
        }
        self.entries.insert(key.clone(), ());
        self.order.push_back(key);
        if self.order.len() > self.capacity
            && let Some(oldest) = self.order.pop_front()
        {
            self.entries.remove(&oldest);
        }
        true
    }

    /// Drops all recorded salts (called when the engine reboots).
    fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }
}

/// Per-engine and per-(engine, username) guard state behind the interior mutex.
#[derive(Default)]
struct ReplayState {
    baselines: HashMap<Vec<u8>, EngineBaseline>,
    salt_caches: HashMap<(Vec<u8>, String), SaltCache>,
}

/// RFC 3414 §3.2.7 receive-side replay and time-window checks
/// (notify/v3.py:188–285).
///
/// Tracks the authoritative engine (boots, time) baseline per engine_id,
/// anchored to the injected monotonic clock, plus a bounded per-(engine_id,
/// username) salt cache. Notifications that fail a check are dropped by the
/// caller; the returned [`V3ReceiveVerdict`] carries the reason.
///
/// The reference's `clock` callable is the `Clock` seam (§7) — a deterministic
/// test clock advances replay windows in the unit tests below.
pub struct V3ReplayGuard {
    state: std::sync::Mutex<ReplayState>,
    time_window: f64,
    salt_cache_size: usize,
    clock: Arc<dyn Clock>,
}

impl V3ReplayGuard {
    /// Creates a guard with the reference defaults (150 s window, 64-salt LRU).
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self::with_limits(clock, TIME_WINDOW_SECONDS, SALT_CACHE_SIZE)
    }

    /// Creates a guard with explicit window and cache limits (test seam).
    #[must_use]
    pub fn with_limits(clock: Arc<dyn Clock>, time_window: f64, salt_cache_size: usize) -> Self {
        Self {
            state: std::sync::Mutex::new(ReplayState::default()),
            time_window,
            salt_cache_size,
            clock,
        }
    }

    /// Returns `Accept` for a fresh message, otherwise the drop reason
    /// (notify/v3.py:212–237).
    #[must_use]
    pub fn check(
        &self,
        engine_id: &[u8],
        engine_boots: i64,
        engine_time: i64,
        username: &str,
        salt: &[u8],
    ) -> V3ReceiveVerdict {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let verdict = self.check_boots_and_time(&mut state, engine_id, engine_boots, engine_time);
        if verdict != V3ReceiveVerdict::Accept {
            return verdict;
        }
        if !salt.is_empty()
            && !self.check_salt(
                &mut state,
                engine_id,
                username,
                engine_boots,
                engine_time,
                salt,
            )
        {
            return V3ReceiveVerdict::DuplicateSalt;
        }
        V3ReceiveVerdict::Accept
    }

    fn check_boots_and_time(
        &self,
        state: &mut ReplayState,
        engine_id: &[u8],
        engine_boots: i64,
        engine_time: i64,
    ) -> V3ReceiveVerdict {
        let Some(baseline) = state.baselines.get(engine_id) else {
            state.baselines.insert(
                engine_id.to_vec(),
                EngineBaseline {
                    engine_boots,
                    engine_time,
                    monotonic: self.clock.monotonic(),
                },
            );
            return V3ReceiveVerdict::Accept;
        };
        if engine_boots < baseline.engine_boots {
            return V3ReceiveVerdict::EngineBootsReplay;
        }
        if engine_boots == baseline.engine_boots {
            let elapsed = self
                .clock
                .monotonic()
                .saturating_sub(baseline.monotonic)
                .as_secs_f64();
            let expected_time = baseline.engine_time as f64 + elapsed;
            if (engine_time as f64 - expected_time).abs() > self.time_window {
                return V3ReceiveVerdict::OutsideTimeWindow;
            }
            return V3ReceiveVerdict::Accept;
        }
        // Engine rebooted: accept and rebase the baseline (and the salt cache).
        state.baselines.insert(
            engine_id.to_vec(),
            EngineBaseline {
                engine_boots,
                engine_time,
                monotonic: self.clock.monotonic(),
            },
        );
        self.reset_salt_caches(state, engine_id);
        V3ReceiveVerdict::Accept
    }

    fn check_salt(
        &self,
        state: &mut ReplayState,
        engine_id: &[u8],
        username: &str,
        engine_boots: i64,
        engine_time: i64,
        salt: &[u8],
    ) -> bool {
        let key = (engine_id.to_vec(), username.to_string());
        let cache = state
            .salt_caches
            .entry(key)
            .or_insert_with(|| SaltCache::new(self.salt_cache_size));
        cache.check_and_record(engine_boots, engine_time, salt)
    }

    fn reset_salt_caches(&self, state: &mut ReplayState, engine_id: &[u8]) {
        for (cached_engine_id, cache) in &mut state.salt_caches {
            if cached_engine_id.0 == engine_id {
                cache.clear();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::Clock;
    use std::time::Duration;

    const ENGINE_ID: &[u8] = b"\x80\x00\x01\x02\x03DDDDDDDDDDDD";
    const USER: &str = "listener";
    const SALT_A: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
    const SALT_B: &[u8] = &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18];
    const SALT_C: &[u8] = &[0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28];

    /// Deterministic clock; `monotonic()` returns the frozen reading.
    struct FakeClock {
        now: std::sync::Mutex<Duration>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                now: std::sync::Mutex::new(Duration::from_secs(1000)),
            }
        }

        fn advance(&self, seconds: f64) {
            *self.now.lock().unwrap() += Duration::from_secs_f64(seconds);
        }
    }

    impl Clock for FakeClock {
        fn monotonic(&self) -> Duration {
            *self.now.lock().unwrap()
        }

        fn unix(&self) -> u64 {
            0
        }
    }

    fn clock() -> Arc<dyn Clock> {
        Arc::new(FakeClock::new())
    }

    fn check(guard: &V3ReplayGuard, boots: i64, time: i64, salt: &[u8]) -> V3ReceiveVerdict {
        guard.check(ENGINE_ID, boots, time, USER, salt)
    }

    #[test]
    fn accepts_first_seen_engine() {
        let guard = V3ReplayGuard::new(clock());
        assert_eq!(check(&guard, 5, 100, b""), V3ReceiveVerdict::Accept);
    }

    #[test]
    fn rejects_engine_boots_going_backwards() {
        let guard = V3ReplayGuard::new(clock());
        assert_eq!(check(&guard, 5, 100, b""), V3ReceiveVerdict::Accept);
        assert_eq!(
            check(&guard, 4, 200, b""),
            V3ReceiveVerdict::EngineBootsReplay
        );
    }

    #[test]
    fn rejects_time_outside_window() {
        let fake = Arc::new(FakeClock::new());
        let guard = V3ReplayGuard::new(fake.clone());
        assert_eq!(check(&guard, 5, 100, b""), V3ReceiveVerdict::Accept);
        fake.advance(1.0);
        assert_eq!(
            check(&guard, 5, 1100, b""),
            V3ReceiveVerdict::OutsideTimeWindow
        );
    }

    #[test]
    fn accepts_time_advancing_with_monotonic_clock() {
        let fake = Arc::new(FakeClock::new());
        let guard = V3ReplayGuard::new(fake.clone());
        assert_eq!(check(&guard, 5, 100, b""), V3ReceiveVerdict::Accept);
        fake.advance(1.0);
        assert_eq!(check(&guard, 5, 101, b""), V3ReceiveVerdict::Accept);
        assert_eq!(check(&guard, 5, 99, b""), V3ReceiveVerdict::Accept);
    }

    #[test]
    fn accepts_higher_boots_as_reboot() {
        let fake = Arc::new(FakeClock::new());
        let guard = V3ReplayGuard::new(fake.clone());
        assert_eq!(check(&guard, 5, 100, b""), V3ReceiveVerdict::Accept);
        fake.advance(2.0);
        assert_eq!(check(&guard, 6, 200, b""), V3ReceiveVerdict::Accept);
        // Baseline is rebased to the reboot snapshot.
        fake.advance(1.0);
        assert_eq!(check(&guard, 6, 201, b""), V3ReceiveVerdict::Accept);
        assert_eq!(
            check(&guard, 5, 999, b""),
            V3ReceiveVerdict::EngineBootsReplay
        );
    }

    #[test]
    fn rejects_duplicate_salt_for_same_boots_time() {
        let guard = V3ReplayGuard::new(clock());
        assert_eq!(check(&guard, 5, 100, SALT_A), V3ReceiveVerdict::Accept);
        assert_eq!(
            check(&guard, 5, 100, SALT_A),
            V3ReceiveVerdict::DuplicateSalt
        );
    }

    #[test]
    fn accepts_distinct_salt_for_same_boots_time() {
        let guard = V3ReplayGuard::new(clock());
        assert_eq!(check(&guard, 5, 100, SALT_A), V3ReceiveVerdict::Accept);
        assert_eq!(check(&guard, 5, 100, SALT_B), V3ReceiveVerdict::Accept);
    }

    #[test]
    fn accepts_same_salt_after_time_advances() {
        let fake = Arc::new(FakeClock::new());
        let guard = V3ReplayGuard::new(fake.clone());
        assert_eq!(check(&guard, 5, 100, SALT_A), V3ReceiveVerdict::Accept);
        fake.advance(1.0);
        assert_eq!(check(&guard, 5, 101, SALT_A), V3ReceiveVerdict::Accept);
    }

    #[test]
    fn reboot_clears_salt_cache() {
        let guard = V3ReplayGuard::with_limits(clock(), 150.0, 2);
        assert_eq!(check(&guard, 5, 100, SALT_A), V3ReceiveVerdict::Accept);
        // A reboot may legitimately reuse a pre-reboot salt.
        assert_eq!(check(&guard, 6, 200, SALT_A), V3ReceiveVerdict::Accept);
        // ... and the post-reboot salt is now protected against replay.
        assert_eq!(
            check(&guard, 6, 200, SALT_A),
            V3ReceiveVerdict::DuplicateSalt
        );
    }

    #[test]
    fn ignores_empty_salt_for_unencrypted_messages() {
        let guard = V3ReplayGuard::new(clock());
        assert_eq!(check(&guard, 5, 100, b""), V3ReceiveVerdict::Accept);
        // No privacy salt to fingerprint, so an identical unencrypted datagram
        // is only bounded by the boots/time window check.
        assert_eq!(check(&guard, 5, 100, b""), V3ReceiveVerdict::Accept);
    }

    #[test]
    fn salt_cache_is_bounded() {
        let guard = V3ReplayGuard::with_limits(clock(), 150.0, 2);
        assert_eq!(check(&guard, 5, 100, SALT_A), V3ReceiveVerdict::Accept);
        assert_eq!(check(&guard, 5, 100, SALT_B), V3ReceiveVerdict::Accept);
        // Inserting a third salt evicts SALT_A, which is then indistinguishable
        // from a fresh salt.
        assert_eq!(check(&guard, 5, 100, SALT_C), V3ReceiveVerdict::Accept);
        assert_eq!(check(&guard, 5, 100, SALT_A), V3ReceiveVerdict::Accept);
    }

    #[test]
    fn verdict_reason_labels_match_reference() {
        assert_eq!(
            drop_reason_from_verdict(V3ReceiveVerdict::EngineBootsReplay).as_str(),
            "engine-boots-replay"
        );
        assert_eq!(
            drop_reason_from_verdict(V3ReceiveVerdict::OutsideTimeWindow).as_str(),
            "outside-time-window"
        );
        assert_eq!(
            drop_reason_from_verdict(V3ReceiveVerdict::DuplicateSalt).as_str(),
            "duplicate-salt"
        );
        for (reason, label) in [
            (DropReason::UndecodableBer, "undecodable-ber"),
            (DropReason::WrongCommunity, "wrong-community"),
            (DropReason::UnsupportedVersion, "unsupported-version"),
            (DropReason::WrongUser, "wrong-user"),
            (DropReason::NotNotification, "not-notification"),
            (DropReason::AuthenticationFailed, "authentication-failed"),
        ] {
            assert_eq!(reason.as_str(), label);
        }
    }
}
