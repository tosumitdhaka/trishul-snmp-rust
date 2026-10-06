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
/// Maximum number of distinct engine IDs a guard tracks (LRU; §8 bounded
/// engine tracking). The reference keeps unbounded per-engine dicts
/// (notify/v3.py:203–204); only noAuthNoPriv traffic reaches the guard (auth
/// verification precedes it), so rotating engine IDs could otherwise grow the
/// maps without bound.
const DEFAULT_ENGINE_CAP: usize = 1024;

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
    /// (engine_boots, engine_time, salt) tuple was seen before (replay). A
    /// duplicate still refreshes recency (v3.py:174–175 `move_to_end`) so it
    /// does not become the next eviction victim.
    fn check_and_record(&mut self, engine_boots: i64, engine_time: i64, salt: &[u8]) -> bool {
        let key = (engine_boots, engine_time, salt.to_vec());
        if self.entries.contains_key(&key) {
            if let Some(position) = self.order.iter().position(|candidate| *candidate == key)
                && let Some(recent) = self.order.remove(position)
            {
                self.order.push_back(recent);
            }
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

/// One entry in the engine recency order: the engine id plus the generation it
/// was pushed with. An entry is a live recency record while its generation
/// matches `ReplayState::engine_generations`; after the engine is touched (or
/// re-adopted) a newer entry supersedes it and the old one is a dead tombstone,
/// skipped during eviction and swept by compaction.
#[derive(Debug)]
struct EngineOrderEntry {
    engine_id: Vec<u8>,
    generation: u64,
}

/// Per-engine and per-(engine, username) guard state behind the interior mutex.
#[derive(Default)]
struct ReplayState {
    baselines: HashMap<Vec<u8>, EngineBaseline>,
    salt_caches: HashMap<(Vec<u8>, String), SaltCache>,
    /// Live generation per engine — doubles as the live-engine set, which is
    /// always bounded by `engine_cap` (§8 bounded engine tracking).
    engine_generations: HashMap<Vec<u8>, u64>,
    /// Least-recently-used engine order (back = most recent) with lazy
    /// tombstones: touching an engine pushes a fresh entry and leaves the old
    /// one dead instead of splicing the deque (amortized O(1) — the O(cap)
    /// scan + `VecDeque::remove` of the pre-hardening implementation would run
    /// under the guard mutex on every datagram). The front-most *live* entry
    /// is evicted at the cap; dead entries are swept by
    /// [`V3ReplayGuard::compact_engine_order`] once they exceed the live
    /// bound.
    engine_order: VecDeque<EngineOrderEntry>,
    /// Monotonic generation counter, incremented on every push and never
    /// reused, so a re-adopted engine can never collide with its old
    /// tombstones.
    next_generation: u64,
}

/// RFC 3414 §3.2.7 receive-side replay and time-window checks
/// (notify/v3.py:188–285).
///
/// Tracks the authoritative engine (boots, time) baseline per engine_id,
/// anchored to the injected monotonic clock, plus a bounded per-(engine_id,
/// username) salt cache. Notifications that fail a check are dropped by the
/// caller; the returned [`V3ReceiveVerdict`] carries the reason.
///
/// The number of tracked engines is bounded by `engine_cap` (default 1024,
/// LRU): a new engine evicts the least-recently-used one at the cap, which
/// reverts to first-seen adoption on its next datagram — identical to a
/// brand-new engine (§8 bounded engine tracking). Recency tracking is
/// amortized O(1) per datagram: touched engines push a fresh recency entry and
/// leave the superseded one as a dead tombstone, swept by compaction once the
/// dead entries exceed the live bound (see [`V3ReplayGuard::with_engine_limit`]
/// for the test seam that pins the compaction invariant).
///
/// The salt-cache bound is per (engine, username): each tracked engine carries
/// one `SaltCache` (capacity `salt_cache_size`, default 64) *per username*.
/// A single-user listener therefore holds at most
/// `engine_cap × 1 × salt_cache_size` salt tuples; a multi-user listener would
/// grow one cache per username per engine, so the engine LRU bounds the total
/// to `engine_cap × users × salt_cache_size`. Only noAuthNoPriv traffic
/// reaches the guard (auth verification precedes it), so every salt is empty
/// in practice and the salt path is skipped (`check`) — the per-(engine, user)
/// bound is defensive.
///
/// The reference's `clock` callable is the `Clock` seam (§7) — a deterministic
/// test clock advances replay windows in the unit tests below.
pub struct V3ReplayGuard {
    state: std::sync::Mutex<ReplayState>,
    time_window: f64,
    salt_cache_size: usize,
    engine_cap: usize,
    clock: Arc<dyn Clock>,
}

impl V3ReplayGuard {
    /// Creates a guard with the reference defaults (150 s window, 64-salt LRU,
    /// 1024 tracked engines).
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self::with_limits(clock, TIME_WINDOW_SECONDS, SALT_CACHE_SIZE)
    }

    /// Creates a guard with explicit window and cache limits (test seam).
    #[must_use]
    pub fn with_limits(clock: Arc<dyn Clock>, time_window: f64, salt_cache_size: usize) -> Self {
        Self::with_engine_limit(clock, time_window, salt_cache_size, DEFAULT_ENGINE_CAP)
    }

    /// Creates a guard with explicit window, cache, and engine-tracking limits
    /// (test seam).
    ///
    /// An `engine_cap` of 0 degenerates to **first-seen-only adoption**: every
    /// datagram's engine is adopted and immediately evicted, so the replay and
    /// time-window checks never have a baseline to compare against and every
    /// datagram is accepted (the duplicate-salt cache is likewise reset on
    /// every adoption). This is a test-only seam — the public constructors
    /// [`V3ReplayGuard::new`] and [`V3ReplayGuard::with_limits`] always use the
    /// default 1024-engine cap, so the degenerate form is unreachable outside
    /// tests.
    #[must_use]
    pub fn with_engine_limit(
        clock: Arc<dyn Clock>,
        time_window: f64,
        salt_cache_size: usize,
        engine_cap: usize,
    ) -> Self {
        Self {
            state: std::sync::Mutex::new(ReplayState::default()),
            time_window,
            salt_cache_size,
            engine_cap,
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
        self.touch_engine(&mut state, engine_id);
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

    /// Marks `engine_id` as most-recently-used; a tracked engine is never
    /// evicted while it keeps sending datagrams. O(1): the old recency entry
    /// is left as a dead tombstone (swept by [`Self::compact_engine_order`]).
    fn touch_engine(&self, state: &mut ReplayState, engine_id: &[u8]) {
        if state.engine_generations.contains_key(engine_id) {
            self.push_engine_order(state, engine_id);
        }
        self.compact_engine_order(state);
    }

    /// Pushes a fresh recency entry for a live engine and records its new
    /// generation (the superseded entry becomes a tombstone).
    fn push_engine_order(&self, state: &mut ReplayState, engine_id: &[u8]) {
        let generation = state.next_generation;
        state.next_generation += 1;
        state
            .engine_generations
            .insert(engine_id.to_vec(), generation);
        state.engine_order.push_back(EngineOrderEntry {
            engine_id: engine_id.to_vec(),
            generation,
        });
    }

    /// Sweeps dead tombstones once they exceed the live bound: dead entries
    /// are `order.len() - live` (live ≤ `engine_cap`), so when dead ≥ cap the
    /// order is compacted back to exactly the live set. Amortized O(1) — at
    /// least `cap` pushes happen between compactions, and each sweep costs
    /// O(len) ≤ O(2·cap).
    fn compact_engine_order(&self, state: &mut ReplayState) {
        if self.engine_cap > 0
            && state
                .engine_order
                .len()
                .saturating_sub(state.engine_generations.len())
                >= self.engine_cap
        {
            state.engine_order.retain(|entry| {
                state.engine_generations.get(&entry.engine_id) == Some(&entry.generation)
            });
        }
    }

    /// Adopts a first-seen engine's baseline, recording LRU recency and
    /// evicting the least-recently-used engine at the cap. The evicted engine
    /// is removed from both maps, so its next datagram is adopted as
    /// first-seen (§8 bounded engine tracking).
    fn adopt_engine(&self, state: &mut ReplayState, engine_id: &[u8], baseline: EngineBaseline) {
        state.baselines.insert(engine_id.to_vec(), baseline);
        self.push_engine_order(state, engine_id);
        // The live set is now at cap + 1: evict the front-most *live* entry,
        // skipping dead tombstones (the front-most live entry is the LRU
        // engine). Adopting at most one engine per datagram means exactly one
        // live eviction restores the cap.
        while state.engine_generations.len() > self.engine_cap {
            let Some(oldest) = state.engine_order.pop_front() else {
                break;
            };
            if state.engine_generations.get(&oldest.engine_id) == Some(&oldest.generation) {
                state.engine_generations.remove(&oldest.engine_id);
                state.baselines.remove(&oldest.engine_id);
                state
                    .salt_caches
                    .retain(|(cached_engine_id, _), _| cached_engine_id != &oldest.engine_id);
                break;
            }
        }
        self.compact_engine_order(state);
    }

    fn check_boots_and_time(
        &self,
        state: &mut ReplayState,
        engine_id: &[u8],
        engine_boots: i64,
        engine_time: i64,
    ) -> V3ReceiveVerdict {
        let Some(baseline) = state.baselines.get(engine_id) else {
            self.adopt_engine(
                state,
                engine_id,
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
        // The engine is already tracked — recency was refreshed by
        // `touch_engine` at the top of `check`, so no LRU push here.
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
    const ENGINE_A: &[u8] = b"\x80\x00\x00\x00\x00AAAAAAAA";
    const ENGINE_B: &[u8] = b"\x80\x00\x00\x00\x00BBBBBBBB";
    const ENGINE_C: &[u8] = b"\x80\x00\x00\x00\x00CCCCCCCC";
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
    fn duplicate_salt_refreshes_recency() {
        // A duplicate still counts as a recent touch (v3.py:174–175
        // move_to_end): after A/B then a duplicate A, inserting C evicts B,
        // not A.
        let guard = V3ReplayGuard::with_limits(clock(), 150.0, 2);
        assert_eq!(check(&guard, 5, 100, SALT_A), V3ReceiveVerdict::Accept);
        assert_eq!(check(&guard, 5, 100, SALT_B), V3ReceiveVerdict::Accept);
        // Duplicate A refreshes its recency.
        assert_eq!(
            check(&guard, 5, 100, SALT_A),
            V3ReceiveVerdict::DuplicateSalt
        );
        // C evicts the least-recently-used entry: B.
        assert_eq!(check(&guard, 5, 100, SALT_C), V3ReceiveVerdict::Accept);
        assert_eq!(
            check(&guard, 5, 100, SALT_A),
            V3ReceiveVerdict::DuplicateSalt,
            "A survived the eviction"
        );
        assert_eq!(
            check(&guard, 5, 100, SALT_B),
            V3ReceiveVerdict::Accept,
            "B was evicted"
        );
    }

    #[test]
    fn engine_tracking_is_bounded_at_cap() {
        // Inserting cap+1 engines retains exactly the cap: the oldest engine
        // is evicted and the two most recent keep their baselines.
        let guard = V3ReplayGuard::with_engine_limit(clock(), 150.0, 2, 2);
        assert_eq!(
            guard.check(ENGINE_A, 5, 100, USER, b""),
            V3ReceiveVerdict::Accept
        );
        assert_eq!(
            guard.check(ENGINE_B, 5, 100, USER, b""),
            V3ReceiveVerdict::Accept
        );
        // C evicts A (the LRU engine).
        assert_eq!(
            guard.check(ENGINE_C, 5, 100, USER, b""),
            V3ReceiveVerdict::Accept
        );
        // B and C are still tracked: going backwards is a replay.
        assert_eq!(
            guard.check(ENGINE_B, 4, 200, USER, b""),
            V3ReceiveVerdict::EngineBootsReplay
        );
        assert_eq!(
            guard.check(ENGINE_C, 4, 200, USER, b""),
            V3ReceiveVerdict::EngineBootsReplay
        );
        // A was evicted: its next datagram is adopted first-seen — a lower
        // boots value is accepted, exactly like a brand-new engine.
        assert_eq!(
            guard.check(ENGINE_A, 1, 10, USER, b""),
            V3ReceiveVerdict::Accept
        );
    }

    #[test]
    fn access_refreshes_engine_recency() {
        let guard = V3ReplayGuard::with_engine_limit(clock(), 150.0, 2, 2);
        assert_eq!(
            guard.check(ENGINE_A, 5, 100, USER, b""),
            V3ReceiveVerdict::Accept
        );
        assert_eq!(
            guard.check(ENGINE_B, 5, 100, USER, b""),
            V3ReceiveVerdict::Accept
        );
        // Accessing A refreshes its recency; B is now the LRU engine.
        assert_eq!(
            guard.check(ENGINE_A, 5, 101, USER, b""),
            V3ReceiveVerdict::Accept
        );
        // Inserting C evicts B, not A.
        assert_eq!(
            guard.check(ENGINE_C, 5, 100, USER, b""),
            V3ReceiveVerdict::Accept
        );
        // A is still tracked: going backwards is a replay.
        assert_eq!(
            guard.check(ENGINE_A, 4, 200, USER, b""),
            V3ReceiveVerdict::EngineBootsReplay
        );
        // B was evicted and reverts to first-seen adoption.
        assert_eq!(
            guard.check(ENGINE_B, 1, 10, USER, b""),
            V3ReceiveVerdict::Accept
        );
    }

    #[test]
    fn engine_tracking_compacts_tombstones_within_the_cap_plus_tombstone_bound() {
        // The amortized-O(1) claim, pinned as a compaction invariant (the task
        // explicitly does NOT require a time-budget test): a large sequence of
        // distinct engines plus hot re-touches must never grow the live maps
        // past the cap, and the recency deque (live entries + lazy tombstones)
        // must never exceed cap + tombstone bound. Tombstones are swept once
        // they reach the cap, so every surviving order entry matches its
        // generation.
        const CAP: usize = 32;
        const ENGINES: usize = 4096;
        let guard = V3ReplayGuard::with_engine_limit(clock(), 150.0, 2, CAP);
        for i in 0..ENGINES {
            let mut engine = vec![0x80, 0x00, 0x00, 0x00, 0x00];
            engine.extend_from_slice(format!("{i:08}").as_bytes());
            assert_eq!(
                guard.check(&engine, 5, 100, USER, b""),
                V3ReceiveVerdict::Accept
            );
            // Hot re-touch: revisiting a tracked engine keeps it live and
            // accumulates tombstones (the pre-hardening O(cap) scan would
            // dominate this sequence).
            if i % 64 == 0 {
                let hot = b"\x80\x00\x00\x00\x00hot      ".to_vec();
                assert_eq!(
                    guard.check(&hot, 5, 100, USER, b""),
                    V3ReceiveVerdict::Accept
                );
            }
        }
        let state = guard.state.lock().unwrap();
        assert!(
            state.baselines.len() <= CAP,
            "live baselines bounded by the cap: {}",
            state.baselines.len()
        );
        assert!(
            state.engine_generations.len() <= CAP,
            "live generation map bounded by the cap: {}",
            state.engine_generations.len()
        );
        let dead = state.engine_order.len() - state.engine_generations.len();
        assert!(
            dead <= CAP,
            "tombstones swept once they reach the cap: {dead}"
        );
        assert!(
            state.engine_order.len() <= state.engine_generations.len() + CAP,
            "recency deque bounded by live count + tombstone bound (2×cap): {}",
            state.engine_order.len()
        );
    }

    #[test]
    fn evicted_engine_reverts_to_first_seen_adoption() {
        // Cap of one: every new engine evicts the previous one. The evicted
        // engine's next datagram is adopted as a brand-new baseline — a lower
        // boots value does NOT trigger the replay check.
        let guard = V3ReplayGuard::with_engine_limit(clock(), 150.0, 2, 1);
        assert_eq!(
            guard.check(ENGINE_A, 9, 900, USER, b""),
            V3ReceiveVerdict::Accept
        );
        assert_eq!(
            guard.check(ENGINE_B, 9, 900, USER, b""),
            V3ReceiveVerdict::Accept,
            "B evicts A"
        );
        assert_eq!(
            guard.check(ENGINE_A, 1, 10, USER, b""),
            V3ReceiveVerdict::Accept,
            "evicted A is adopted first-seen"
        );
        // The re-adopted baseline now guards A normally.
        assert_eq!(
            guard.check(ENGINE_A, 0, 10, USER, b""),
            V3ReceiveVerdict::EngineBootsReplay
        );
    }

    #[test]
    fn engine_cap_does_not_affect_verdicts_within_capacity() {
        // The cap bounds tracked-engine COUNT, not per-engine semantics:
        // within the cap every check behaves exactly like the default guard
        // (boots replay, salt dedup, reboot rebase all unchanged).
        let fake = Arc::new(FakeClock::new());
        let guard = V3ReplayGuard::with_engine_limit(fake.clone(), 150.0, 2, 2);
        assert_eq!(
            guard.check(ENGINE_A, 5, 100, USER, SALT_A),
            V3ReceiveVerdict::Accept
        );
        assert_eq!(
            guard.check(ENGINE_B, 5, 100, USER, SALT_A),
            V3ReceiveVerdict::Accept
        );
        // Duplicate salt is still rejected for a tracked engine.
        assert_eq!(
            guard.check(ENGINE_A, 5, 100, USER, SALT_A),
            V3ReceiveVerdict::DuplicateSalt
        );
        // Boots going backwards is still a replay.
        assert_eq!(
            guard.check(ENGINE_A, 4, 200, USER, b""),
            V3ReceiveVerdict::EngineBootsReplay
        );
        // A reboot still rebases the baseline (and the salt cache).
        assert_eq!(
            guard.check(ENGINE_B, 6, 200, USER, SALT_A),
            V3ReceiveVerdict::Accept
        );
        assert_eq!(
            guard.check(ENGINE_B, 6, 200, USER, SALT_A),
            V3ReceiveVerdict::DuplicateSalt
        );
    }

    #[test]
    fn engine_cap_zero_degrades_to_first_seen_only_adoption() {
        // Pins the documented `with_engine_limit(.., 0)` seam (test-only;
        // unreachable publicly): every datagram's engine is adopted and
        // immediately evicted, so no baseline or salt state survives — a lower
        // boots value and a repeated salt are both accepted, exactly like a
        // brand-new engine every time.
        let guard = V3ReplayGuard::with_engine_limit(clock(), 150.0, 2, 0);
        assert_eq!(
            guard.check(ENGINE_A, 9, 900, USER, b""),
            V3ReceiveVerdict::Accept
        );
        assert_eq!(
            guard.check(ENGINE_A, 1, 10, USER, b""),
            V3ReceiveVerdict::Accept,
            "no baseline survives cap 0"
        );
        assert_eq!(
            guard.check(ENGINE_A, 0, 10, USER, b""),
            V3ReceiveVerdict::Accept
        );
        assert_eq!(
            guard.check(ENGINE_A, 5, 100, USER, SALT_A),
            V3ReceiveVerdict::Accept
        );
        assert_eq!(
            guard.check(ENGINE_A, 5, 100, USER, SALT_A),
            V3ReceiveVerdict::Accept,
            "no salt-cache state survives cap 0"
        );
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
