//! Peer/local engine state, recovery flag (← usm.py engine state region)

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::security::usm::kdf::AuthProtocol;

/// Clamp an advanced engineTime to the signed BER INTEGER maximum
/// (usm.py:_clamp_engine_time): RFC 3414 defines engineTime as a 32-bit
/// counter, but the wire INTEGER is signed.
const MAX_ENGINE_TIME: u32 = (1 << 31) - 1;

/// Bounded-LRU capacity for localized-key derivations (usm.py:_KEY_CACHE_CAPACITY).
const KEY_CACHE_CAPACITY: usize = 64;

/// Explicit sender-authoritative engine state for outbound SNMPv3 traps
/// (usm.py:UsmLocalEngine).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsmLocalEngine {
    /// Authoritative engine identifier.
    pub engine_id: Vec<u8>,
    /// Authoritative engine boots counter.
    pub engine_boots: u32,
    /// Engine time at the moment the state is supplied; senders advance it
    /// with a monotonic clock.
    pub engine_time: u32,
}

/// Length-prefixed key-material wrapper usable as a HashMap key. The prefix
/// removes the ambiguity of variable-length engineID‖passphrase concatenations
/// (review NIT 11) and the payload is `Zeroizing` on drop.
#[derive(Clone)]
pub(crate) struct KeyMaterial(Zeroizing<Vec<u8>>);

impl KeyMaterial {
    /// Builds the key from length-prefixed parts (`[len][part]…`).
    pub(crate) fn new(parts: &[&[u8]]) -> Self {
        let mut key = Vec::new();
        for part in parts {
            key.extend_from_slice(&(part.len() as u32).to_be_bytes());
            key.extend_from_slice(part);
        }
        Self(Zeroizing::new(key))
    }
}

impl PartialEq for KeyMaterial {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}
impl Eq for KeyMaterial {}
impl std::hash::Hash for KeyMaterial {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_slice().hash(state);
    }
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyMaterial(<redacted>)")
    }
}

/// Bounded LRU of derived keys keyed by [`KeyMaterial`] (usm.py:_LocalizedKeyCache).
#[derive(Clone)]
pub(crate) struct KeyCache {
    entries: HashMap<KeyMaterial, Zeroizing<Vec<u8>>>,
    order: VecDeque<KeyMaterial>,
    capacity: usize,
}

impl Default for KeyCache {
    fn default() -> Self {
        Self::new(KEY_CACHE_CAPACITY)
    }
}

impl KeyCache {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    /// Looks up a key, touching recency (real LRU, usm.py:154–158 `move_to_end`).
    pub(crate) fn get(&mut self, key: &KeyMaterial) -> Option<Zeroizing<Vec<u8>>> {
        if !self.entries.contains_key(key) {
            return None;
        }
        if let Some(position) = self.order.iter().position(|k| k == key)
            && let Some(recent) = self.order.remove(position)
        {
            self.order.push_back(recent);
        }
        self.entries.get(key).cloned()
    }

    pub(crate) fn set(&mut self, key: KeyMaterial, value: Zeroizing<Vec<u8>>) {
        if !self.entries.contains_key(&key) {
            self.order.push_back(key.clone());
            if self.order.len() > self.capacity
                && let Some(oldest) = self.order.pop_front()
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(key, value);
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Peer engine state and per-model bookkeeping, all behind the model's
/// `std::sync::Mutex` (§5.4 — no guard is ever held across an await).
#[derive(Clone, Default)]
pub(crate) struct UsmEngineState {
    /// Authoritative peer engine id (empty until discovery).
    pub(crate) peer_engine_id: Vec<u8>,
    /// Authoritative peer engine boots.
    pub(crate) peer_engine_boots: u32,
    /// Authoritative peer engine time at the monotonic anchor.
    pub(crate) peer_engine_time: u32,
    /// Monotonic anchor captured when authoritative state was adopted; lets
    /// `wrap_pdu` advance engineTime without a new discovery probe
    /// (usm.py:_monotonic_ref).
    pub(crate) monotonic_ref: Option<Duration>,
    /// Monotonic anchor for the local authoritative engine (traps)
    /// (usm.py:_local_engine_monotonic_ref).
    pub(crate) local_engine_anchor: Option<Duration>,
    /// Set when a usmStatsNotInTimeWindows REPORT was received and adopted.
    pub(crate) engine_recovery_needed: bool,
    /// The stashed recovery report awaiting `take_recovery`.
    pub(crate) recovery_report: Option<crate::error::EngineReport>,
    /// Per-(protocol, password) engine-independent Ku cache.
    pub(crate) ku_cache: HashMap<(AuthProtocol, KeyMaterial), Zeroizing<Vec<u8>>>,
    /// Bounded LRU of localized auth keys keyed by `engine_id || password`.
    pub(crate) localized_cache: KeyCache,
    /// Bounded LRU of localized privacy keys keyed by `protocol || engine_id || password`
    /// (usm.py:_localized_priv_cache).
    pub(crate) priv_key_cache: KeyCache,
    /// First octet of the last CBC (3DES) salt, for the first-octet change
    /// rule (usm.py:_fresh_cbc_salt).
    pub(crate) last_cbc_salt_first_octet: Option<u8>,
    /// Message id counter.
    pub(crate) msg_id_counter: u32,
}

impl UsmEngineState {
    /// Next monotonically increasing message id (wraps at u32).
    pub(crate) fn next_msg_id(&mut self) -> u32 {
        self.msg_id_counter = self.msg_id_counter.wrapping_add(1);
        self.msg_id_counter
    }

    /// Record authoritative peer engine state and reset the time base
    /// (usm.py:_adopt_engine_state). A changed engine id or a reboot
    /// (boots change) invalidates the localized-key caches.
    pub(crate) fn adopt_engine_state(
        &mut self,
        engine_id: Vec<u8>,
        engine_boots: u32,
        engine_time: u32,
        now: Duration,
    ) {
        if engine_id != self.peer_engine_id || engine_boots != self.peer_engine_boots {
            self.localized_cache.clear();
        }
        self.peer_engine_id = engine_id;
        self.peer_engine_boots = engine_boots;
        self.peer_engine_time = engine_time;
        self.monotonic_ref = Some(now);
    }

    /// Peer engine time now: discovery value plus elapsed monotonic time
    /// (usm.py:_current_engine_time).
    pub(crate) fn current_engine_time(&self, now: Duration) -> u32 {
        let base = self.peer_engine_time;
        let elapsed = match self.monotonic_ref {
            Some(ref_then) => now.saturating_sub(ref_then).as_secs() as u32,
            None => 0,
        };
        base.saturating_add(elapsed).min(MAX_ENGINE_TIME)
    }
}

/// Advances a local engine's time by the elapsed monotonic time since the
/// anchor (usm.py:_advance_local_engine), clamping to the signed-INTEGER max.
pub(crate) fn advance_local_engine(
    engine: &UsmLocalEngine,
    anchor: Option<Duration>,
    now: Duration,
) -> (UsmLocalEngine, Option<Duration>) {
    let anchor = match anchor {
        Some(a) => a,
        None => now,
    };
    let elapsed = now.saturating_sub(anchor).as_secs() as u32;
    let advanced = UsmLocalEngine {
        engine_id: engine.engine_id.clone(),
        engine_boots: engine.engine_boots,
        engine_time: engine
            .engine_time
            .saturating_add(elapsed)
            .min(MAX_ENGINE_TIME),
    };
    (advanced, Some(anchor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_cache_evicts_lru_at_capacity() {
        let mut cache = KeyCache::new(2);
        let a = KeyMaterial::new(&[b"a"]);
        let b = KeyMaterial::new(&[b"b"]);
        let c = KeyMaterial::new(&[b"c"]);
        cache.set(a.clone(), Zeroizing::new(vec![1]));
        cache.set(b.clone(), Zeroizing::new(vec![2]));
        // Touch "a" so it becomes most-recently-used.
        assert!(cache.get(&a).is_some());
        cache.set(c.clone(), Zeroizing::new(vec![3]));
        assert_eq!(cache.len(), 2);
        // "b" was least-recently-used when "c" arrived.
        assert!(cache.get(&a).is_some());
        assert!(cache.get(&b).is_none());
        assert!(cache.get(&c).is_some());
    }

    #[test]
    fn key_material_length_prefixes_parts() {
        // engine_id‖passphrase must not be ambiguous: "ab"+"c" vs "a"+"bc".
        let one = KeyMaterial::new(&[b"ab", b"c"]);
        let two = KeyMaterial::new(&[b"a", b"bc"]);
        assert_ne!(one, two);
    }

    #[test]
    fn engine_time_advances_from_anchor() {
        let mut state = UsmEngineState::default();
        state.adopt_engine_state(vec![1, 2], 9, 1000, Duration::from_secs(100));
        assert_eq!(state.current_engine_time(Duration::from_secs(150)), 1050);
        // A reboot (boots change) clears the localized cache.
        state
            .localized_cache
            .set(KeyMaterial::new(&[b"k"]), Zeroizing::new(vec![1]));
        state.adopt_engine_state(vec![1, 2], 10, 1, Duration::from_secs(200));
        assert_eq!(state.localized_cache.len(), 0);
    }

    #[test]
    fn engine_time_clamps_to_signed_max() {
        let mut state = UsmEngineState::default();
        state.adopt_engine_state(vec![1], 0, MAX_ENGINE_TIME - 5, Duration::from_secs(0));
        assert_eq!(
            state.current_engine_time(Duration::from_secs(100)),
            MAX_ENGINE_TIME
        );
    }

    #[test]
    fn local_engine_advances_with_anchor() {
        let engine = UsmLocalEngine {
            engine_id: vec![1],
            engine_boots: 17,
            engine_time: 900,
        };
        let (advanced, anchor) = advance_local_engine(&engine, None, Duration::from_secs(60));
        assert_eq!(anchor, Some(Duration::from_secs(60)));
        assert_eq!(advanced.engine_time, 900); // no elapsed at the anchor itself
        let (advanced2, _) = advance_local_engine(&engine, anchor, Duration::from_secs(90));
        assert_eq!(advanced2.engine_time, 930);
    }
}
