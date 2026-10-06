//! Simulation rules (← rules.py)
//!
//! Dynamic OID value rules for the responder's object sources. Rules are
//! `Send + Sync` (shared behind the responder's source) and take their
//! time/randomness from the injected [`Clock`]/[`Rng`] seams (§7) instead of
//! Python's global `time`/`random` — the reference's monkeypatch surfaces
//! (`rule._start`, `random.randint`) become controllable inputs.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::Error;
use crate::time::{Clock, Rng};
use crate::types::value::SnmpValue;

/// Protocol for dynamic OID value simulation rules (← rules.py:37–44).
///
/// Interior state uses atomics or a mutex so a rule can be shared across
/// awaits; [`ObjectValue::Rule`](crate::responder::sources::ObjectValue::Rule)
/// stores one behind a trait object.
pub trait SimulationRule: Send + Sync {
    /// Return the current simulated value.
    fn get_value(&self) -> SnmpValue;
}

/// The value type (and wire modulus) of a [`CounterRule`]
/// (← rules.py:_wire_modulus: Counter32Value | Counter64Value).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CounterValueType {
    /// Counter32 — wraps at 2**32 (the reference default).
    #[default]
    Counter32,
    /// Counter64 — wraps at 2**64.
    Counter64,
}

/// Monotonically increasing counter, incremented on each read
/// (← rules.py:46–82).
///
/// Values wrap at the wire modulus of the configured value type so a
/// long-running simulation never produces a value that cannot be encoded on
/// the wire: a Counter32 at `2**32 - 1` wraps to `0` on the next read, and a
/// Counter64 wraps at `2**64`.
pub struct CounterRule {
    current: AtomicU64,
    increment: u64,
    value_type: CounterValueType,
    modulus: Option<u64>,
}

impl CounterRule {
    /// Creates a counter.
    ///
    /// The reference rejects negative `start`/`increment` with a `ValueError`;
    /// both are `u64` here so the negative cases are unrepresentable, and a
    /// `start` at or beyond the wire modulus is rejected exactly as the
    /// reference does (rules.py:62–75).
    pub fn new(start: u64, increment: u64, value_type: CounterValueType) -> Result<Self, Error> {
        let modulus = match value_type {
            // Counter64 wraps via wrapping arithmetic (2**64 is not
            // representable in u64; `%= 2**64` is a no-op on an already
            // wrapped value).
            CounterValueType::Counter64 => None,
            CounterValueType::Counter32 => Some(1 << 32),
        };
        if let Some(modulus) = modulus
            && start >= modulus
        {
            return Err(Error::InvalidInput(format!(
                "CounterRule start must be below the wire modulus {modulus} of {value_type:?}"
            )));
        }
        Ok(Self {
            current: AtomicU64::new(start),
            increment,
            value_type,
            modulus,
        })
    }

    /// The current counter value, then advance (← rules.py:77–82).
    #[must_use]
    pub fn get_value(&self) -> SnmpValue {
        let value = self.current.load(Ordering::Relaxed);
        let mut next = value.wrapping_add(self.increment);
        if let Some(modulus) = self.modulus
            && next >= modulus
        {
            next %= modulus;
        }
        self.current.store(next, Ordering::Relaxed);
        match self.value_type {
            CounterValueType::Counter32 => SnmpValue::Counter32(value as u32),
            CounterValueType::Counter64 => SnmpValue::Counter64(value),
        }
    }
}

impl SimulationRule for CounterRule {
    fn get_value(&self) -> SnmpValue {
        CounterRule::get_value(self)
    }
}

/// The value type of a [`RandomNumericRule`] (← rules.py:85–101;
/// `Gauge32Value` default, `IntegerValue` exercised by the reference tests).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RandomValueType {
    /// Gauge32 (the reference default).
    #[default]
    Gauge32,
    /// Integer32.
    Integer,
}

/// Random integer in a range, re-sampled on each read
/// (← rules.py:85–101).
///
/// The reference samples Python's global `random`; the injected [`Rng`] seam
/// keeps the rule deterministic in tests.
pub struct RandomNumericRule {
    min: u64,
    span: u64,
    value_type: RandomValueType,
    rng: Arc<dyn Rng>,
}

impl RandomNumericRule {
    /// Creates a rule drawing from `min..=max` (inclusive, as
    /// `random.randint`).
    #[must_use]
    pub fn new(min: u64, max: u64, value_type: RandomValueType, rng: Arc<dyn Rng>) -> Self {
        Self {
            min,
            span: max.saturating_sub(min).saturating_add(1),
            value_type,
            rng,
        }
    }

    /// Draws one value (← rules.py:99–100).
    #[must_use]
    pub fn get_value(&self) -> SnmpValue {
        let mut buf = [0u8; 8];
        self.rng.fill_bytes(&mut buf);
        let draw = u64::from_be_bytes(buf) % self.span;
        let value = self.min + draw;
        match self.value_type {
            RandomValueType::Gauge32 => SnmpValue::Gauge32(value as u32),
            RandomValueType::Integer => SnmpValue::Integer(value as i64),
        }
    }
}

impl SimulationRule for RandomNumericRule {
    fn get_value(&self) -> SnmpValue {
        RandomNumericRule::get_value(self)
    }
}

/// Auto-incrementing timeticks (centiseconds) since construction
/// (← rules.py:103–115).
///
/// The value wraps at the TimeTicks wire modulus (`2**32`) so a long-running
/// simulation never produces an unencodable value. Elapsed time comes from
/// the injected [`Clock`].
pub struct UptimeRule {
    start: std::time::Duration,
    clock: Arc<dyn Clock>,
}

impl UptimeRule {
    /// Creates a rule anchored at the clock's current monotonic reading.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            start: clock.monotonic(),
            clock,
        }
    }

    /// The elapsed centiseconds since construction, wrapped at 2**32
    /// (← rules.py:113–115).
    #[must_use]
    pub fn get_value(&self) -> SnmpValue {
        let elapsed_cs = self
            .clock
            .monotonic()
            .saturating_sub(self.start)
            .as_millis()
            / 10;
        SnmpValue::TimeTicks((elapsed_cs % (1 << 32)) as u32)
    }
}

impl SimulationRule for UptimeRule {
    fn get_value(&self) -> SnmpValue {
        UptimeRule::get_value(self)
    }
}

/// The value type of a [`TimestampRule`] (← rules.py:118–130;
/// `IntegerValue` default, `Counter32Value` exercised by the reference tests).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TimestampValueType {
    /// Integer32 (the reference default).
    #[default]
    Integer,
    /// Counter32.
    Counter32,
}

/// Current Unix epoch time as a scalar value (← rules.py:118–130).
pub struct TimestampRule {
    clock: Arc<dyn Clock>,
    value_type: TimestampValueType,
}

impl TimestampRule {
    /// Creates a rule reading the injected clock's Unix time.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>, value_type: TimestampValueType) -> Self {
        Self { clock, value_type }
    }

    /// The current Unix epoch time (← rules.py:128–129).
    #[must_use]
    pub fn get_value(&self) -> SnmpValue {
        let unix = self.clock.unix();
        match self.value_type {
            TimestampValueType::Integer => SnmpValue::Integer(unix as i64),
            TimestampValueType::Counter32 => SnmpValue::Counter32(unix as u32),
        }
    }
}

impl SimulationRule for TimestampRule {
    fn get_value(&self) -> SnmpValue {
        TimestampRule::get_value(self)
    }
}
