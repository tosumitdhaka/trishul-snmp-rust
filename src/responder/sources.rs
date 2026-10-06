//! ResponderSource trait, InMemory, Callback (← sources.py)
//!
//! The responder's data sources. The `BTreeMap<Oid, ObjectValue>` store
//! replaces the reference's dict + sorted list + `bisect`/`insort`
//! (sources.py:54–96): `range()` gives lexicographic `lookup_next` directly
//! (§5.7).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::ops::Bound;
use std::sync::{Arc, Mutex};

use crate::error::{Error, TranslationError};
use crate::mib::MibBundle;
use crate::responder::rules::{
    CounterRule, CounterValueType, RandomNumericRule, RandomValueType, SimulationRule, UptimeRule,
};
use crate::target::{Target, normalize_target};
use crate::time::{Clock, Rng};
use crate::types::oid::Oid;
use crate::types::value::SnmpValue;

/// One stored object: a literal value or a dynamic rule (← sources.py:21;
/// §5.7 `ObjectValue`).
pub enum ObjectValue {
    /// A fixed value.
    Static(SnmpValue),
    /// A simulation rule evaluated on every read.
    Rule(Box<dyn SimulationRule>),
}

impl ObjectValue {
    /// The current value of this stored object (sources.py:58–75).
    fn value(&self) -> SnmpValue {
        match self {
            Self::Static(value) => value.clone(),
            Self::Rule(rule) => rule.get_value(),
        }
    }
}

/// `(target, value-or-rule)` input pair (← sources.py:22 `ObjectInput`).
pub type ObjectInput = (Target, ObjectValue);

/// Protocol for read-only responder lookup sources (← sources.py:34–41;
/// §5.7).
pub trait ResponderSource: Send + Sync {
    /// Return the exact value for `oid`, or `None` when missing.
    fn lookup_exact(&self, oid: &Oid) -> Option<SnmpValue>;

    /// Return the next lexicographic OID/value pair strictly after `oid`.
    fn lookup_next(&self, oid: &Oid) -> Option<(Oid, SnmpValue)>;
}

/// Mutable in-memory object source for responder and simulator use
/// (← sources.py:44–133).
///
/// Mutators take `&self` (a `Mutex` guards the map) so the source stays
/// usable behind `Arc<dyn ResponderSource>` while the responder serves.
pub struct InMemoryObjectSource {
    bundle: Option<Arc<MibBundle>>,
    objects: Mutex<BTreeMap<Oid, ObjectValue>>,
}

impl InMemoryObjectSource {
    /// Creates a source seeded with `objects` (symbolic targets resolve
    /// against `bundle`; ← sources.py:47–56).
    pub fn new(bundle: Option<Arc<MibBundle>>, objects: Vec<ObjectInput>) -> Result<Self, Error> {
        let source = Self {
            bundle,
            objects: Mutex::new(BTreeMap::new()),
        };
        source.set_objects(objects)?;
        Ok(source)
    }

    /// Insert or replace an object value or rule and return its normalized
    /// OID (← sources.py:77–83).
    pub fn set_object(&self, target: impl Into<Target>, value: ObjectValue) -> Result<Oid, Error> {
        let oid = normalize_target(&target.into(), self.bundle.as_deref())?;
        self.objects
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(oid.clone(), value);
        Ok(oid)
    }

    /// Insert or replace multiple object values or rules (← sources.py:85–87).
    pub fn set_objects(&self, objects: Vec<ObjectInput>) -> Result<Vec<Oid>, Error> {
        objects
            .into_iter()
            .map(|(target, value)| self.set_object(target, value))
            .collect()
    }

    /// Delete an object value when present (← sources.py:89–96).
    pub fn delete_object(&self, target: impl Into<Target>) -> Result<bool, Error> {
        let oid = normalize_target(&target.into(), self.bundle.as_deref())?;
        Ok(self
            .objects
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&oid)
            .is_some())
    }

    /// Remove all stored objects (← sources.py:98–101).
    pub fn clear(&self) {
        self.objects
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }

    /// Stored OIDs in lexicographic order (← sources.py:103–106).
    #[must_use]
    pub fn oids(&self) -> Vec<Oid> {
        self.objects
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .keys()
            .cloned()
            .collect()
    }

    /// The bundle used to resolve symbolic `set_object` targets.
    #[must_use]
    pub fn bundle(&self) -> Option<&Arc<MibBundle>> {
        self.bundle.as_ref()
    }

    /// Generate a populated source from bundle objects with sensible default
    /// values (← sources.py:108–130).
    ///
    /// `clock`/`rng` feed the default simulation rules (UptimeRule,
    /// CounterRule, RandomNumericRule).
    pub fn from_bundle(
        bundle: Arc<MibBundle>,
        max_instances: u32,
        include_deprecated: bool,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
    ) -> Result<Self, Error> {
        let source = Self::new(Some(bundle.clone()), Vec::new())?;
        {
            let mut objects = source
                .objects
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for node in bundle.iter_objects(None, None) {
                if node.max_access.as_deref() == Some("not-accessible") {
                    continue;
                }
                if node.status.as_deref() == Some("obsolete") {
                    continue;
                }
                if !include_deprecated && node.status.as_deref() == Some("deprecated") {
                    continue;
                }
                match node.nodetype.as_deref() {
                    Some("scalar") => {
                        let mut arcs = node.oid.arcs().to_vec();
                        arcs.push(0);
                        let oid = Oid::from_arcs(&arcs).map_err(TranslationError::InvalidOid)?;
                        objects.insert(oid, default_value(node.syntax.as_deref(), 0, &clock, &rng));
                    }
                    Some("column") => {
                        for instance in 1..=max_instances {
                            let mut arcs = node.oid.arcs().to_vec();
                            arcs.push(instance);
                            let oid =
                                Oid::from_arcs(&arcs).map_err(TranslationError::InvalidOid)?;
                            objects.insert(
                                oid,
                                default_value(node.syntax.as_deref(), instance, &clock, &rng),
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(source)
    }
}

impl ResponderSource for InMemoryObjectSource {
    fn lookup_exact(&self, oid: &Oid) -> Option<SnmpValue> {
        let objects = self
            .objects
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        objects.get(oid).map(ObjectValue::value)
    }

    fn lookup_next(&self, oid: &Oid) -> Option<(Oid, SnmpValue)> {
        let objects = self
            .objects
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        objects
            .range((Bound::Excluded(oid), Bound::Unbounded))
            .next()
            .map(|(next_oid, value)| (next_oid.clone(), value.value()))
    }
}

/// Callback-backed responder source for dynamic simulation
/// (← sources.py:163–181).
pub struct CallbackObjectSource {
    exact_lookup: Arc<ExactLookup>,
    next_lookup: Arc<NextLookup>,
}

/// The exact-lookup callback shape (← sources.py:24 `ExactLookup`).
type ExactLookup = dyn Fn(&Oid) -> Option<SnmpValue> + Send + Sync;

/// The next-lookup callback shape (← sources.py:25 `NextLookup`).
type NextLookup = dyn Fn(&Oid) -> Option<(Oid, SnmpValue)> + Send + Sync;

impl CallbackObjectSource {
    /// Creates a source delegating both lookups to the callbacks
    /// (← sources.py:166–172).
    #[must_use]
    pub fn new(exact_lookup: Arc<ExactLookup>, next_lookup: Arc<NextLookup>) -> Self {
        Self {
            exact_lookup,
            next_lookup,
        }
    }
}

impl ResponderSource for CallbackObjectSource {
    fn lookup_exact(&self, oid: &Oid) -> Option<SnmpValue> {
        (self.exact_lookup)(oid)
    }

    fn lookup_next(&self, oid: &Oid) -> Option<(Oid, SnmpValue)> {
        (self.next_lookup)(oid)
    }
}

/// The default value for a bundle object's syntax (← sources.py:136–160).
fn default_value(
    syntax: Option<&str>,
    instance: u32,
    clock: &Arc<dyn Clock>,
    rng: &Arc<dyn Rng>,
) -> ObjectValue {
    let Some(syntax) = syntax else {
        return ObjectValue::Static(SnmpValue::OctetString(Vec::new()));
    };
    let base = syntax.split('(').next().unwrap_or_default().trim();
    match base {
        "Counter32" | "ZeroBasedCounter32" => ObjectValue::Rule(Box::new(
            CounterRule::new(0, 1, CounterValueType::Counter32)
                .expect("default counter start is below the modulus"),
        )),
        "Counter64" | "ZeroBasedCounter64" | "CounterBasedGauge64" => ObjectValue::Rule(Box::new(
            CounterRule::new(0, 1, CounterValueType::Counter64)
                .expect("default counter start is below the modulus"),
        )),
        "Gauge32" | "Unsigned32" => ObjectValue::Rule(Box::new(RandomNumericRule::new(
            0,
            1000,
            RandomValueType::Gauge32,
            Arc::clone(rng),
        ))),
        "TimeTicks" | "TimeStamp" | "TimeInterval" => {
            ObjectValue::Rule(Box::new(UptimeRule::new(Arc::clone(clock))))
        }
        "IpAddress" => ObjectValue::Static(SnmpValue::IpAddress(Ipv4Addr::UNSPECIFIED)),
        "Integer32" | "Integer" | "InterfaceIndex" | "TruthValue" | "RowStatus" | "StorageType"
        | "ColumnStatus" => ObjectValue::Static(SnmpValue::Integer(i64::from(instance))),
        _ => ObjectValue::Static(SnmpValue::OctetString(Vec::new())),
    }
}
