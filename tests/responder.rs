//! Responder suites (← tests/test_responder.py + tests/test_simulation_rules.py).
//!
//! Ports the reference's responder and simulation-rule tests against the
//! loopback responder, plus the Rust-extension answer paths the reference
//! does not have: v1 answering (the reference drops v1 at the boundary,
//! server.py:136–140) and the v3 USM answer path (discovery REPORT, auth
//! verify, priv decrypt, response stamping).
//!
//! Test accounting against the reference suites:
//! - test_responder.py: 19 tests → 19 tests here (3 re-specified: serve
//!   negative-count validation is unrepresentable with `usize`; the
//!   unencodable-value case cannot be constructed with the `SnmpValue` enum —
//!   re-specified on the v3 auth-failure path; `drops_v1_requests` is
//!   INVERTED to `answers_v1_requests` — the Rust responder answers v1 per
//!   the Phase 7 spec).
//! - test_simulation_rules.py: 21 tests → 21 tests here (3 re-specified: the
//!   negative start/increment rejection is unrepresentable with `u64`; the
//!   protocol `isinstance` check is structural in Rust; `_start`
//!   monkeypatching becomes the injected FakeClock).
//! - test_snmpd_integration.py responder tests: 3 → 3, ported into the
//!   env-gated conformance suite.

mod common;

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::json;

use common::fake::{CounterRng, FakeClock};
use common::mib::{TempDir, if_mib_payload, write_json};
use common::oid;
use common::responder::{
    ENGINE_ID, config, exchange, get_bulk_pdu, get_bulk_pdu_multi, get_next_pdu, get_pdu,
    local_engine, message, object, set_pdu, spawn, v3_auth_user, v3_priv_user,
};

use trishul_snmp::codec::message::{SnmpVersion, decode_message};
use trishul_snmp::codec::pdu::{Pdu, PduKind};
use trishul_snmp::codec::v3::{decode_scoped_pdu, decode_v3_message};
use trishul_snmp::error::UnwrapOutcome;
use trishul_snmp::manager::Manager;
use trishul_snmp::manager::walk::WalkOptions;
use trishul_snmp::mib::load_bundle;
use trishul_snmp::responder::{
    CallbackObjectSource, CounterRule, CounterValueType, InMemoryObjectSource, ObjectValue,
    RandomNumericRule, RandomValueType, ResponderSource, SimulationRule, SnmpResponder,
    TimestampRule, TimestampValueType, UptimeRule,
};
use trishul_snmp::security::usm::UsmModel;
use trishul_snmp::security::usm::V3Config;
use trishul_snmp::time::{Clock, Rng, SystemClock, SystemRng};
use trishul_snmp::types::oid::Oid;
use trishul_snmp::types::value::SnmpValue;
use trishul_snmp::types::varbind::{ErrorStatus, VarBind};

fn clock() -> Arc<dyn trishul_snmp::time::Clock> {
    Arc::new(SystemClock)
}

fn rng() -> Arc<dyn Rng> {
    Arc::new(SystemRng)
}

/// The RFC1213-MIB payload (test_simulation_rules.py:_sys_mib_payload).
fn sys_mib_payload() -> serde_json::Value {
    let mut payload = common::mib::base_module("RFC1213-MIB", None);
    payload["objects"] = json!({
        "sysDescr": {
            "oid": "1.3.6.1.2.1.1.1",
            "oid_path": [1, 3, 6, 1, 2, 1, 1, 1],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "scalar",
            "syntax": "DisplayString",
            "max_access": "read-only",
            "status": "current",
        },
        "sysUpTime": {
            "oid": "1.3.6.1.2.1.1.3",
            "oid_path": [1, 3, 6, 1, 2, 1, 1, 3],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "scalar",
            "syntax": "TimeTicks",
            "max_access": "read-only",
            "status": "current",
        },
        "ifTable": {
            "oid": "1.3.6.1.2.1.2.2",
            "oid_path": [1, 3, 6, 1, 2, 1, 2, 2],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "table",
            "syntax": "SEQUENCE OF IfEntry",
            "max_access": "not-accessible",
            "status": "current",
        },
        "ifIndex": {
            "oid": "1.3.6.1.2.1.2.2.1.1",
            "oid_path": [1, 3, 6, 1, 2, 1, 2, 2, 1, 1],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "column",
            "syntax": "Integer32",
            "max_access": "read-only",
            "status": "current",
        },
        "ifInOctets": {
            "oid": "1.3.6.1.2.1.2.2.1.10",
            "oid_path": [1, 3, 6, 1, 2, 1, 2, 2, 1, 10],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "column",
            "syntax": "Counter32",
            "max_access": "read-only",
            "status": "current",
        },
    });
    payload
}

/// The DEP-MIB payload (test_simulation_rules.py:test_from_bundle_skips_deprecated_by_default).
fn dep_mib_payload() -> serde_json::Value {
    let mut payload = common::mib::base_module("DEP-MIB", None);
    payload["objects"] = json!({
        "oldObj": {
            "oid": "1.3.6.1.2.1.99.1",
            "oid_path": [1, 3, 6, 1, 2, 1, 99, 1],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "scalar",
            "syntax": "Integer32",
            "max_access": "read-only",
            "status": "deprecated",
        },
        "newObj": {
            "oid": "1.3.6.1.2.1.99.2",
            "oid_path": [1, 3, 6, 1, 2, 1, 99, 2],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "scalar",
            "syntax": "Integer32",
            "max_access": "read-only",
            "status": "current",
        },
    });
    payload
}

/// Writes a single-module payload and loads it as a bundle.
fn bundle_from_payload(
    dir: &TempDir,
    name: &str,
    payload: &serde_json::Value,
) -> Arc<trishul_snmp::mib::MibBundle> {
    write_json(&dir.path().join(format!("{name}.json")), payload);
    Arc::new(load_bundle(dir.path().join(format!("{name}.json"))).expect("bundle loads"))
}

/// Spawns a serve loop for the responder (stopped via `close`).
fn start_serve(responder: &Arc<SnmpResponder>) -> tokio::task::JoinHandle<usize> {
    let responder = Arc::clone(responder);
    tokio::spawn(async move { responder.serve(0).await.expect("serve loop") })
}

// ── Simulation rules (test_simulation_rules.py) ─────────────────────────────

#[test]
fn counter_rule_increments_on_each_get() {
    let rule = CounterRule::new(10, 5, CounterValueType::Counter32).unwrap();
    assert_eq!(rule.get_value(), SnmpValue::Counter32(10));
    assert_eq!(rule.get_value(), SnmpValue::Counter32(15));
    assert_eq!(rule.get_value(), SnmpValue::Counter32(20));
}

#[test]
fn counter_rule_defaults() {
    let rule = CounterRule::new(0, 1, CounterValueType::Counter32).unwrap();
    assert_eq!(rule.get_value(), SnmpValue::Counter32(0));
    assert_eq!(rule.get_value(), SnmpValue::Counter32(1));
}

#[test]
fn counter_rule_custom_value_type() {
    let rule = CounterRule::new(0, 100, CounterValueType::Counter64).unwrap();
    assert_eq!(rule.get_value(), SnmpValue::Counter64(0));
    assert_eq!(rule.get_value(), SnmpValue::Counter64(100));
}

#[test]
fn counter_rule_wraps_at_counter32_modulus() {
    let rule = CounterRule::new((1u64 << 32) - 1, 1, CounterValueType::Counter32).unwrap();
    assert_eq!(rule.get_value(), SnmpValue::Counter32(u32::MAX));
    assert_eq!(rule.get_value(), SnmpValue::Counter32(0));
    assert_eq!(rule.get_value(), SnmpValue::Counter32(1));
}

#[test]
fn counter_rule_wraps_at_counter64_modulus() {
    let rule = CounterRule::new(u64::MAX, 2, CounterValueType::Counter64).unwrap();
    assert_eq!(rule.get_value(), SnmpValue::Counter64(u64::MAX));
    assert_eq!(rule.get_value(), SnmpValue::Counter64(1));
}

#[test]
fn counter_rule_increment_larger_than_modulus_wraps() {
    let rule = CounterRule::new(5, (1 << 32) + 3, CounterValueType::Counter32).unwrap();
    assert_eq!(rule.get_value(), SnmpValue::Counter32(5));
    assert_eq!(rule.get_value(), SnmpValue::Counter32(8));
}

#[test]
fn counter_rule_rejects_invalid_inputs() {
    // RE-SPECIFIED: the reference's negative start/increment ValueError is
    // unrepresentable with u64; the wire-modulus check is portable.
    let err = match CounterRule::new(1 << 32, 1, CounterValueType::Counter32) {
        Err(err) => err,
        Ok(_) => panic!("start at the wire modulus must be rejected"),
    };
    assert!(err.to_string().contains("wire modulus"), "{err}");
    assert!(CounterRule::new(1, 1, CounterValueType::Counter32).is_ok());
}

#[test]
fn random_numeric_rule_stays_in_range() {
    let rule = RandomNumericRule::new(
        10,
        20,
        RandomValueType::Gauge32,
        Arc::new(CounterRng::new(7)),
    );
    for _ in 0..50 {
        let value = rule.get_value();
        let SnmpValue::Gauge32(value) = value else {
            panic!("expected Gauge32, got {value:?}");
        };
        assert!((10..=20).contains(&value));
    }
}

#[test]
fn random_numeric_rule_custom_type() {
    let rule = RandomNumericRule::new(0, 0, RandomValueType::Integer, Arc::new(CounterRng::new(0)));
    assert_eq!(rule.get_value(), SnmpValue::Integer(0));
}

/// A clock-typed clone of the fake clock for the rule constructors.
fn fake_clock_typed(fake: &Arc<FakeClock>) -> Arc<dyn trishul_snmp::time::Clock> {
    let clock: Arc<dyn trishul_snmp::time::Clock> = fake.clone();
    clock
}

#[test]
fn uptime_rule_increases_over_time() {
    let fake = Arc::new(FakeClock::new(Duration::ZERO, 0));
    let rule = UptimeRule::new(fake_clock_typed(&fake));
    let v1 = rule.get_value();
    fake.set_monotonic(Duration::from_millis(20));
    let v2 = rule.get_value();
    let (SnmpValue::TimeTicks(a), SnmpValue::TimeTicks(b)) = (v1, v2) else {
        panic!("expected TimeTicks values");
    };
    assert!(b >= a);
}

#[test]
fn uptime_rule_starts_near_zero() {
    let fake = Arc::new(FakeClock::new(Duration::ZERO, 0));
    let rule = UptimeRule::new(fake_clock_typed(&fake));
    let SnmpValue::TimeTicks(value) = rule.get_value() else {
        panic!("expected TimeTicks");
    };
    assert!(value < 100, "under a second in centiseconds, got {value}");
}

#[test]
fn uptime_rule_wraps_at_timeticks_modulus() {
    // The reference monkeypatches `rule._start`; the injected clock provides
    // the same seam: pretend the process started 2**32+50 centiseconds ago.
    let fake = Arc::new(FakeClock::new(Duration::ZERO, 0));
    let rule = UptimeRule::new(fake_clock_typed(&fake));
    let elapsed = (((1u64 << 32) + 50) as f64) / 100.0;
    fake.set_monotonic(Duration::from_secs_f64(elapsed));
    let SnmpValue::TimeTicks(value) = rule.get_value() else {
        panic!("expected TimeTicks");
    };
    assert!((0..100).contains(&value), "wrapped value {value}");
}

#[test]
fn timestamp_rule_returns_current_epoch() {
    let fake = Arc::new(FakeClock::new(Duration::ZERO, 1_700_000_000));
    let rule = TimestampRule::new(fake_clock_typed(&fake), TimestampValueType::Integer);
    assert_eq!(rule.get_value(), SnmpValue::Integer(1_700_000_000));
}

#[test]
fn timestamp_rule_custom_type() {
    let fake = Arc::new(FakeClock::new(Duration::ZERO, 1234));
    let rule = TimestampRule::new(fake_clock_typed(&fake), TimestampValueType::Counter32);
    assert_eq!(rule.get_value(), SnmpValue::Counter32(1234));
}

#[test]
fn simulation_rule_protocol_check() {
    // RE-SPECIFIED: the reference's runtime isinstance probe becomes a
    // structural check — every rule type stores as a `Box<dyn SimulationRule>`
    // and evaluates through the trait object.
    let rules: Vec<Box<dyn SimulationRule>> = vec![
        Box::new(CounterRule::new(0, 1, CounterValueType::Counter32).unwrap()),
        Box::new(RandomNumericRule::new(
            0,
            1,
            RandomValueType::Gauge32,
            Arc::new(CounterRng::new(0)),
        )),
        Box::new(UptimeRule::new(fake_clock_typed(&Arc::new(
            FakeClock::new(Duration::ZERO, 0),
        )))),
        Box::new(TimestampRule::new(
            fake_clock_typed(&Arc::new(FakeClock::new(Duration::ZERO, 0))),
            TimestampValueType::Integer,
        )),
    ];
    let values: Vec<SnmpValue> = rules.iter().map(|rule| rule.get_value()).collect();
    assert!(values.iter().all(|value| matches!(
        value,
        SnmpValue::Counter32(_)
            | SnmpValue::Gauge32(_)
            | SnmpValue::TimeTicks(_)
            | SnmpValue::Integer(_)
    )));
}

#[test]
fn in_memory_source_with_counter_rule() {
    let source = InMemoryObjectSource::new(None, vec![]).unwrap();
    source
        .set_object(
            "1.3.6.1.2.1.1.3.0",
            ObjectValue::Rule(Box::new(
                CounterRule::new(0, 10, CounterValueType::Counter32).unwrap(),
            )),
        )
        .unwrap();
    assert_eq!(
        source.lookup_exact(&oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0])),
        Some(SnmpValue::Counter32(0))
    );
    assert_eq!(
        source.lookup_exact(&oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0])),
        Some(SnmpValue::Counter32(10))
    );
}

#[test]
fn in_memory_source_lookup_next_with_rule() {
    let source = InMemoryObjectSource::new(None, vec![]).unwrap();
    source
        .set_object(
            "1.3.6.1.2.1.1.3.0",
            ObjectValue::Rule(Box::new(
                CounterRule::new(7, 1, CounterValueType::Counter32).unwrap(),
            )),
        )
        .unwrap();
    source
        .set_object(
            "1.3.6.1.2.1.1.4.0",
            ObjectValue::Static(SnmpValue::Integer(99)),
        )
        .unwrap();
    let (next_oid, value) = source
        .lookup_next(&oid(&[1, 3, 6, 1, 2, 1, 1, 2]))
        .expect("successor");
    assert_eq!(next_oid, oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]));
    assert_eq!(value, SnmpValue::Counter32(7));
}

#[test]
fn in_memory_source_mixes_rules_and_static_values() {
    let source = InMemoryObjectSource::new(None, vec![]).unwrap();
    source
        .set_object(
            "1.3.6.1.2.1.1.1.0",
            ObjectValue::Static(SnmpValue::OctetString(b"router".to_vec())),
        )
        .unwrap();
    source
        .set_object(
            "1.3.6.1.2.1.1.3.0",
            ObjectValue::Rule(Box::new(UptimeRule::new(fake_clock_typed(&Arc::new(
                FakeClock::new(Duration::ZERO, 0),
            ))))),
        )
        .unwrap();
    let static_value = source.lookup_exact(&oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]));
    let dynamic = source.lookup_exact(&oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]));
    assert_eq!(
        static_value,
        Some(SnmpValue::OctetString(b"router".to_vec()))
    );
    assert!(matches!(dynamic, Some(SnmpValue::TimeTicks(_))));
}

#[test]
fn from_bundle_generates_scalar_and_column_instances() {
    let dir = TempDir::new("responder-rfc1213");
    let bundle = bundle_from_payload(&dir, "RFC1213-MIB", &sys_mib_payload());
    let source = InMemoryObjectSource::from_bundle(bundle, 2, false, clock(), rng()).unwrap();

    // Static types stay static.
    assert_eq!(
        source.lookup_exact(&oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0])),
        Some(SnmpValue::OctetString(Vec::new()))
    );
    assert_eq!(
        source.lookup_exact(&oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1])),
        Some(SnmpValue::Integer(1))
    );
    assert_eq!(
        source.lookup_exact(&oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 2])),
        Some(SnmpValue::Integer(2))
    );

    // TimeTicks scalar → UptimeRule: value changes over time.
    let SnmpValue::TimeTicks(t1) = source
        .lookup_exact(&oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]))
        .unwrap()
    else {
        panic!("expected TimeTicks");
    };
    let SnmpValue::TimeTicks(t2) = source
        .lookup_exact(&oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]))
        .unwrap()
    else {
        panic!("expected TimeTicks");
    };
    assert!(t2 >= t1, "uptime rule advances: {t1} then {t2}");

    // Counter32 column → CounterRule: value increments on each poll.
    let SnmpValue::Counter32(c1) = source
        .lookup_exact(&oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 10, 1]))
        .unwrap()
    else {
        panic!("expected Counter32");
    };
    let SnmpValue::Counter32(c2) = source
        .lookup_exact(&oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 10, 1]))
        .unwrap()
    else {
        panic!("expected Counter32");
    };
    assert!(c2 > c1, "counter rule increments: {c1} then {c2}");

    // Not-accessible table row must be absent.
    assert_eq!(source.lookup_exact(&oid(&[1, 3, 6, 1, 2, 1, 2, 2])), None);
    assert_eq!(
        source.lookup_exact(&oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1])),
        None
    );
}

#[test]
fn from_bundle_respects_max_instances() {
    let dir = TempDir::new("responder-rfc1213");
    let bundle = bundle_from_payload(&dir, "RFC1213-MIB", &sys_mib_payload());
    let source = InMemoryObjectSource::from_bundle(bundle, 1, false, clock(), rng()).unwrap();
    assert_eq!(
        source.lookup_exact(&oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1])),
        Some(SnmpValue::Integer(1))
    );
    assert_eq!(
        source.lookup_exact(&oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 2])),
        None
    );
}

#[test]
fn from_bundle_skips_deprecated_by_default() {
    let dir = TempDir::new("responder-dep-mib");
    let bundle = bundle_from_payload(&dir, "DEP-MIB", &dep_mib_payload());
    let default =
        InMemoryObjectSource::from_bundle(bundle.clone(), 1, false, clock(), rng()).unwrap();
    assert_eq!(
        default.lookup_exact(&oid(&[1, 3, 6, 1, 2, 1, 99, 1, 0])),
        None
    );
    assert_eq!(
        default.lookup_exact(&oid(&[1, 3, 6, 1, 2, 1, 99, 2, 0])),
        Some(SnmpValue::Integer(0))
    );
    let with_dep = InMemoryObjectSource::from_bundle(bundle, 1, true, clock(), rng()).unwrap();
    assert_eq!(
        with_dep.lookup_exact(&oid(&[1, 3, 6, 1, 2, 1, 99, 1, 0])),
        Some(SnmpValue::Integer(0))
    );
}

// ── Sources (test_responder.py) ─────────────────────────────────────────────

#[test]
fn in_memory_source_supports_symbolic_targets_and_order() {
    let dir = TempDir::new("responder-if-mib");
    let bundle = bundle_from_payload(&dir, "IF-MIB", &if_mib_payload(false));
    let source = InMemoryObjectSource::new(Some(bundle), vec![]).unwrap();

    let first_oid = source
        .set_object(
            "IF-MIB::ifDescr.2",
            ObjectValue::Static(SnmpValue::OctetString(b"eth1".to_vec())),
        )
        .unwrap();
    let inserted = source
        .set_objects(vec![
            (
                "IF-MIB::ifIndex.1".into(),
                ObjectValue::Static(SnmpValue::Integer(1)),
            ),
            (
                "IF-MIB::ifDescr.1".into(),
                ObjectValue::Static(SnmpValue::OctetString(b"eth0".to_vec())),
            ),
        ])
        .unwrap();

    assert_eq!(first_oid, oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 2]));
    assert_eq!(
        inserted,
        vec![
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1]),
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1]),
        ]
    );
    assert_eq!(
        source.oids(),
        vec![
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1]),
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1]),
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 2]),
        ]
    );
    assert_eq!(
        source.lookup_exact(&oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1])),
        Some(SnmpValue::OctetString(b"eth0".to_vec()))
    );
    assert_eq!(
        source.lookup_next(&oid(&[1, 3, 6, 1, 2, 1, 2, 2])),
        Some((
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1]),
            SnmpValue::Integer(1)
        ))
    );
    assert!(source.delete_object("IF-MIB::ifDescr.2").unwrap());
    assert!(!source.delete_object("IF-MIB::ifDescr.2").unwrap());
}

#[test]
fn callback_source_delegates() {
    let seen: Arc<Mutex<Vec<(&'static str, Oid)>>> = Arc::new(Mutex::new(Vec::new()));
    let source = CallbackObjectSource::new(
        Arc::new({
            let seen = Arc::clone(&seen);
            move |queried: &Oid| {
                seen.lock().unwrap().push(("exact", queried.clone()));
                Some(SnmpValue::Integer(7))
            }
        }),
        Arc::new({
            let seen = Arc::clone(&seen);
            move |queried: &Oid| {
                seen.lock().unwrap().push(("next", queried.clone()));
                Some((
                    oid(&[1, 3, 6, 1, 2]),
                    SnmpValue::OctetString(b"eth0".to_vec()),
                ))
            }
        }),
    );
    assert_eq!(
        source.lookup_exact(&oid(&[1, 3, 6, 1])),
        Some(SnmpValue::Integer(7))
    );
    assert_eq!(
        source.lookup_next(&oid(&[1, 3, 6, 1])),
        Some((
            oid(&[1, 3, 6, 1, 2]),
            SnmpValue::OctetString(b"eth0".to_vec())
        ))
    );
    assert_eq!(
        *seen.lock().unwrap(),
        vec![("exact", oid(&[1, 3, 6, 1])), ("next", oid(&[1, 3, 6, 1]))]
    );
}

// ── Responder surface (test_responder.py) ───────────────────────────────────

#[tokio::test]
async fn responder_default_source_mutators_and_properties() {
    let (responder, _port) = spawn(config(None, vec![])).await;
    assert!(responder.is_in_memory());
    let set_oid = responder
        .set_object(
            "1.3.6.1.2.1.1.3.0",
            ObjectValue::Static(SnmpValue::TimeTicks(5)),
        )
        .unwrap();
    assert_eq!(set_oid, oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]));
    responder.clear_objects().unwrap();
    assert_eq!(
        responder
            .source()
            .lookup_exact(&oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0])),
        None
    );
}

#[tokio::test]
async fn responder_serves_manager_reads() {
    let dir = TempDir::new("responder-if-mib");
    let bundle = bundle_from_payload(&dir, "IF-MIB", &if_mib_payload(false));
    let objects = vec![
        object(&[1, 3, 6, 1, 2, 1, 1, 3, 0], SnmpValue::TimeTicks(12345)),
        object(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1], SnmpValue::Integer(1)),
        object(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 2], SnmpValue::Integer(2)),
        object(
            &[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1],
            SnmpValue::OctetString(b"eth0".to_vec()),
        ),
        object(
            &[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 2],
            SnmpValue::OctetString(b"eth1".to_vec()),
        ),
    ];
    let (responder, port) = spawn(config(Some(&["public"]), objects)).await;
    let serve = tokio::spawn({
        let responder = Arc::clone(&responder);
        async move { responder.serve(4).await.expect("serve loop") }
    });
    let manager = Manager::connect_v2c(trishul_snmp::security::community::CommunityConfig {
        host: "127.0.0.1".to_string(),
        port,
        community: "public".to_string(),
        bundle: Some(bundle),
        timeout: Duration::from_millis(500),
        retries: 0,
        rng: rng(),
    })
    .await
    .expect("connect v2c manager");

    let get_response = manager.get(vec!["IF-MIB::ifDescr.1"]).await.unwrap();
    let next_response = manager.get_next(vec!["IF-MIB::ifTable"]).await.unwrap();
    let bulk_response = manager
        .get_bulk(vec!["IF-MIB::ifTable"], 0, 3)
        .await
        .unwrap();
    let missing_response = manager.get(vec!["1.3.6.1.2.1.999.0"]).await.unwrap();
    let handled = serve.await.unwrap();

    assert_eq!(handled, 4);
    assert_eq!(get_response.error_status, ErrorStatus::NoError);
    assert_eq!(
        get_response.varbinds[0].display_name.as_deref(),
        Some("IF-MIB::ifDescr.1")
    );
    assert_eq!(
        get_response.varbinds[0].display_value.as_deref(),
        Some("eth0")
    );
    let names: Vec<&str> = next_response
        .varbinds
        .iter()
        .map(|v| v.display_name.as_deref().unwrap_or(""))
        .collect();
    assert_eq!(names, vec!["IF-MIB::ifIndex.1"]);
    let bulk_names: Vec<&str> = bulk_response
        .varbinds
        .iter()
        .map(|v| v.display_name.as_deref().unwrap_or(""))
        .collect();
    assert_eq!(
        bulk_names,
        vec![
            "IF-MIB::ifIndex.1",
            "IF-MIB::ifIndex.2",
            "IF-MIB::ifDescr.1"
        ]
    );
    assert_eq!(missing_response.varbinds[0].value, SnmpValue::NoSuchObject);
    assert_eq!(
        missing_response.varbinds[0].display_value.as_deref(),
        Some("noSuchObject")
    );
}

#[tokio::test]
async fn responder_serves_symbolic_walk() {
    let dir = TempDir::new("responder-if-mib");
    let bundle = bundle_from_payload(&dir, "IF-MIB", &if_mib_payload(false));
    let mut cfg = config(Some(&["public"]), vec![]);
    cfg.bundle = Some(Arc::clone(&bundle));
    let (responder, port) = spawn(cfg).await;
    responder
        .set_objects(vec![
            (
                "IF-MIB::ifIndex.1".into(),
                ObjectValue::Static(SnmpValue::Integer(1)),
            ),
            (
                "IF-MIB::ifIndex.2".into(),
                ObjectValue::Static(SnmpValue::Integer(2)),
            ),
            (
                "IF-MIB::ifDescr.1".into(),
                ObjectValue::Static(SnmpValue::OctetString(b"eth0".to_vec())),
            ),
            (
                "IF-MIB::ifDescr.2".into(),
                ObjectValue::Static(SnmpValue::OctetString(b"eth1".to_vec())),
            ),
        ])
        .unwrap();
    let serve = tokio::spawn({
        let responder = Arc::clone(&responder);
        async move { responder.serve(1).await.expect("serve loop") }
    });
    let manager = Manager::connect_v2c(trishul_snmp::security::community::CommunityConfig {
        host: "127.0.0.1".to_string(),
        port,
        community: "public".to_string(),
        bundle: Some(bundle),
        timeout: Duration::from_millis(500),
        retries: 0,
        rng: rng(),
    })
    .await
    .expect("connect v2c manager");
    let walked = manager
        .walk("IF-MIB::ifTable", WalkOptions::default())
        .await
        .unwrap();
    let handled = serve.await.unwrap();

    assert_eq!(handled, 1, "one GETBULK answers the whole walk");
    let names: Vec<&str> = walked
        .iter()
        .map(|v| v.display_name.as_deref().unwrap_or(""))
        .collect();
    assert_eq!(
        names,
        vec![
            "IF-MIB::ifIndex.1",
            "IF-MIB::ifIndex.2",
            "IF-MIB::ifDescr.1",
            "IF-MIB::ifDescr.2"
        ]
    );
    let values: Vec<&str> = walked
        .iter()
        .map(|v| v.display_value.as_deref().unwrap_or(""))
        .collect();
    assert_eq!(values, vec!["1", "2", "eth0", "eth1"]);
}

#[tokio::test]
async fn responder_community_filter_causes_timeout() {
    let (responder, port) = spawn(config(
        Some(&["private"]),
        vec![object(
            &[1, 3, 6, 1, 2, 1, 1, 3, 0],
            SnmpValue::TimeTicks(12345),
        )],
    ))
    .await;
    let serve = start_serve(&responder);
    let manager = common::test_v2c_manager_with(port, "public", Duration::from_millis(50), 0).await;
    let err = manager.get(vec!["1.3.6.1.2.1.1.3.0"]).await.unwrap_err();
    assert!(
        matches!(err, trishul_snmp::error::Error::Timeout { .. }),
        "{err}"
    );
    responder.close();
    let handled = serve.await.unwrap();
    assert_eq!(handled, 0);
}

#[tokio::test]
async fn responder_supports_callback_source() {
    let objects: Arc<Mutex<Vec<(Oid, SnmpValue)>>> = Arc::new(Mutex::new(vec![
        (
            oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]),
            SnmpValue::TimeTicks(12345),
        ),
        (
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1]),
            SnmpValue::Integer(1),
        ),
    ]));
    let source = CallbackObjectSource::new(
        Arc::new({
            let objects = Arc::clone(&objects);
            move |oid: &Oid| {
                objects
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|(known, _)| known == oid)
                    .map(|(_, v)| v.clone())
            }
        }),
        Arc::new({
            let objects = Arc::clone(&objects);
            move |oid: &Oid| {
                objects
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|(known, _)| known > oid)
                    .map(|(known, v)| (known.clone(), v.clone()))
            }
        }),
    );
    let mut cfg = config(Some(&["public"]), vec![]);
    cfg.source = Some(Arc::new(source));
    let (responder, port) = spawn(cfg).await;
    let serve = tokio::spawn({
        let responder = Arc::clone(&responder);
        async move { responder.serve(2).await.expect("serve loop") }
    });
    let manager = common::test_v2c_manager(port).await;
    let exact_response = manager.get(vec!["1.3.6.1.2.1.1.3.0"]).await.unwrap();
    let next_response = manager.get_next(vec!["1.3.6.1.2.1.1.3.0"]).await.unwrap();
    let handled = serve.await.unwrap();

    assert_eq!(handled, 2);
    assert_eq!(
        exact_response.varbinds[0].value,
        SnmpValue::TimeTicks(12345)
    );
    assert_eq!(
        next_response.varbinds[0].oid,
        oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1])
    );
}

#[tokio::test]
async fn responder_rejects_object_seed_with_custom_source() {
    let source = CallbackObjectSource::new(Arc::new(|_: &Oid| None), Arc::new(|_: &Oid| None));
    let mut cfg = config(
        None,
        vec![object(
            &[1, 3, 6, 1, 2, 1, 1, 3, 0],
            SnmpValue::TimeTicks(1),
        )],
    );
    cfg.source = Some(Arc::new(source));
    let err = match SnmpResponder::bind(cfg).await {
        Err(err) => err,
        Ok(_) => panic!("objects + source must be rejected"),
    };
    assert!(
        err.to_string()
            .contains("objects cannot be used when source is provided"),
        "{err}"
    );
}

#[tokio::test]
async fn responder_rejects_in_memory_only_mutators_with_custom_source() {
    let source = CallbackObjectSource::new(Arc::new(|_: &Oid| None), Arc::new(|_: &Oid| None));
    let mut cfg = config(None, vec![]);
    cfg.source = Some(Arc::new(source));
    let (responder, _port) = spawn(cfg).await;
    let err = responder
        .set_object(
            "1.3.6.1.2.1.1.3.0",
            ObjectValue::Static(SnmpValue::TimeTicks(1)),
        )
        .unwrap_err();
    assert!(err.to_string().contains("InMemoryObjectSource"), "{err}");
    let err = responder.clear_objects().unwrap_err();
    assert!(err.to_string().contains("InMemoryObjectSource"), "{err}");
}

#[tokio::test]
async fn responder_serve_validation_and_forever_forwarding() {
    // RE-SPECIFIED: the reference's negative `count` ValueError is
    // unrepresentable with `usize`; `serve_forever` forwarding to
    // `serve(count=0)` and close-driven termination are the portable surface.
    let (responder, _port) = spawn(config(
        None,
        vec![object(
            &[1, 3, 6, 1, 2, 1, 1, 3, 0],
            SnmpValue::TimeTicks(9),
        )],
    ))
    .await;
    let serve = start_serve(&responder);
    let reply = exchange(
        &responder,
        &message(
            SnmpVersion::V2c,
            "public",
            get_pdu(1, &[1, 3, 6, 1, 2, 1, 1, 3, 0]),
        ),
    )
    .await;
    assert!(reply.is_some(), "serve_forever answered");
    responder.close();
    let handled = serve.await.unwrap();
    assert_eq!(handled, 1);
}

#[tokio::test]
async fn responder_skips_invalid_and_unsupported_messages() {
    let (responder, _port) = spawn(config(
        None,
        vec![object(
            &[1, 3, 6, 1, 2, 1, 1, 3, 0],
            SnmpValue::TimeTicks(9),
        )],
    ))
    .await;
    let serve = start_serve(&responder);

    assert!(exchange(&responder, b"not-snmp").await.is_none());
    let unsupported = message(
        SnmpVersion::V2c,
        "public",
        Pdu {
            kind: PduKind::Response,
            request_id: 8,
            error_status: 0,
            error_index: 0,
            varbinds: vec![],
            v1_trap: None,
        },
    );
    assert!(exchange(&responder, &unsupported).await.is_none());
    let valid = message(
        SnmpVersion::V2c,
        "public",
        get_pdu(7, &[1, 3, 6, 1, 2, 1, 1, 3, 0]),
    );
    let reply = exchange(&responder, &valid)
        .await
        .expect("valid GET answered");
    let response = decode_message(&reply).unwrap();
    assert_eq!(response.pdu.kind, PduKind::Response);
    assert_eq!(response.pdu.request_id, 7);
    assert_eq!(response.pdu.varbinds[0].value, SnmpValue::TimeTicks(9));

    responder.close();
    serve.await.unwrap();
}

#[tokio::test]
async fn responder_set_and_bulk_edge_cases() {
    // RE-SPECIFIED: the reference drives the responder's private helpers
    // directly; the Rust equivalents run through the serve loop.
    let (responder, _port) = spawn(config(
        None,
        vec![object(
            &[1, 3, 6, 1, 2, 1, 1, 3, 0],
            SnmpValue::TimeTicks(9),
        )],
    ))
    .await;
    let serve = start_serve(&responder);

    // SET → notWritable (17), error-index 1, varbinds echoed.
    let set_bytes = message(
        SnmpVersion::V2c,
        "public",
        set_pdu(4, &[1, 3, 6, 1, 2, 1, 1, 3, 0], SnmpValue::Integer(1)),
    );
    let reply = exchange(&responder, &set_bytes)
        .await
        .expect("SET answered");
    let response = decode_message(&reply).unwrap();
    assert_eq!(response.pdu.kind, PduKind::Response);
    assert_eq!(response.pdu.error_status, ErrorStatus::NotWritable.as_raw());
    assert_eq!(response.pdu.error_index, 1);
    assert_eq!(response.pdu.varbinds.len(), 1, "varbinds echoed");

    // GETBULK with negative non-repeaters and zero repetitions: empty list.
    let bulk_bytes = message(
        SnmpVersion::V2c,
        "public",
        get_bulk_pdu_multi(
            5,
            -1,
            0,
            &[&[1, 3, 6, 1, 2, 1, 1, 3, 0], &[1, 3, 6, 1, 2, 1, 999, 0]],
        ),
    );
    let reply = exchange(&responder, &bulk_bytes)
        .await
        .expect("GETBULK answered");
    let response = decode_message(&reply).unwrap();
    assert!(
        response.pdu.varbinds.is_empty(),
        "zero repetitions, empty response"
    );

    // GETNEXT past the end: endOfMibView at the requested OID.
    let next_bytes = message(SnmpVersion::V2c, "public", get_next_pdu(6, &[1, 3, 6, 99]));
    let reply = exchange(&responder, &next_bytes)
        .await
        .expect("GETNEXT answered");
    let response = decode_message(&reply).unwrap();
    assert_eq!(response.pdu.varbinds[0].oid, oid(&[1, 3, 6, 99]));
    assert_eq!(response.pdu.varbinds[0].value, SnmpValue::EndOfMibView);

    responder.close();
    serve.await.unwrap();
}

#[tokio::test]
async fn responder_rejects_invalid_limits() {
    // RE-SPECIFIED: the reference's negative `max_bulk_repetitions` ValueError
    // is unrepresentable with `u32`.
    let mut cfg = config(None, vec![]);
    cfg.max_response_bytes = 0;
    let err = match SnmpResponder::bind(cfg).await {
        Err(err) => err,
        Ok(_) => panic!("zero max_response_bytes must be rejected"),
    };
    assert!(err.to_string().contains("max_response_bytes"), "{err}");
    let cfg = config(None, vec![]);
    let (responder, _port) = spawn(cfg).await;
    assert!(responder.local_addr().port() > 0);
}

#[tokio::test]
async fn responder_answers_v1_requests() {
    // RE-SPECIFIED (inverted from the reference): the reference drops v1 at
    // the boundary (server.py:136–140); the Phase 7 spec's v1 answer path
    // replies with RFC 1157 semantics instead.
    let (responder, _port) = spawn(config(
        None,
        vec![object(
            &[1, 3, 6, 1, 2, 1, 1, 3, 0],
            SnmpValue::TimeTicks(9),
        )],
    ))
    .await;
    let serve = start_serve(&responder);

    let v1_get = message(
        SnmpVersion::V1,
        "public",
        get_pdu(7, &[1, 3, 6, 1, 2, 1, 1, 3, 0]),
    );
    let v2c_get = message(
        SnmpVersion::V2c,
        "public",
        get_pdu(8, &[1, 3, 6, 1, 2, 1, 1, 3, 0]),
    );
    let reply = exchange(&responder, &v1_get)
        .await
        .expect("v1 GET answered");
    let response = decode_message(&reply).unwrap();
    assert_eq!(response.version, SnmpVersion::V1);
    assert_eq!(response.pdu.request_id, 7);
    assert_eq!(response.pdu.varbinds[0].value, SnmpValue::TimeTicks(9));

    let reply = exchange(&responder, &v2c_get)
        .await
        .expect("v2c GET answered");
    let response = decode_message(&reply).unwrap();
    assert_eq!(response.version, SnmpVersion::V2c);
    assert_eq!(response.pdu.request_id, 8);

    responder.close();
    serve.await.unwrap();
}

#[tokio::test]
async fn getbulk_freezes_exhausted_repeater_columns() {
    let (responder, _port) = spawn(config(
        None,
        vec![object(
            &[1, 3, 6, 1, 2, 1, 1, 3, 0],
            SnmpValue::TimeTicks(9),
        )],
    ))
    .await;
    let serve = start_serve(&responder);
    let bulk_bytes = message(
        SnmpVersion::V2c,
        "public",
        get_bulk_pdu(9, 0, 100_000, &[1, 3, 6, 99]),
    );
    let reply = exchange(&responder, &bulk_bytes)
        .await
        .expect("GETBULK answered");
    let response = decode_message(&reply).unwrap();
    // A missing OID with a huge repetition count yields exactly one
    // endOfMibView for the exhausted column instead of 100000 of them.
    assert_eq!(response.pdu.varbinds.len(), 1);
    assert_eq!(response.pdu.varbinds[0].value, SnmpValue::EndOfMibView);
    responder.close();
    serve.await.unwrap();
}

#[tokio::test]
async fn getbulk_stops_exhausted_column_but_continues_others() {
    let (responder, _port) = spawn(config(
        None,
        vec![
            object(&[1, 3, 6, 1, 2, 1, 1, 3, 0], SnmpValue::TimeTicks(9)),
            object(&[1, 3, 6, 1, 2, 1, 1, 4, 0], SnmpValue::TimeTicks(10)),
            object(&[1, 3, 6, 1, 2, 1, 1, 5, 0], SnmpValue::TimeTicks(11)),
        ],
    ))
    .await;
    let serve = start_serve(&responder);
    let bulk_bytes = message(
        SnmpVersion::V2c,
        "public",
        get_bulk_pdu_multi(9, 0, 5, &[&[1, 3, 6, 1, 2, 1, 1, 3, 0], &[1, 3, 6, 99]]),
    );
    let reply = exchange(&responder, &bulk_bytes)
        .await
        .expect("GETBULK answered");
    let response = decode_message(&reply).unwrap();
    let end_of_mib: Vec<&VarBind> = response
        .pdu
        .varbinds
        .iter()
        .filter(|v| v.value == SnmpValue::EndOfMibView)
        .collect();
    let live: Vec<&VarBind> = response
        .pdu
        .varbinds
        .iter()
        .filter(|v| v.value != SnmpValue::EndOfMibView)
        .collect();
    // The exhausted column emits endOfMibView exactly once and then stops;
    // the live column keeps advancing until it exhausts as well.
    assert_eq!(end_of_mib.len(), 2);
    assert_eq!(
        live.iter().map(|v| v.oid.clone()).collect::<Vec<_>>(),
        vec![
            oid(&[1, 3, 6, 1, 2, 1, 1, 4, 0]),
            oid(&[1, 3, 6, 1, 2, 1, 1, 5, 0])
        ]
    );
    assert_eq!(response.pdu.varbinds.len(), 4);
    responder.close();
    serve.await.unwrap();
}

#[tokio::test]
async fn getbulk_max_repetitions_is_clamped() {
    let mut cfg = config(
        None,
        vec![
            object(&[1, 3, 6, 1, 2, 1, 1, 3, 0], SnmpValue::TimeTicks(9)),
            object(&[1, 3, 6, 1, 2, 1, 1, 4, 0], SnmpValue::TimeTicks(10)),
            object(&[1, 3, 6, 1, 2, 1, 1, 5, 0], SnmpValue::TimeTicks(11)),
            object(&[1, 3, 6, 1, 2, 1, 1, 6, 0], SnmpValue::TimeTicks(12)),
        ],
    );
    cfg.max_bulk_repetitions = 2;
    let (responder, _port) = spawn(cfg).await;
    let serve = start_serve(&responder);
    let bulk_bytes = message(
        SnmpVersion::V2c,
        "public",
        get_bulk_pdu(9, 0, 100_000, &[1, 3, 6, 1, 2, 1, 1, 3, 0]),
    );
    let reply = exchange(&responder, &bulk_bytes)
        .await
        .expect("GETBULK answered");
    let response = decode_message(&reply).unwrap();
    // The wire-requested count never drives more than the configured cap.
    assert_eq!(response.pdu.varbinds.len(), 2);
    responder.close();
    serve.await.unwrap();
}

#[tokio::test]
async fn getbulk_response_truncated_to_max_response_bytes() {
    let mut objects = Vec::new();
    for index in 1..=8u32 {
        objects.push(object(
            &[1, 3, 6, 1, 2, 1, 1, index, 0],
            SnmpValue::OctetString(vec![b'x'; 200]),
        ));
    }
    let mut cfg = config(None, objects);
    cfg.max_response_bytes = 600;
    let (responder, _port) = spawn(cfg).await;
    let serve = start_serve(&responder);
    let bulk_bytes = message(
        SnmpVersion::V2c,
        "public",
        get_bulk_pdu(9, 0, 100, &[1, 3, 6, 1, 2, 1, 1, 1, 0]),
    );
    let reply = exchange(&responder, &bulk_bytes)
        .await
        .expect("GETBULK answered");
    let response = decode_message(&reply).unwrap();
    let encoded = trishul_snmp::codec::message::encode_message(&response).unwrap();
    // RFC 3416 GETBULK truncation: trailing varbinds are dropped until the
    // encoded response fits; the response is never answered with tooBig.
    assert!(encoded.len() <= 600, "encoded {} bytes", encoded.len());
    assert!(!response.pdu.varbinds.is_empty());
    assert!(response.pdu.varbinds.len() < 100);
    responder.close();
    serve.await.unwrap();
}

#[tokio::test]
async fn responder_recovers_from_bad_datagram() {
    // RE-SPECIFIED: the reference's unencodable-value case (Counter32(2**32))
    // cannot be constructed with the SnmpValue enum. The loop-resilience
    // property is exercised on the v3 path instead: a bad-HMAC datagram is
    // dropped and the next valid datagram is still answered.
    let user = v3_auth_user("simulator");
    let mut cfg = config(
        None,
        vec![object(
            &[1, 3, 6, 1, 2, 1, 1, 3, 0],
            SnmpValue::TimeTicks(9),
        )],
    );
    cfg.v3 = Some((user.clone(), local_engine(1000)));
    let (responder, _port) = spawn(cfg).await;
    let serve = start_serve(&responder);

    let model = UsmModel::new(user, Vec::new(), None, clock(), rng());
    model.adopt_engine_state(ENGINE_ID.to_vec(), 1, 1000);
    let mut bad = model
        .wrap_pdu(&get_pdu(7, &[1, 3, 6, 1, 2, 1, 1, 3, 0]))
        .unwrap();
    let last = bad.len() - 1;
    bad[last] ^= 0x01; // HMAC no longer verifies
    assert!(
        exchange(&responder, &bad).await.is_none(),
        "tampered request dropped"
    );

    let good = model
        .wrap_pdu(&get_pdu(8, &[1, 3, 6, 1, 2, 1, 1, 3, 0]))
        .unwrap();
    let reply = exchange(&responder, &good)
        .await
        .expect("valid request answered");
    match model.unwrap_message(&reply) {
        UnwrapOutcome::Ok(pdu) => {
            assert_eq!(pdu.request_id, 8);
            assert_eq!(pdu.varbinds[0].value, SnmpValue::TimeTicks(9));
        }
        other => panic!("expected Ok response, got {other:?}"),
    }
    responder.close();
    serve.await.unwrap();
}

// ── v1 answer path (Rust extension; the reference drops v1) ─────────────────

#[tokio::test]
async fn v1_manager_roundtrip() {
    let (responder, port) = spawn(config(
        Some(&["public"]),
        vec![
            object(
                &[1, 3, 6, 1, 2, 1, 1, 1, 0],
                SnmpValue::OctetString(b"v1 responder".to_vec()),
            ),
            object(&[1, 3, 6, 1, 2, 1, 1, 3, 0], SnmpValue::TimeTicks(12345)),
            object(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1], SnmpValue::Integer(1)),
            object(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 2], SnmpValue::Integer(2)),
        ],
    ))
    .await;
    let serve = start_serve(&responder);
    let manager = common::test_v1_manager(port).await;

    let get = manager.get(vec!["1.3.6.1.2.1.1.1.0"]).await.unwrap();
    assert_eq!(get.error_status, ErrorStatus::NoError);
    assert_eq!(
        get.varbinds[0].value,
        SnmpValue::OctetString(b"v1 responder".to_vec())
    );

    let next = manager.get_next(vec!["1.3.6.1.2.1.1.1.0"]).await.unwrap();
    assert_eq!(next.error_status, ErrorStatus::NoError);
    assert_eq!(next.varbinds[0].oid, oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]));

    // v1 walk terminates cleanly on the noSuchName end signal.
    let walked = manager
        .walk(
            "1.3.6.1.2.1.2.2",
            WalkOptions {
                bulk: false,
                max_repetitions: 10,
            },
        )
        .await
        .unwrap();
    assert_eq!(walked.len(), 2);

    responder.close();
    serve.await.unwrap();
}

#[tokio::test]
async fn v1_missing_get_is_no_such_name() {
    let (responder, port) = spawn(config(
        None,
        vec![object(
            &[1, 3, 6, 1, 2, 1, 1, 3, 0],
            SnmpValue::TimeTicks(9),
        )],
    ))
    .await;
    let serve = start_serve(&responder);
    let manager = common::test_v1_manager(port).await;
    let response = manager.get(vec!["1.3.6.1.2.1.1.99.0"]).await.unwrap();
    assert_eq!(response.error_status, ErrorStatus::NoSuchName);
    assert_eq!(response.error_index, 1);
    responder.close();
    serve.await.unwrap();
}

#[tokio::test]
async fn v1_getnext_past_end_is_no_such_name() {
    let (responder, _port) = spawn(config(
        None,
        vec![object(
            &[1, 3, 6, 1, 2, 1, 1, 3, 0],
            SnmpValue::TimeTicks(9),
        )],
    ))
    .await;
    let serve = start_serve(&responder);
    let bytes = message(SnmpVersion::V1, "public", get_next_pdu(7, &[1, 3, 6, 99]));
    let reply = exchange(&responder, &bytes)
        .await
        .expect("v1 GETNEXT answered");
    let response = decode_message(&reply).unwrap();
    assert_eq!(response.version, SnmpVersion::V1);
    assert_eq!(response.pdu.error_status, ErrorStatus::NoSuchName.as_raw());
    assert_eq!(response.pdu.error_index, 1);
    assert_eq!(response.pdu.varbinds.len(), 1, "request varbinds echoed");
    responder.close();
    serve.await.unwrap();
}

#[tokio::test]
async fn v1_set_is_read_only() {
    // RFC 1157 has no notWritable (17); a v1 read-only SET is rejected with
    // readOnly (4) (§8 deviation).
    let (responder, _port) = spawn(config(
        None,
        vec![object(
            &[1, 3, 6, 1, 2, 1, 1, 3, 0],
            SnmpValue::TimeTicks(9),
        )],
    ))
    .await;
    let serve = start_serve(&responder);
    let bytes = message(
        SnmpVersion::V1,
        "public",
        set_pdu(7, &[1, 3, 6, 1, 2, 1, 1, 3, 0], SnmpValue::Integer(1)),
    );
    let reply = exchange(&responder, &bytes).await.expect("v1 SET answered");
    let response = decode_message(&reply).unwrap();
    assert_eq!(response.pdu.kind, PduKind::Response);
    assert_eq!(response.pdu.error_status, ErrorStatus::ReadOnly.as_raw());
    assert_eq!(response.pdu.error_index, 1);
    responder.close();
    serve.await.unwrap();
}

// ── v3 answer path (Rust extension; the reference has no v3 responder) ──────

#[tokio::test]
async fn v3_discovery_probe_reports_engine() {
    let user = v3_auth_user("simulator");
    let mut cfg = config(None, vec![]);
    cfg.v3 = Some((user.clone(), local_engine(1000)));
    let (responder, _port) = spawn(cfg).await;
    let serve = start_serve(&responder);

    let probe_model = UsmModel::new(user, Vec::new(), None, clock(), rng());
    let probe = probe_model.build_discovery_probe().unwrap();
    let reply = exchange(&responder, &probe)
        .await
        .expect("discovery REPORT");

    let view = decode_v3_message(&reply).unwrap();
    assert_eq!(view.usm_params.engine_id, ENGINE_ID);
    assert_eq!(view.usm_params.engine_boots, 1);
    assert!(view.usm_params.username.is_empty());
    let (_engine_id, _context, pdu) = decode_scoped_pdu(&view.msg_data_bytes).unwrap();
    assert_eq!(pdu.kind, PduKind::Report);
    assert_eq!(pdu.varbinds[0].value, SnmpValue::Counter32(1));
    responder.close();
    serve.await.unwrap();
}

#[tokio::test]
async fn v3_manager_roundtrip() {
    let user = v3_auth_user("simulator");
    let mut cfg = config(
        None,
        vec![
            object(
                &[1, 3, 6, 1, 2, 1, 1, 1, 0],
                SnmpValue::OctetString(b"v3 responder".to_vec()),
            ),
            object(&[1, 3, 6, 1, 2, 1, 1, 3, 0], SnmpValue::TimeTicks(12345)),
            object(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1], SnmpValue::Integer(1)),
            object(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 2], SnmpValue::Integer(2)),
        ],
    );
    cfg.v3 = Some((user.clone(), local_engine(1000)));
    let (responder, port) = spawn(cfg).await;
    let serve = start_serve(&responder);

    let manager = Manager::connect_v3(V3Config {
        host: "127.0.0.1".to_string(),
        port,
        user,
        context_name: Vec::new(),
        local_engine: None,
        bundle: None,
        timeout: Duration::from_millis(500),
        retries: 0,
        clock: Arc::new(SystemClock),
        rng: Arc::new(SystemRng),
    })
    .await
    .expect("connect v3 manager");

    let get = manager.get(vec!["1.3.6.1.2.1.1.1.0"]).await.unwrap();
    assert_eq!(get.error_status, ErrorStatus::NoError);
    assert_eq!(
        get.varbinds[0].value,
        SnmpValue::OctetString(b"v3 responder".to_vec())
    );

    let next = manager.get_next(vec!["1.3.6.1.2.1.1.1.0"]).await.unwrap();
    assert_eq!(next.varbinds[0].oid, oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]));

    let bulk = manager
        .get_bulk(vec!["1.3.6.1.2.1.2.2"], 0, 3)
        .await
        .unwrap();
    assert_eq!(bulk.error_status, ErrorStatus::NoError);
    // Two live rows, then the frozen endOfMibView column.
    assert_eq!(
        bulk.varbinds
            .iter()
            .map(|v| v.oid.clone())
            .collect::<Vec<_>>(),
        vec![
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1]),
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 2]),
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 2]),
        ]
    );
    assert_eq!(bulk.varbinds[2].value, SnmpValue::EndOfMibView);

    responder.close();
    serve.await.unwrap();
}

#[tokio::test]
async fn v3_auth_priv_roundtrip() {
    let user = v3_priv_user("simulator");
    let mut cfg = config(
        None,
        vec![
            object(
                &[1, 3, 6, 1, 2, 1, 1, 1, 0],
                SnmpValue::OctetString(b"v3 priv responder".to_vec()),
            ),
            object(&[1, 3, 6, 1, 2, 1, 1, 3, 0], SnmpValue::TimeTicks(12345)),
        ],
    );
    cfg.v3 = Some((user.clone(), local_engine(1000)));
    let (responder, port) = spawn(cfg).await;
    let serve = start_serve(&responder);

    let manager = Manager::connect_v3(V3Config {
        host: "127.0.0.1".to_string(),
        port,
        user,
        context_name: Vec::new(),
        local_engine: None,
        bundle: None,
        timeout: Duration::from_millis(500),
        retries: 0,
        clock: Arc::new(SystemClock),
        rng: Arc::new(SystemRng),
    })
    .await
    .expect("connect v3 manager");

    let get = manager.get(vec!["1.3.6.1.2.1.1.1.0"]).await.unwrap();
    assert_eq!(get.error_status, ErrorStatus::NoError);
    assert_eq!(
        get.varbinds[0].value,
        SnmpValue::OctetString(b"v3 priv responder".to_vec())
    );
    let next = manager.get_next(vec!["1.3.6.1.2.1.1.1.0"]).await.unwrap();
    assert_eq!(next.varbinds[0].oid, oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]));

    responder.close();
    serve.await.unwrap();
}

#[tokio::test]
async fn v3_set_is_not_writable() {
    let user = v3_auth_user("simulator");
    let mut cfg = config(
        None,
        vec![object(
            &[1, 3, 6, 1, 2, 1, 1, 3, 0],
            SnmpValue::TimeTicks(9),
        )],
    );
    cfg.v3 = Some((user.clone(), local_engine(1000)));
    let (responder, _port) = spawn(cfg).await;
    let serve = start_serve(&responder);

    let model = UsmModel::new(user, Vec::new(), None, clock(), rng());
    model.adopt_engine_state(ENGINE_ID.to_vec(), 1, 1000);
    let raw = model
        .wrap_pdu(&set_pdu(
            4,
            &[1, 3, 6, 1, 2, 1, 1, 3, 0],
            SnmpValue::Integer(5),
        ))
        .unwrap();
    let reply = exchange(&responder, &raw).await.expect("v3 SET answered");
    match model.unwrap_message(&reply) {
        UnwrapOutcome::Ok(pdu) => {
            assert_eq!(pdu.kind, PduKind::Response);
            assert_eq!(pdu.error_status, ErrorStatus::NotWritable.as_raw());
            assert_eq!(pdu.error_index, 1);
            assert_eq!(pdu.varbinds.len(), 1, "varbinds echoed");
        }
        other => panic!("expected Ok response, got {other:?}"),
    }
    responder.close();
    serve.await.unwrap();
}

#[tokio::test]
async fn v3_wrong_user_is_dropped() {
    let user = v3_auth_user("simulator");
    let mut cfg = config(
        None,
        vec![object(
            &[1, 3, 6, 1, 2, 1, 1, 3, 0],
            SnmpValue::TimeTicks(9),
        )],
    );
    cfg.v3 = Some((user, local_engine(1000)));
    let (responder, _port) = spawn(cfg).await;
    let serve = start_serve(&responder);

    let wrong = UsmModel::new(
        v3_auth_user("someone-else"),
        Vec::new(),
        None,
        clock(),
        rng(),
    );
    wrong.adopt_engine_state(ENGINE_ID.to_vec(), 1, 1000);
    let raw = wrong
        .wrap_pdu(&get_pdu(7, &[1, 3, 6, 1, 2, 1, 1, 3, 0]))
        .unwrap();
    assert!(
        exchange(&responder, &raw).await.is_none(),
        "wrong-user request dropped"
    );
    responder.close();
    serve.await.unwrap();
}

// ── shared harness sanity: the FakeClock used by the rule tests ─────────────

#[test]
fn harness_fake_clock_and_rng_are_deterministic() {
    let fake = FakeClock::new(Duration::from_secs(5), 42);
    assert_eq!(fake.monotonic(), Duration::from_secs(5));
    assert_eq!(fake.unix(), 42);
    let mut buf = [0u8; 4];
    Arc::new(CounterRng::new(7)).fill_bytes(&mut buf);
    assert_eq!(buf, [0, 0, 0, 7]);
}
