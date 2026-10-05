//! Shared test harness: loopback UDP agent, FakeClock/FakeRng, helpers.
//!
//! Each integration test crate includes only the pieces it needs; the harness
//! is compiled per-crate, so dead-code linting for the un-used pieces is
//! expected and suppressed here.

#![allow(dead_code)]

pub mod agent;
pub mod fake;

use trishul_snmp::types::oid::Oid;
use trishul_snmp::types::value::SnmpValue;
use trishul_snmp::types::varbind::VarBind;

/// Parses a contiguous or whitespace-separated hex string.
pub fn hex(s: &str) -> Vec<u8> {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..compact.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&compact[i..i + 2], 16).unwrap())
        .collect()
}

/// Builds a valid OID.
pub fn oid(arcs: &[u32]) -> Oid {
    Oid::from_arcs(arcs).expect("valid OID in test")
}

/// Builds a varbind.
pub fn vb(arcs: &[u32], value: SnmpValue) -> VarBind {
    VarBind::new(oid(arcs), value)
}

/// The standard sysUpTime.0 instance OID.
pub fn sys_uptime_instance() -> Oid {
    oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0])
}

/// The standard snmpTrapOID.0 instance OID.
pub fn snmp_trap_oid_instance() -> Oid {
    oid(&[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0])
}
