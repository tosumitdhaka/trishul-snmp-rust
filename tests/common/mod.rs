//! Shared test harness: loopback UDP agent, FakeClock/FakeRng, runtime
//! builders, helpers.
//!
//! Each integration test crate includes only the pieces it needs; the harness
//! is compiled per-crate, so dead-code linting for the un-used pieces is
//! expected and suppressed here.

#![allow(dead_code)]

pub mod agent;
pub mod fake;
pub mod transport;

use std::sync::Arc;
use std::time::Duration;

use trishul_snmp::manager::{Manager, V1Config, V2cConfig};
use trishul_snmp::notify::sender::{Notifier, V1NotifierConfig, V2cNotifierConfig};
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

// ── runtime builders (port-only config literals live here) ─────────────────

const TEST_HOST: &str = "127.0.0.1";
const TEST_TIMEOUT: Duration = Duration::from_millis(300);
const TEST_RETRIES: u32 = 0;

/// Connects a v2c manager to a loopback agent (community `public`, 300ms, 0
/// retries).
pub async fn test_v2c_manager(port: u16) -> Manager {
    test_v2c_manager_with(port, "public", TEST_TIMEOUT, TEST_RETRIES).await
}

/// Connects a v1 manager to a loopback agent.
pub async fn test_v1_manager(port: u16) -> Manager {
    test_v1_manager_with(port, "public", TEST_TIMEOUT, TEST_RETRIES).await
}

/// Connects a v2c manager with explicit community/timeout/retries.
pub async fn test_v2c_manager_with(
    port: u16,
    community: &str,
    timeout: Duration,
    retries: u32,
) -> Manager {
    try_connect_v2c_manager_with(port, community, timeout, retries)
        .await
        .expect("connect v2c test manager")
}

/// Fallible variant (for readiness probes that expect connection failures).
pub async fn try_connect_v2c_manager_with(
    port: u16,
    community: &str,
    timeout: Duration,
    retries: u32,
) -> Result<Manager, trishul_snmp::error::Error> {
    Manager::connect_v2c(V2cConfig {
        host: TEST_HOST.to_string(),
        port,
        community: community.to_string(),
        timeout,
        retries,
        ..Default::default()
    })
    .await
}

/// Connects a v1 manager with explicit community/timeout/retries.
pub async fn test_v1_manager_with(
    port: u16,
    community: &str,
    timeout: Duration,
    retries: u32,
) -> Manager {
    Manager::connect_v1(V1Config {
        host: TEST_HOST.to_string(),
        port,
        community: community.to_string(),
        timeout,
        retries,
        ..Default::default()
    })
    .await
    .expect("connect v1 test manager")
}

/// Connects a v2c notifier to a loopback agent.
pub async fn test_v2c_notifier(port: u16) -> Notifier {
    test_v2c_notifier_with(port, "public", TEST_TIMEOUT, TEST_RETRIES).await
}

/// Connects a v1 notifier to a loopback agent.
pub async fn test_v1_notifier(port: u16) -> Notifier {
    Notifier::connect_v1(V1NotifierConfig {
        host: TEST_HOST.to_string(),
        port,
        community: "public".to_string(),
        timeout: TEST_TIMEOUT,
        retries: TEST_RETRIES,
        ..Default::default()
    })
    .await
    .expect("connect v1 test notifier")
}

/// Connects a v2c notifier with explicit community/timeout/retries.
pub async fn test_v2c_notifier_with(
    port: u16,
    community: &str,
    timeout: Duration,
    retries: u32,
) -> Notifier {
    Notifier::connect_v2c(V2cNotifierConfig {
        host: TEST_HOST.to_string(),
        port,
        community: community.to_string(),
        timeout,
        retries,
        ..Default::default()
    })
    .await
    .expect("connect v2c test notifier")
}

/// A shared dispatcher input for request-id tests.
pub fn counter_rng(start: u32) -> Arc<dyn trishul_snmp::time::Rng> {
    Arc::new(fake::CounterRng::new(start))
}
