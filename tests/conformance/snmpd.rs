//! Conformance suite against a live net-snmp `snmpd` agent (v1/v2c).
//!
//! Gated on the `TSNMP_SNMPD` environment variable: with the variable unset
//! the suite self-skips (returns immediately); with `TSNMP_SNMPD=1` it spawns
//! a raw `snmpd` subprocess adapted from `fixtures/snmpd/snmpd.conf`, waits
//! for the agent on `127.0.0.1:1161`, runs the v1+v2c get/getnext/getbulk/walk
//! matrix over the system subtree, and tears the agent down.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use trishul_snmp::codec::message::SnmpVersion;
use trishul_snmp::codec::pdu::PduKind;
use trishul_snmp::manager::walk::WalkOptions;
use trishul_snmp::manager::{Manager, V1Config, V2cConfig};
use trishul_snmp::types::value::SnmpValue;
use trishul_snmp::types::varbind::ErrorStatus;

const AGENT_PORT: u16 = 1161;
const SYSTEM_ROOT: &str = "1.3.6.1.2.1.1";
const SYS_UPTIME_INSTANCE: &str = "1.3.6.1.2.1.1.3.0";
const SYS_DESCR_INSTANCE: &str = "1.3.6.1.2.1.1.1.0";

/// Whether the gate is open (TSNMP_SNMPD set).
fn gate_open() -> bool {
    std::env::var("TSNMP_SNMPD").is_ok()
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Builds the v1/v2c-only agent config from the fixture (drops the v3 users,
/// notification sinks, and extra listeners; forces the single 1161 endpoint).
fn adapted_conf() -> String {
    let fixture = std::fs::read_to_string(manifest_dir().join("fixtures/snmpd/snmpd.conf"))
        .expect("fixtures/snmpd/snmpd.conf must exist");
    let relevant = fixture
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("rocommunity ") || line.starts_with("engineID "))
        .collect::<Vec<_>>()
        .join("\n");
    format!("{relevant}\nagentaddress 127.0.0.1:{AGENT_PORT}\n")
}

/// Spawns the adapted agent; returns the child plus the working directory.
fn spawn_agent() -> Option<(Child, PathBuf)> {
    let workdir = manifest_dir().join("target/snmpd-conformance");
    std::fs::create_dir_all(&workdir).ok()?;
    let conf = workdir.join("snmpd.conf");
    std::fs::write(&conf, adapted_conf()).ok()?;
    let child = Command::new("snmpd")
        .args([
            "-C",
            "-f",
            "-c",
            conf.to_str()?,
            "-p",
            workdir.join("snmpd.pid").to_str()?,
            "-Lf",
            workdir.join("snmpd.log").to_str()?,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    Some((child, workdir))
}

/// Polls the agent until it answers a v2c GET or the deadline expires.
async fn wait_for_agent(timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        let config = V2cConfig {
            host: "127.0.0.1".to_string(),
            port: AGENT_PORT,
            timeout: Duration::from_millis(200),
            retries: 0,
            ..Default::default()
        };
        let Ok(manager) = Manager::connect_v2c(config).await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        if manager.get(vec![SYS_UPTIME_INSTANCE]).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test]
async fn conformance_v1_v2c_get_getnext_getbulk_walk() {
    if !gate_open() {
        eprintln!("TSNMP_SNMPD unset: skipping snmpd conformance suite");
        return;
    }

    let (mut agent, _workdir) = spawn_agent().expect("snmpd must be available and spawnable");
    let ready = wait_for_agent(Duration::from_secs(10)).await;
    if !ready {
        let _ = agent.kill();
        let _ = agent.wait();
        panic!("snmpd agent did not become ready on 127.0.0.1:{AGENT_PORT}");
    }

    let v2c = Manager::connect_v2c(V2cConfig {
        host: "127.0.0.1".to_string(),
        port: AGENT_PORT,
        timeout: Duration::from_secs(1),
        retries: 1,
        ..Default::default()
    })
    .await
    .expect("connect v2c");
    let v1 = Manager::connect_v1(V1Config {
        host: "127.0.0.1".to_string(),
        port: AGENT_PORT,
        timeout: Duration::from_secs(1),
        retries: 1,
        ..Default::default()
    })
    .await
    .expect("connect v1");

    // v2c GETs over the system subtree.
    let uptime = v2c
        .get(vec![SYS_UPTIME_INSTANCE])
        .await
        .expect("v2c get sysUpTime");
    assert_eq!(uptime.error_status, ErrorStatus::NoError);
    assert_ne!(uptime.request_id, 0);
    assert!(matches!(uptime.varbinds[0].value, SnmpValue::TimeTicks(_)));

    let descr = v2c
        .get(vec![SYS_DESCR_INSTANCE])
        .await
        .expect("v2c get sysDescr");
    assert!(matches!(descr.varbinds[0].value, SnmpValue::OctetString(_)));

    // v1 GET.
    let uptime_v1 = v1
        .get(vec![SYS_UPTIME_INSTANCE])
        .await
        .expect("v1 get sysUpTime");
    assert_eq!(uptime_v1.error_status, ErrorStatus::NoError);
    assert!(matches!(
        uptime_v1.varbinds[0].value,
        SnmpValue::TimeTicks(_)
    ));

    // GETNEXT (both versions): sysDescr.0 -> sysObjectID.0.
    let next = v2c
        .get_next(vec![SYS_DESCR_INSTANCE])
        .await
        .expect("v2c getnext");
    assert_eq!(next.varbinds[0].oid.display(), "1.3.6.1.2.1.1.2.0");
    let next_v1 = v1
        .get_next(vec![SYS_DESCR_INSTANCE])
        .await
        .expect("v1 getnext");
    assert_eq!(next_v1.varbinds[0].oid.display(), "1.3.6.1.2.1.1.2.0");

    // GETBULK (v2c) on the system subtree with several repetitions.
    let bulk = v2c
        .get_bulk(vec![SYSTEM_ROOT], 0, 5)
        .await
        .expect("v2c getbulk");
    assert_eq!(bulk.error_status, ErrorStatus::NoError);
    assert!(!bulk.varbinds.is_empty(), "getbulk returned rows");
    assert!(
        bulk.varbinds.iter().all(|v| v.oid.starts_with(
            &trishul_snmp::types::oid::Oid::from_arcs(&[1, 3, 6, 1, 2, 1, 1]).unwrap()
        ))
    );

    // v1 GETBULK downgrade.
    let bulk_v1 = v1
        .get_bulk(vec![SYSTEM_ROOT], 0, 3)
        .await
        .expect("v1 getbulk downgrade");
    assert!(!bulk_v1.varbinds.is_empty(), "v1 getbulk returned rows");

    // WALK of the system subtree (v2c bulkwalk + plain walk; v1 walk).
    let walked = v2c
        .walk(
            SYSTEM_ROOT,
            WalkOptions {
                bulk: true,
                max_repetitions: 10,
            },
        )
        .await
        .expect("v2c bulkwalk");
    assert!(
        walked.len() >= 5,
        "system subtree walk produced {}",
        walked.len()
    );
    assert!(walked.iter().any(|v| v.oid
        == trishul_snmp::types::oid::Oid::from_arcs(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap()));
    assert!(walked.iter().any(|v| v.oid
        == trishul_snmp::types::oid::Oid::from_arcs(&[1, 3, 6, 1, 2, 1, 1, 3, 0]).unwrap()));

    let walked_next = v2c
        .walk(
            SYSTEM_ROOT,
            WalkOptions {
                bulk: false,
                max_repetitions: 10,
            },
        )
        .await
        .expect("v2c getnext walk");
    assert!(!walked_next.is_empty());

    let walked_v1 = v1
        .walk(SYSTEM_ROOT, WalkOptions::default())
        .await
        .expect("v1 walk");
    assert!(!walked_v1.is_empty());
    assert!(
        walked_v1.iter().all(|v| v.oid.starts_with(
            &trishul_snmp::types::oid::Oid::from_arcs(&[1, 3, 6, 1, 2, 1, 1]).unwrap()
        ))
    );

    // Teardown.
    let _ = agent.kill();
    let _ = agent.wait();
    eprintln!("conformance: v1/v2c get/getnext/getbulk/walk passed against live snmpd");
}

#[test]
fn version_marker_compiles() {
    let _ = SnmpVersion::V1;
    let _ = SnmpVersion::V2c;
    let _ = PduKind::GetRequest;
}
