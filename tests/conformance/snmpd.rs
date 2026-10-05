//! Conformance suite against a live net-snmp `snmpd` agent (v1/v2c).
//!
//! Gated on the `TSNMP_SNMPD` environment variable: with the variable unset
//! the suite self-skips (returns immediately); with `TSNMP_SNMPD=1` it spawns
//! a raw `snmpd` subprocess adapted from `fixtures/snmpd/snmpd.conf`, waits
//! for the agent on `127.0.0.1:1161`, runs the v1+v2c get/getnext/getbulk/walk
//! matrix over the system subtree, and tears the agent down.

#[path = "../common/mod.rs"]
mod common;

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use std::sync::Arc;

use trishul_snmp::codec::message::SnmpVersion;
use trishul_snmp::codec::pdu::PduKind;
use trishul_snmp::manager::Manager;
use trishul_snmp::manager::walk::WalkOptions;
use trishul_snmp::security::usm::kdf::{AuthProtocol, PrivProtocol};
use trishul_snmp::security::usm::{AuthKey, PrivKey, UsmUser, V3Config};
use trishul_snmp::types::value::SnmpValue;
use trishul_snmp::types::varbind::ErrorStatus;

const AGENT_PORT: u16 = 1161;
const SYSTEM_ROOT: &str = "1.3.6.1.2.1.1";
const SYS_UPTIME_INSTANCE: &str = "1.3.6.1.2.1.1.3.0";
const SYS_DESCR_INSTANCE: &str = "1.3.6.1.2.1.1.1.0";

/// Whether the gate is open (TSNMP_SNMPD set to exactly "1").
fn gate_open() -> bool {
    std::env::var("TSNMP_SNMPD").is_ok_and(|value| value == "1")
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

/// Builds the v3-only agent config: engineID + every `createUser`/`rouser`
/// line byte-identical from the fixture, plus the MD5/SHA-1 auth-only users
/// (ADAPTATION: the fixture's matrix is SHA-2-only; MD5/SHA-1 auth interop is
/// exercised with added users, documented here). Port is chosen by the caller.
fn v3_conf(port: u16) -> String {
    let fixture = std::fs::read_to_string(manifest_dir().join("fixtures/snmpd/snmpd.conf"))
        .expect("fixtures/snmpd/snmpd.conf must exist");
    let mut relevant = fixture
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.starts_with("engineID ")
                || line.starts_with("createUser ")
                || line.starts_with("rouser ")
        })
        .map(str::to_string)
        .collect::<Vec<_>>();
    relevant.push(
        "createUser -e 0x80001f8804726565646572696e76657374 userMD5 MD5 \"authpassword12345\""
            .to_string(),
    );
    relevant.push("rouser userMD5".to_string());
    relevant.push(
        "createUser -e 0x80001f8804726565646572696e76657374 userSHA1 SHA-1 \"authpassword12345\""
            .to_string(),
    );
    relevant.push("rouser userSHA1".to_string());
    relevant.push(format!("agentaddress 127.0.0.1:{port}"));
    relevant.join("\n")
}

/// Finds a free loopback UDP port (the fixture's 1162 is occupied on this
/// machine; ports are not part of USM identity — engineID is).
fn free_udp_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = socket.local_addr().expect("bound").port();
    drop(socket);
    port
}

/// Spawns a snmpd with `conf`; returns the child plus the working directory.
fn spawn_snmpd(conf: &str, name: &str) -> Option<(Child, PathBuf)> {
    let workdir = manifest_dir().join(format!("target/snmpd-conformance/{name}"));
    std::fs::create_dir_all(&workdir).ok()?;
    let conf_path = workdir.join("snmpd.conf");
    std::fs::write(&conf_path, conf).ok()?;
    let child = Command::new("snmpd")
        .args([
            "-C",
            "-f",
            "-c",
            conf_path.to_str()?,
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

/// Spawns the adapted agent; returns the child plus the working directory.
fn spawn_agent() -> Option<(Child, PathBuf)> {
    spawn_snmpd(&adapted_conf(), "main")
}

/// Polls the agent until it answers a v2c GET or the deadline expires.
async fn wait_for_agent(timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        let Ok(manager) = common::try_connect_v2c_manager_with(
            AGENT_PORT,
            "public",
            Duration::from_millis(200),
            0,
        )
        .await
        else {
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

    let v2c = common::test_v2c_manager_with(AGENT_PORT, "public", Duration::from_secs(1), 1).await;
    let v1 = common::test_v1_manager_with(AGENT_PORT, "public", Duration::from_secs(1), 1).await;

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

#[tokio::test]
async fn conformance_v3_authnopriv_matrix() {
    if !gate_open() {
        eprintln!("TSNMP_SNMPD unset: skipping snmpd v3 conformance suite");
        return;
    }
    let port = free_udp_port();
    let (mut agent, _workdir) =
        spawn_snmpd(&v3_conf(port), "v3").expect("snmpd must spawn for the v3 agent");

    // Readiness: a v3 noAuth user is not configured, so probe with the MD5
    // user's connect (discovery) until it succeeds.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut ready = false;
    while tokio::time::Instant::now() < deadline {
        let user = v3_user("userMD5", AuthProtocol::Md5);
        let Ok(manager) = Manager::connect_v3(v3_config(port, user)).await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        if manager.get(vec![SYS_UPTIME_INSTANCE]).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if !ready {
        let _ = agent.kill();
        let _ = agent.wait();
        panic!("snmpd v3 agent did not become ready on 127.0.0.1:{port}");
    }

    // authNoPriv GET across the user matrix.
    let matrix = [
        ("tsnmpuser", AuthProtocol::Sha256),
        ("user224", AuthProtocol::Sha224),
        ("user384", AuthProtocol::Sha384),
        ("user512", AuthProtocol::Sha512),
        ("userSha256Aes192", AuthProtocol::Sha256),
        ("userMD5", AuthProtocol::Md5),
        ("userSHA1", AuthProtocol::Sha1),
    ];
    for (username, auth) in matrix {
        let manager = Manager::connect_v3(v3_config(port, v3_user(username, auth)))
            .await
            .unwrap_or_else(|e| panic!("{username}: connect_v3 failed: {e}"));
        let response = manager
            .get(vec![SYS_UPTIME_INSTANCE])
            .await
            .unwrap_or_else(|e| panic!("{username}: get failed: {e}"));
        assert_eq!(
            response.error_status,
            ErrorStatus::NoError,
            "{username}: authNoPriv GET rejected"
        );
        assert!(
            matches!(response.varbinds[0].value, SnmpValue::TimeTicks(_)),
            "{username}: sysUpTime expected"
        );
    }

    let _ = agent.kill();
    let _ = agent.wait();
    eprintln!("conformance: v3 authNoPriv matrix passed against live snmpd");
}

#[test]
fn version_marker_compiles() {
    let _ = SnmpVersion::V1;
    let _ = SnmpVersion::V2c;
    let _ = SnmpVersion::V3;
    let _ = PduKind::GetRequest;
}

// ── v3 conformance helpers ──────────────────────────────────────────────────

fn v3_user(username: &str, auth: AuthProtocol) -> UsmUser {
    UsmUser::new(
        username.to_string(),
        auth,
        AuthKey::Passphrase(b"authpassword12345".to_vec()),
        PrivProtocol::None_,
        PrivKey::Passphrase(Vec::new()),
    )
    .unwrap()
}

fn v3_config(port: u16, user: UsmUser) -> V3Config {
    V3Config {
        host: "127.0.0.1".to_string(),
        port,
        user,
        context_name: Vec::new(),
        local_engine: None,
        timeout: Duration::from_secs(1),
        retries: 1,
        clock: Arc::new(trishul_snmp::time::SystemClock),
        rng: Arc::new(trishul_snmp::time::SystemRng),
    }
}
