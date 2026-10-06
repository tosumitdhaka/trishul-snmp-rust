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
use trishul_snmp::types::oid::Oid;
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
                // v3view's VACM story (review I3): without these lines the
                // user has no access entry and every request is refused with
                // AuthorizationError. With them, RFC 3415 picks the noauth
                // access row for higher-level requests, so v3view serves
                // authPriv GETs within its `restricted` view.
                || line.starts_with("view restricted ")
                || line.starts_with("com2sec restsec ")
                || line.starts_with("group restgroup ")
                || line.starts_with("access restgroup ")
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

/// The v3 authNoPriv agent binds the fixture's 1162 (the fixture's v3 users
/// are pinned to that port; USM identity is the engineID, and the createUser
/// lines are kept byte-identical). If the port is occupied at test time the
/// suite self-skips with a clear message rather than falling back.
const V3_PORT: u16 = 1162;

/// The v3 authPriv agent binds a DISTINCT port from the authNoPriv suite so
/// the two suites can run in parallel under the default test harness (each
/// spawns its own snmpd; the loser of a shared port would fail to bind and
/// the readiness loop would spin — review I2). 1174 is the fixture's
/// dedicated v3-only port in the reference deployment.
const V3_PRIV_PORT: u16 = 1174;

/// Spawns a snmpd with `conf`; returns the child plus the working directory.
/// Kills the snmpd child on drop so a panicking test cannot leak an agent.
struct AgentGuard(Child);

impl AgentGuard {
    /// Whether the child has exited (bind failures exit immediately).
    fn try_wait(&mut self) -> Option<std::process::ExitStatus> {
        self.0.try_wait().ok().flatten()
    }

    /// Kills and reaps the child, consuming the guard.
    fn kill(mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for AgentGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_snmpd(conf: &str, name: &str) -> Option<(AgentGuard, PathBuf)> {
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
    Some((AgentGuard(child), workdir))
}

/// Spawns the adapted agent; returns the child plus the working directory.
fn spawn_agent() -> Option<(AgentGuard, PathBuf)> {
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

    let (agent, _workdir) = spawn_agent().expect("snmpd must be available and spawnable");
    let ready = wait_for_agent(Duration::from_secs(10)).await;
    if !ready {
        agent.kill();
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
    agent.kill();
    eprintln!("conformance: v1/v2c get/getnext/getbulk/walk passed against live snmpd");
}

#[tokio::test]
async fn conformance_v3_authnopriv_matrix() {
    if !gate_open() {
        eprintln!("TSNMP_SNMPD unset: skipping snmpd v3 conformance suite");
        return;
    }
    let port = V3_PORT;
    let Some((mut agent, _workdir)) = spawn_snmpd(&v3_conf(port), "v3") else {
        eprintln!("conformance: cannot spawn snmpd for the v3 agent on {port}; skipping v3 suite");
        return;
    };
    // A v3 agent that exits immediately means the bind failed (port in use).
    if let Some(_status) = agent.try_wait() {
        drop(agent);
        eprintln!(
            "conformance: v3 agent on {port} exited immediately (port in use?); skipping v3 suite"
        );
        return;
    }

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
        agent.kill();
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

    agent.kill();
    eprintln!("conformance: v3 authNoPriv matrix passed against live snmpd");
}

#[tokio::test]
async fn conformance_v3_authpriv_matrix() {
    if !gate_open() {
        eprintln!("TSNMP_SNMPD unset: skipping snmpd v3 authPriv conformance suite");
        return;
    }
    let port = V3_PRIV_PORT;
    let Some((mut agent, _workdir)) = spawn_snmpd(&v3_conf(port), "v3priv") else {
        eprintln!("conformance: cannot spawn snmpd for the v3 authPriv agent on {port}; skipping");
        return;
    };
    if let Some(_status) = agent.try_wait() {
        drop(agent);
        eprintln!(
            "conformance: v3 authPriv agent on {port} exited immediately (port in use?); skipping"
        );
        return;
    }
    // authPriv users from the fixture's createUser rows. v3view is included:
    // with the VACM group/access lines present (v3_conf), RFC 3415 grants its
    // authPriv requests under the noauth access row's `restricted` view
    // (review I3 — the earlier AuthorizationError was the dropped VACM lines).
    let matrix = [
        ("tsnmpuser", AuthProtocol::Sha256, PrivProtocol::Aes256),
        ("user224", AuthProtocol::Sha224, PrivProtocol::Aes256),
        ("user384", AuthProtocol::Sha384, PrivProtocol::Aes192),
        ("user512", AuthProtocol::Sha512, PrivProtocol::Aes256),
        (
            "userSha256Aes192",
            AuthProtocol::Sha256,
            PrivProtocol::Aes192,
        ),
        ("v3view", AuthProtocol::Sha256, PrivProtocol::Aes128),
        ("v3only", AuthProtocol::Sha256, PrivProtocol::Aes128),
    ];
    for (username, auth, priv_protocol) in matrix {
        let user = v3_authpriv_user(username, auth, priv_protocol);
        // Readiness per user: discovery + an authed+priv'd get. The connect
        // failure branch MUST also check the deadline (review I2: under
        // parallel invocation a bind failure would otherwise spin forever).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let manager = loop {
            let Ok(manager) = Manager::connect_v3(v3_config(port, user.clone())).await else {
                if tokio::time::Instant::now() >= deadline {
                    agent.kill();
                    panic!("{username}: authPriv agent never became reachable");
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            };
            if manager.get(vec![SYS_UPTIME_INSTANCE]).await.is_ok() {
                break manager;
            }
            if tokio::time::Instant::now() >= deadline {
                agent.kill();
                panic!("{username}: authPriv agent never became ready");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        // get: sysUpTime.0 is TimeTicks.
        let response = manager
            .get(vec![SYS_UPTIME_INSTANCE])
            .await
            .unwrap_or_else(|e| panic!("{username}: authPriv get failed: {e}"));
        assert_eq!(
            response.error_status,
            ErrorStatus::NoError,
            "{username}: get rejected"
        );
        assert!(
            matches!(response.varbinds[0].value, SnmpValue::TimeTicks(_)),
            "{username}: sysUpTime expected"
        );
        // getnext: sysDescr.0 -> sysObjectID.0
        let response = manager
            .get_next(vec![SYS_DESCR_INSTANCE])
            .await
            .unwrap_or_else(|e| panic!("{username}: getnext failed: {e}"));
        assert_eq!(
            response.varbinds[0].oid,
            Oid::from_arcs(&[1, 3, 6, 1, 2, 1, 1, 2, 0]).unwrap(),
            "{username}: getnext successor"
        );
        // getbulk: the system subtree in one shot.
        let response = manager
            .get_bulk(vec![SYS_DESCR_INSTANCE], 0, 5)
            .await
            .unwrap_or_else(|e| panic!("{username}: getbulk failed: {e}"));
        assert_eq!(
            response.error_status,
            ErrorStatus::NoError,
            "{username}: getbulk rejected"
        );
        assert!(
            response.varbinds.len() >= 3,
            "{username}: getbulk returned {} varbinds",
            response.varbinds.len()
        );
        // walk: the whole system subtree.
        let walked = manager
            .walk(
                [1, 3, 6, 1, 2, 1, 1].as_slice(),
                trishul_snmp::manager::walk::WalkOptions::default(),
            )
            .await
            .unwrap_or_else(|e| panic!("{username}: authPriv walk failed: {e}"));
        assert!(
            walked.len() >= 7,
            "{username}: system subtree walk returned {} varbinds",
            walked.len()
        );
        if username == "v3view" {
            // Port of the reference restricted-view tests
            // (test_snmpd_integration.py view suite): an inside-view GET is
            // served with a real value; an outside-view GET surfaces a
            // noSuchObject varbind under NO_ERROR.
            let inside = manager
                .get(vec![SYS_DESCR_INSTANCE])
                .await
                .unwrap_or_else(|e| panic!("v3view: inside-view get failed: {e}"));
            assert_eq!(inside.error_status, ErrorStatus::NoError);
            assert!(
                matches!(inside.varbinds[0].value, SnmpValue::OctetString(_)),
                "v3view: inside-view sysDescr should be served, got {:?}",
                inside.varbinds[0].value
            );
            let outside = manager
                .get(vec!["1.3.6.1.2.1.2.2.1.1.1"])
                .await
                .unwrap_or_else(|e| panic!("v3view: outside-view get failed: {e}"));
            assert_eq!(outside.error_status, ErrorStatus::NoError);
            assert!(
                matches!(
                    outside.varbinds[0].value,
                    SnmpValue::NoSuchObject | SnmpValue::EndOfMibView
                ),
                "v3view: outside-view ifIndex.1 should be restricted, got {:?}",
                outside.varbinds[0].value
            );
        }
    }
    agent.kill();
    eprintln!("conformance: v3 authPriv matrix passed against live snmpd");
}

#[test]
fn version_marker_compiles() {
    let _ = SnmpVersion::V1;
    let _ = SnmpVersion::V2c;
    let _ = SnmpVersion::V3;
    let _ = PduKind::GetRequest;
}

// ── Responder inverse direction (real net-snmp clients → trishul responder) ──
//
// Port of test_snmpd_integration.py:466–619 — the plan.md Phase 7 gate: the
// net-snmp `snmpget`/`snmpwalk` client tools read from our responder (the
// reference does exactly this). Gated on `TSNMP_SNMPD=1` like the rest of
// this suite, and additionally self-skipping when the tools are absent.

/// The responder's object seed set (test_snmpd_integration.py:_RESPONDER_OBJECTS).
fn responder_objects() -> Vec<(
    trishul_snmp::target::Target,
    trishul_snmp::responder::ObjectValue,
)> {
    use trishul_snmp::responder::ObjectValue;
    use trishul_snmp::target::Target;
    vec![
        (
            Target::from("1.3.6.1.2.1.1.1.0"),
            ObjectValue::Static(SnmpValue::OctetString(
                b"trishul-responder integration agent".to_vec(),
            )),
        ),
        (
            Target::from("1.3.6.1.2.1.1.3.0"),
            ObjectValue::Static(SnmpValue::TimeTicks(123456)),
        ),
        (
            Target::from("1.3.6.1.2.1.2.2.1.1.1"),
            ObjectValue::Static(SnmpValue::Integer(1)),
        ),
        (
            Target::from("1.3.6.1.2.1.2.2.1.1.2"),
            ObjectValue::Static(SnmpValue::Integer(2)),
        ),
        (
            Target::from("1.3.6.1.2.1.2.2.1.2.1"),
            ObjectValue::Static(SnmpValue::OctetString(b"eth0".to_vec())),
        ),
        (
            Target::from("1.3.6.1.2.1.2.2.1.2.2"),
            ObjectValue::Static(SnmpValue::OctetString(b"eth1".to_vec())),
        ),
    ]
}

/// Whether the net-snmp client tools are installed.
fn net_snmp_tools_available() -> bool {
    std::process::Command::new("snmpget")
        .arg("-h")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
        && std::process::Command::new("snmpwalk")
            .arg("-h")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
}

/// Runs a net-snmp client tool and returns `(exit_code, combined output)`
/// (test_snmpd_integration.py:_run_net_snmp).
async fn run_net_snmp(tool: &str, args: &[&str]) -> (i32, String) {
    let tool = tool.to_string();
    let args = args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>();
    tokio::task::spawn_blocking(move || {
        let output = std::process::Command::new(&tool)
            .args(&args)
            .output()
            .expect("net-snmp tool runs");
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        (
            output.status.code().unwrap_or(1),
            format!("{stdout}{stderr}"),
        )
    })
    .await
    .expect("subprocess task")
}

/// Binds a v2c responder seeded with the integration objects and serves it on
/// a spawned task; returns `(responder, port, serve_handle)`.
async fn spawn_responder_agent() -> (
    Arc<trishul_snmp::responder::SnmpResponder>,
    u16,
    tokio::task::JoinHandle<usize>,
) {
    let responder = Arc::new(
        trishul_snmp::responder::SnmpResponder::bind(trishul_snmp::responder::ResponderConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            communities: Some(vec![b"public".to_vec()]),
            objects: responder_objects(),
            ..Default::default()
        })
        .await
        .expect("bind responder"),
    );
    let port = responder.local_addr().port();
    let serve = {
        let responder = Arc::clone(&responder);
        tokio::spawn(async move { responder.serve(0).await.expect("serve loop") })
    };
    (responder, port, serve)
}

#[tokio::test]
async fn conformance_responder_real_snmpget() {
    if !gate_open() {
        eprintln!("TSNMP_SNMPD unset: skipping responder net-snmp conformance");
        return;
    }
    if !net_snmp_tools_available() {
        eprintln!("conformance: net-snmp client tools not installed; skipping");
        return;
    }
    let (responder, port, serve) = spawn_responder_agent().await;
    let target = format!("127.0.0.1:{port}");

    let (code_descr, out_descr) = run_net_snmp(
        "snmpget",
        &[
            "-v2c",
            "-c",
            "public",
            "-On",
            "-t",
            "1",
            "-r",
            "0",
            &target,
            "1.3.6.1.2.1.1.1.0",
        ],
    )
    .await;
    let (code_uptime, out_uptime) = run_net_snmp(
        "snmpget",
        &[
            "-v2c",
            "-c",
            "public",
            "-On",
            "-t",
            "1",
            "-r",
            "0",
            &target,
            "1.3.6.1.2.1.1.3.0",
        ],
    )
    .await;

    responder.close();
    let _handled = serve.await.expect("serve loop");

    assert_eq!(code_descr, 0, "snmpget sysDescr: {out_descr}");
    assert!(
        out_descr.contains("trishul-responder integration agent"),
        "snmpget output: {out_descr}"
    );
    assert_eq!(code_uptime, 0, "snmpget sysUpTime: {out_uptime}");
    assert!(
        out_uptime.contains("Timeticks: (123456)"),
        "snmpget output: {out_uptime}"
    );
}

#[tokio::test]
async fn conformance_responder_real_snmpwalk() {
    if !gate_open() {
        eprintln!("TSNMP_SNMPD unset: skipping responder net-snmp conformance");
        return;
    }
    if !net_snmp_tools_available() {
        eprintln!("conformance: net-snmp client tools not installed; skipping");
        return;
    }
    let (responder, port, serve) = spawn_responder_agent().await;
    let target = format!("127.0.0.1:{port}");

    let (code, out) = run_net_snmp(
        "snmpwalk",
        &[
            "-v2c",
            "-c",
            "public",
            "-On",
            "-t",
            "1",
            "-r",
            "0",
            &target,
            "1.3.6.1.2.1.2.2.1.1",
        ],
    )
    .await;

    responder.close();
    let _handled = serve.await.expect("serve loop");

    assert_eq!(code, 0, "snmpwalk: {out}");
    assert!(
        out.contains(".1.3.6.1.2.1.2.2.1.1.1 = INTEGER: 1"),
        "snmpwalk output: {out}"
    );
    assert!(
        out.contains(".1.3.6.1.2.1.2.2.1.1.2 = INTEGER: 2"),
        "snmpwalk output: {out}"
    );
}

#[tokio::test]
async fn conformance_responder_real_snmpget_missing_oid() {
    if !gate_open() {
        eprintln!("TSNMP_SNMPD unset: skipping responder net-snmp conformance");
        return;
    }
    if !net_snmp_tools_available() {
        eprintln!("conformance: net-snmp client tools not installed; skipping");
        return;
    }
    let (responder, port, serve) = spawn_responder_agent().await;
    let target = format!("127.0.0.1:{port}");

    let (code, out) = run_net_snmp(
        "snmpget",
        &[
            "-v2c",
            "-c",
            "public",
            "-On",
            "-t",
            "1",
            "-r",
            "0",
            &target,
            "1.3.6.1.2.1.1.1.99",
        ],
    )
    .await;

    responder.close();
    let _handled = serve.await.expect("serve loop");

    // A GET for an absent OID surfaces noSuchObject to a real net-snmp client.
    assert_eq!(code, 0, "snmpget missing OID: {out}");
    assert!(out.contains("No Such Object"), "snmpget output: {out}");
}

/// The coldStart notification OID (1.3.6.1.6.3.1.1.5.1) — the Phase 5 gate's
/// "snmpd coldStart trap + inform fixtures" (test_snmpd_integration.py:74).
const COLDSTART_OID: &str = "1.3.6.1.6.3.1.1.5.1";

/// Starts a dedicated snmpd whose coldStart fires into a bound listener.
///
/// The listener binds *before* the agent starts, so the one-shot coldStart v1
/// trap, v2c trap, and inform are all captured. The listener auto-ACKs the
/// inform (the v2c inform ack path); snmpd would otherwise retry it
/// (test_snmpd_integration.py:369–419).
#[tokio::test]
async fn conformance_snmpd_coldstart_notifications() {
    if !gate_open() {
        eprintln!("TSNMP_SNMPD unset: skipping snmpd coldStart notification suite");
        return;
    }
    let listener = trishul_snmp::notify::listener::NotificationListener::bind(
        trishul_snmp::notify::listener::ListenerConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            communities: Some(vec![b"public".to_vec()]),
            ..Default::default()
        },
    )
    .await
    .expect("bind the notification listener");
    let sink_port = listener.local_addr().port();
    let conf = format!(
        "rocommunity public 127.0.0.1\n\
         agentaddress 127.0.0.1:0\n\
         engineID tsnmpv3notifyengine\n\
         trapsink 127.0.0.1:{sink_port} public\n\
         trap2sink 127.0.0.1:{sink_port} public\n\
         informsink 127.0.0.1:{sink_port} public\n"
    );
    let Some((agent, _workdir)) = spawn_snmpd(&conf, "notify") else {
        eprintln!("conformance: cannot spawn snmpd for coldStart notifications; skipping");
        return;
    };

    // Collect the v1 trap, v2c trap, and inform. Informs are retried by snmpd
    // until the listener's ACK lands, so tolerate duplicates while collecting
    // the three distinct pdu_types.
    let mut events = std::collections::HashMap::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while events.len() < 3 && tokio::time::Instant::now() < deadline {
        let Ok(Some(Ok(event))) =
            tokio::time::timeout(Duration::from_secs(5), listener.recv()).await
        else {
            continue;
        };
        events.insert(event.pdu_type.clone(), event);
    }
    let expected: std::collections::HashSet<&str> = ["trap", "snmpv2-trap", "inform-request"]
        .into_iter()
        .collect();
    let got: std::collections::HashSet<&str> = events.keys().map(String::as_str).collect();
    assert_eq!(
        got, expected,
        "expected coldStart notifications {:?}, got {:?}",
        expected, got
    );

    // v1 Trap-PDU metadata (test_snmpd_integration.py:422–434).
    let v1 = &events["trap"];
    assert_eq!(v1.community.as_deref(), Some(b"public".as_slice()));
    assert_eq!(v1.source_host().as_deref(), Some("127.0.0.1"));
    assert_eq!(v1.generic_trap, Some(0)); // coldStart
    assert!(v1.enterprise.is_some(), "v1 enterprise present");
    assert!(v1.agent_addr.is_some(), "v1 agent_addr present");
    assert!(v1.timestamp.is_some(), "v1 Trap-PDU sysUpTime present");

    // v2c trap (test_snmpd_integration.py:437–445).
    let v2c = &events["snmpv2-trap"];
    assert_eq!(
        v2c.notification_oid.as_ref().map(Oid::display).as_deref(),
        Some(COLDSTART_OID)
    );
    assert!(v2c.uptime.is_some(), "v2c uptime present");

    // Inform, auto-acked (test_snmpd_integration.py:448–463).
    let inform = &events["inform-request"];
    assert!(inform.is_inform());
    assert_eq!(
        inform
            .notification_oid
            .as_ref()
            .map(Oid::display)
            .as_deref(),
        Some(COLDSTART_OID)
    );
    assert!(inform.uptime.is_some(), "inform uptime present");

    drop(listener);
    agent.kill();
    eprintln!("conformance: snmpd coldStart v1/v2c traps + inform passed against live snmpd");
}

// ── v3 conformance helpers ──────────────────────────────────────────────────

fn v3_user(username: &str, auth: AuthProtocol) -> UsmUser {
    v3_authpriv_user(username, auth, PrivProtocol::None_)
}

/// An authPriv user matching the fixture's createUser rows
/// (auth "authpassword12345", priv "privpassword12345").
fn v3_authpriv_user(username: &str, auth: AuthProtocol, priv_protocol: PrivProtocol) -> UsmUser {
    UsmUser::new(
        username.to_string(),
        auth,
        AuthKey::Passphrase(b"authpassword12345".to_vec()),
        priv_protocol,
        PrivKey::Passphrase(b"privpassword12345".to_vec()),
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
        bundle: None,
        timeout: Duration::from_secs(1),
        retries: 1,
        clock: Arc::new(trishul_snmp::time::SystemClock),
        rng: Arc::new(trishul_snmp::time::SystemRng),
    }
}
