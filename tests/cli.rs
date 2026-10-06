//! CLI subprocess suites (← tests/test_cli.py + tests/test_cli_common.py +
//! tests/test_cli_output.py).
//!
//! The reference's 57 monkeypatch/patch sites (grep-verified: 52 lines in
//! test_cli.py, 5 in test_cli_common.py) are replaced by running the built
//! `tsnmp` binary as a subprocess against an in-process responder or listener
//! on a deterministic loopback port, asserting stdout + exit codes. Output
//! string-pinning value is preserved — the pinned reference strings appear
//! verbatim in the assertions below.
//!
//! Test accounting against the reference CLI suites:
//! - test_cli.py: 38 tests → 38 here (1 re-specified: the v3-import-error
//!   case is unrepresentable — the Rust toolkit has no optional v3 extras;
//!   the equivalent surface is a runtime failure path; 1 not-portable: the
//!   pyproject console-scripts pin is Python packaging; the Cargo equivalent
//!   is the single `tsnmp` bin declared in Cargo.toml).
//! - test_cli_common.py: 42 tests → ported as `#[cfg(test)]` unit tests in
//!   src/cli/common.rs (plan.md: "Unit tests for internals live #[cfg(test)]
//!   in their modules") + the pinned validation messages re-asserted through
//!   the binary here.
//! - test_cli_output.py: 13 tests → ported as `#[cfg(test)]` unit tests in
//!   src/cli/output.rs; the JSON/text shapes are additionally exercised
//!   end-to-end through the binary in this suite.
//!
//! ## Subprocess-test design
//!
//! - **Binary path**: `env!("CARGO_BIN_EXE_tsnmp")` — cargo sets it for
//!   integration tests when the crate declares the `tsnmp` bin.
//! - **Port selection**: OS-assigned at bind time (race-free). Every
//!   in-process responder/listener binds port 0 and the test reads the actual
//!   port back via `local_addr().port()` before building the CLI args — there
//!   is no fixed port base and no bind-check-then-rebind probe, so parallel
//!   test binaries can never collide on a deterministic port (a former
//!   fixed-base 21500 collision surfaced in CI and was removed). The one
//!   exception is the `listen` subprocess tests: there the port is a CLI
//!   argument consumed by the child before it binds, and the CLI does not
//!   report its bound address, so the test reserves an OS-assigned port first
//!   (bind 0, read, release) and the child rebinds it — no deterministic
//!   component remains, and the residual release-then-rebind window is
//!   documented on [`reserved_port`].
//! - **Blocking calls**: subprocess spawns run through
//!   `tokio::task::spawn_blocking` so the in-process responder/listener tasks
//!   keep being polled on the executor while the CLI runs.
//! - **Cleanup**: every spawned child is either waited on (count-bounded
//!   listen) or killed + reaped (the interrupt test); responder/listener
//!   teardown is Drop-driven.

mod common;

use std::io::BufRead;
use std::net::Ipv4Addr;
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::agent::{AgentReply, FakeAgent};
use common::fake::CounterRng;
use common::mib::{TempDir, if_mib_payload, notif_mib_payload, write_json};
use common::notify::make_local_engine;
use common::oid;
use common::responder::{local_engine, v3_auth_user};

use trishul_snmp::codec::message::{SnmpMessage, SnmpVersion, encode_message};
use trishul_snmp::codec::pdu::{Pdu, PduKind, V1TrapFields};
use trishul_snmp::notify::listener::{
    ListenerConfig, NotificationListener, V3NotificationListener,
};
use trishul_snmp::responder::sources::ObjectValue;
use trishul_snmp::responder::{ResponderConfig, SnmpResponder};
use trishul_snmp::security::usm::kdf::{AuthProtocol, PrivProtocol};
use trishul_snmp::security::usm::{AuthKey, PrivKey, UsmLocalEngine, UsmModel, UsmUser};
use trishul_snmp::target::Target;
use trishul_snmp::time::SystemClock;
use trishul_snmp::types::oid::Oid;
use trishul_snmp::types::value::SnmpValue;
use trishul_snmp::types::varbind::VarBind;

/// The crate version (Cargo.toml), pinned by the `version` command test.
const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Reserves an OS-assigned loopback port for a server that must be told its
/// port *before* binding — the `listen` subprocess tests, where the CLI
/// consumes `--port` before binding and does not report its bound address.
///
/// The probe binds port 0, reads the assigned port, and releases it; the child
/// process then rebinds it. Unlike the fixed-base machinery this replaces,
/// there is no deterministic cross-process collision (two parallel binaries
/// get disjoint OS-assigned ports), but the release-then-rebind window is
/// inherent to subprocess servers that cannot report their own port.
fn reserved_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("bind port probe")
        .local_addr()
        .expect("probe has an address")
        .port()
}

/// The built binary under test (set by cargo for integration tests).
fn tsnmp_bin() -> &'static str {
    env!("CARGO_BIN_EXE_tsnmp")
}

/// Captured subprocess output.
struct CliOutcome {
    stdout: String,
    stderr: String,
    code: i32,
}

/// Runs the binary with the given args, no extra environment.
fn run(args: &[&str]) -> CliOutcome {
    run_with_env(args, &[])
}

/// Runs the binary with extra environment variables (`--auth-key-env` tests).
fn run_with_env(args: &[&str], env: &[(&str, &str)]) -> CliOutcome {
    let mut command = Command::new(tsnmp_bin());
    command.args(args);
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command.output().expect("spawn tsnmp");
    outcome(output)
}

/// Runs the binary from an async context without blocking the executor: the
/// subprocess blocks a spawn_blocking worker while in-process responder /
/// listener tasks keep running.
async fn run_async(args: &[&str]) -> CliOutcome {
    let args: Vec<String> = args.iter().map(|arg| (*arg).to_string()).collect();
    tokio::task::spawn_blocking(move || run_owned(&args))
        .await
        .expect("blocking task joined")
}

async fn run_async_with_env(args: &[&str], env: &[(&str, &str)]) -> CliOutcome {
    let args: Vec<String> = args.iter().map(|arg| (*arg).to_string()).collect();
    let env: Vec<(String, String)> = env
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect();
    tokio::task::spawn_blocking(move || run_owned_with_env(&args, &env))
        .await
        .expect("blocking task joined")
}

fn run_owned(args: &[String]) -> CliOutcome {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run(&refs)
}

fn run_owned_with_env(args: &[String], env: &[(String, String)]) -> CliOutcome {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let env_refs: Vec<(&str, &str)> = env
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    run_with_env(&refs, &env_refs)
}

fn outcome(output: Output) -> CliOutcome {
    CliOutcome {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        code: output.status.code().unwrap_or(-1),
    }
}

/// Binds a responder on an OS-assigned loopback port and drives its serve loop
/// on the executor. Callers read the actual port back via
/// [`SnmpResponder::local_addr`].
async fn spawn_responder(
    communities: Option<&[&str]>,
    objects: Vec<(Oid, SnmpValue)>,
) -> std::sync::Arc<SnmpResponder> {
    let responder = std::sync::Arc::new(
        SnmpResponder::bind(ResponderConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            communities: communities
                .map(|list| list.iter().map(|s| s.as_bytes().to_vec()).collect()),
            objects: object_inputs(objects),
            ..Default::default()
        })
        .await
        .expect("bind loopback responder"),
    );
    let serve = std::sync::Arc::clone(&responder);
    tokio::spawn(async move {
        serve.serve(0).await.expect("serve loop");
    });
    responder
}

/// Binds a v2c listener on an OS-assigned loopback port. Callers read the
/// actual port back via [`NotificationListener::local_addr`].
async fn spawn_v2c_listener() -> NotificationListener {
    NotificationListener::bind(ListenerConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        ..Default::default()
    })
    .await
    .expect("bind loopback listener")
}

/// The CLI test user shared by the v3 suites (sha256 authNoPriv).
fn cli_v3_auth_user(username: &str) -> UsmUser {
    v3_auth_user(username)
}

/// Writes an IF-MIB bundle to a scratch dir; returns the bundle path and the
/// dir guard (dropped only when the test finishes).
fn write_if_mib_bundle() -> (String, TempDir) {
    let dir = TempDir::new("cli-ifmib");
    write_json(&dir.path().join("IF-MIB.json"), &if_mib_payload(false));
    (
        dir.path().join("IF-MIB.json").to_string_lossy().to_string(),
        dir,
    )
}

/// Writes a NOTIF-MIB bundle (the notification-payload fixture); returns the
/// path and the dir guard.
fn write_notif_mib_bundle() -> (String, TempDir) {
    let dir = TempDir::new("cli-notifmib");
    write_json(&dir.path().join("NOTIF-MIB.json"), &notif_mib_payload());
    (
        dir.path()
            .join("NOTIF-MIB.json")
            .to_string_lossy()
            .to_string(),
        dir,
    )
}

/// Encodes a v2c trap with the standard sysUpTime.0 / snmpTrapOID.0 / extra
/// varbinds.
fn v2c_trap(community: &str, request_id: u32, extra: Option<(Oid, SnmpValue)>) -> Vec<u8> {
    let mut varbinds = vec![
        VarBind::new(oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]), SnmpValue::TimeTicks(55)),
        VarBind::new(
            oid(&[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0]),
            SnmpValue::ObjectIdentifier(oid(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 3])),
        ),
    ];
    if let Some((oid, value)) = extra {
        varbinds.push(VarBind::new(oid, value));
    }
    encode_message(&SnmpMessage {
        version: SnmpVersion::V2c,
        community: community.as_bytes().to_vec(),
        pdu: Pdu {
            kind: PduKind::SnmpV2Trap,
            request_id,
            error_status: 0,
            error_index: 0,
            varbinds,
            v1_trap: None,
        },
    })
    .expect("trap encodes")
}

/// Encodes a v1 Trap-PDU.
fn v1_trap(community: &str) -> Vec<u8> {
    encode_message(&SnmpMessage {
        version: SnmpVersion::V1,
        community: community.as_bytes().to_vec(),
        pdu: Pdu {
            kind: PduKind::Trap,
            request_id: 0,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]),
                SnmpValue::TimeTicks(654321),
            )],
            v1_trap: Some(V1TrapFields {
                enterprise: oid(&[1, 3, 6, 1, 4, 1, 999]),
                agent_addr: Ipv4Addr::new(192, 0, 2, 10),
                generic_trap: 6,
                specific_trap: 0,
                timestamp: 654321,
            }),
        },
    })
    .expect("v1 trap encodes")
}

/// Wraps a v3 trap for `user` with `engine` authoritative.
fn v3_trap(user: &UsmUser, engine: &UsmLocalEngine, request_id: u32) -> Vec<u8> {
    let model = UsmModel::new(
        user.clone(),
        Vec::new(),
        Some(engine.clone()),
        std::sync::Arc::new(SystemClock),
        std::sync::Arc::new(CounterRng::new(7)),
    );
    model
        .wrap_pdu(&Pdu {
            kind: PduKind::SnmpV2Trap,
            request_id,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                SnmpValue::Integer(7),
            )],
            v1_trap: None,
        })
        .expect("v3 trap wraps")
}

/// Sends one UDP datagram to the loopback port.
fn send_udp(port: u16, data: &[u8]) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sender socket");
    socket
        .send_to(data, ("127.0.0.1", port))
        .expect("send datagram");
}

/// A spawned subprocess with line-streaming stdout/stderr pipes.
struct StreamingChild {
    child: Child,
    stdout_rx: std::sync::mpsc::Receiver<String>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl StreamingChild {
    fn spawn(args: &[&str]) -> Self {
        let mut child = Command::new(tsnmp_bin())
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn tsnmp");
        let stdout = child.stdout.take().expect("stdout pipe");
        let (stdout_tx, stdout_rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                let line = line.unwrap_or_default();
                if stdout_tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdout_rx,
            threads: vec![reader],
        }
    }

    /// Waits for the child to exit and returns its exit code, draining the
    /// remaining stdout.
    fn wait(mut self) -> (i32, Vec<String>) {
        let code = self.child.wait().expect("wait tsnmp").code().unwrap_or(-1);
        let mut lines = Vec::new();
        while let Ok(line) = self.stdout_rx.try_recv() {
            lines.push(line);
        }
        self.threads.drain(..).for_each(|thread| {
            let _ = thread.join();
        });
        (code, lines)
    }

    /// Kills the child and reaps it (returns the exit code, or -1 when the
    /// process was terminated by a signal).
    fn kill(mut self) -> (i32, Vec<String>) {
        let _ = self.child.kill();
        self.wait()
    }

    /// Whether the child is still running.
    fn running(&mut self) -> bool {
        self.child.try_wait().expect("try_wait").is_none()
    }

    /// Waits up to `timeout` for one stdout line.
    fn next_line(&self, timeout: Duration) -> Option<String> {
        self.stdout_rx.recv_timeout(timeout).ok()
    }
}

impl Drop for StreamingChild {
    fn drop(&mut self) {
        // Kill-on-drop: a failed assertion between spawn and the explicit
        // kill()/wait() must not leak the tsnmp process.
        if self.child.try_wait().map(|s| s.is_none()).unwrap_or(false) {
            let _ = self.child.kill();
        }
    }
}

/// Drives a count-bounded listen subprocess: repeatedly sends `send` until
/// the child exits (it exits after printing the whole event), then returns
/// its exit code and every stdout line.
fn send_until_exit(child: StreamingChild, send: impl Fn()) -> (i32, Vec<String>) {
    let mut child = child;
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.running() {
        if Instant::now() > deadline {
            let (_code, lines) = child.kill();
            panic!("listen did not exit within the deadline; stdout: {lines:?}");
        }
        send();
        std::thread::sleep(Duration::from_millis(25));
    }
    child.wait()
}

/// Drives a listen subprocess: repeatedly sends `send` until a stdout line
/// appears (the listener may not be bound yet), then returns the line.
fn wait_for_event_line(child: &StreamingChild, send: impl Fn()) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(line) = child.next_line(Duration::from_millis(25)) {
            return line;
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for the listen event line");
        }
        send();
    }
}

// ── version / usage ─────────────────────────────────────────────────────────

#[test]
fn cli_version_prints_version_and_exits_zero() {
    let outcome = run(&["version"]);
    assert_eq!(outcome.code, 0);
    assert_eq!(outcome.stdout.trim(), CRATE_VERSION);
    assert_eq!(outcome.stderr, "");
}

#[test]
fn cli_unknown_subcommand_exits_2() {
    let outcome = run(&["not-a-command"]);
    assert_eq!(outcome.code, 2);
    assert!(
        outcome.stderr.contains("unrecognized subcommand"),
        "{:?}",
        outcome.stderr
    );
}

#[test]
fn cli_missing_required_args_exit_2() {
    let get = run(&["get"]);
    assert_eq!(get.code, 2);
    assert!(get.stderr.contains("--host"), "{:?}", get.stderr);

    let translate = run(&["translate", "1.3.6.1.2.1.2.2"]);
    assert_eq!(translate.code, 2);
    assert!(
        translate.stderr.contains("--bundle"),
        "{:?}",
        translate.stderr
    );
}

#[test]
fn cli_invalid_snmp_version_choice_exits_2() {
    let outcome = run(&[
        "get",
        "--host",
        "127.0.0.1",
        "--snmp-version",
        "4",
        "1.3.6.1.2.1.1.3.0",
    ]);
    assert_eq!(outcome.code, 2);
}

// ── translate ───────────────────────────────────────────────────────────────

#[test]
fn cli_translate_symbolic_to_numeric() {
    let (bundle, _dir) = write_if_mib_bundle();
    let outcome = run(&["translate", "--bundle", &bundle, "IF-MIB::ifDescr.7"]);
    assert_eq!(outcome.code, 0);
    assert_eq!(outcome.stdout.trim(), "1.3.6.1.2.1.2.2.1.2.7");
}

#[test]
fn cli_translate_numeric_to_symbolic() {
    let (bundle, _dir) = write_if_mib_bundle();
    let outcome = run(&["translate", "--bundle", &bundle, "1.3.6.1.2.1.2.2.1.2.7"]);
    assert_eq!(outcome.code, 0);
    assert_eq!(outcome.stdout.trim(), "IF-MIB::ifDescr.7");
}

#[test]
fn cli_translate_unknown_symbol_exits_1() {
    let (bundle, _dir) = write_if_mib_bundle();
    let outcome = run(&["translate", "--bundle", &bundle, "NOPE-MIB::missing"]);
    assert_eq!(outcome.code, 1);
    assert!(
        outcome.stderr.starts_with("tsnmp: "),
        "{:?}",
        outcome.stderr
    );
}

// ── get ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn cli_get_renders_text() {
    let responder = spawn_responder(
        Some(&["public"]),
        vec![(oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]), SnmpValue::TimeTicks(123))],
    )
    .await;
    let port = responder.local_addr().port();

    let outcome = run_async(&[
        "get",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "1.3.6.1.2.1.1.3.0",
    ])
    .await;
    assert_eq!(outcome.code, 0);
    assert_eq!(outcome.stdout.trim(), "1.3.6.1.2.1.1.3.0 = 123");
    assert_eq!(outcome.stderr, "");
}

#[tokio::test]
async fn cli_get_renders_text_and_uses_bundle() {
    // ← test_cli_get_renders_text_and_uses_bundle: pinned output string.
    let (bundle, _dir) = write_if_mib_bundle();
    let responder = spawn_responder(
        Some(&["public"]),
        vec![(
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1]),
            SnmpValue::OctetString(b"eth0".to_vec()),
        )],
    )
    .await;
    let port = responder.local_addr().port();

    let outcome = run_async(&[
        "get",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--bundle",
        &bundle,
        "IF-MIB::ifDescr.1",
    ])
    .await;
    assert_eq!(outcome.code, 0);
    assert_eq!(outcome.stdout.trim(), "IF-MIB::ifDescr.1 = eth0");
}

#[tokio::test]
async fn cli_get_numeric_flag_forces_numeric_oids() {
    let (bundle, _dir) = write_if_mib_bundle();
    let responder = spawn_responder(
        Some(&["public"]),
        vec![(
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1]),
            SnmpValue::OctetString(b"eth0".to_vec()),
        )],
    )
    .await;
    let port = responder.local_addr().port();

    let outcome = run_async(&[
        "get",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--bundle",
        &bundle,
        "--numeric",
        "IF-MIB::ifDescr.1",
    ])
    .await;
    assert_eq!(outcome.code, 0);
    assert_eq!(outcome.stdout.trim(), "1.3.6.1.2.1.2.2.1.2.1 = eth0");
}

#[tokio::test]
async fn cli_get_json_output() {
    let responder = spawn_responder(
        None,
        vec![(oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]), SnmpValue::TimeTicks(55))],
    )
    .await;
    let port = responder.local_addr().port();

    let outcome = run_async(&[
        "get",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--json",
        "1.3.6.1.2.1.1.3.0",
    ])
    .await;
    assert_eq!(outcome.code, 0);
    let payload: serde_json::Value = serde_json::from_str(&outcome.stdout).expect("valid JSON");
    assert_eq!(payload["error_status"], "no_error");
    assert_eq!(payload["error_status_code"], 0);
    assert_eq!(payload["error_index"], 0);
    assert_eq!(payload["varbinds"][0]["oid"], "1.3.6.1.2.1.1.3.0");
    assert_eq!(payload["varbinds"][0]["value_type"], "timeticks");
    assert_eq!(payload["varbinds"][0]["display_value"], "55");
}

#[tokio::test]
async fn cli_get_v1_uses_v1_community() {
    let responder = spawn_responder(
        Some(&["public"]),
        vec![(
            oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
            SnmpValue::OctetString(b"v1".to_vec()),
        )],
    )
    .await;
    let port = responder.local_addr().port();

    let outcome = run_async(&[
        "get",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--snmp-version",
        "1",
        "1.3.6.1.2.1.1.1.0",
    ])
    .await;
    assert_eq!(outcome.code, 0);
    assert_eq!(outcome.stdout.trim(), "1.3.6.1.2.1.1.1.0 = v1");
}

#[tokio::test]
async fn cli_get_v3_authnopriv_discovers_and_gets() {
    // ← test_cli_get_v3_uses_v3manager: the constructor wiring is replaced by
    // the real discovery + request flow against the responder's v3 path.
    let responder = spawn_responder_v3(
        vec![(oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]), SnmpValue::TimeTicks(7))],
        cli_v3_auth_user("alice"),
    )
    .await;
    let port = responder.local_addr().port();

    let outcome = run_async(&[
        "get",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--snmp-version",
        "3",
        "--username",
        "alice",
        "--auth-protocol",
        "sha256",
        "--auth-key",
        "authpassword12345",
        "1.3.6.1.2.1.1.3.0",
    ])
    .await;
    assert_eq!(outcome.code, 0, "stderr: {:?}", outcome.stderr);
    assert_eq!(outcome.stdout.trim(), "1.3.6.1.2.1.1.3.0 = 7");
}

#[tokio::test]
async fn cli_get_v3_authkey_env_reads_the_named_variable() {
    // ← test_parse_cli_security_builds_v3_authpriv_from_env: the user names an
    // environment variable and the CLI reads the passphrase from it.
    let responder = spawn_responder_v3(
        vec![(oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]), SnmpValue::TimeTicks(3))],
        cli_v3_auth_user("alice"),
    )
    .await;
    let port = responder.local_addr().port();

    let outcome = run_async_with_env(
        &[
            "get",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--snmp-version",
            "3",
            "--username",
            "alice",
            "--auth-protocol",
            "sha256",
            "--auth-key-env",
            "TSNMP_AUTH",
            "1.3.6.1.2.1.1.3.0",
        ],
        &[("TSNMP_AUTH", "authpassword12345")],
    )
    .await;
    assert_eq!(outcome.code, 0, "stderr: {:?}", outcome.stderr);
    assert_eq!(outcome.stdout.trim(), "1.3.6.1.2.1.1.3.0 = 3");
}

#[tokio::test]
async fn cli_get_v3_accepts_sha2_and_reeder_protocols() {
    // ← test_cli_get_v3_accepts_sha2_and_reeder_protocols: sha512 + 3des-ede
    // end-to-end through the responder.
    let responder = spawn_responder_v3(
        vec![(oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]), SnmpValue::TimeTicks(4))],
        UsmUser::new(
            "alice".to_string(),
            AuthProtocol::Sha512,
            AuthKey::Passphrase(b"authpassword12345".to_vec()),
            PrivProtocol::Des3Ede,
            PrivKey::Passphrase(b"privpassword12345".to_vec()),
        )
        .expect("valid v3 user"),
    )
    .await;
    let port = responder.local_addr().port();

    let outcome = run_async(&[
        "get",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--snmp-version",
        "3",
        "--username",
        "alice",
        "--auth-protocol",
        "sha512",
        "--auth-key",
        "authpassword12345",
        "--priv-protocol",
        "3des-ede",
        "--priv-key",
        "privpassword12345",
        "1.3.6.1.2.1.1.3.0",
    ])
    .await;
    assert_eq!(outcome.code, 0, "stderr: {:?}", outcome.stderr);
    assert_eq!(outcome.stdout.trim(), "1.3.6.1.2.1.1.3.0 = 4");
}

#[tokio::test]
async fn cli_get_timeout_failure_exits_1() {
    // A bound-but-silent socket: the request retries once and fails with the
    // timeout error (an unbound local port would surface ICMP ECONNREFUSED
    // instead — Linux behavior).
    let (_agent, port) = common::agent::silent_agent().await;
    let outcome = run_async(&[
        "get",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--timeout",
        "0.1",
        "--retries",
        "0",
        "1.3.6.1.2.1.1.3.0",
    ])
    .await;
    assert_eq!(outcome.code, 1);
    assert_eq!(outcome.stdout, "");
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: request timed out after 1 attempt(s)"
    );
}

#[tokio::test]
async fn cli_get_symbolic_target_without_bundle_exits_1() {
    // No socket is bound in this test: target normalization fails before any
    // connect, so the port is a neutral literal that is never reached.
    let outcome = run_async(&[
        "get",
        "--host",
        "127.0.0.1",
        "--port",
        "161",
        "IF-MIB::ifDescr.1",
    ])
    .await;
    assert_eq!(outcome.code, 1);
    assert!(
        outcome
            .stderr
            .contains("Symbolic target requires a loaded bundle"),
        "{:?}",
        outcome.stderr
    );
}

// ── getnext ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn cli_getnext_returns_successor() {
    let responder = spawn_responder(
        None,
        vec![
            (
                oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1]),
                SnmpValue::Integer(1),
            ),
            (
                oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1]),
                SnmpValue::OctetString(b"eth0".to_vec()),
            ),
        ],
    )
    .await;
    let port = responder.local_addr().port();

    let outcome = run_async(&[
        "getnext",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "1.3.6.1.2.1.2.2",
    ])
    .await;
    assert_eq!(outcome.code, 0);
    assert_eq!(outcome.stdout.trim(), "1.3.6.1.2.1.2.2.1.1.1 = 1");
}

// ── getbulk ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn cli_getbulk_json_output() {
    // ← test_cli_getbulk_json_output: pinned payload fields.
    let responder = spawn_responder(
        None,
        vec![(
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1]),
            SnmpValue::OctetString(b"eth0".to_vec()),
        )],
    )
    .await;
    let port = responder.local_addr().port();

    let outcome = run_async(&[
        "getbulk",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--json",
        "--non-repeaters",
        "1",
        "--max-repetitions",
        "4",
        "1.3.6.1.2.1.2.2",
    ])
    .await;
    assert_eq!(outcome.code, 0);
    let payload: serde_json::Value = serde_json::from_str(&outcome.stdout).expect("valid JSON");
    assert_eq!(payload["error_status"], "no_error");
    assert_eq!(payload["varbinds"][0]["oid"], "1.3.6.1.2.1.2.2.1.2.1");
    assert_eq!(payload["varbinds"][0]["display_value"], "eth0");
}

#[tokio::test]
async fn cli_getbulk_text_output() {
    let responder = spawn_responder(
        None,
        vec![(
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1]),
            SnmpValue::OctetString(b"eth0".to_vec()),
        )],
    )
    .await;
    let port = responder.local_addr().port();

    let outcome = run_async(&[
        "getbulk",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "1.3.6.1.2.1.2.2",
    ])
    .await;
    assert_eq!(outcome.code, 0);
    // The responder's GETBULK expansion emits one terminal endOfMibView per
    // exhausted column (server.py:267–306), which the CLI renders.
    assert_eq!(
        outcome.stdout.trim().split('\n').collect::<Vec<_>>(),
        [
            "1.3.6.1.2.1.2.2.1.2.1 = eth0",
            "1.3.6.1.2.1.2.2.1.2.1 = endOfMibView",
        ]
    );
}

// ── walk / bulkwalk ─────────────────────────────────────────────────────────

/// The standard walk table: three objects under 1.3.6.1.2.1.2.2.1.
fn walk_objects() -> Vec<(Oid, SnmpValue)> {
    vec![
        (
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1]),
            SnmpValue::Integer(1),
        ),
        (
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1]),
            SnmpValue::OctetString(b"eth0".to_vec()),
        ),
        (
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 2]),
            SnmpValue::OctetString(b"eth1".to_vec()),
        ),
    ]
}

fn assert_walk_lines(outcome: &CliOutcome) {
    assert_eq!(outcome.code, 0, "stderr: {:?}", outcome.stderr);
    assert_eq!(
        outcome.stdout.trim().split('\n').collect::<Vec<_>>(),
        [
            "1.3.6.1.2.1.2.2.1.1.1 = 1",
            "1.3.6.1.2.1.2.2.1.2.1 = eth0",
            "1.3.6.1.2.1.2.2.1.2.2 = eth1",
        ]
    );
}

#[tokio::test]
async fn cli_walk_no_bulk_uses_getnext() {
    // ← test_cli_walk_and_bulkwalk_flags: `--no-bulk` flips to GETNET.
    let responder = spawn_responder(None, walk_objects()).await;
    let port = responder.local_addr().port();

    let outcome = run_async(&[
        "walk",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--no-bulk",
        "1.3.6.1.2.1.2.2.1",
    ])
    .await;
    assert_walk_lines(&outcome);
}

#[tokio::test]
async fn cli_walk_bulk_default() {
    let responder = spawn_responder(None, walk_objects()).await;
    let port = responder.local_addr().port();

    let outcome = run_async(&[
        "walk",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "1.3.6.1.2.1.2.2.1",
    ])
    .await;
    assert_walk_lines(&outcome);
}

#[tokio::test]
async fn cli_walk_json_output() {
    let responder = spawn_responder(None, walk_objects()).await;
    let port = responder.local_addr().port();

    let outcome = run_async(&[
        "walk",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--json",
        "1.3.6.1.2.1.2.2.1",
    ])
    .await;
    assert_eq!(outcome.code, 0);
    let payload: serde_json::Value = serde_json::from_str(&outcome.stdout).expect("valid JSON");
    let varbinds = payload["varbinds"].as_array().expect("varbinds array");
    assert_eq!(varbinds.len(), 3);
    assert_eq!(varbinds[1]["oid"], "1.3.6.1.2.1.2.2.1.2.1");
    assert_eq!(varbinds[1]["display_value"], "eth0");
}

#[tokio::test]
async fn cli_bulkwalk_max_repetitions() {
    // ← test_cli_walk_and_bulkwalk_flags: `--max-repetitions` threads through.
    let responder = spawn_responder(None, walk_objects()).await;
    let port = responder.local_addr().port();

    let outcome = run_async(&[
        "bulkwalk",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--max-repetitions",
        "6",
        "1.3.6.1.2.1.2.2.1",
    ])
    .await;
    assert_walk_lines(&outcome);
}

#[tokio::test]
async fn cli_walk_v1_downgrades_to_getnext() {
    let responder = spawn_responder(Some(&["public"]), walk_objects()).await;
    let port = responder.local_addr().port();

    let outcome = run_async(&[
        "walk",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--snmp-version",
        "1",
        "1.3.6.1.2.1.2.2.1",
    ])
    .await;
    assert_walk_lines(&outcome);
}

#[tokio::test]
async fn cli_walk_surfaces_walk_error_exit_code() {
    // ← test_cli_walk_surfaces_walk_error_exit_code: pinned message.
    let (agent, port) = FakeAgent::spawn(Arc::new(|_oid, _kind| AgentReply::error(1, 0))).await;
    let _ = agent;

    let outcome = run_async(&[
        "walk",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--no-bulk",
        "1.3.6.1.2.1.2.2",
    ])
    .await;
    assert_eq!(outcome.code, 1);
    assert_eq!(outcome.stdout, "");
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: walk aborted: agent reported too_big (error-index 0)"
    );
}

#[tokio::test]
async fn cli_bulkwalk_surfaces_walk_error_exit_code() {
    // ← test_cli_bulkwalk_surfaces_walk_error_exit_code: pinned message.
    let (_agent, port) = FakeAgent::spawn(Arc::new(|_oid, _kind| AgentReply::error(5, 1))).await;

    let outcome = run_async(&[
        "bulkwalk",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "1.3.6.1.2.1.2.2",
    ])
    .await;
    assert_eq!(outcome.code, 1);
    assert_eq!(outcome.stdout, "");
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: walk aborted: agent reported gen_err (error-index 1)"
    );
}

// ── trap ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn cli_trap_v2c_sends_and_prints_request_id() {
    let listener = spawn_v2c_listener().await;
    let port = listener.local_addr().port();

    let outcome = run_async(&[
        "trap",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--varbind",
        "1.3.6.1.2.1.2.2.1.1.7=int:7",
        "1.3.6.1.6.3.1.1.5.3",
    ])
    .await;

    let event = listener
        .recv()
        .await
        .expect("channel open")
        .expect("decoded event");
    assert_eq!(outcome.code, 0, "stderr: {:?}", outcome.stderr);
    let request_id: u32 = outcome
        .stdout
        .trim()
        .strip_prefix("request_id=")
        .expect("request_id line")
        .parse()
        .expect("numeric request id");
    assert_eq!(event.request_id, request_id);
    assert_eq!(event.pdu_type, "snmpv2-trap");
    assert_eq!(event.community.as_deref(), Some(&b"public"[..]));
    assert_eq!(
        event.notification_oid,
        Some(oid(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 3]))
    );
    assert_eq!(event.uptime, Some(0));
    let extras: Vec<&VarBind> = event
        .varbinds
        .iter()
        .filter(|varbind| varbind.oid != oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]))
        .filter(|varbind| varbind.oid != oid(&[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0]))
        .collect();
    assert_eq!(extras.len(), 1);
    assert_eq!(extras[0].value, SnmpValue::Integer(7));
}

#[tokio::test]
async fn cli_trap_parses_typed_varbinds() {
    // ← test_cli_trap_parses_typed_varbinds: OID=TYPE:VALUE parsing, incl.
    // symbolic `oid:` resolution through the bundle.
    let (bundle, _dir) = write_notif_mib_bundle();
    let listener = spawn_v2c_listener().await;
    let port = listener.local_addr().port();

    let outcome = run_async(&[
        "trap",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--bundle",
        &bundle,
        "--uptime",
        "55",
        "--varbind",
        "1.3.6.1.6.3.1.1.4.1.0=oid:NOTIF-MIB::linkDown",
        "--varbind",
        "NOTIF-MIB::ifIndex.7=int:7",
        "NOTIF-MIB::linkDown",
    ])
    .await;
    assert_eq!(outcome.code, 0, "stderr: {:?}", outcome.stderr);
    assert!(
        outcome.stdout.trim().starts_with("request_id="),
        "{:?}",
        outcome.stdout
    );

    let event = listener
        .recv()
        .await
        .expect("channel open")
        .expect("decoded event");
    assert_eq!(event.uptime, Some(55));
    assert_eq!(
        event.notification_oid,
        Some(oid(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 3]))
    );
    let extras: Vec<&VarBind> = event
        .varbinds
        .iter()
        .filter(|varbind| varbind.oid != oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]))
        .filter(|varbind| varbind.oid != oid(&[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0]))
        .collect();
    assert_eq!(extras.len(), 1);
    assert_eq!(extras[0].oid, oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 7]));
    assert_eq!(extras[0].value, SnmpValue::Integer(7));
}

#[tokio::test]
async fn cli_trap_v3_requires_local_engine() {
    let outcome = run_async(&[
        "trap",
        "--host",
        "127.0.0.1",
        "--snmp-version",
        "3",
        "--username",
        "alice",
        "1.3.6.1.6.3.1.1.5.3",
    ])
    .await;
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: SNMPv3 trap requires --local-engine-id, --local-engine-boots, and --local-engine-time"
    );
}

#[tokio::test]
async fn cli_trap_v3_sends_with_local_engine() {
    // ← test_cli_trap_v3_routes_to_v3notifier: the local engine state reaches
    // the wire (the listener reports the authoritative engine id).
    let user = cli_v3_auth_user("alice");
    let listener = V3NotificationListener::bind(
        ListenerConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            ..Default::default()
        },
        user,
        make_local_engine(0x41, 7, 100),
    )
    .await
    .expect("bind v3 listener");
    let port = listener.local_addr().port();

    let outcome = run_async(&[
        "trap",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--snmp-version",
        "3",
        "--username",
        "alice",
        "--auth-protocol",
        "sha256",
        "--auth-key",
        "authpassword12345",
        "--local-engine-id",
        "80:00:01:02:03:41:41:41:41:41:41:41:41:41:41:41:41",
        "--local-engine-boots",
        "7",
        "--local-engine-time",
        "100",
        "1.3.6.1.6.3.1.1.5.3",
    ])
    .await;
    assert_eq!(outcome.code, 0, "stderr: {:?}", outcome.stderr);
    assert!(
        outcome.stdout.trim().starts_with("request_id="),
        "{:?}",
        outcome.stdout
    );

    let event = listener
        .recv()
        .await
        .expect("channel open")
        .expect("decoded event");
    assert_eq!(event.username.as_deref(), Some("alice"));
    assert_eq!(
        event.authoritative_engine_id.as_deref(),
        Some(make_local_engine(0x41, 7, 100).engine_id.as_slice())
    );
}

#[tokio::test]
async fn cli_trap_v1_routes_full_fields() {
    // ← test_cli_trap_v1_routes_to_v1notifier: all Trap-PDU fields reach the
    // wire; stdout is the timestamp.
    let listener = spawn_v2c_listener().await;
    let port = listener.local_addr().port();

    let outcome = run_async(&[
        "trap",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--snmp-version",
        "1",
        "--enterprise",
        "1.3.6.1.4.1.999",
        "--agent-addr",
        "192.0.2.10",
        "--generic-trap",
        "1",
        "--specific-trap",
        "5",
        "--timestamp",
        "123456",
        "--varbind",
        "1.3.6.1.2.1.2.2.1.1.7=int:7",
    ])
    .await;
    assert_eq!(outcome.code, 0, "stderr: {:?}", outcome.stderr);
    assert_eq!(outcome.stdout.trim(), "timestamp=123456");

    let event = listener
        .recv()
        .await
        .expect("channel open")
        .expect("decoded event");
    assert_eq!(event.pdu_type, "trap");
    assert_eq!(event.enterprise, Some(oid(&[1, 3, 6, 1, 4, 1, 999])));
    assert_eq!(event.agent_addr.as_deref(), Some("192.0.2.10"));
    assert_eq!(event.generic_trap, Some(1));
    assert_eq!(event.specific_trap, Some(5));
    assert_eq!(event.timestamp, Some(123456));
}

#[tokio::test]
async fn cli_trap_v1_applies_default_trap_fields() {
    // ← test_cli_trap_v1_applies_default_trap_fields.
    let listener = spawn_v2c_listener().await;
    let port = listener.local_addr().port();

    let outcome = run_async(&[
        "trap",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--snmp-version",
        "1",
        "--enterprise",
        "1.3.6.1.4.1.999",
    ])
    .await;
    assert_eq!(outcome.code, 0);
    assert_eq!(outcome.stdout.trim(), "timestamp=0");

    let event = listener
        .recv()
        .await
        .expect("channel open")
        .expect("decoded event");
    assert_eq!(event.agent_addr.as_deref(), Some("0.0.0.0"));
    assert_eq!(event.generic_trap, Some(6));
    assert_eq!(event.specific_trap, Some(0));
    assert_eq!(event.timestamp, Some(0));
}

#[test]
fn cli_trap_v1_requires_enterprise() {
    let outcome = run(&["trap", "--host", "127.0.0.1", "--snmp-version", "1"]);
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: --enterprise is required with --snmp-version 1"
    );
}

#[test]
fn cli_trap_v1_rejects_uptime() {
    let outcome = run(&[
        "trap",
        "--host",
        "127.0.0.1",
        "--snmp-version",
        "1",
        "--uptime",
        "55",
        "--enterprise",
        "1.3.6.1.4.1.999",
    ]);
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: --uptime is invalid with --snmp-version 1; use --timestamp"
    );
}

#[test]
fn cli_trap_v1_rejects_positional_target() {
    let outcome = run(&[
        "trap",
        "--host",
        "127.0.0.1",
        "--snmp-version",
        "1",
        "--enterprise",
        "1.3.6.1.4.1.999",
        "1.3.6.1.6.3.1.1.5.3",
    ]);
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: a positional notification OID is invalid with --snmp-version 1; use --enterprise"
    );
}

#[test]
fn cli_trap_v2c_rejects_enterprise() {
    let outcome = run(&[
        "trap",
        "--host",
        "127.0.0.1",
        "--enterprise",
        "1.3.6.1.4.1.999",
        "1.3.6.1.6.3.1.1.5.3",
    ]);
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: --enterprise requires --snmp-version 1"
    );
}

#[test]
fn cli_trap_requires_notification_target() {
    let outcome = run(&["trap", "--host", "127.0.0.1"]);
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: trap requires a notification OID target"
    );
}

#[test]
fn cli_trap_rejects_malformed_varbind() {
    let outcome = run(&[
        "trap",
        "--host",
        "127.0.0.1",
        "--varbind",
        "not-a-varbind",
        "1.3.6.1.6.3.1.1.5.3",
    ]);
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: Varbind must use OID=TYPE:VALUE form: not-a-varbind"
    );
}

#[test]
fn cli_trap_rejects_unsupported_value_type() {
    let outcome = run(&[
        "trap",
        "--host",
        "127.0.0.1",
        "--varbind",
        "1.3.6.1.6.3.1.1.5.3=unknown:1",
        "1.3.6.1.6.3.1.1.5.3",
    ]);
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: Unsupported value type: unknown"
    );
}

// ── inform ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn cli_inform_v2c_renders_response() {
    // ← test_cli_inform_renders_response: the listener acks; the CLI prints
    // the response varbinds.
    let listener = spawn_v2c_listener().await;
    let port = listener.local_addr().port();

    let outcome = run_async(&[
        "inform",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--varbind",
        "1.3.6.1.2.1.2.2.1.1.7=int:7",
        "1.3.6.1.6.3.1.1.5.3",
    ])
    .await;
    assert_eq!(outcome.code, 0, "stderr: {:?}", outcome.stderr);
    assert!(
        outcome.stdout.contains("1.3.6.1.2.1.2.2.1.1.7 = 7"),
        "{:?}",
        outcome.stdout
    );

    let event = listener
        .recv()
        .await
        .expect("channel open")
        .expect("decoded event");
    assert_eq!(event.pdu_type, "inform-request");
}

#[tokio::test]
async fn cli_inform_v3_discovers_and_acks() {
    // ← test_cli_inform_v3_routes_to_v3notifier: the v3 listener answers the
    // discovery probe and acks the inform.
    let user = cli_v3_auth_user("alice");
    let listener = V3NotificationListener::bind(
        ListenerConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            ..Default::default()
        },
        user,
        make_local_engine(0x41, 7, 111),
    )
    .await
    .expect("bind v3 listener");
    let port = listener.local_addr().port();

    let outcome = run_async(&[
        "inform",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--snmp-version",
        "3",
        "--username",
        "alice",
        "--auth-protocol",
        "sha256",
        "--auth-key",
        "authpassword12345",
        "1.3.6.1.6.3.1.1.5.3",
    ])
    .await;
    assert_eq!(outcome.code, 0, "stderr: {:?}", outcome.stderr);
    assert!(
        outcome
            .stdout
            .contains("1.3.6.1.6.3.1.1.4.1.0 = 1.3.6.1.6.3.1.1.5.3"),
        "{:?}",
        outcome.stdout
    );

    let event = listener
        .recv()
        .await
        .expect("channel open")
        .expect("decoded event");
    assert_eq!(event.pdu_type, "inform-request");
    assert_eq!(event.username.as_deref(), Some("alice"));
}

#[test]
fn cli_inform_v1_fails_fast() {
    let outcome = run(&[
        "inform",
        "--host",
        "127.0.0.1",
        "--snmp-version",
        "1",
        "1.3.6.1.6.3.1.1.5.3",
    ]);
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: SNMPv1 has no inform operations — use trap"
    );
}

#[test]
fn cli_inform_requires_notification_target() {
    let outcome = run(&["inform", "--host", "127.0.0.1"]);
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: inform requires a notification OID target"
    );
}

#[test]
fn cli_inform_rejects_local_engine_flags() {
    let outcome = run(&[
        "inform",
        "--host",
        "127.0.0.1",
        "--snmp-version",
        "3",
        "--username",
        "alice",
        "--local-engine-id",
        "8000010203",
        "--local-engine-boots",
        "1",
        "--local-engine-time",
        "2",
        "1.3.6.1.6.3.1.1.5.3",
    ]);
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: --local-engine-* options are only valid for SNMPv3 trap"
    );
}

// ── listen ──────────────────────────────────────────────────────────────────

#[test]
fn cli_listen_receives_configured_count() {
    // ← test_cli_listen_receives_configured_count: bounded by --count 1. The
    // event renders across multiple lines; keep sending until the process
    // exits, then assert the joined output.
    let port = reserved_port();
    let child = StreamingChild::spawn(&[
        "listen",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--community",
        "public",
        "--count",
        "1",
    ]);
    let (code, lines) = send_until_exit(child, || send_udp(port, &v2c_trap("public", 7, None)));
    assert_eq!(code, 0);
    let joined = lines.join("\n");
    assert!(
        joined.contains("notification=1.3.6.1.6.3.1.1.5.3 uptime=55"),
        "{joined}"
    );
    assert_eq!(lines.len(), 4, "header + detail + 2 varbinds: {joined}");
}

#[test]
fn cli_listen_v1_uses_community_listener() {
    // ← test_cli_listen_v1_uses_community_listener: `--snmp-version 1` routes
    // to the community listener and v1 Trap-PDU metadata renders.
    let port = reserved_port();
    let child = StreamingChild::spawn(&[
        "listen",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--snmp-version",
        "1",
        "--community",
        "public",
        "--count",
        "1",
    ]);
    let (code, lines) = send_until_exit(child, || send_udp(port, &v1_trap("public")));
    assert_eq!(code, 0);
    let joined = lines.join("\n");
    assert!(
        joined.contains("type=trap request_id=0 community=public"),
        "{joined}"
    );
    assert!(
        joined.contains("enterprise=1.3.6.1.4.1.999 agent-addr=192.0.2.10 generic-trap=6 specific-trap=0 timestamp=654321"),
        "{joined}"
    );
    assert!(joined.contains("uptime=654321"), "{joined}");
}

#[test]
fn cli_listen_v3_receives_authnopriv_trap() {
    // ← test_cli_listen_v3_uses_v3_listener: the v3 listener surfaces the
    // user/level header.
    let user = cli_v3_auth_user("alice");
    let port = reserved_port();
    let child = StreamingChild::spawn(&[
        "listen",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--snmp-version",
        "3",
        "--username",
        "alice",
        "--auth-protocol",
        "sha256",
        "--auth-key",
        "authpassword12345",
        "--local-engine-id",
        "80:00:01:02:03:41:41:41:41:41:41:41:41:41:41:41:41",
        "--local-engine-boots",
        "7",
        "--local-engine-time",
        "100",
        "--count",
        "1",
    ]);
    let sender_engine = make_local_engine(0x42, 7, 111);
    let (code, lines) =
        send_until_exit(child, || send_udp(port, &v3_trap(&user, &sender_engine, 3)));
    assert_eq!(code, 0, "stderr not shown; stdout: {:?}", lines);
    let joined = lines.join("\n");
    assert!(
        joined.contains("type=snmpv2-trap request_id=3 user=alice level=authNoPriv"),
        "{joined}"
    );
}

#[test]
fn cli_listen_runs_until_interrupted() {
    // Bounded-runtime test of the run-until-interrupted path: spawn without
    // --count, receive one event, terminate the process.
    let port = reserved_port();
    let mut child =
        StreamingChild::spawn(&["listen", "--host", "127.0.0.1", "--port", &port.to_string()]);
    let line = wait_for_event_line(&child, || send_udp(port, &v2c_trap("public", 9, None)));
    assert!(line.contains("type=snmpv2-trap"), "{line}");
    assert!(
        child.running(),
        "listen without --count must keep running until interrupted"
    );
    let (code, _) = child.kill();
    assert_ne!(code, 0, "killed listen must not report a clean exit");
}

#[test]
fn cli_listen_json_emits_one_object_per_line() {
    // ← test_cli_listen_json_emits_one_object_per_line.
    let port = reserved_port();
    let child = StreamingChild::spawn(&[
        "listen",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--json",
        "--count",
        "1",
    ]);
    let (code, lines) = send_until_exit(child, || send_udp(port, &v2c_trap("public", 5, None)));
    assert_eq!(code, 0);
    assert_eq!(lines.len(), 1, "one JSON object per line: {:?}", lines);
    let payload: serde_json::Value = serde_json::from_str(&lines[0]).expect("valid JSON");
    assert_eq!(payload["pdu_type"], "snmpv2-trap");
    assert_eq!(payload["request_id"], 5);
}

#[test]
fn cli_listen_rejects_negative_count() {
    let outcome = run(&["listen", "--count", "-1"]);
    assert_eq!(outcome.code, 1);
    assert_eq!(outcome.stderr.trim(), "tsnmp: --count cannot be negative");
}

#[test]
fn cli_listen_rejects_community_with_v3() {
    let outcome = run(&[
        "listen",
        "--snmp-version",
        "3",
        "--username",
        "alice",
        "--community",
        "public",
    ]);
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: --community is invalid with --snmp-version 3"
    );
}

#[test]
fn cli_listen_v3_requires_local_engine() {
    let outcome = run(&["listen", "--snmp-version", "3", "--username", "alice"]);
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: SNMPv3 listener requires --local-engine-id, --local-engine-boots, and --local-engine-time"
    );
}

// ── decode-notification ─────────────────────────────────────────────────────

#[test]
fn cli_decode_notification_accepts_hex_input() {
    // ← test_cli_decode_notification_accepts_hex_input.
    let data = v2c_trap("public", 12, None);
    let hex = hex_string(&data);
    let outcome = run(&["decode-notification", "--hex", &hex]);
    assert_eq!(outcome.code, 0, "stderr: {:?}", outcome.stderr);
    assert!(
        outcome.stdout.contains("type=snmpv2-trap request_id=12"),
        "{:?}",
        outcome.stdout
    );
    assert!(
        outcome
            .stdout
            .contains("notification=1.3.6.1.6.3.1.1.5.3 uptime=55"),
        "{:?}",
        outcome.stdout
    );
}

#[test]
fn cli_decode_notification_v1_renders_trap_metadata() {
    // ← test_cli_decode_notification_v1_renders_trap_metadata.
    let data = v1_trap("public");
    let hex = hex_string(&data);
    let outcome = run(&["decode-notification", "--snmp-version", "1", "--hex", &hex]);
    assert_eq!(outcome.code, 0);
    assert!(
        outcome
            .stdout
            .contains("type=trap request_id=0 community=public"),
        "{:?}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("enterprise=1.3.6.1.4.1.999 agent-addr=192.0.2.10 generic-trap=6 specific-trap=0 timestamp=654321"),
        "{:?}",
        outcome.stdout
    );
}

#[test]
fn cli_decode_notification_v1_json_output() {
    // ← test_cli_decode_notification_v1_json_output.
    let data = v1_trap("public");
    let hex = hex_string(&data);
    let outcome = run(&[
        "decode-notification",
        "--snmp-version",
        "1",
        "--json",
        "--hex",
        &hex,
    ]);
    assert_eq!(outcome.code, 0);
    let payload: serde_json::Value = serde_json::from_str(&outcome.stdout).expect("valid JSON");
    assert_eq!(payload["enterprise"], "1.3.6.1.4.1.999");
    assert_eq!(payload["agent_addr"], "192.0.2.10");
    assert_eq!(payload["generic_trap"], 6);
    assert_eq!(payload["specific_trap"], 0);
    assert_eq!(payload["timestamp"], 654321);
}

#[test]
fn cli_decode_notification_v3_passes_user() {
    // ← test_cli_decode_notification_v3_passes_user: a strict USM decode.
    let user = cli_v3_auth_user("alice");
    let engine = make_local_engine(0x42, 7, 111);
    let data = v3_trap(&user, &engine, 13);
    let hex = hex_string(&data);
    let outcome = run(&[
        "decode-notification",
        "--snmp-version",
        "3",
        "--username",
        "alice",
        "--auth-protocol",
        "sha256",
        "--auth-key",
        "authpassword12345",
        "--hex",
        &hex,
    ]);
    assert_eq!(outcome.code, 0, "stderr: {:?}", outcome.stderr);
    assert!(
        outcome
            .stdout
            .contains("type=snmpv2-trap request_id=13 user=alice level=authNoPriv"),
        "{:?}",
        outcome.stdout
    );
}

#[test]
fn cli_decode_notification_requires_input() {
    let outcome = run(&["decode-notification"]);
    assert_eq!(outcome.code, 2, "clap usage error");
}

#[test]
fn cli_decode_notification_rejects_invalid_hex() {
    let outcome = run(&["decode-notification", "--hex", "zz"]);
    assert_eq!(outcome.code, 1);
    assert_eq!(outcome.stderr.trim(), "tsnmp: Invalid hex payload: zz");
}

// ── security validation (pinned messages through the binary) ────────────────

#[test]
fn cli_get_v3_rejects_community() {
    let outcome = run(&[
        "get",
        "--host",
        "127.0.0.1",
        "--snmp-version",
        "3",
        "--community",
        "public",
        "--username",
        "alice",
        "1.3.6.1.2.1.2.2",
    ]);
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: --community is invalid with --snmp-version 3"
    );
}

#[test]
fn cli_get_v1_rejects_v3_flags() {
    let outcome = run(&[
        "get",
        "--host",
        "127.0.0.1",
        "--snmp-version",
        "1",
        "--username",
        "alice",
        "1.3.6.1.2.1.2.2",
    ]);
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: --username is invalid with --snmp-version 1"
    );
}

#[test]
fn cli_get_v3_requires_username() {
    let outcome = run(&[
        "get",
        "--host",
        "127.0.0.1",
        "--snmp-version",
        "3",
        "1.3.6.1.2.1.2.2",
    ]);
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: --username is required with --snmp-version 3"
    );
}

#[test]
fn cli_get_v3_auth_requires_exactly_one_key() {
    let outcome = run(&[
        "get",
        "--host",
        "127.0.0.1",
        "--snmp-version",
        "3",
        "--username",
        "alice",
        "--auth-protocol",
        "md5",
        "1.3.6.1.2.1.2.2",
    ]);
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: SNMPv3 auth requires exactly one of --auth-key or --auth-key-env"
    );
}

#[test]
fn cli_get_v3_rejects_both_inline_and_env_key() {
    let outcome = run(&[
        "get",
        "--host",
        "127.0.0.1",
        "--snmp-version",
        "3",
        "--username",
        "alice",
        "--auth-protocol",
        "md5",
        "--auth-key",
        "inline",
        "--auth-key-env",
        "TSNMP_AUTH",
        "1.3.6.1.2.1.2.2",
    ]);
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: Use only one of --auth-key or --auth-key-env"
    );
}

#[test]
fn cli_get_v3_rejects_unset_env_secret() {
    let outcome = run(&[
        "get",
        "--host",
        "127.0.0.1",
        "--snmp-version",
        "3",
        "--username",
        "alice",
        "--auth-protocol",
        "sha1",
        "--auth-key-env",
        "TSNMP_AUTH",
        "1.3.6.1.2.1.2.2",
    ]);
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: Environment variable TSNMP_AUTH is not set for SNMPv3 auth credentials"
    );
}

#[test]
fn cli_get_v3_rejects_priv_without_auth() {
    let outcome = run(&[
        "get",
        "--host",
        "127.0.0.1",
        "--snmp-version",
        "3",
        "--username",
        "alice",
        "--priv-protocol",
        "aes128",
        "--priv-key",
        "secret",
        "1.3.6.1.2.1.2.2",
    ]);
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: --priv-protocol requires --auth-protocol to be enabled"
    );
}

#[test]
fn cli_get_v3_rejects_des_priv() {
    let outcome = run(&[
        "get",
        "--host",
        "127.0.0.1",
        "--snmp-version",
        "3",
        "--username",
        "alice",
        "--auth-protocol",
        "md5",
        "--auth-key",
        "secret",
        "--priv-protocol",
        "des",
        "--priv-key",
        "priv",
        "1.3.6.1.2.1.2.2",
    ]);
    assert_eq!(outcome.code, 1);
    assert!(
        outcome.stderr.contains("DES-CBC privacy is unavailable"),
        "{:?}",
        outcome.stderr
    );
}

#[test]
fn cli_get_v1_rejects_context_name() {
    let outcome = run(&[
        "get",
        "--host",
        "127.0.0.1",
        "--snmp-version",
        "1",
        "--context-name",
        "alerts",
        "1.3.6.1.2.1.2.2",
    ]);
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr.trim(),
        "tsnmp: --context-name is invalid with --snmp-version 1"
    );
}

#[test]
fn cli_get_rejects_unknown_target_format() {
    // No socket is bound in this test: target parsing fails before any
    // connect, so the port is a neutral literal that is never reached.
    let outcome = run(&["get", "--host", "127.0.0.1", "--port", "161", "not-an-oid"]);
    assert_eq!(outcome.code, 1);
    assert!(
        outcome.stderr.contains("Unrecognized target format"),
        "{:?}",
        outcome.stderr
    );
}

// ── helpers ─────────────────────────────────────────────────────────────────

/// Lowercase hex (the reference's `bytes.hex()`).
fn hex_string(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// Binds a responder with the v3 answer path enabled on an OS-assigned
/// loopback port; callers read the actual port back via
/// [`SnmpResponder::local_addr`]. USM identity is the engineID, not the port
/// (Phase 7 finding), so an OS-assigned port is safe for the v3 users.
async fn spawn_responder_v3(
    objects: Vec<(Oid, SnmpValue)>,
    user: UsmUser,
) -> std::sync::Arc<SnmpResponder> {
    let responder = std::sync::Arc::new(
        SnmpResponder::bind(ResponderConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            objects: object_inputs(objects),
            v3: Some((user, local_engine(1000))),
            ..Default::default()
        })
        .await
        .expect("bind loopback v3 responder"),
    );
    let serve = std::sync::Arc::clone(&responder);
    tokio::spawn(async move {
        serve.serve(0).await.expect("serve loop");
    });
    responder
}

/// Converts `(Oid, SnmpValue)` seeds to responder `ObjectInput`s.
fn object_inputs(objects: Vec<(Oid, SnmpValue)>) -> Vec<(Target, ObjectValue)> {
    objects
        .into_iter()
        .map(|(oid, value)| (Target::from(oid), ObjectValue::Static(value)))
        .collect()
}
