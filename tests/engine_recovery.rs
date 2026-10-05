//! Engine-recovery REPORT delivery: immediate dispatcher surfacing + one
//! client retry (ported from test_engine_recovery.py; §6 typed flow).
//!
//! The typed flow: `unwrap_message` returns `EngineRecoveryPending` only after
//! the model adopted the report's authoritative engine state; the dispatcher
//! maps it to `Error::EngineRecovery` only if `take_recovery()` confirms; the
//! manager retries exactly once, then propagates.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::agent::{build_recovery_report, usm_agent_model};
use common::transport::{FakeTransport, upcast};

use trishul_snmp::codec::message::SnmpVersion;
use trishul_snmp::codec::pdu::{Pdu, PduKind};
use trishul_snmp::error::Error;
use trishul_snmp::manager::Manager;
use trishul_snmp::security::SecurityModel;
use trishul_snmp::security::usm::kdf::{AuthProtocol, PrivProtocol};
use trishul_snmp::security::usm::{AuthKey, PrivKey, UsmModel, UsmUser};
use trishul_snmp::session::SnmpSession;
use trishul_snmp::transport::dispatcher::RequestDispatcher;
use trishul_snmp::types::oid::Oid;
use trishul_snmp::types::value::SnmpValue;
use trishul_snmp::types::varbind::VarBind;

const ENGINE_ID: [u8; 11] = [
    0x80, 0x00, 0x1f, 0x88, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const REPORT_BOOTS: u32 = 9;
const REPORT_TIME: u32 = 1234;

fn user(username: &str) -> UsmUser {
    // The recovery REPORTs are noAuth (reference parity); the model must not
    // demand a tag it cannot verify. Real agents auth their reports, which the
    // conformance suite exercises against snmpd.
    UsmUser::new(
        username.to_string(),
        AuthProtocol::None_,
        AuthKey::Passphrase(Vec::new()),
        PrivProtocol::None_,
        PrivKey::Passphrase(Vec::new()),
    )
    .unwrap()
}

/// A noAuth UsmModel with authoritative peer state pre-adopted (the manager
/// side; no discovery needed for these tests).
fn discovered_model(username: &str) -> UsmModel {
    let model = UsmModel::new(
        user(username),
        Vec::new(),
        None,
        Arc::new(trishul_snmp::time::SystemClock),
    );
    model.adopt_engine_state(ENGINE_ID.to_vec(), 2, 100);
    model
}

/// Builds a Manager over an in-memory transport (mirrors the reference's
/// session internals swap).
fn manager_over(transport: Arc<FakeTransport>) -> Manager {
    let model = discovered_model("simulator");
    let security = Arc::new(SecurityModel::Usm(model));
    let dispatcher = RequestDispatcher::new(
        upcast(Arc::clone(&transport)),
        Arc::clone(&security),
        Duration::from_millis(200),
        0,
        Arc::new(common::fake::CounterRng::new(7)),
    )
    .unwrap();
    let session = SnmpSession::from_parts(security, upcast(transport), dispatcher);
    Manager {
        session,
        version: SnmpVersion::V3,
    }
}

/// The agent-side model wrapping responses (peer = its own engine).
fn agent_model() -> Arc<UsmModel> {
    Arc::new(usm_agent_model(
        user("simulator"),
        ENGINE_ID.to_vec(),
        2,
        100,
    ))
}

/// A v3 RESPONSE echoing the request id, authed by the agent model.
fn v3_response_for(request: &[u8], model: &UsmModel) -> Vec<u8> {
    let view = trishul_snmp::codec::v3::decode_v3_message(request).unwrap();
    let (_eid, _ctx, pdu) =
        trishul_snmp::codec::v3::decode_scoped_pdu(&view.msg_data_bytes).unwrap();
    let response = Pdu {
        kind: PduKind::Response,
        request_id: pdu.request_id,
        error_status: 0,
        error_index: 0,
        varbinds: vec![VarBind::new(
            Oid::from_arcs(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap(),
            SnmpValue::Null,
        )],
        v1_trap: None,
    };
    model.wrap_pdu(&response).unwrap()
}

#[tokio::test]
async fn manager_retries_once_after_recovery_report() {
    // The first request draws a usmStatsNotInTimeWindows REPORT (which the
    // model adopts); the manager retries immediately and succeeds.
    let agent = agent_model();
    let report = build_recovery_report(&ENGINE_ID, REPORT_BOOTS, REPORT_TIME, b"simulator");
    let sent = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let transport = FakeTransport::new({
        let agent = Arc::clone(&agent);
        let report = report.clone();
        let sent = Arc::clone(&sent);
        move |request: &[u8]| {
            let n = sent.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            if n == 1 {
                vec![report.clone()]
            } else {
                vec![v3_response_for(request, &agent)]
            }
        }
    });
    let manager = manager_over(Arc::clone(&transport));

    let response = manager.get(vec!["1.3.6.1.2.1.1.1.0"]).await.unwrap();
    // The response echoes the retried request's id (the retry re-prepares).
    let retried = transport.sent_datagrams()[1].clone();
    let retried_view = trishul_snmp::codec::v3::decode_v3_message(&retried).unwrap();
    let (_eid, _ctx, retried_pdu) =
        trishul_snmp::codec::v3::decode_scoped_pdu(&retried_view.msg_data_bytes).unwrap();
    assert_eq!(response.request_id, retried_pdu.request_id);
    assert_eq!(
        sent.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "one retry"
    );
    // The adopted report state replaced the stale discovery state.
    let model = match &*manager.session.security {
        SecurityModel::Usm(model) => model,
        _ => unreachable!(),
    };
    assert_eq!(model.peer_engine_id(), ENGINE_ID.to_vec());
    assert!(model.take_recovery().is_none(), "recovery consumed");
}

#[tokio::test]
async fn manager_recovery_report_without_adoption_is_swallowed() {
    // A REPORT that is NOT a notInTimeWindows report must not trigger recovery:
    // it is skipped like any other stray datagram, and the request times out.
    let transport = FakeTransport::new(|_request| {
        // A REPORT with a non-recovery varbind.
        let report = Pdu {
            kind: PduKind::Report,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                Oid::from_arcs(&[1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0]).unwrap(),
                SnmpValue::Counter32(1),
            )],
            v1_trap: None,
        };
        let scoped = trishul_snmp::codec::v3::encode_scoped_pdu(&ENGINE_ID, b"", &report).unwrap();
        let usm = trishul_snmp::codec::v3::UsmSecurityParameters {
            engine_id: ENGINE_ID.to_vec(),
            engine_boots: i64::from(REPORT_BOOTS),
            engine_time: i64::from(REPORT_TIME),
            username: b"simulator".to_vec(),
            auth_params: Vec::new(),
            priv_params: Vec::new(),
        };
        let bytes = trishul_snmp::codec::v3::encode_v3_message(1, 65507, 0, &usm, &scoped).unwrap();
        vec![bytes]
    });
    let manager = manager_over(Arc::clone(&transport));
    let err = manager.get(vec!["1.3.6.1.2.1.1.1.0"]).await.unwrap_err();
    assert!(matches!(err, Error::Timeout { .. }), "got {err:?}");
}

#[tokio::test]
async fn manager_second_report_on_retry_propagates() {
    // Both attempts draw a recovery REPORT: the first is retried once, the
    // second propagates (no loop, no leftover flag).
    let report = build_recovery_report(&ENGINE_ID, REPORT_BOOTS, REPORT_TIME, b"simulator");
    let transport = FakeTransport::new(move |_request| vec![report.clone()]);
    let manager = manager_over(Arc::clone(&transport));

    let err = manager.get(vec!["1.3.6.1.2.1.1.1.0"]).await.unwrap_err();
    assert!(matches!(err, Error::EngineRecovery(_)), "got {err:?}");
    assert_eq!(transport.sent_count(), 2, "exactly one retry");
    // The residual flag was cleared; a later stray datagram cannot loop.
    let model = match &*manager.session.security {
        SecurityModel::Usm(model) => model,
        _ => unreachable!(),
    };
    assert!(model.take_recovery().is_none());
}

#[tokio::test]
async fn manager_timeout_propagates_without_recovery() {
    // No REPORT at all: the request times out and nothing is retried.
    let transport = FakeTransport::new(|_request| vec![]);
    let manager = manager_over(Arc::clone(&transport));
    let err = manager.get(vec!["1.3.6.1.2.1.1.1.0"]).await.unwrap_err();
    assert!(matches!(err, Error::Timeout { .. }), "got {err:?}");
    assert_eq!(transport.sent_count(), 1);
}

#[tokio::test]
async fn recovery_adopts_engine_state_from_report() {
    // After a recovery, the model's engine params come from the REPORT
    // (boots 9, time 1234) — the retried message carries them.
    let agent = agent_model();
    let report = build_recovery_report(&ENGINE_ID, REPORT_BOOTS, REPORT_TIME, b"simulator");
    let sent = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let transport = FakeTransport::new({
        let agent = Arc::clone(&agent);
        let report = report.clone();
        let sent = Arc::clone(&sent);
        move |request: &[u8]| {
            let n = sent.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            if n == 1 {
                vec![report.clone()]
            } else {
                vec![v3_response_for(request, &agent)]
            }
        }
    });
    let manager = manager_over(Arc::clone(&transport));
    let _ = manager.get(vec!["1.3.6.1.2.1.1.1.0"]).await.unwrap();
    // The retried message carries the REPORT's authoritative state.
    let retried = transport.sent_datagrams()[1].clone();
    let view = trishul_snmp::codec::v3::decode_v3_message(&retried).unwrap();
    assert_eq!(view.usm_params.engine_boots, i64::from(REPORT_BOOTS));
    assert_eq!(view.usm_params.engine_time, i64::from(REPORT_TIME));
}

#[test]
fn helper_surface_compiles() {
    let _ = SnmpVersion::V3;
    let _: Vec<u8> = ENGINE_ID.to_vec();
}
