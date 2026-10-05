//! Engine-recovery REPORT delivery: immediate dispatcher surfacing + one
//! client retry (ported from test_engine_recovery.py; §6 typed flow).
//!
//! The typed flow: `unwrap_message` returns `EngineRecoveryPending` only after
//! the model adopted the report's authoritative engine state; the dispatcher
//! maps it to `Error::EngineRecovery` only if `take_recovery()` confirms; the
//! manager retries exactly once, then propagates.

mod common;

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::agent::{build_recovery_report, usm_agent_model};
use common::transport::{FakeTransport, upcast};

use trishul_snmp::codec::message::SnmpVersion;
use trishul_snmp::codec::pdu::{Pdu, PduKind};
use trishul_snmp::error::Error;
use trishul_snmp::manager::Manager;
use trishul_snmp::manager::walk::WalkOptions;
use trishul_snmp::notify::sender::Notifier;
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
        Arc::new(common::fake::CounterRng::new(7)),
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

// ── walk / notifier recovery (review batch) ─────────────────────────────────

/// A v3 GETNEXT/GETBULK response echoing the request id and returning the
/// next table object after the requested OID (EoMv past the end).
fn v3_next_response_for(request: &[u8], model: &UsmModel, objects: &[(Oid, SnmpValue)]) -> Vec<u8> {
    let view = trishul_snmp::codec::v3::decode_v3_message(request).unwrap();
    let (_eid, _ctx, pdu) =
        trishul_snmp::codec::v3::decode_scoped_pdu(&view.msg_data_bytes).unwrap();
    let requested = pdu
        .varbinds
        .first()
        .map(|v| v.oid.clone())
        .unwrap_or_else(|| Oid::from_arcs(&[0, 0]).unwrap());
    let varbind = match objects.iter().find(|(oid, _)| *oid > requested) {
        Some((oid, value)) => VarBind::new(oid.clone(), value.clone()),
        None => VarBind::new(requested, SnmpValue::EndOfMibView),
    };
    let response = Pdu {
        kind: PduKind::Response,
        request_id: pdu.request_id,
        error_status: 0,
        error_index: 0,
        varbinds: vec![varbind],
        v1_trap: None,
    };
    model.wrap_pdu(&response).unwrap()
}

/// A v3 notifier built over an in-memory transport (peer state discovered).
fn notifier_over(transport: Arc<FakeTransport>) -> Notifier {
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
    Notifier {
        session,
        version: SnmpVersion::V3,
    }
}

#[tokio::test]
async fn walk_recovers_from_report_and_continues() {
    // The first GETNEXT draws a notInTimeWindows REPORT; the walk retries that
    // exchange exactly once and then walks the table to completion.
    let agent = agent_model();
    let objects = vec![
        (
            Oid::from_arcs(&[1, 3, 6, 1, 4, 1, 99999, 1]).unwrap(),
            SnmpValue::Integer(1),
        ),
        (
            Oid::from_arcs(&[1, 3, 6, 1, 4, 1, 99999, 2]).unwrap(),
            SnmpValue::Integer(2),
        ),
        (
            Oid::from_arcs(&[1, 3, 6, 1, 4, 1, 99999, 3]).unwrap(),
            SnmpValue::Integer(3),
        ),
    ];
    let report = build_recovery_report(&ENGINE_ID, 2, 100, b"simulator");
    let sends = Arc::new(AtomicUsize::new(0));
    let requested: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let transport = FakeTransport::new({
        let agent = Arc::clone(&agent);
        let report = report.clone();
        let objects = objects.clone();
        let sends = Arc::clone(&sends);
        let requested = Arc::clone(&requested);
        move |request| {
            sends.fetch_add(1, Ordering::SeqCst);
            let view = trishul_snmp::codec::v3::decode_v3_message(request).unwrap();
            let (_eid, _ctx, pdu) =
                trishul_snmp::codec::v3::decode_scoped_pdu(&view.msg_data_bytes).unwrap();
            requested
                .lock()
                .unwrap()
                .push(pdu.varbinds[0].oid.display());
            if sends.load(Ordering::SeqCst) == 1 {
                vec![report.clone()]
            } else {
                vec![v3_next_response_for(request, &agent, &objects)]
            }
        }
    });
    let manager = manager_over(transport);
    let walked = manager
        .walk(
            &[1, 3, 6, 1, 4, 1, 99999][..],
            WalkOptions {
                bulk: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        walked.iter().map(|v| v.oid.display()).collect::<Vec<_>>(),
        vec![
            "1.3.6.1.4.1.99999.1".to_string(),
            "1.3.6.1.4.1.99999.2".to_string(),
            "1.3.6.1.4.1.99999.3".to_string(),
        ]
    );
    // Exactly one retried exchange: root requested twice, then A, B, C.
    assert_eq!(sends.load(Ordering::SeqCst), 5);
    assert_eq!(
        *requested.lock().unwrap(),
        vec![
            "1.3.6.1.4.1.99999".to_string(),
            "1.3.6.1.4.1.99999".to_string(),
            "1.3.6.1.4.1.99999.1".to_string(),
            "1.3.6.1.4.1.99999.2".to_string(),
            "1.3.6.1.4.1.99999.3".to_string(),
        ]
    );
}

#[tokio::test]
async fn v3notifier_send_inform_retries_immediately_on_report_error() {
    // The first inform exchange draws a REPORT; send_inform re-issues once and
    // returns the retried exchange's response (notify/client.py:307–322).
    let agent = agent_model();
    let report = build_recovery_report(&ENGINE_ID, 2, 100, b"simulator");
    let sends = Arc::new(AtomicUsize::new(0));
    let request_ids: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
    let transport = FakeTransport::new({
        let agent = Arc::clone(&agent);
        let report = report.clone();
        let sends = Arc::clone(&sends);
        let request_ids = Arc::clone(&request_ids);
        move |request| {
            sends.fetch_add(1, Ordering::SeqCst);
            let view = trishul_snmp::codec::v3::decode_v3_message(request).unwrap();
            let (_eid, _ctx, pdu) =
                trishul_snmp::codec::v3::decode_scoped_pdu(&view.msg_data_bytes).unwrap();
            request_ids.lock().unwrap().push(pdu.request_id);
            if sends.load(Ordering::SeqCst) == 1 {
                vec![report.clone()]
            } else {
                vec![v3_response_for(request, &agent)]
            }
        }
    });
    let notifier = notifier_over(transport);
    let response = notifier
        .send_inform("1.3.6.1.6.3.1.1.5.1", &[], 1)
        .await
        .unwrap();
    assert_eq!(sends.load(Ordering::SeqCst), 2);
    // The response corresponds to the retried (second) exchange.
    let ids = request_ids.lock().unwrap();
    assert_eq!(response.request_id, ids[1]);
    assert_ne!(ids[0], ids[1]);
}

#[tokio::test]
async fn v3notifier_send_inform_unrelated_errors_propagate_without_retry() {
    // Re-spec of test_engine_recovery.py:243–263: the typed dispatcher only
    // surfaces EngineRecovery after the model adopted the REPORT, so a
    // "flagless recovery error" is unrepresentable. The equivalent guarantee
    // is that unrelated errors (e.g. timeout) propagate unchanged — no retry.
    let sends = Arc::new(AtomicUsize::new(0));
    let transport = FakeTransport::new({
        let sends = Arc::clone(&sends);
        move |_| {
            sends.fetch_add(1, Ordering::SeqCst);
            vec![]
        }
    });
    let notifier = notifier_over(transport);
    let err = notifier
        .send_inform("1.3.6.1.6.3.1.1.5.1", &[], 1)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Timeout { .. }), "got {err:?}");
    assert_eq!(sends.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn v3notifier_send_inform_second_report_clears_flag_and_propagates() {
    // Both exchanges draw a REPORT: the first is retried once, the second
    // propagates and the residual recovery flag is cleared (no loop).
    let report = build_recovery_report(&ENGINE_ID, 2, 100, b"simulator");
    let sends = Arc::new(AtomicUsize::new(0));
    let transport = FakeTransport::new({
        let report = report.clone();
        let sends = Arc::clone(&sends);
        move |_| {
            sends.fetch_add(1, Ordering::SeqCst);
            vec![report.clone()]
        }
    });
    let notifier = notifier_over(transport);
    let err = notifier
        .send_inform("1.3.6.1.6.3.1.1.5.1", &[], 1)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::EngineRecovery(_)), "got {err:?}");
    assert_eq!(sends.load(Ordering::SeqCst), 2);
    // The retry path cleared the residual flag.
    assert!(notifier.session.security.take_recovery().is_none());
}

#[tokio::test]
async fn v3notifier_send_inform_recovers_via_report_without_timeout() {
    // End-to-end: the REPORT surfaces immediately and the retried inform
    // completes — no timeout on the recovery path.
    let agent = agent_model();
    let report = build_recovery_report(&ENGINE_ID, 2, 100, b"simulator");
    let calls = Arc::new(AtomicUsize::new(0));
    let transport = FakeTransport::new({
        let agent = Arc::clone(&agent);
        let report = report.clone();
        let calls = Arc::clone(&calls);
        move |request| {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                vec![report.clone()]
            } else {
                vec![v3_response_for(request, &agent)]
            }
        }
    });
    let notifier = notifier_over(transport);
    let response = notifier
        .send_inform("1.3.6.1.6.3.1.1.5.1", &[], 1)
        .await
        .unwrap();
    assert!(response.error_status == trishul_snmp::types::varbind::ErrorStatus::NoError);
}
