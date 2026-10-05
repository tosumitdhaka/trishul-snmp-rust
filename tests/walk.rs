//! Walk semantics tests: the reference's scripted-agent quirk scenarios
//! (test_walk_quirks.py) run against loopback fake agents, plus walk_subtree
//! stop-rule hardening (test_walk_hardening.py).
//!
//! Walk termination is the plan's risk #7; the quirk scenarios below are the
//! core of this suite.

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use common::agent::{FakeAgent, object_logic, scripted_logic};
use common::{oid, vb};

use trishul_snmp::error::Error;
use trishul_snmp::manager::walk::{WalkOptions, walk_subtree};

use trishul_snmp::types::oid::Oid;
use trishul_snmp::types::value::SnmpValue;
use trishul_snmp::types::varbind::ErrorStatus;
use trishul_snmp::types::varbind::{Response, VarBind};

const ROOT: [u32; 7] = [1, 3, 6, 1, 4, 1, 99999];
const A: [u32; 8] = [1, 3, 6, 1, 4, 1, 99999, 1];
const B: [u32; 8] = [1, 3, 6, 1, 4, 1, 99999, 2];
const C: [u32; 8] = [1, 3, 6, 1, 4, 1, 99999, 3];
const OUTSIDE: [u32; 7] = [1, 3, 6, 1, 4, 1, 99998];

fn vb_i(arcs: &[u32], value: i64) -> VarBind {
    vb(arcs, SnmpValue::Integer(value))
}

fn eomv(arcs: &[u32]) -> VarBind {
    vb(arcs, SnmpValue::EndOfMibView)
}

async fn walk_scenario(
    script: Vec<(Oid, Vec<VarBind>)>,
    errors: Vec<(Oid, (i32, i32))>,
    echo: bool,
    bulk: bool,
    v1: bool,
    max_repetitions: u32,
) -> (Vec<VarBind>, Arc<FakeAgent>) {
    let script_map: HashMap<Oid, Vec<VarBind>> = script.into_iter().collect();
    let error_map: HashMap<Oid, (i32, i32)> = errors.into_iter().collect();
    let (agent, port) = FakeAgent::spawn(scripted_logic(script_map, error_map, echo)).await;
    let manager = if v1 {
        common::test_v1_manager(port).await
    } else {
        common::test_v2c_manager(port).await
    };
    let results = manager
        .walk(
            oid(&ROOT),
            WalkOptions {
                bulk,
                max_repetitions,
            },
        )
        .await;
    (results.unwrap_or_default(), agent)
}

fn oids(varbinds: &[VarBind]) -> Vec<Oid> {
    varbinds.iter().map(|v| v.oid.clone()).collect()
}

// ── quirk scenarios (walk.py:79–105) ──────────────────────────────────────

#[tokio::test]
async fn walk_terminates_on_zero_progress_echo() {
    for bulk in [true, false] {
        let (walked, agent) = walk_scenario(vec![], vec![], true, bulk, false, 10).await;
        assert!(walked.is_empty(), "no phantom rows on echo");
        assert_eq!(agent.requested_oids(), vec![oid(&ROOT)]);
        agent.stop();
    }
}

#[tokio::test]
async fn walk_terminates_when_agent_jumps_out_of_subtree() {
    let (walked, agent) = walk_scenario(
        vec![(oid(&ROOT), vec![vb_i(&OUTSIDE, 1)])],
        vec![],
        false,
        true,
        false,
        10,
    )
    .await;
    assert!(walked.is_empty());
    assert_eq!(agent.requested_oids(), vec![oid(&ROOT)]);
    agent.stop();
}

#[tokio::test]
async fn walk_continues_after_agent_skips_ahead() {
    let script = vec![(oid(&ROOT), vec![vb_i(&C, 3)]), (oid(&C), vec![eomv(&C)])];
    let (walked, agent) = walk_scenario(script, vec![], false, true, false, 10).await;
    assert_eq!(oids(&walked), vec![oid(&C)]);
    assert_eq!(agent.requested_oids(), vec![oid(&ROOT), oid(&C)]);
    agent.stop();
}

#[tokio::test]
async fn walk_stops_at_out_of_subtree_after_in_subtree_rows() {
    // Two rows inside, then the agent jumps outside: rows are kept, walk ends.
    let script = vec![(
        oid(&ROOT),
        vec![vb_i(&A, 1), vb_i(&B, 2), vb_i(&OUTSIDE, 3)],
    )];
    let (walked, agent) = walk_scenario(script, vec![], false, true, false, 10).await;
    assert_eq!(oids(&walked), vec![oid(&A), oid(&B)]);
    agent.stop();
}

#[tokio::test]
async fn walk_collects_rows_until_end_of_mib_view() {
    let script = vec![
        (oid(&ROOT), vec![vb_i(&A, 1)]),
        (oid(&A), vec![vb_i(&B, 2)]),
        (oid(&B), vec![eomv(&B)]),
    ];
    let (walked, agent) = walk_scenario(script, vec![], false, true, false, 10).await;
    assert_eq!(oids(&walked), vec![oid(&A), oid(&B)]);
    assert_eq!(agent.requested_oids(), vec![oid(&ROOT), oid(&A), oid(&B)]);
    agent.stop();
}

#[tokio::test]
async fn walk_backtracking_oid_terminates() {
    // The agent answers the second request with an OID lexicographically
    // before the requested one (backtrack below current): stop, trust nothing
    // further, keep what was already collected.
    let script = vec![
        (oid(&ROOT), vec![vb_i(&A, 1)]),
        (oid(&A), vec![vb_i(&ROOT, 9)]),
    ];
    let (walked, agent) = walk_scenario(script, vec![], false, true, false, 10).await;
    assert_eq!(oids(&walked), vec![oid(&A)]);
    agent.stop();
}

#[tokio::test]
async fn bulkwalk_survives_agent_clamping_max_repetitions() {
    // Agent returns one row per GETBULK despite max_repetitions=10.
    let script = vec![
        (oid(&ROOT), vec![vb_i(&A, 1)]),
        (oid(&A), vec![vb_i(&B, 2)]),
        (oid(&B), vec![eomv(&B)]),
    ];
    let (walked, agent) = walk_scenario(script, vec![], false, true, false, 10).await;
    assert_eq!(oids(&walked), vec![oid(&A), oid(&B)]);
    assert!(agent.requested_max_repetitions().iter().all(|n| *n == 10));
    agent.stop();
}

#[tokio::test]
async fn bulkwalk_stops_at_end_of_mib_view_in_non_final_position() {
    // Port of test_walk_quirks.py:225: an endOfMibView before the final
    // varbind still terminates the walk there.
    let script = vec![(oid(&ROOT), vec![vb_i(&A, 1), eomv(&A), vb_i(&B, 3)])];
    let (walked, agent) = walk_scenario(script, vec![], false, true, false, 10).await;
    assert_eq!(oids(&walked), vec![oid(&A)]);
    assert_eq!(agent.requested_oids(), vec![oid(&ROOT)]);
    agent.stop();
}

#[tokio::test]
async fn walk_ignores_varbinds_after_leading_end_of_mib_view() {
    // Port of test_walk_quirks.py:237: data after a leading endOfMibView in
    // the same response is discarded.
    let script = vec![(oid(&ROOT), vec![eomv(&A), vb_i(&B, 3)])];
    let (walked, agent) = walk_scenario(script, vec![], false, true, false, 10).await;
    assert!(walked.is_empty());
    assert_eq!(agent.requested_oids(), vec![oid(&ROOT)]);
    agent.stop();
}

#[tokio::test]
async fn bulkwalk_dedupes_repeated_oid_within_response() {
    // Port of test_walk_quirks.py:303: a duplicated row in one response is
    // dropped (it equals the just-appended cursor) and the walk continues.
    let script = vec![
        (oid(&ROOT), vec![vb_i(&A, 1), vb_i(&A, 2), vb_i(&B, 3)]),
        (oid(&B), vec![eomv(&B)]),
    ];
    let (walked, agent) = walk_scenario(script, vec![], false, true, false, 10).await;
    assert_eq!(oids(&walked), vec![oid(&A), oid(&B)]);
    assert_eq!(agent.requested_oids(), vec![oid(&ROOT), oid(&B)]);
    agent.stop();
}

#[tokio::test]
async fn walk_aborts_on_agent_error_status() {
    let script = vec![(oid(&ROOT), vec![vb_i(&A, 1)])];
    let errors = vec![(oid(&A), (5, 2))]; // genErr, error-index 2
    let (agent, port) = FakeAgent::spawn(scripted_logic(
        script.into_iter().collect(),
        errors.into_iter().collect(),
        false,
    ))
    .await;
    let manager = common::test_v2c_manager(port).await;
    let err = manager
        .walk(oid(&ROOT), WalkOptions::default())
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::WalkAborted {
                status: ErrorStatus::GenErr,
                index: 2
            }
        ),
        "got {err:?}"
    );
    agent.stop();
}

#[tokio::test]
async fn v1_walk_terminates_cleanly_on_no_such_name() {
    // v1 GETNEXT past the end answers noSuchName: the walk ends cleanly.
    let objects = vec![(oid(&A), SnmpValue::Integer(1))];
    let (agent, port) = FakeAgent::spawn(object_logic(objects, true)).await;
    let manager = common::test_v1_manager(port).await;
    let results = manager
        .walk(oid(&ROOT), WalkOptions::default())
        .await
        .unwrap();
    assert_eq!(oids(&results), vec![oid(&A)]);
    assert!(
        agent
            .requested_kinds()
            .iter()
            .all(|kind| *kind == trishul_snmp::codec::pdu::PduKind::GetNextRequest)
    );
    agent.stop();
}

#[tokio::test]
async fn v2c_walk_aborts_on_no_such_name() {
    // For v2c, a noSuchName from the agent is an error, not a walk end.
    let objects = vec![(oid(&A), SnmpValue::Integer(1))];
    let (agent, port) = FakeAgent::spawn(object_logic(objects, true)).await;
    let manager = common::test_v2c_manager(port).await;
    let err = manager
        .walk(
            oid(&ROOT),
            WalkOptions {
                bulk: false,
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::WalkAborted {
                status: ErrorStatus::NoSuchName,
                ..
            }
        ),
        "got {err:?}"
    );
    agent.stop();
}

#[tokio::test]
async fn v1_walk_uses_getnext_requests_even_when_bulk_requested() {
    let objects = vec![(oid(&A), SnmpValue::Integer(1))];
    let (agent, port) = FakeAgent::spawn(object_logic(objects, true)).await;
    let manager = common::test_v1_manager(port).await;
    let _ = manager
        .walk(
            oid(&ROOT),
            WalkOptions {
                bulk: true,
                max_repetitions: 10,
            },
        )
        .await
        .unwrap();
    assert!(
        agent
            .requested_kinds()
            .iter()
            .all(|kind| *kind == trishul_snmp::codec::pdu::PduKind::GetNextRequest)
    );
    agent.stop();
}

// ── walk_subtree stop-rule hardening (test_walk_hardening.py) ─────────────

fn response(varbinds: Vec<VarBind>) -> Response {
    Response {
        request_id: 1,
        error_status: ErrorStatus::NoError,
        error_index: 0,
        varbinds,
    }
}

fn error_response(status: ErrorStatus, index: u32) -> Response {
    Response {
        request_id: 1,
        error_status: status,
        error_index: index,
        varbinds: Vec::new(),
    }
}

#[tokio::test]
async fn walk_subtree_error_aborts_with_collected_rows_lost() {
    // A clean row, then an error response: the walk aborts (rows so far are
    // discarded, matching the reference's raise-on-error).
    let script = vec![(oid(&ROOT), vec![vb_i(&A, 1)]), (oid(&A), vec![eomv(&A)])];
    let errors = vec![(oid(&A), (5, 1))];
    let (agent, port) = FakeAgent::spawn(scripted_logic(
        script.into_iter().collect(),
        errors.into_iter().collect(),
        false,
    ))
    .await;
    let manager = common::test_v2c_manager(port).await;
    let err = manager
        .walk(oid(&ROOT), WalkOptions::default())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::WalkAborted { .. }), "got {err:?}");
    agent.stop();
}

#[tokio::test]
async fn walk_subtree_reports_error_status_and_index() {
    let request_fn = |_current: &Oid, _max: Option<u32>| async move {
        Ok(error_response(ErrorStatus::TooBig, 7))
    };
    let err = walk_subtree(request_fn, &oid(&ROOT), false, 10, false)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::WalkAborted {
                status: ErrorStatus::TooBig,
                index: 7
            }
        ),
        "got {err:?}"
    );
}

#[tokio::test]
async fn walk_subtree_empty_response_terminates() {
    let request_fn = |_current: &Oid, _max: Option<u32>| async move { Ok(response(vec![])) };
    let results = walk_subtree(request_fn, &oid(&ROOT), false, 10, false)
        .await
        .unwrap();
    assert!(results.is_empty());
}

#[tokio::test]
async fn walk_subtree_v1_no_such_name_is_clean_end() {
    let request_fn = |_current: &Oid, _max: Option<u32>| async move {
        Ok(error_response(ErrorStatus::NoSuchName, 1))
    };
    let results = walk_subtree(request_fn, &oid(&ROOT), false, 10, true)
        .await
        .unwrap();
    assert!(results.is_empty());
}

#[tokio::test]
async fn walk_subtree_v2c_no_such_name_is_an_error() {
    let request_fn = |_current: &Oid, _max: Option<u32>| async move {
        Ok(error_response(ErrorStatus::NoSuchName, 1))
    };
    let err = walk_subtree(request_fn, &oid(&ROOT), false, 10, false)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::WalkAborted { .. }));
}
