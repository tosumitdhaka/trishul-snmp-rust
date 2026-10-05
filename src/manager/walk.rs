//! Walk stop rules (← walk.py)

use std::future::Future;

use crate::error::Error;
use crate::types::oid::Oid;
use crate::types::value::SnmpValue;
use crate::types::varbind::{ErrorStatus, Response, VarBind};

/// Options controlling subtree walks (← walk.py:walk, bulkwalk).
#[derive(Clone, Copy, Debug)]
pub struct WalkOptions {
    /// Use GETBULK (v2c+). Ignored for v1, which always GETNEXTs.
    pub bulk: bool,
    /// GETBULK repetition count (default 10).
    pub max_repetitions: u32,
}

impl Default for WalkOptions {
    fn default() -> Self {
        Self {
            bulk: true,
            max_repetitions: 10,
        }
    }
}

/// Walks a subtree, implementing the reference stop rules verbatim
/// (← walk.py:36, 79–105).
///
/// `request_fn(current_oid, max_repetitions)` performs one GETNEXT
/// (`None`) or GETBULK (`Some(n)`) and returns the response.
///
/// Termination is decided on these signals, in order:
/// - an error status: for v1, `NoSuchName` ends the walk cleanly; any other
///   status (or a v2c error) aborts with [`Error::WalkAborted`];
/// - an empty response, an `EndOfMibView`, an out-of-subtree OID, or a
///   non-progressing OID ends the walk;
/// - a varbind whose OID echoes the current cursor (agent echo quirk) is
///   skipped without ending the walk;
/// - repeated same-OID responses across requests ("no progress") end it.
pub async fn walk_subtree<F, Fut>(
    request_fn: F,
    root: &Oid,
    bulk: bool,
    max_repetitions: u32,
    v1: bool,
) -> Result<Vec<VarBind>, Error>
where
    F: Fn(&Oid, Option<u32>) -> Fut,
    Fut: Future<Output = Result<Response, Error>> + Send,
{
    let mut results = Vec::new();
    let mut current = root.clone();

    loop {
        let response =
            request_fn(&current, if bulk { Some(max_repetitions) } else { None }).await?;

        if response.error_status != ErrorStatus::NoError {
            if v1 && response.error_status == ErrorStatus::NoSuchName {
                break;
            }
            return Err(Error::WalkAborted {
                status: response.error_status,
                index: response.error_index,
            });
        }
        if response.varbinds.is_empty() {
            break;
        }

        let mut stop = false;
        let mut progressed = false;
        for varbind in &response.varbinds {
            if varbind.value == SnmpValue::EndOfMibView {
                stop = true;
                break;
            }
            if !varbind.oid.starts_with(root) {
                stop = true;
                break;
            }
            if varbind.oid < current {
                // Backtrack: the agent walked outside the subtree and came
                // back. Reference walks terminate here rather than loop.
                stop = true;
                break;
            }
            if varbind.oid == current {
                // Echo quirk: agent returns the requested OID unchanged.
                continue;
            }
            results.push(varbind.clone());
            current = varbind.oid.clone();
            progressed = true;
        }

        if stop || !progressed {
            // ``stop`` is terminal. ``not progressed`` means the response only
            // echoed the requested OID back — zero progress, so terminate
            // instead of looping against an agent that never advances
            // (walk.py:99–105).
            break;
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::oid::Oid;
    use crate::types::value::SnmpValue;
    use crate::types::varbind::VarBind;
    use std::sync::Arc;

    fn oid(arcs: &[u32]) -> Oid {
        Oid::from_arcs(arcs).unwrap()
    }

    fn vb(arcs: &[u32], value: SnmpValue) -> VarBind {
        VarBind::new(oid(arcs), value)
    }

    fn response(varbinds: Vec<VarBind>) -> Response {
        Response {
            request_id: 1,
            error_status: ErrorStatus::NoError,
            error_index: 0,
            varbinds,
        }
    }

    #[tokio::test]
    async fn walks_entire_subtree_in_lexicographic_order() {
        let root = oid(&[1, 3, 6, 1, 2, 1, 2, 2]);
        let table: &'static [(Oid, SnmpValue)] = Box::leak(
            vec![
                (oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1]), SnmpValue::Integer(1)),
                (
                    oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2]),
                    SnmpValue::OctetString(b"eth0".to_vec()),
                ),
                (
                    oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 3]),
                    SnmpValue::Integer(1500),
                ),
                (oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 8]), SnmpValue::Integer(1)),
            ]
            .into_boxed_slice(),
        );
        let request_fn = move |current: &Oid, _max: Option<u32>| {
            let current = current.clone();
            async move {
                let next = table
                    .iter()
                    .find(|(oid, _)| oid > &current)
                    .map(|(oid, value)| vb(oid.arcs(), value.clone()))
                    .unwrap_or_else(|| vb(current.arcs(), SnmpValue::EndOfMibView));
                Ok(response(vec![next]))
            }
        };
        let results = walk_subtree(request_fn, &root, false, 10, false)
            .await
            .unwrap();
        assert_eq!(results.len(), 4);
        assert_eq!(results[0].oid, oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1]));
        assert_eq!(results[3].oid, oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 8]));
    }

    #[tokio::test]
    async fn stops_at_first_out_of_subtree_oid() {
        let root = oid(&[1, 3, 6, 1, 2, 1, 1]);
        let table: &'static [(Oid, SnmpValue)] = Box::leak(
            vec![
                (oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]), SnmpValue::TimeTicks(1)),
                (oid(&[1, 3, 6, 1, 2, 1, 2, 1, 0]), SnmpValue::Integer(1)),
            ]
            .into_boxed_slice(),
        );
        let request_fn = move |current: &Oid, _max: Option<u32>| {
            let current = current.clone();
            async move {
                let next = table
                    .iter()
                    .find(|(oid, _)| oid > &current)
                    .map(|(oid, value)| vb(oid.arcs(), value.clone()))
                    .unwrap_or_else(|| vb(current.arcs(), SnmpValue::EndOfMibView));
                Ok(response(vec![next]))
            }
        };
        let results = walk_subtree(request_fn, &root, false, 10, false)
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].oid, oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]));
    }

    #[tokio::test]
    async fn skips_echo_varbind_inside_a_progressing_response() {
        let root = oid(&[1, 3, 6, 1, 2, 1, 1, 3]);
        // One response carrying an echo of the requested OID PLUS a real
        // successor: the echo is dropped, the walk continues from the
        // successor.
        let successor = oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]);
        let responses = vec![
            response(vec![
                vb(&[1, 3, 6, 1, 2, 1, 1, 3], SnmpValue::Null),
                vb(&[1, 3, 6, 1, 2, 1, 1, 3, 0], SnmpValue::Integer(1)),
            ]),
            response(vec![vb(
                &[1, 3, 6, 1, 2, 1, 1, 3, 0],
                SnmpValue::EndOfMibView,
            )]),
        ];
        let responses = Arc::new(responses);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let request_fn = move |_current: &Oid, _max: Option<u32>| {
            let responses = Arc::clone(&responses);
            let calls = Arc::clone(&calls);
            async move {
                let index = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(responses[index].clone())
            }
        };
        let results = walk_subtree(request_fn, &root, false, 10, false)
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].oid, successor);
    }

    #[tokio::test]
    async fn terminates_on_zero_progress_echo() {
        let root = oid(&[1, 3, 6, 1, 2, 1, 1, 3]);
        // Agent only ever echoes the requested OID: zero progress, no loop.
        let request_fn = |_current: &Oid, _max: Option<u32>| async move {
            Ok(response(vec![vb(
                &[1, 3, 6, 1, 2, 1, 1, 3],
                SnmpValue::Null,
            )]))
        };
        let results = walk_subtree(request_fn, &root, false, 10, false)
            .await
            .unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn continues_after_agent_skips_ahead() {
        let root = oid(&[1, 3, 6, 1, 2, 1, 1, 3]);
        let c = oid(&[1, 3, 6, 1, 2, 1, 1, 3, 9]);
        let responses = vec![
            response(vec![vb(
                &[1, 3, 6, 1, 2, 1, 1, 3, 9],
                SnmpValue::Integer(1),
            )]),
            response(vec![vb(
                &[1, 3, 6, 1, 2, 1, 1, 3, 9],
                SnmpValue::EndOfMibView,
            )]),
        ];
        let responses = Arc::new(responses);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let request_fn = move |_current: &Oid, _max: Option<u32>| {
            let responses = Arc::clone(&responses);
            let calls = Arc::clone(&calls);
            async move {
                let index = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(responses[index].clone())
            }
        };
        let results = walk_subtree(request_fn, &root, false, 10, false)
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].oid, c);
    }

    #[tokio::test]
    async fn v1_no_such_name_ends_walk_cleanly() {
        let root = oid(&[1, 3, 6, 1, 2, 1, 99]);
        let request_fn = |_current: &Oid, _max: Option<u32>| async move {
            Ok(Response {
                request_id: 1,
                error_status: ErrorStatus::NoSuchName,
                error_index: 1,
                varbinds: Vec::new(),
            })
        };
        let results = walk_subtree(request_fn, &root, false, 10, true)
            .await
            .unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn non_v1_error_aborts_with_walk_error() {
        let root = oid(&[1, 3, 6, 1, 2, 1, 99]);
        let request_fn = |_current: &Oid, _max: Option<u32>| async move {
            Ok(Response {
                request_id: 1,
                error_status: ErrorStatus::TooBig,
                error_index: 3,
                varbinds: Vec::new(),
            })
        };
        let err = walk_subtree(request_fn, &root, false, 10, false)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Error::WalkAborted {
                status: ErrorStatus::TooBig,
                index: 3
            }
        ));
    }

    #[tokio::test]
    async fn stops_on_no_progress_after_two_rounds() {
        let root = oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]);
        // Agent keeps returning the same OID forever.
        let request_fn = |_current: &Oid, _max: Option<u32>| async move {
            Ok(response(vec![vb(
                &[1, 3, 6, 1, 2, 1, 1, 3, 0],
                SnmpValue::TimeTicks(1),
            )]))
        };
        let results = walk_subtree(request_fn, &root, false, 10, false)
            .await
            .unwrap();
        assert!(results.is_empty());
    }
}
