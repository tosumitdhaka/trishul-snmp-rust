//! V1 GETBULK→GETNEXT downgrade (← client.py:229–308)

use crate::error::Error;
use crate::manager::Manager;
use crate::target::{Target, normalize_targets};
use crate::types::value::SnmpValue;
use crate::types::varbind::{ErrorStatus, Response, VarBind};

/// Implements GETBULK semantics for v1 managers by downgrading to repeated
/// GETNEXT requests (← client.py:V1Manager.get_bulk, client.py:229–308).
///
/// - the first `non_repeaters` OIDs are fetched once each;
/// - the remaining OIDs are fetched `max_repetitions` times, interleaved in
///   repetition-major order (column-major: one GETNEXT per column per round);
/// - a `noSuchName` from the v1 agent contributes an `EndOfMibView` slot and
///   retires that column;
/// - any other error status aborts the composite and returns the failing
///   response's status/index with the varbinds collected so far.
pub(crate) async fn v1_get_bulk(
    manager: &Manager,
    targets: impl IntoIterator<Item = impl Into<Target>>,
    non_repeaters: u32,
    max_repetitions: u32,
) -> Result<Response, Error> {
    let targets: Vec<Target> = targets.into_iter().map(Into::into).collect();
    let oids = normalize_targets(&targets)?;
    let split = (non_repeaters as usize).min(oids.len());

    let mut collected: Vec<VarBind> = Vec::new();
    let mut last_request_id: u32 = 0;

    // Non-repeater columns: single GETNEXT each.
    for oid in &oids[..split] {
        let response = manager.get_next_oid(oid).await?;
        last_request_id = response.request_id;
        match response.error_status {
            ErrorStatus::NoError => {
                if let Some(varbind) = response.varbinds.first() {
                    collected.push(varbind.clone());
                }
            }
            ErrorStatus::NoSuchName => {
                collected.push(VarBind::new(oid.clone(), SnmpValue::EndOfMibView));
            }
            status => {
                return Ok(error_response(
                    last_request_id,
                    status,
                    response.error_index,
                    collected,
                ));
            }
        }
    }

    // Repeater columns: repetition-major interleaved GETNEXTs.
    let mut current: Vec<Option<crate::types::oid::Oid>> =
        oids[split..].iter().cloned().map(Some).collect();
    for _round in 0..max_repetitions {
        for column in current.iter_mut() {
            let Some(oid) = column.as_ref() else {
                continue;
            };
            let response = manager.get_next_oid(oid).await?;
            last_request_id = response.request_id;
            match response.error_status {
                ErrorStatus::NoError => {
                    if let Some(varbind) = response.varbinds.first() {
                        if varbind.value == SnmpValue::EndOfMibView {
                            *column = None;
                        } else {
                            *column = Some(varbind.oid.clone());
                        }
                        collected.push(varbind.clone());
                    } else {
                        *column = None;
                    }
                }
                ErrorStatus::NoSuchName => {
                    collected.push(VarBind::new(oid.clone(), SnmpValue::EndOfMibView));
                    *column = None;
                }
                status => {
                    return Ok(error_response(
                        last_request_id,
                        status,
                        response.error_index,
                        collected,
                    ));
                }
            }
        }
    }

    Ok(Response {
        request_id: last_request_id,
        error_status: ErrorStatus::NoError,
        error_index: 0,
        varbinds: collected,
    })
}

fn error_response(
    request_id: u32,
    status: ErrorStatus,
    index: u32,
    collected: Vec<VarBind>,
) -> Response {
    Response {
        request_id,
        error_status: status,
        error_index: index,
        varbinds: collected,
    }
}
