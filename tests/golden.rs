//! Golden-bytes parity against fixtures/wire-golden/golden.json.
//!
//! 26 of 28 cases are consumed (the two `v3-*` cases gate in Phase 3 with USM
//! auth). For each case:
//!
//! * our encode of the reconstructed message == the golden bytes, and
//! * our decode of the golden bytes == the reconstructed message.
//!
//! `v2c-report` uses tag 0xA8 (`PduKind::Report`) which the Python library
//! cannot produce — this crate is its first consumer.

use std::net::Ipv4Addr;

mod common;

use serde_json::Value;

use trishul_snmp::codec::message::{SnmpMessage, SnmpVersion, decode_message, encode_message};
use trishul_snmp::codec::pdu::{Pdu, PduKind, V1TrapFields};
use trishul_snmp::types::value::SnmpValue;
use trishul_snmp::types::varbind::VarBind;

const GOLDEN: &str = include_str!("../fixtures/wire-golden/golden.json");

const SYSUPTIME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];
const SYSDESCR: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
const SYSNAME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 5, 0];
const SYSLOCATION: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 6, 0];
const SNMP_TRAP_OID: &[u32] = &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0];
const SNMP_TRAP_OID_VALUE: &[u32] = &[1, 3, 6, 1, 6, 3, 1, 1, 5, 1];
const USM_STATS_UNKNOWN_USERS: &[u32] = &[1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0];
const VALUE_OID_PREFIX: &[u32] = &[1, 3, 6, 1, 4, 1, 99999];

// `hex`/`oid`/`vb` come from `tests/common` (golden's former `unhex` ≡
// common's `hex`); the message builders below are golden-specific and stay
// local.
use common::{hex, oid, vb};

fn pdu(
    kind: PduKind,
    request_id: u32,
    error_status: i32,
    error_index: i32,
    varbinds: Vec<VarBind>,
) -> Pdu {
    Pdu {
        kind,
        request_id,
        error_status,
        error_index,
        varbinds,
        v1_trap: None,
    }
}

fn msg(version: SnmpVersion, pdu: Pdu) -> SnmpMessage {
    SnmpMessage {
        version,
        community: b"public".to_vec(),
        pdu,
    }
}

fn value_oid(index: u32) -> Vec<u32> {
    [VALUE_OID_PREFIX, &[index]].concat()
}

fn all_values() -> Vec<VarBind> {
    let values = [
        SnmpValue::Integer(42),
        SnmpValue::OctetString(b"hello".to_vec()),
        SnmpValue::Null,
        SnmpValue::ObjectIdentifier(oid(&[1, 3, 6, 1, 4, 1, 4242])),
        SnmpValue::IpAddress(Ipv4Addr::new(192, 0, 2, 1)),
        SnmpValue::Counter32(u32::MAX),
        SnmpValue::Gauge32(12345),
        SnmpValue::TimeTicks(123456),
        SnmpValue::Opaque(vec![0x00, 0xFF, 0x10]),
        SnmpValue::Counter64(2_u64.pow(40)),
        SnmpValue::NoSuchObject,
        SnmpValue::NoSuchInstance,
        SnmpValue::EndOfMibView,
    ];
    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| vb(&value_oid(index as u32 + 1), value))
        .collect()
}

/// Reconstructs each golden message from its documented parameters
/// (fixtures/wire-golden/generate.py is the provenance).
fn build(name: &str) -> SnmpMessage {
    match name {
        "value-integer" => msg(
            SnmpVersion::V2c,
            pdu(
                PduKind::Response,
                2001,
                0,
                0,
                vec![vb(&value_oid(1), SnmpValue::Integer(42))],
            ),
        ),
        "value-octet-string" => msg(
            SnmpVersion::V2c,
            pdu(
                PduKind::Response,
                2002,
                0,
                0,
                vec![vb(&value_oid(2), SnmpValue::OctetString(b"hello".to_vec()))],
            ),
        ),
        "value-null" => msg(
            SnmpVersion::V2c,
            pdu(
                PduKind::Response,
                2003,
                0,
                0,
                vec![vb(&value_oid(3), SnmpValue::Null)],
            ),
        ),
        "value-object-identifier" => msg(
            SnmpVersion::V2c,
            pdu(
                PduKind::Response,
                2004,
                0,
                0,
                vec![vb(
                    &value_oid(4),
                    SnmpValue::ObjectIdentifier(oid(&[1, 3, 6, 1, 4, 1, 4242])),
                )],
            ),
        ),
        "value-ip-address" => msg(
            SnmpVersion::V2c,
            pdu(
                PduKind::Response,
                2005,
                0,
                0,
                vec![vb(
                    &value_oid(5),
                    SnmpValue::IpAddress(Ipv4Addr::new(192, 0, 2, 1)),
                )],
            ),
        ),
        "value-counter32" => msg(
            SnmpVersion::V2c,
            pdu(
                PduKind::Response,
                2006,
                0,
                0,
                vec![vb(&value_oid(6), SnmpValue::Counter32(u32::MAX))],
            ),
        ),
        "value-gauge32" => msg(
            SnmpVersion::V2c,
            pdu(
                PduKind::Response,
                2007,
                0,
                0,
                vec![vb(&value_oid(7), SnmpValue::Gauge32(12345))],
            ),
        ),
        "value-timeticks" => msg(
            SnmpVersion::V2c,
            pdu(
                PduKind::Response,
                2008,
                0,
                0,
                vec![vb(&value_oid(8), SnmpValue::TimeTicks(123456))],
            ),
        ),
        "value-opaque" => msg(
            SnmpVersion::V2c,
            pdu(
                PduKind::Response,
                2009,
                0,
                0,
                vec![vb(&value_oid(9), SnmpValue::Opaque(vec![0x00, 0xFF, 0x10]))],
            ),
        ),
        "value-counter64" => msg(
            SnmpVersion::V2c,
            pdu(
                PduKind::Response,
                2010,
                0,
                0,
                vec![vb(&value_oid(10), SnmpValue::Counter64(2_u64.pow(40)))],
            ),
        ),
        "value-no-such-object" => msg(
            SnmpVersion::V2c,
            pdu(
                PduKind::Response,
                2011,
                0,
                0,
                vec![vb(&value_oid(11), SnmpValue::NoSuchObject)],
            ),
        ),
        "value-no-such-instance" => msg(
            SnmpVersion::V2c,
            pdu(
                PduKind::Response,
                2012,
                0,
                0,
                vec![vb(&value_oid(12), SnmpValue::NoSuchInstance)],
            ),
        ),
        "value-end-of-mib-view" => msg(
            SnmpVersion::V2c,
            pdu(
                PduKind::Response,
                2013,
                0,
                0,
                vec![vb(&value_oid(13), SnmpValue::EndOfMibView)],
            ),
        ),
        "value-all-types" => msg(
            SnmpVersion::V2c,
            pdu(PduKind::Response, 2014, 0, 0, all_values()),
        ),
        "v1-get" => msg(
            SnmpVersion::V1,
            pdu(
                PduKind::GetRequest,
                1001,
                0,
                0,
                vec![
                    vb(SYSUPTIME, SnmpValue::Null),
                    vb(SYSDESCR, SnmpValue::Null),
                ],
            ),
        ),
        "v1-getnext" => msg(
            SnmpVersion::V1,
            pdu(
                PduKind::GetNextRequest,
                1002,
                0,
                0,
                vec![vb(&[1, 3, 6, 1, 2, 1], SnmpValue::Null)],
            ),
        ),
        "v1-set" => msg(
            SnmpVersion::V1,
            pdu(
                PduKind::SetRequest,
                1003,
                0,
                0,
                vec![
                    vb(SYSLOCATION, SnmpValue::OctetString(b"server room".to_vec())),
                    vb(SYSNAME, SnmpValue::OctetString(b"goldengate".to_vec())),
                ],
            ),
        ),
        "v1-response" => msg(
            SnmpVersion::V1,
            pdu(
                PduKind::Response,
                1004,
                0,
                0,
                vec![
                    vb(
                        SYSDESCR,
                        SnmpValue::OctetString(b"golden v1 agent".to_vec()),
                    ),
                    vb(SYSUPTIME, SnmpValue::TimeTicks(654321)),
                ],
            ),
        ),
        "v1-trap" => msg(
            SnmpVersion::V1,
            Pdu {
                kind: PduKind::Trap,
                request_id: 0,
                error_status: 0,
                error_index: 0,
                varbinds: vec![vb(SYSUPTIME, SnmpValue::TimeTicks(123456))],
                v1_trap: Some(V1TrapFields {
                    enterprise: oid(&[1, 3, 6, 1, 4, 1, 8072]),
                    agent_addr: Ipv4Addr::new(127, 0, 0, 1),
                    generic_trap: 0,
                    specific_trap: 0,
                    timestamp: 123456,
                }),
            },
        ),
        "v2c-get" => msg(
            SnmpVersion::V2c,
            pdu(
                PduKind::GetRequest,
                1101,
                0,
                0,
                vec![vb(SYSUPTIME, SnmpValue::Null)],
            ),
        ),
        "v2c-getnext" => msg(
            SnmpVersion::V2c,
            pdu(
                PduKind::GetNextRequest,
                1102,
                0,
                0,
                vec![vb(&[1, 3, 6, 1, 2, 1, 2], SnmpValue::Null)],
            ),
        ),
        "v2c-getbulk" => msg(
            SnmpVersion::V2c,
            pdu(
                PduKind::GetBulkRequest,
                1103,
                1,
                2,
                vec![
                    vb(SYSDESCR, SnmpValue::Null),
                    vb(&[1, 3, 6, 1, 2, 1, 2, 1], SnmpValue::Null),
                ],
            ),
        ),
        "v2c-response-error" => msg(
            SnmpVersion::V2c,
            pdu(
                PduKind::Response,
                1104,
                2,
                1,
                vec![
                    vb(SYSDESCR, SnmpValue::Null),
                    vb(&[1, 3, 6, 1, 2, 1, 99, 99], SnmpValue::NoSuchInstance),
                ],
            ),
        ),
        "v2c-inform" => msg(
            SnmpVersion::V2c,
            pdu(
                PduKind::InformRequest,
                1105,
                0,
                0,
                vec![
                    vb(SYSUPTIME, SnmpValue::TimeTicks(42)),
                    vb(
                        SNMP_TRAP_OID,
                        SnmpValue::ObjectIdentifier(oid(SNMP_TRAP_OID_VALUE)),
                    ),
                ],
            ),
        ),
        "v2c-snmpv2-trap" => msg(
            SnmpVersion::V2c,
            pdu(
                PduKind::SnmpV2Trap,
                0,
                0,
                0,
                vec![
                    vb(SYSUPTIME, SnmpValue::TimeTicks(42)),
                    vb(
                        SNMP_TRAP_OID,
                        SnmpValue::ObjectIdentifier(oid(SNMP_TRAP_OID_VALUE)),
                    ),
                ],
            ),
        ),
        "v2c-report" => msg(
            SnmpVersion::V2c,
            pdu(
                PduKind::Report,
                1106,
                0,
                0,
                vec![vb(USM_STATS_UNKNOWN_USERS, SnmpValue::Counter32(1))],
            ),
        ),
        other => panic!("golden case {other} has no reconstruction"),
    }
}

#[test]
fn golden_encode_and_decode_parity() {
    let value: Value = serde_json::from_str(GOLDEN).expect("golden.json parses");
    let cases = value["cases"].as_array().expect("cases is an array");
    let mut consumed = 0;
    let mut skipped = 0;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        if name.starts_with("v3-") {
            skipped += 1;
            continue;
        }
        let expected = hex(case["hex"].as_str().unwrap());
        let message = build(name);

        let encoded =
            encode_message(&message).unwrap_or_else(|e| panic!("{name}: encode failed: {e}"));
        assert_eq!(
            encoded, expected,
            "{name}: encoded bytes differ from golden"
        );

        let decoded =
            decode_message(&expected).unwrap_or_else(|e| panic!("{name}: decode failed: {e}"));
        assert_eq!(decoded, message, "{name}: decoded structure differs");

        consumed += 1;
    }
    assert_eq!(consumed, 26, "expected 26 non-v3 golden cases");
    assert_eq!(skipped, 2, "expected 2 v3 golden cases to be skipped");
}
