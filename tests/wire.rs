//! Ported wire-codec units from test_wire_codec.py, test_wire_values.py,
//! test_wire_bounds.py, test_wire_hardening.py, test_wire_v1.py, plus the
//! three locate_auth_params offset vectors from test_v3_wire.py (78/202/302).
//!
//! The three latin-1 community tests are re-specified as bytewise round-trips
//! (locked decision: community is `Vec<u8>`, no latin-1 fallback). Tests whose
//! invalid states are unrepresentable in Rust (e.g. Counter32 > u32::MAX,
//! negative OID arcs) are dropped or re-specified — see the module docs.
//!
//! Some internal tag-mismatch errors surface through rasn's structural decode
//! (mandated DER mode, §5.3a); those assertions pin `ProtocolError` without a
//! message, because rasn's error text differs from the reference's hand-rolled
//! wording.

use std::net::Ipv4Addr;

use trishul_snmp::codec::message::{SnmpMessage, SnmpVersion, decode_message, encode_message};
use trishul_snmp::codec::pdu::{
    Pdu, PduKind, V1TrapFields, decode_pdu, encode_pdu, response_error_status,
};
use trishul_snmp::codec::v3::locate_auth_params;
use trishul_snmp::codec::{decode_value, encode_value};
use trishul_snmp::error::ProtocolError;
use trishul_snmp::types::oid::Oid;
use trishul_snmp::types::value::SnmpValue;
use trishul_snmp::types::varbind::{ErrorStatus, VarBind};

// ── helpers ────────────────────────────────────────────────────────────────

fn hex(s: &str) -> Vec<u8> {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..compact.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&compact[i..i + 2], 16).unwrap())
        .collect()
}

fn oid(arcs: &[u32]) -> Oid {
    Oid::from_arcs(arcs).unwrap()
}

fn vb(arcs: &[u32], value: SnmpValue) -> VarBind {
    VarBind::new(oid(arcs), value)
}

fn sys_uptime_vb(value: SnmpValue) -> VarBind {
    vb(&[1, 3, 6, 1, 2, 1, 1, 3, 0], value)
}

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

fn get_pdu(request_id: u32) -> Pdu {
    pdu(
        PduKind::GetRequest,
        request_id,
        0,
        0,
        vec![sys_uptime_vb(SnmpValue::Null)],
    )
}

fn message(version: SnmpVersion, community: &[u8], pdu: Pdu) -> SnmpMessage {
    SnmpMessage {
        version,
        community: community.to_vec(),
        pdu,
    }
}

fn trap_pdu(generic_trap: u8, specific_trap: i32, agent_addr: Ipv4Addr, timestamp: u32) -> Pdu {
    Pdu {
        kind: PduKind::Trap,
        request_id: 0,
        error_status: 0,
        error_index: 0,
        varbinds: vec![sys_uptime_vb(SnmpValue::TimeTicks(timestamp))],
        v1_trap: Some(V1TrapFields {
            enterprise: oid(&[1, 3, 6, 1, 4, 1, 999]),
            agent_addr,
            generic_trap,
            specific_trap,
            timestamp,
        }),
    }
}

fn etlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if content.len() < 0x80 {
        out.push(content.len() as u8);
    } else {
        let mut bytes = Vec::new();
        let mut n = content.len();
        while n > 0 {
            bytes.push((n & 0xFF) as u8);
            n >>= 8;
        }
        bytes.reverse();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend(content);
    out
}

fn sint(value: i64) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1
        && ((bytes[0] == 0x00 && bytes[1] & 0x80 == 0)
            || (bytes[0] == 0xFF && bytes[1] & 0x80 == 0x80))
    {
        bytes.remove(0);
    }
    etlv(0x02, &bytes)
}

fn assert_protocol_error(result: Result<(), ProtocolError>) {
    assert!(result.is_err(), "expected ProtocolError");
}

// ── test_wire_codec.py ──────────────────────────────────────────────────────

#[test]
fn snmp_get_message_roundtrip() {
    let message = message(
        SnmpVersion::V1,
        b"public",
        pdu(
            PduKind::GetRequest,
            123,
            0,
            0,
            vec![sys_uptime_vb(SnmpValue::Null)],
        ),
    );
    let decoded = decode_message(&encode_message(&message).unwrap()).unwrap();
    assert_eq!(decoded.version, SnmpVersion::V1);
    assert_eq!(decoded.community, b"public");
    assert_eq!(decoded.pdu.kind, PduKind::GetRequest);
    assert_eq!(decoded.pdu.request_id, 123);
    assert_eq!(
        decoded.pdu.varbinds[0].oid,
        oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0])
    );
    assert_eq!(decoded.pdu.varbinds[0].value, SnmpValue::Null);
}

#[test]
fn snmp_response_message_roundtrip() {
    let message = message(
        SnmpVersion::V1,
        b"public",
        pdu(
            PduKind::Response,
            99,
            0,
            0,
            vec![
                sys_uptime_vb(SnmpValue::TimeTicks(12345)),
                vb(
                    &[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1],
                    SnmpValue::OctetString(b"eth0".to_vec()),
                ),
            ],
        ),
    );
    let decoded = decode_message(&encode_message(&message).unwrap()).unwrap();
    assert_eq!(decoded.pdu.kind, PduKind::Response);
    assert_eq!(decoded.pdu.request_id, 99);
    assert_eq!(decoded.pdu.varbinds[0].value, SnmpValue::TimeTicks(12345));
    assert_eq!(
        decoded.pdu.varbinds[1].value,
        SnmpValue::OctetString(b"eth0".to_vec())
    );
}

#[test]
fn community_bytes_roundtrip() {
    // Re-specification of test_snmp_message_community_latin1_roundtrip:
    // the community is bytewise, no latin-1 fallback.
    let message = message(
        SnmpVersion::V1,
        &[0xFF, 0xFE],
        pdu(
            PduKind::GetRequest,
            1,
            0,
            0,
            vec![sys_uptime_vb(SnmpValue::Null)],
        ),
    );
    let decoded = decode_message(&encode_message(&message).unwrap()).unwrap();
    assert_eq!(decoded.community, vec![0xFF, 0xFE]);
}

#[test]
fn varbind_construction() {
    // Re-specification of test_raw_varbind_builder_helpers against the single
    // public `VarBind` type (no RawVarBind split, §5.2).
    let null_vb = vb(&[1, 3, 6], SnmpValue::Null);
    let octet_vb = vb(&[1, 3, 6, 1], SnmpValue::OctetString(b"eth0".to_vec()));
    let ticks_vb = vb(&[1, 3, 6, 2], SnmpValue::TimeTicks(42));
    assert_eq!(null_vb.oid_str(), "1.3.6");
    assert_eq!(null_vb.value_type(), "null");
    assert_eq!(octet_vb.value_type(), "octet-string");
    assert_eq!(ticks_vb.value_type(), "timeticks");
}

// ── test_wire_values.py ─────────────────────────────────────────────────────

#[test]
fn encode_value_roundtrip_for_supported_types() {
    let cases: Vec<(SnmpValue, &str)> = vec![
        (SnmpValue::Integer(-128), "020180"),
        (SnmpValue::Integer(128), "02020080"),
        (SnmpValue::OctetString(b"eth0".to_vec()), "040465746830"),
        (SnmpValue::Null, "0500"),
        (
            SnmpValue::ObjectIdentifier(oid(&[1, 3, 6, 1, 4, 1, 128])),
            "06072b060104018100",
        ),
        (
            SnmpValue::IpAddress(Ipv4Addr::new(192, 0, 2, 1)),
            "4004c0000201",
        ),
        (SnmpValue::Counter32(128), "41020080"),
        (SnmpValue::Gauge32(7), "420107"),
        (SnmpValue::TimeTicks(12345), "43023039"),
        (SnmpValue::Opaque(vec![0x00, 0xFF]), "440200ff"),
        (SnmpValue::Counter64(2_u64.pow(40)), "4606010000000000"),
        (SnmpValue::NoSuchObject, "8000"),
        (SnmpValue::NoSuchInstance, "8100"),
        (SnmpValue::EndOfMibView, "8200"),
    ];
    for (value, encoded_hex) in cases {
        let encoded = encode_value(&value).unwrap();
        assert_eq!(hex(encoded_hex), encoded, "encode mismatch for {value:?}");
        assert_eq!(
            decode_value(&encoded).unwrap(),
            value,
            "round-trip mismatch"
        );
    }
}

#[test]
fn decode_value_rejects_unsupported_tag() {
    // test_decode_value_rejects_unsupported_tag (0x7f).
    let err = decode_value(&hex("7f00")).unwrap_err();
    assert_eq!(err.message, "Unsupported SNMP value tag 0x7f");
}

#[test]
fn decode_value_accepts_non_minimal_signed_integer() {
    // asn1.py applies minimality only to unsigned content; `02 02 00 01` is a
    // valid signed 1 (see also tests/rasn_pins.rs).
    assert_eq!(
        decode_value(&hex("02020001")).unwrap(),
        SnmpValue::Integer(1)
    );
}

#[test]
fn decode_value_rejects_non_minimal_counter32() {
    let err = decode_value(&hex("41020001")).unwrap_err();
    assert_eq!(err.message, "Counter32 content is not minimally encoded");
}

#[test]
fn decode_value_rejects_counter64_beyond_bound() {
    let data = [vec![0x46, 0x09], (1u128 << 64).to_be_bytes()[7..].to_vec()].concat();
    let err = decode_value(&data).unwrap_err();
    assert_eq!(
        err.message,
        "Counter64 value 18446744073709551616 exceeds maximum 18446744073709551615"
    );
}

#[test]
fn decode_value_rejects_counter32_beyond_bound() {
    let data = [vec![0x41, 0x05], (1u64 << 32).to_be_bytes()[3..].to_vec()].concat();
    let err = decode_value(&data).unwrap_err();
    assert_eq!(
        err.message,
        "Counter32 value 4294967296 exceeds maximum 4294967295"
    );
}

#[test]
fn decode_value_rejects_gauge32_beyond_bound() {
    let data = [vec![0x42, 0x05], (1u64 << 32).to_be_bytes()[3..].to_vec()].concat();
    let err = decode_value(&data).unwrap_err();
    assert_eq!(
        err.message,
        "Gauge32 value 4294967296 exceeds maximum 4294967295"
    );
}

#[test]
fn decode_value_rejects_timeticks_beyond_bound() {
    let data = [vec![0x43, 0x05], (1u64 << 32).to_be_bytes()[3..].to_vec()].concat();
    let err = decode_value(&data).unwrap_err();
    assert_eq!(
        err.message,
        "TimeTicks value 4294967296 exceeds maximum 4294967295"
    );
}

#[test]
fn decode_value_rejects_overwidth_signed_integer() {
    // The exact vector pinned as rasn's silent corruption in tests/rasn_pins.rs
    // (over-width strip → -1): our manual decoder must reject it instead
    // (content length > 8 octets, even though the magnitude would fit).
    let err = decode_value(&hex("020900FFFFFFFFFFFFFFFF")).unwrap_err();
    assert_eq!(err.message, "INTEGER content exceeds i64 bounds");
}

#[test]
fn bulk_field_getters_saturate_negative_raw_values() {
    // Architecture §5.3: getters saturate negative raw values to 0 (no
    // reference coverage — pins our own type contract).
    let pdu = Pdu {
        kind: PduKind::GetBulkRequest,
        request_id: 7,
        error_status: -5,
        error_index: -3,
        varbinds: Vec::new(),
        v1_trap: None,
    };
    assert_eq!(pdu.non_repeaters(), 0);
    assert_eq!(pdu.max_repetitions(), 0);
    let pdu = Pdu {
        kind: PduKind::GetBulkRequest,
        request_id: 7,
        error_status: 2,
        error_index: 10,
        varbinds: Vec::new(),
        v1_trap: None,
    };
    assert_eq!(pdu.non_repeaters(), 2);
    assert_eq!(pdu.max_repetitions(), 10);
}

#[test]
fn encode_value_accepts_exact_unsigned_bounds() {
    for value in [
        SnmpValue::Counter32(u32::MAX),
        SnmpValue::Gauge32(u32::MAX),
        SnmpValue::TimeTicks(u32::MAX),
        SnmpValue::Counter64(u64::MAX),
    ] {
        assert_eq!(decode_value(&encode_value(&value).unwrap()).unwrap(), value);
    }
}

#[test]
fn encode_value_counter64_max_uses_minimal_encoding() {
    assert_eq!(
        encode_value(&SnmpValue::Counter64(u64::MAX)).unwrap(),
        hex("460900ffffffffffffffff")
    );
    assert_eq!(
        encode_value(&SnmpValue::Counter32(u32::MAX)).unwrap(),
        hex("410500ffffffff")
    );
}

#[test]
fn decode_value_rejects_truncated_oid_first_subidentifier() {
    let err = decode_value(&hex("060181")).unwrap_err();
    assert_eq!(err.message, "Truncated base-128 value");
}

#[test]
fn decode_value_rejects_oversized_oid_first_subidentifier() {
    // First subidentifier 80 + 2**32; the split second arc exceeds u32.
    let err = decode_value(&hex("06059080808050")).unwrap_err();
    assert!(err.message.contains("exceeds maximum"), "{:?}", err.message);
}

#[test]
fn decode_value_rejects_trailing_content() {
    let err = decode_value(&hex("020105ff")).unwrap_err();
    assert_eq!(err.message, "Unexpected trailing BER content");
}

#[test]
fn decode_message_rejects_invalid_message_shape() {
    let bad_top_tag = hex("020101");
    let err = decode_message(&bad_top_tag).unwrap_err();
    assert_eq!(err.message, "Expected SNMP message SEQUENCE, found 0x02");

    // Wrong version field tag (OCTET STRING where INTEGER expected).
    let wrong_version_tag = etlv(
        0x30,
        &[
            etlv(0x04, &[0x01]),
            etlv(0x04, b"public"),
            encode_pdu(&get_pdu(1)).unwrap(),
        ]
        .concat(),
    );
    assert_protocol_error(decode_message(&wrong_version_tag).map(|_| ()));

    // Wrong community field tag (INTEGER where OCTET STRING expected).
    let wrong_community_tag = etlv(
        0x30,
        &[sint(1), sint(1), encode_pdu(&get_pdu(1)).unwrap()].concat(),
    );
    assert_protocol_error(decode_message(&wrong_community_tag).map(|_| ()));
}

#[test]
fn decode_pdu_rejects_invalid_shapes() {
    let valid_payload = [
        sint(1),
        sint(0),
        sint(0),
        etlv(
            0x30,
            &etlv(
                0x30,
                &[
                    encode_oid_content_vb_oid(),
                    encode_value(&SnmpValue::Null).unwrap(),
                ]
                .concat(),
            ),
        ),
    ]
    .concat();

    // The reference's 0xA8 rejection is inverted: REPORT is now supported
    // (PduKind::Report). Unsupported tag 0xA9 exercises the same path.
    let unsupported = etlv(0xA9, &valid_payload);
    let err = decode_pdu(&unsupported).unwrap_err();
    assert_eq!(err.message, "Unsupported PDU tag 0xa9");

    // Wrong request-id tag (OCTET STRING where INTEGER expected).
    let wrong_integer_tag = etlv(
        0xA0,
        &[etlv(0x04, &[0x01]), sint(0), sint(0), etlv(0x30, &[])].concat(),
    );
    assert_protocol_error(decode_pdu(&wrong_integer_tag).map(|_| ()));

    // Wrong varbind-list tag (INTEGER where SEQUENCE expected) — surfaced by
    // the strict manual list codec with the reference message.
    let wrong_varbind_list_tag = etlv(0xA0, &[sint(1), sint(0), sint(0), sint(0)].concat());
    let err = decode_pdu(&wrong_varbind_list_tag).unwrap_err();
    assert!(
        err.message
            .contains("Expected VarBindList SEQUENCE, found 0x02"),
        "{:?}",
        err.message
    );

    // Wrong varbind tag (INTEGER where VarBind SEQUENCE expected).
    let wrong_varbind_tag = etlv(
        0xA0,
        &[sint(1), sint(0), sint(0), etlv(0x30, &etlv(0x02, &[0x00]))].concat(),
    );
    let err = decode_pdu(&wrong_varbind_tag).unwrap_err();
    assert!(
        err.message
            .contains("Expected VarBind SEQUENCE, found 0x02"),
        "{:?}",
        err.message
    );

    // Wrong varbind OID tag (INTEGER where OBJECT IDENTIFIER expected) — this
    // one surfaces with the reference message from the manual Oid Decode.
    let wrong_oid_tag = etlv(
        0xA0,
        &[
            sint(1),
            sint(0),
            sint(0),
            etlv(
                0x30,
                &etlv(
                    0x30,
                    &[sint(1), encode_value(&SnmpValue::Null).unwrap()].concat(),
                ),
            ),
        ]
        .concat(),
    );
    let err = decode_pdu(&wrong_oid_tag).unwrap_err();
    // rasn wraps field-decode errors with the field name.
    assert!(
        err.message
            .contains("Expected OBJECT IDENTIFIER, found 0x02"),
        "{:?}",
        err.message
    );
}

/// The OID content bytes for `1.3.6.1.2.1.1.3.0` (matches the encoder output
/// of the reference `_valid_varbind`).
fn encode_oid_content_vb_oid() -> Vec<u8> {
    hex("06082b06010201010300")
}

#[test]
fn decode_pdu_accepts_report_tag() {
    // Inversion of the reference's `unsupported_tag` 0xA8 case: REPORT (0xA8)
    // is now a first-class kind (§5.3); the golden v2c-report fixture is the
    // authoritative byte test.
    let payload = [sint(1106), sint(0), sint(0), etlv(0x30, &[])].concat();
    let decoded = decode_pdu(&etlv(0xA8, &payload)).unwrap();
    assert_eq!(decoded.kind, PduKind::Report);
    assert_eq!(decoded.request_id, 1106);
}

#[test]
fn response_error_status_rejects_unknown_values() {
    let err = response_error_status(999).unwrap_err();
    assert_eq!(err.message, "Unsupported SNMP error-status value 999");
    assert_eq!(response_error_status(0).unwrap(), ErrorStatus::NoError);
    assert_eq!(response_error_status(2).unwrap(), ErrorStatus::NoSuchName);
}

// ── test_wire_hardening.py ──────────────────────────────────────────────────

#[test]
fn decode_message_rejects_unsupported_version() {
    let data = etlv(
        0x30,
        &[
            sint(2),
            etlv(0x04, b"public"),
            encode_pdu(&get_pdu(1)).unwrap(),
        ]
        .concat(),
    );
    let err = decode_message(&data).unwrap_err();
    assert_eq!(err.message, "Unsupported SNMP version 2");
}

#[test]
fn decode_message_rejects_empty_integer_content() {
    let data = etlv(
        0x30,
        &[
            etlv(0x02, &[]),
            etlv(0x04, b"public"),
            encode_pdu(&get_pdu(1)).unwrap(),
        ]
        .concat(),
    );
    assert_protocol_error(decode_message(&data).map(|_| ()));
}

#[test]
fn decode_message_accepts_non_utf8_community_bytes() {
    // Re-specification: community is bytewise, asserted as bytes.
    let data = etlv(
        0x30,
        &[
            sint(1),
            etlv(0x04, &[0xFF, 0xFE]),
            encode_pdu(&get_pdu(1)).unwrap(),
        ]
        .concat(),
    );
    let decoded = decode_message(&data).unwrap();
    assert_eq!(decoded.community, vec![0xFF, 0xFE]);
}

fn valid_message_bytes() -> Vec<u8> {
    encode_message(&message(SnmpVersion::V1, b"public", get_pdu(1))).unwrap()
}

#[test]
fn decode_message_rejects_wrong_request_id_tag() {
    let mut data = valid_message_bytes();
    let pdu_start = data.iter().position(|&b| b == 0xA0).unwrap() + 2;
    data[pdu_start] = 0x04; // replace request-id INTEGER (0x02) with OCTET STRING
    assert_protocol_error(decode_message(&data).map(|_| ()));
}

#[test]
fn decode_message_rejects_wrong_oid_tag() {
    let mut data = valid_message_bytes();
    let oid_len_pos = data.iter().position(|&b| b == 0x06).unwrap();
    data[oid_len_pos] = 0x02; // same mutation as the reference test
    assert_protocol_error(decode_message(&data).map(|_| ()));
}

#[test]
fn decode_message_rejects_trailing_bytes() {
    let mut data = valid_message_bytes();
    data.push(0x00);
    let err = decode_message(&data).unwrap_err();
    assert_eq!(err.message, "Unexpected trailing BER content");
}

#[test]
fn decode_pdu_rejects_empty_integer_content() {
    let data = etlv(
        0xA0,
        &[etlv(0x02, &[]), sint(0), sint(0), etlv(0x30, &[])].concat(),
    );
    assert_protocol_error(decode_pdu(&data).map(|_| ()));
}

#[test]
fn oid_from_arcs_rejects_invalid_first_arc() {
    // Re-specification of test_encode_message_rejects_invalid_oid_first_arc:
    // the Oid newtype rejects invalid arcs at construction (§8 early failure).
    let err = Oid::from_arcs(&[3, 0]).unwrap_err();
    assert_eq!(err.0, "First OID arc must be 0, 1, or 2");
}

// ── test_wire_v1.py ─────────────────────────────────────────────────────────

const SYS_UPTIME_OID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];

#[test]
fn v1_get_request_roundtrip_and_golden_bytes() {
    let message = message(
        SnmpVersion::V1,
        b"public",
        pdu(
            PduKind::GetRequest,
            123,
            0,
            0,
            vec![sys_uptime_vb(SnmpValue::Null)],
        ),
    );
    let encoded = encode_message(&message).unwrap();
    assert_eq!(
        encoded,
        hex("302602010004067075626c6963a01902017b020100020100300e300c06082b060102010103000500")
    );
    let decoded = decode_message(&encoded).unwrap();
    assert_eq!(decoded.version, SnmpVersion::V1);
    assert_eq!(decoded.community, b"public");
    assert_eq!(decoded.pdu.kind, PduKind::GetRequest);
    assert_eq!(decoded.pdu.request_id, 123);
    assert_eq!(decoded.pdu.varbinds[0].oid, oid(SYS_UPTIME_OID));
    assert_eq!(decoded.pdu.varbinds[0].value, SnmpValue::Null);
}

#[test]
fn v1_get_response_roundtrip_and_golden_bytes() {
    let message = message(
        SnmpVersion::V1,
        b"public",
        pdu(
            PduKind::Response,
            99,
            0,
            0,
            vec![
                sys_uptime_vb(SnmpValue::TimeTicks(123456)),
                vb(
                    &[1, 3, 6, 1, 2, 1, 1, 1, 0],
                    SnmpValue::OctetString(b"eth0".to_vec()),
                ),
            ],
        ),
    );
    let encoded = encode_message(&message).unwrap();
    assert_eq!(
        encoded,
        hex(concat!(
            "303b02010004067075626c6963a22e0201630201000201003023300f06082b06010201010300430301e240",
            "301006082b06010201010100040465746830"
        ))
    );
    let decoded = decode_message(&encoded).unwrap();
    assert_eq!(decoded.version, SnmpVersion::V1);
    assert_eq!(decoded.pdu.kind, PduKind::Response);
    assert_eq!(decoded.pdu.request_id, 99);
    assert_eq!(decoded.pdu.varbinds[0].value, SnmpValue::TimeTicks(123456));
    assert_eq!(
        decoded.pdu.varbinds[1].value,
        SnmpValue::OctetString(b"eth0".to_vec())
    );
}

#[test]
fn v1_trap_roundtrip_and_golden_bytes() {
    let message = message(
        SnmpVersion::V1,
        b"public",
        trap_pdu(0, 0, Ipv4Addr::new(192, 0, 2, 1), 123456),
    );
    let encoded = encode_message(&message).unwrap();
    assert_eq!(
        encoded,
        hex(concat!(
            "303a02010004067075626c6963a42d06072b0601040187674004c0000201020100020100430301e240",
            "3011300f06082b06010201010300430301e240"
        ))
    );
    let decoded = decode_message(&encoded).unwrap();
    assert_eq!(decoded.version, SnmpVersion::V1);
    assert_eq!(decoded.pdu.kind, PduKind::Trap);
    let trap = decoded.pdu.v1_trap.as_ref().unwrap();
    assert_eq!(trap.enterprise, oid(&[1, 3, 6, 1, 4, 1, 999]));
    assert_eq!(trap.agent_addr, Ipv4Addr::new(192, 0, 2, 1));
    assert_eq!(trap.generic_trap, 0);
    assert_eq!(trap.specific_trap, 0);
    assert_eq!(trap.timestamp, 123456);
    assert_eq!(decoded.pdu.varbinds[0].oid, oid(SYS_UPTIME_OID));
}

#[test]
fn v1_trap_datagram_decodes_from_raw_bytes() {
    // Raw v1 trap datagram (pysnmp-comparable case from issue #8).
    let raw = hex(concat!(
        "303a02010004067075626c6963a42d06072b0601040187674004cb007107020101020105430309fbf1",
        "3011300f06082b06010201010300430309fbf1",
    ));
    let decoded = decode_message(&raw).unwrap();
    assert_eq!(decoded.version, SnmpVersion::V1);
    assert_eq!(decoded.pdu.kind, PduKind::Trap);
    let trap = decoded.pdu.v1_trap.as_ref().unwrap();
    assert_eq!(trap.enterprise, oid(&[1, 3, 6, 1, 4, 1, 999]));
    assert_eq!(trap.agent_addr, Ipv4Addr::new(203, 0, 113, 7));
    assert_eq!(trap.generic_trap, 1);
    assert_eq!(trap.specific_trap, 5);
    assert_eq!(trap.timestamp, 654321);
    assert_eq!(decoded.pdu.varbinds[0].value, SnmpValue::TimeTicks(654321));
}

#[test]
fn v1_trap_roundtrip_for_each_generic_trap() {
    for generic_trap in 0..=6u8 {
        let message = message(
            SnmpVersion::V1,
            b"public",
            trap_pdu(generic_trap, 0, Ipv4Addr::new(192, 0, 2, 1), 123456),
        );
        let decoded = decode_message(&encode_message(&message).unwrap()).unwrap();
        assert_eq!(decoded.pdu.kind, PduKind::Trap);
        assert_eq!(
            decoded.pdu.v1_trap.as_ref().unwrap().generic_trap,
            generic_trap
        );
        assert_eq!(
            decoded.pdu.v1_trap.as_ref().unwrap().enterprise,
            oid(&[1, 3, 6, 1, 4, 1, 999])
        );
        assert_eq!(decoded.pdu.v1_trap.as_ref().unwrap().timestamp, 123456);
    }
}

#[test]
fn decode_pdu_handles_bare_trap_pdu() {
    let trap = trap_pdu(6, 42, Ipv4Addr::new(192, 0, 2, 1), 123456);
    assert_eq!(decode_pdu(&encode_pdu(&trap).unwrap()).unwrap(), trap);
}

#[test]
fn encode_rejects_generic_trap_out_of_range() {
    // generic_trap is u8 in V1TrapFields, so -1 is unrepresentable; 7 and 10
    // exercise the same rejection path.
    for generic_trap in [7u8, 10] {
        let err = encode_message(&message(
            SnmpVersion::V1,
            b"public",
            trap_pdu(generic_trap, 0, Ipv4Addr::new(192, 0, 2, 1), 123456),
        ))
        .unwrap_err();
        assert_eq!(
            err.message,
            format!("generic-trap {generic_trap} must be between 0 and 6")
        );
    }
}

fn raw_trap_payload(generic_trap: u8, specific_trap: u8, agent_addr: &[u8]) -> Vec<u8> {
    [
        hex("06072b060104018767"), // enterprise 1.3.6.1.4.1.999
        etlv(0x40, agent_addr),
        etlv(0x02, &[generic_trap]), // raw content octet, as the reference test
        etlv(0x02, &[specific_trap]),
        hex("430309fbf1"), // timestamp 654321
        etlv(0x30, &[]),   // empty varbind-list
    ]
    .concat()
}

#[test]
fn decode_rejects_generic_trap_out_of_range() {
    let raw = etlv(0xA4, &raw_trap_payload(7, 5, &[0xCB, 0x00, 0x71, 0x07]));
    let err = decode_pdu(&raw).unwrap_err();
    assert_eq!(err.message, "generic-trap 7 must be between 0 and 6");
}

#[test]
fn encode_rejects_negative_specific_trap() {
    let message = message(
        SnmpVersion::V1,
        b"public",
        trap_pdu(6, -1, Ipv4Addr::new(192, 0, 2, 1), 123456),
    );
    let err = encode_message(&message).unwrap_err();
    assert_eq!(err.message, "specific-trap -1 cannot be negative");
}

#[test]
fn decode_rejects_negative_specific_trap() {
    // 0xFF as INTEGER content decodes to -1.
    let raw = etlv(0xA4, &raw_trap_payload(1, 0xFF, &[0xCB, 0x00, 0x71, 0x07]));
    let err = decode_pdu(&raw).unwrap_err();
    assert_eq!(err.message, "specific-trap -1 cannot be negative");
}

#[test]
fn trap_agent_addr_requires_four_octets() {
    // The encode side is unrepresentable (agent_addr is Ipv4Addr, always four
    // octets); the decode side rejects short content.
    let raw = etlv(0xA4, &raw_trap_payload(1, 5, &[0xC0, 0x00, 0x02]));
    let err = decode_pdu(&raw).unwrap_err();
    // rasn wraps field-decode errors with the field name.
    assert!(
        err.message.contains("exactly four octets"),
        "{:?}",
        err.message
    );
}

#[test]
fn v1_community_bytes_roundtrip() {
    // Re-specification of test_v1_community_latin1_fallback.
    let message = message(
        SnmpVersion::V1,
        &[0xFF, 0xFE],
        trap_pdu(0, 0, Ipv4Addr::new(192, 0, 2, 1), 123456),
    );
    let decoded = decode_message(&encode_message(&message).unwrap()).unwrap();
    assert_eq!(decoded.community, vec![0xFF, 0xFE]);
    assert_eq!(decoded.pdu.kind, PduKind::Trap);
}

// ── test_v3_wire.py offset vectors (78/202/302) ─────────────────────────────

fn v3_usm_params(auth: &[u8]) -> Vec<u8> {
    let engine_id = [vec![0x80, 0x00, 0x1F, 0x88, 0x80], vec![0x00; 11]].concat();
    let content = [
        etlv(0x04, &engine_id),
        sint(5),
        sint(12345),
        etlv(0x04, b"simulator"),
        etlv(0x04, auth),
        etlv(0x04, &[]),
    ]
    .concat();
    etlv(0x30, &content)
}

fn v3_message(auth: &[u8]) -> Vec<u8> {
    let header = etlv(
        0x30,
        &[sint(9), sint(65507), etlv(0x04, &[0x05]), sint(3)].concat(),
    );
    let sp = etlv(0x04, &v3_usm_params(auth));
    let scoped = etlv(
        0x30,
        &[etlv(0x04, &[]), etlv(0x04, &[]), etlv(0x30, &[])].concat(),
    );
    etlv(0x30, &[sint(3), header, sp, scoped].concat())
}

#[test]
fn usm_params_auth_params_offset_points_to_content() {
    // test_v3_wire.py:78 — the offset points at the auth_params content bytes.
    let sentinel = [
        0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    ];
    let raw = v3_message(&sentinel);
    let offset = locate_auth_params(&raw).unwrap();
    assert_eq!(&raw[offset..offset + sentinel.len()], &sentinel);
}

#[test]
fn v3_message_auth_params_offset_is_correct() {
    // test_v3_wire.py:202 — full-message offset.
    let sentinel = [
        0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    ];
    let raw = v3_message(&sentinel);
    let offset = locate_auth_params(&raw).unwrap();
    assert_eq!(&raw[offset..offset + sentinel.len()], &sentinel);
}

#[test]
fn v3_message_auth_params_offset_non_canonical_length() {
    // test_v3_wire.py:302 — the outer SEQUENCE uses a non-canonical long-form
    // length; the offset must still point at the sentinel.
    let sentinel = [
        0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    ];
    let canonical = v3_message(&sentinel);
    assert_eq!(canonical[0], 0x30);
    let inner_len = canonical[1];
    assert!(inner_len < 0x80, "test assumption: short-form outer length");
    let non_canonical = [vec![0x30, 0x81, inner_len], canonical[2..].to_vec()].concat();

    let offset = locate_auth_params(&non_canonical).unwrap();
    assert_eq!(&non_canonical[offset..offset + sentinel.len()], &sentinel);
}
