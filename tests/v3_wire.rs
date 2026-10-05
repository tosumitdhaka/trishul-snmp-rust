//! Ported test_v3_wire.py (16 functions deferred from Phase 1) — the
//! UsmSecurityParameters / ScopedPDU / V3Message codecs now complete in
//! `codec::v3`. The reference's private `_encode_usm_params` /
//! `_decode_usm_params_with_offset` are exercised here at the full-message
//! level (the message offset is what USM verification uses); the
//! non-canonical-length and offset vectors already live in tests/wire.rs.

use trishul_snmp::codec::pdu::{Pdu, PduKind};
use trishul_snmp::codec::v3::{
    MSG_FLAG_AUTH, MSG_FLAG_PRIV, MSG_FLAG_REPORTABLE, UsmSecurityParameters, decode_scoped_pdu,
    decode_v3_message, encode_scoped_pdu, encode_v3_message,
};
use trishul_snmp::error::ProtocolError;
use trishul_snmp::types::oid::Oid;
use trishul_snmp::types::value::SnmpValue;
use trishul_snmp::types::varbind::VarBind;

fn engine_id() -> Vec<u8> {
    vec![
        0x80, 0x00, 0x1f, 0x88, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
}

fn get_pdu(request_id: u32) -> Pdu {
    Pdu {
        kind: PduKind::GetRequest,
        request_id,
        error_status: 0,
        error_index: 0,
        varbinds: vec![VarBind::new(
            Oid::from_arcs(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap(),
            SnmpValue::Null,
        )],
        v1_trap: None,
    }
}

fn usm(auth: &[u8], priv_params: &[u8]) -> UsmSecurityParameters {
    UsmSecurityParameters {
        engine_id: engine_id(),
        engine_boots: 5,
        engine_time: 12345,
        username: b"simulator".to_vec(),
        auth_params: auth.to_vec(),
        priv_params: priv_params.to_vec(),
    }
}

// ── UsmSecurityParameters roundtrips (message-level) ────────────────────────

#[test]
fn usm_params_roundtrip_no_auth_no_priv() {
    let params = usm(&[], &[]);
    let scoped = encode_scoped_pdu(&params.engine_id, b"", &get_pdu(1)).unwrap();
    let raw = encode_v3_message(1, 65507, MSG_FLAG_REPORTABLE, &params, &scoped).unwrap();
    let view = decode_v3_message(&raw).unwrap();
    assert_eq!(view.usm_params.engine_id, params.engine_id);
    assert_eq!(view.usm_params.engine_boots, params.engine_boots);
    assert_eq!(view.usm_params.engine_time, params.engine_time);
    assert_eq!(view.usm_params.username, params.username);
    assert_eq!(view.usm_params.auth_params, b"");
    assert_eq!(view.usm_params.priv_params, b"");
}

#[test]
fn usm_params_roundtrip_with_auth_and_priv() {
    let params = usm(&[0xaa; 12], &[0xbb; 8]);
    // PRIV set: msgData is an encryptedPDU OCTET STRING.
    let msg_data = vec![0x04, 0x03, 0xde, 0xad, 0xbe];
    let raw = encode_v3_message(
        1,
        65507,
        MSG_FLAG_AUTH | MSG_FLAG_PRIV | MSG_FLAG_REPORTABLE,
        &params,
        &msg_data,
    )
    .unwrap();
    let view = decode_v3_message(&raw).unwrap();
    assert_eq!(view.usm_params.auth_params, vec![0xaa; 12]);
    assert_eq!(view.usm_params.priv_params, vec![0xbb; 8]);
}

#[test]
fn usm_params_auth_params_offset_points_to_content() {
    // The offset points at the auth_params *content* (past tag+length) within
    // the full message — exactly what USM verification zero-fills.
    let sentinel = [
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    ];
    let params = usm(&sentinel, &[]);
    let scoped = encode_scoped_pdu(&params.engine_id, b"", &get_pdu(1)).unwrap();
    let raw = encode_v3_message(1, 65507, MSG_FLAG_AUTH, &params, &scoped).unwrap();
    let offset = decode_v3_message(&raw).unwrap().auth_params_offset;
    assert_eq!(&raw[offset..offset + sentinel.len()], &sentinel);
}

// ── ScopedPDU roundtrips ────────────────────────────────────────────────────

#[test]
fn scoped_pdu_roundtrip_basic() {
    let pdu = get_pdu(1);
    let encoded = encode_scoped_pdu(&engine_id(), b"", &pdu).unwrap();
    let (dec_engine, dec_ctx, dec_pdu) = decode_scoped_pdu(&encoded).unwrap();
    assert_eq!(dec_engine, engine_id());
    assert!(dec_ctx.is_empty());
    assert_eq!(dec_pdu.kind, PduKind::GetRequest);
    assert_eq!(dec_pdu.request_id, 1);
    assert_eq!(dec_pdu.varbinds[0].value, SnmpValue::Null);
    assert_eq!(
        dec_pdu.varbinds[0].oid,
        Oid::from_arcs(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap()
    );
}

#[test]
fn scoped_pdu_roundtrip_with_context_name() {
    let pdu = get_pdu(9);
    let context = b"public-ctx".to_vec();
    let encoded = encode_scoped_pdu(&engine_id(), &context, &pdu).unwrap();
    let (dec_engine, dec_ctx, dec_pdu) = decode_scoped_pdu(&encoded).unwrap();
    assert_eq!(dec_engine, engine_id());
    assert_eq!(dec_ctx, context);
    assert_eq!(dec_pdu.request_id, 9);
}

// ── V3Message roundtrips ────────────────────────────────────────────────────

#[test]
fn v3_message_roundtrip_no_auth_no_priv() {
    let params = usm(&[], &[]);
    let scoped = encode_scoped_pdu(&params.engine_id, b"", &get_pdu(42)).unwrap();
    let raw = encode_v3_message(101, 65507, MSG_FLAG_REPORTABLE, &params, &scoped).unwrap();
    let view = decode_v3_message(&raw).unwrap();
    assert_eq!(view.msg_id, 101);
    assert_eq!(view.msg_max_size, 65507);
    assert_eq!(view.msg_flags, MSG_FLAG_REPORTABLE);
    assert_eq!(view.msg_security_model, 3);
    assert_eq!(view.usm_params, params);
}

#[test]
fn v3_message_roundtrip_auth_only() {
    let params = usm(&[0u8; 12], &[]);
    let scoped = encode_scoped_pdu(&params.engine_id, b"", &get_pdu(1)).unwrap();
    let raw = encode_v3_message(
        1,
        65507,
        MSG_FLAG_AUTH | MSG_FLAG_REPORTABLE,
        &params,
        &scoped,
    )
    .unwrap();
    let view = decode_v3_message(&raw).unwrap();
    assert_eq!(view.msg_flags & MSG_FLAG_AUTH, MSG_FLAG_AUTH);
    assert_eq!(view.usm_params.auth_params, vec![0u8; 12]);
}

#[test]
fn v3_message_roundtrip_auth_priv() {
    let params = usm(&[0u8; 12], &[0x01; 8]);
    // PRIV set: msgData is an encryptedPDU OCTET STRING.
    let msg_data = vec![0x04, 0x03, 0xde, 0xad, 0xbe];
    let raw = encode_v3_message(
        7,
        65507,
        MSG_FLAG_AUTH | MSG_FLAG_PRIV | MSG_FLAG_REPORTABLE,
        &params,
        &msg_data,
    )
    .unwrap();
    let view = decode_v3_message(&raw).unwrap();
    assert_eq!(view.msg_flags & MSG_FLAG_PRIV, MSG_FLAG_PRIV);
    assert_eq!(view.usm_params.priv_params, vec![0x01; 8]);
    assert_eq!(view.msg_data_bytes, msg_data);
}

#[test]
fn v3_message_auth_params_offset_is_correct() {
    let params = usm(&[0u8; 24], &[]);
    let scoped = encode_scoped_pdu(&params.engine_id, b"ctx", &get_pdu(1)).unwrap();
    let raw = encode_v3_message(
        1,
        65507,
        MSG_FLAG_AUTH | MSG_FLAG_REPORTABLE,
        &params,
        &scoped,
    )
    .unwrap();
    let offset = decode_v3_message(&raw).unwrap().auth_params_offset;
    assert_eq!(&raw[offset..offset + 24], &[0u8; 24]);
}

#[test]
fn v3_message_scoped_pdu_survives_roundtrip() {
    let params = usm(&[], &[]);
    let pdu = get_pdu(77);
    let scoped = encode_scoped_pdu(&params.engine_id, b"", &pdu).unwrap();
    let raw = encode_v3_message(1, 65507, MSG_FLAG_REPORTABLE, &params, &scoped).unwrap();
    let view = decode_v3_message(&raw).unwrap();
    let (eid, ctx, decoded_pdu) = decode_scoped_pdu(&view.msg_data_bytes).unwrap();
    assert_eq!(eid, params.engine_id);
    assert!(ctx.is_empty());
    assert_eq!(decoded_pdu, pdu);
}

// ── decode error cases ──────────────────────────────────────────────────────

#[test]
fn decode_v3_message_wrong_tag() {
    let err = decode_v3_message(&[0x02, 0x01, 0x03]).unwrap_err();
    assert!(
        err.to_string()
            .contains("Expected SNMPv3 message SEQUENCE, found 0x02")
    );
}

#[test]
fn decode_v3_message_wrong_version() {
    let params = usm(&[], &[]);
    let scoped = encode_scoped_pdu(&params.engine_id, b"", &get_pdu(1)).unwrap();
    let raw = encode_v3_message(1, 65507, 0, &params, &scoped).unwrap();
    let mut bytes = raw.clone();
    bytes[4] = 0x02; // version value 3 -> 2
    let err = decode_v3_message(&bytes).unwrap_err();
    assert!(
        err.to_string()
            .contains("Expected SNMPv3 version 3, found 2")
    );
}

#[test]
fn decode_scoped_pdu_wrong_tag() {
    let err = decode_scoped_pdu(&[0x04, 0x01, 0x00]).unwrap_err();
    assert!(
        err.to_string()
            .contains("Expected ScopedPDU SEQUENCE, found 0x04")
    );
}

#[test]
fn decode_scoped_pdu_trailing_bytes() {
    let params = usm(&[], &[]);
    let scoped = encode_scoped_pdu(&params.engine_id, b"", &get_pdu(1)).unwrap();
    let mut bytes = scoped.clone();
    bytes.push(0x00);
    let err = decode_scoped_pdu(&bytes).unwrap_err();
    assert!(err.to_string().contains("Unexpected trailing"));
}

#[test]
fn decode_v3_message_missing_scoped_pdu_raises() {
    // A message whose msgData is empty: the msgData TLV read runs out of bytes.
    let params = usm(&[], &[]);
    let raw = encode_v3_message(1, 65507, MSG_FLAG_REPORTABLE, &params, &[]).unwrap();
    let err = decode_v3_message(&raw).unwrap_err();
    let _: &ProtocolError = &err;
    assert!(!err.to_string().is_empty());
}

#[test]
fn v3_message_auth_params_offset_non_canonical_length() {
    // Long-form (non-canonical) outer length must not shift the offset.
    let params = usm(&[0u8; 24], &[]);
    let scoped = encode_scoped_pdu(&params.engine_id, b"", &get_pdu(1)).unwrap();
    let raw = encode_v3_message(1, 65507, MSG_FLAG_AUTH, &params, &scoped).unwrap();
    let inner_len = raw[1];
    let mut non_canonical = vec![0x30, 0x81, inner_len];
    non_canonical.extend_from_slice(&raw[2..]);
    let offset = decode_v3_message(&non_canonical)
        .unwrap()
        .auth_params_offset;
    assert_eq!(&non_canonical[offset..offset + 24], &[0u8; 24]);
}

#[test]
fn decode_v3_message_priv_set_but_sequence_msgdata_raises() {
    let params = usm(&[], &[]);
    // PRIV set, but msgData is a ScopedPDU SEQUENCE.
    let scoped = encode_scoped_pdu(&params.engine_id, b"", &get_pdu(1)).unwrap();
    let raw = encode_v3_message(1, 65507, MSG_FLAG_PRIV, &params, &scoped).unwrap();
    let err = decode_v3_message(&raw).unwrap_err();
    assert!(
        err.to_string()
            .contains("Expected msgData as encryptedPDU OCTET STRING")
    );
}

#[test]
fn decode_v3_message_priv_clear_but_octet_string_msgdata_raises() {
    let params = usm(&[], &[]);
    // PRIV clear, but msgData is an encryptedPDU OCTET STRING.
    let msg_data = vec![0x04, 0x03, 0xde, 0xad, 0xbe];
    let raw = encode_v3_message(1, 65507, MSG_FLAG_REPORTABLE, &params, &msg_data).unwrap();
    let err = decode_v3_message(&raw).unwrap_err();
    assert!(
        err.to_string()
            .contains("Expected msgData as ScopedPDU SEQUENCE")
    );
}
