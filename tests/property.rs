//! Proptest replacement for test_wire_fuzz.py (21 functions + 3 internal-API
//! targets folded into public-surface properties):
//!
//! * arbitrary bytes → the public decoders never panic and only ever return
//!   `Ok` or `Err(ProtocolError)`;
//! * every SNMP value type survives encode → decode round trips;
//! * OID construction rules hold.
//!
//! The reference's internal-API fuzz targets (`decode_tlv`, `decode_length`,
//! `_decode_oid`) are exercised through the public surfaces that use them.

use std::net::Ipv4Addr;
use std::sync::Arc;

mod common;

use proptest::prelude::*;

use trishul_snmp::codec::message::decode_message;
use trishul_snmp::codec::pdu::{Pdu, PduKind, decode_pdu};
use trishul_snmp::codec::v3::{
    UsmSecurityParameters, decode_v3_message, encode_scoped_pdu, encode_v3_message,
    locate_auth_params,
};
use trishul_snmp::codec::{decode_value, encode_value};
use trishul_snmp::security::usm::kdf::{AuthProtocol, PrivProtocol};
use trishul_snmp::security::usm::privacy::{aes_cfb_decrypt, tripledes_decrypt, tripledes_encrypt};
use trishul_snmp::security::usm::{AuthKey, PrivKey, UsmModel, UsmUser};
use trishul_snmp::types::oid::Oid;
use trishul_snmp::types::value::SnmpValue;
use trishul_snmp::types::varbind::VarBind;

fn oid_strategy() -> impl Strategy<Value = Oid> {
    (
        0..=2u32,
        any::<u32>(),
        prop::collection::vec(any::<u32>(), 0..8),
    )
        .prop_map(|(first, second_raw, tail)| {
            let second = if first < 2 {
                second_raw % 40
            } else {
                second_raw
            };
            let mut arcs = vec![first, second];
            arcs.extend(tail);
            Oid::from_arcs(&arcs).unwrap()
        })
}

fn snmp_value_strategy() -> impl Strategy<Value = SnmpValue> {
    prop_oneof![
        any::<i64>().prop_map(SnmpValue::Integer),
        prop::collection::vec(any::<u8>(), 0..64).prop_map(SnmpValue::OctetString),
        Just(SnmpValue::Null),
        oid_strategy().prop_map(SnmpValue::ObjectIdentifier),
        any::<[u8; 4]>().prop_map(|octets| SnmpValue::IpAddress(Ipv4Addr::from(octets))),
        any::<u32>().prop_map(SnmpValue::Counter32),
        any::<u32>().prop_map(SnmpValue::Gauge32),
        any::<u32>().prop_map(SnmpValue::TimeTicks),
        prop::collection::vec(any::<u8>(), 0..64).prop_map(SnmpValue::Opaque),
        any::<u64>().prop_map(SnmpValue::Counter64),
        Just(SnmpValue::NoSuchObject),
        Just(SnmpValue::NoSuchInstance),
        Just(SnmpValue::EndOfMibView),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    // ── arbitrary input never leaks an unexpected exception ────────────────
    // A panic would fail the test; the only failure type is ProtocolError.

    #[test]
    fn decode_message_never_panics(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = decode_message(&data);
    }

    #[test]
    fn decode_pdu_never_panics(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = decode_pdu(&data);
    }

    #[test]
    fn decode_value_never_panics(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = decode_value(&data);
    }

    #[test]
    fn locate_auth_params_never_panics(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = locate_auth_params(&data);
    }

    // ── round trips for every SNMP value type ──────────────────────────────

    #[test]
    fn snmp_value_round_trip(v in snmp_value_strategy()) {
        // All 13 value types through the wire format.
        let encoded = encode_value(&v).unwrap();
        prop_assert_eq!(decode_value(&encoded).unwrap(), v);
    }

    #[test]
    fn integer_round_trip(v in any::<i64>()) {
        let encoded = encode_value(&SnmpValue::Integer(v)).unwrap();
        prop_assert_eq!(decode_value(&encoded).unwrap(), SnmpValue::Integer(v));
    }

    #[test]
    fn octet_string_round_trip(v in prop::collection::vec(any::<u8>(), 0..64)) {
        let encoded = encode_value(&SnmpValue::OctetString(v.clone())).unwrap();
        prop_assert_eq!(decode_value(&encoded).unwrap(), SnmpValue::OctetString(v));
    }

    #[test]
    fn oid_round_trip(oid in oid_strategy()) {
        let encoded = encode_value(&SnmpValue::ObjectIdentifier(oid.clone())).unwrap();
        prop_assert_eq!(
            decode_value(&encoded).unwrap(),
            SnmpValue::ObjectIdentifier(oid)
        );
    }

    #[test]
    fn counter32_round_trip(v in any::<u32>()) {
        let encoded = encode_value(&SnmpValue::Counter32(v)).unwrap();
        prop_assert_eq!(decode_value(&encoded).unwrap(), SnmpValue::Counter32(v));
    }

    #[test]
    fn gauge32_round_trip(v in any::<u32>()) {
        // SMIv2 Unsigned32 shares Gauge32's BER tag and unsigned-32-bit
        // encoding, so this round trip also pins the Unsigned32 wire format.
        let encoded = encode_value(&SnmpValue::Gauge32(v)).unwrap();
        prop_assert_eq!(decode_value(&encoded).unwrap(), SnmpValue::Gauge32(v));
    }

    #[test]
    fn timeticks_round_trip(v in any::<u32>()) {
        let encoded = encode_value(&SnmpValue::TimeTicks(v)).unwrap();
        prop_assert_eq!(decode_value(&encoded).unwrap(), SnmpValue::TimeTicks(v));
    }

    #[test]
    fn counter64_round_trip(v in any::<u64>()) {
        let encoded = encode_value(&SnmpValue::Counter64(v)).unwrap();
        prop_assert_eq!(decode_value(&encoded).unwrap(), SnmpValue::Counter64(v));
    }

    #[test]
    fn opaque_round_trip(v in prop::collection::vec(any::<u8>(), 0..64)) {
        let encoded = encode_value(&SnmpValue::Opaque(v.clone())).unwrap();
        prop_assert_eq!(decode_value(&encoded).unwrap(), SnmpValue::Opaque(v));
    }

    #[test]
    fn ip_address_round_trip(octets in any::<[u8; 4]>()) {
        let addr = Ipv4Addr::from(octets);
        let encoded = encode_value(&SnmpValue::IpAddress(addr)).unwrap();
        prop_assert_eq!(decode_value(&encoded).unwrap(), SnmpValue::IpAddress(addr));
    }

    // ── OID arc rules ───────────────────────────────────────────────────────

    #[test]
    fn oid_construction_rules(first in 0..=3u32, second in any::<u32>()) {
        let should_succeed = first <= 2 && (first >= 2 || second < 40);
        prop_assert_eq!(
            Oid::from_arcs(&[first, second]).is_ok(),
            should_succeed,
            "from_arcs verdict for first={}, second={}",
            first,
            second
        );
    }

    #[test]
    fn oid_starts_with_is_prefix(prefix in oid_strategy(), tail in oid_strategy()) {
        // Concatenating a valid OID onto a valid prefix is always a valid OID
        // and must be reported as extending the prefix.
        let extended = Oid::from_arcs(&[prefix.arcs(), tail.arcs()].concat()).unwrap();
        prop_assert!(extended.starts_with(&prefix));
        prop_assert!(!prefix.starts_with(&extended));
    }
}

// ── boundary-length inputs (test_wire_fuzz.py, deterministic) ───────────────

fn v3_usm_params() -> UsmSecurityParameters {
    UsmSecurityParameters {
        engine_id: vec![
            0x80, 0x00, 0x1f, 0x88, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        engine_boots: 1,
        engine_time: 500,
        username: b"property-user".to_vec(),
        auth_params: vec![0u8; 12],
        priv_params: Vec::new(),
    }
}

fn v3_pdu(request_id: u32) -> Pdu {
    Pdu {
        kind: PduKind::GetRequest,
        request_id,
        error_status: 0,
        error_index: 0,
        varbinds: vec![VarBind::new(
            trishul_snmp::types::oid::Oid::from_arcs(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap(),
            SnmpValue::Null,
        )],
        v1_trap: None,
    }
}

proptest! {
    /// Risk #2 mitigation: `locate_auth_params` must agree with the full
    /// decoder's `auth_params_offset` on every generated v3 message.
    #[test]
    fn locate_auth_params_agrees_with_decoder(
        msg_id in 0i64..1 << 30,
        max_size in 484i64..65507,
        request_id in 0u32..1 << 31,
        context_len in 0usize..16,
    ) {
        let mut usm = v3_usm_params();
        usm.engine_boots = 1;
        usm.engine_time = (request_id % 1000) as i64;
        let context = vec![0x61u8; context_len];
        let scoped = encode_scoped_pdu(&usm.engine_id, &context, &v3_pdu(request_id)).unwrap();
        let raw = encode_v3_message(
            msg_id,
            max_size,
            0x05, // auth + reportable
            &usm,
            &scoped,
        )
        .unwrap();
        prop_assert_eq!(
            locate_auth_params(&raw).unwrap(),
            decode_v3_message(&raw).unwrap().auth_params_offset
        );
        // And the offset really points at the auth_params content.
        let offset = locate_auth_params(&raw).unwrap();
        prop_assert_eq!(&raw[offset..offset + 12], &[0u8; 12]);
    }

    /// Decoding generated v3 messages never panics.
    #[test]
    fn decode_v3_message_never_panics(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = decode_v3_message(&data);
        let _ = locate_auth_params(&data);
    }
}

#[test]
fn decode_message_rejects_empty_payload() {
    assert!(decode_message(&[]).is_err());
}

#[test]
fn decode_message_rejects_empty_sequence() {
    assert!(decode_message(&[0x30, 0x00]).is_err());
}

#[test]
fn decode_pdu_rejects_empty_payload() {
    assert!(decode_pdu(&[]).is_err());
}

#[test]
fn decode_value_rejects_empty_payload() {
    assert!(decode_value(&[]).is_err());
}

#[test]
fn decode_value_rejects_length_claim_beyond_payload() {
    // Public-surface version of the internal decode_tlv boundary test: an
    // OCTET STRING claims 16 content bytes but only 1 is present.
    assert!(decode_value(&[0x04, 0x83, 0x00, 0x00, 0x10, 0xAA]).is_err());
}

proptest! {
    #[test]
    fn tripledes_decrypt_never_panics_on_arbitrary_ciphertext(
        data in prop::collection::vec(any::<u8>(), 0..300),
        salt in any::<[u8; 8]>(),
    ) {
        // Review item 10: ciphertext length/content is attacker-controlled
        // (wire msgData); unaligned/empty must be typed errors, aligned
        // garbage must decrypt without panicking.
        let material = [0x11u8; 32];
        let _ = tripledes_decrypt(&material, &data, &salt);
    }

    #[test]
    fn aes_cfb_decrypt_never_panics_on_arbitrary_ciphertext(
        data in prop::collection::vec(any::<u8>(), 0..300),
        salt in any::<[u8; 8]>(),
    ) {
        let key = [0x42u8; 16];
        let _ = aes_cfb_decrypt(&key, &data, 1, 2, &salt, 16);
    }

    #[test]
    fn v3_usm_unwrap_never_panics_on_arbitrary_datagrams(
        data in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        // Full typed path (authNoPriv model): arbitrary datagrams always
        // produce a typed UnwrapOutcome, never a panic.
        let model = usm_unwrap_model();
        let _ = model.unwrap_message(&data);
    }
}

/// A noAuth UsmModel with pre-adopted peer state for the unwrap property.
fn usm_unwrap_model() -> UsmModel {
    let user = UsmUser::new(
        "simulator".to_string(),
        AuthProtocol::Sha256,
        AuthKey::Passphrase(b"authpassword12345".to_vec()),
        PrivProtocol::Des3Ede,
        PrivKey::Passphrase(b"privpassword12345".to_vec()),
    )
    .unwrap();
    let model = UsmModel::new(
        user,
        Vec::new(),
        None,
        Arc::new(trishul_snmp::time::SystemClock),
        Arc::new(common::fake::CounterRng::new(7)),
    );
    model.adopt_engine_state(vec![0x80, 0, 0, 0x01], 2, 500);
    model
}

/// Every truncation of a valid 3DES authPriv ciphertext decrypts without
/// panicking (typed errors only) — the B1 class at message level.
#[test]
fn tripledes_truncated_valid_ciphertext_never_panics() {
    let material = [0x11u8; 32];
    let salt = [0x22u8; 8];
    let mut plaintext = vec![0x30, 15];
    plaintext.extend_from_slice(b"scoped pdu body");
    let ct = tripledes_encrypt(&material, &plaintext, &salt).unwrap();
    for len in 0..ct.len() {
        let _ = tripledes_decrypt(&material, &ct[..len], &salt);
    }
}
