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

use proptest::prelude::*;

use trishul_snmp::codec::message::decode_message;
use trishul_snmp::codec::pdu::decode_pdu;
use trishul_snmp::codec::v3::locate_auth_params;
use trishul_snmp::codec::{decode_value, encode_value};
use trishul_snmp::types::oid::Oid;
use trishul_snmp::types::value::SnmpValue;

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
