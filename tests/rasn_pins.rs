//! rasn 0.28.15 dependency-behavior pins (risk #11 insurance).
//!
//! Executable evidence backing docs/architecture.md §codec: these asserts pin
//! the exact rasn behaviors the strictness shims compensate for. They are NOT
//! codec tests — they fail when a rasn upgrade changes decode/encode semantics.

use rasn::{ber, der, prelude::*};

#[derive(AsnType, Decode, Encode)]
struct Seq1 {
    a: u32,
}

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

#[test]
fn rasn_accepts_nonminimal_unsigned_content() {
    // Python rejects `02 02 00 01` (asn1.py:178-179); rasn accepts in BOTH modes.
    let b = hex("02 02 00 01");
    assert_eq!(ber::decode::<u32>(&b).unwrap(), 1);
    assert_eq!(der::decode::<u32>(&b).unwrap(), 1);
}

#[test]
fn rasn_strips_overwidth_leading_zero_and_corrupts() {
    // `00 01 00 00 00` -> strip 00 -> 01 00 00 00 = 16777216, no error.
    // Python rejects this as non-minimal (test_wire_bounds.py:113 analog).
    let b = hex("02 05 00 01 00 00 00");
    assert_eq!(ber::decode::<u32>(&b).unwrap(), 16777216);
}

#[test]
fn rasn_overwidth_strip_inverts_sign_for_i64() {
    let b = hex("02 09 00 FF FF FF FF FF FF FF FF");
    assert_eq!(ber::decode::<i64>(&b).unwrap(), -1);
}

#[test]
fn rasn_ber_accepts_indefinite_der_rejects() {
    let b = hex("30 80 02 01 05 00 00");
    assert!(ber::decode::<Seq1>(&b).is_ok());
    assert!(der::decode::<Seq1>(&b).is_err());
}

#[test]
fn rasn_ber_accepts_constructed_octet_string_der_rejects() {
    // NOTE: Vec<u8> decodes as SEQUENCE-OF in rasn; the OCTET STRING type is
    // rasn::types::OctetString (what SnmpValue::OctetString wraps).
    let b = hex("24 04 04 02 41 42");
    assert_eq!(
        ber::decode::<OctetString>(&b).unwrap(),
        OctetString::from(vec![0x41, 0x42])
    );
    assert!(der::decode::<OctetString>(&b).is_err());
}

#[test]
fn rasn_top_level_decode_ignores_trailing_bytes() {
    // Python rejects trailing content (ber.py expect_end); ber::decode does not
    // check the remainder.
    let b = hex("02 01 05 FF");
    assert_eq!(ber::decode::<u32>(&b).unwrap(), 5);
}

#[test]
fn rasn_rejects_empty_integer_content() {
    let b = hex("02 00");
    assert!(ber::decode::<u32>(&b).is_err());
    assert!(der::decode::<u32>(&b).is_err());
}

#[test]
fn rasn_encode_is_minimal_with_leading_zero_for_msb() {
    assert_eq!(ber::encode(&128u32).unwrap(), hex("02 02 00 80"));
    assert_eq!(ber::encode(&u32::MAX).unwrap(), hex("02 05 00 FF FF FF FF"));
    assert_eq!(ber::encode(&127u32).unwrap(), hex("02 01 7F"));
}

#[test]
fn rasn_decode_sequence_of_silently_drops_malformed_tail() {
    // SEQUENCE OF INTEGER `30 05 02 01 05 02 00`: element 1 decodes (5); the
    // second is a well-framed but EMPTY INTEGER — its decode consumes the whole
    // TLV then fails, the element loop breaks (ber/de.rs decode_sequence_of),
    // the extent is fully consumed, and rasn returns Ok([5]) with the
    // malformed element silently dropped, in BOTH modes. This is why the
    // varbind list has a manual strict codec (architecture §5.3a item 5).
    // Contrast: a tag-MISMATCH error leaves the tag byte unconsumed and
    // surfaces immediately as UnexpectedExtraData.
    let b = hex("30 05 02 01 05 02 00");
    assert_eq!(ber::decode::<Vec<u32>>(&b).unwrap(), vec![5]);
    assert_eq!(der::decode::<Vec<u32>>(&b).unwrap(), vec![5]);
}
