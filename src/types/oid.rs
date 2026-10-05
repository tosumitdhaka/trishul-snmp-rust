//! Oid newtype (← types.py:9, registry.py:77–106)

use std::fmt;

use rasn::prelude::*;
use rasn::types::{Any, Constraints, Identifier, Tag, TagTree};

use crate::error::ProtocolError;

/// Maximum value of a single OID arc (SNMP sub-identifier width, u32).
const OID_ARC_MAX: u32 = u32::MAX;

/// An OBJECT IDENTIFIER: a non-empty sequence of u32 arcs.
///
/// `Ord` is lexicographic — it matches the Python reference's tuple compare
/// (walk.py:36, 88–99 rely on it).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Oid(Vec<u32>);

/// An OID that cannot be represented: malformed, too few arcs, or violating
/// the arc rules (← `errors.py:InvalidOidError`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidOid(pub String);

impl InvalidOid {
    #[must_use]
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl Oid {
    /// Builds an OID from arcs, enforcing the ASN.1/SNMP shape rules:
    /// at least two arcs, first arc 0–2, and second arc < 40 when the first
    /// arc is 0 or 1. There is no arc-count cap (the reference and rasn have
    /// none; registry.py:77–106, asn1.py:186–195).
    pub fn from_arcs(arcs: &[u32]) -> Result<Self, InvalidOid> {
        if arcs.len() < 2 {
            return Err(InvalidOid::new(
                "OBJECT IDENTIFIER requires at least two arcs",
            ));
        }
        if arcs[0] > 2 {
            return Err(InvalidOid::new("First OID arc must be 0, 1, or 2"));
        }
        if arcs[0] < 2 && arcs[1] >= 40 {
            return Err(InvalidOid::new(
                "Second OID arc must be < 40 when the first arc is 0 or 1",
            ));
        }
        Ok(Self(arcs.to_vec()))
    }

    /// Parses a dotted-decimal OID string. Leading dots and surrounding
    /// whitespace are tolerated; negative or non-numeric arcs are rejected
    /// (registry.py:77–100). Arc-shape rules then apply as in `from_arcs`.
    pub fn parse(s: &str) -> Result<Self, InvalidOid> {
        let text = s.trim().trim_start_matches('.');
        if text.is_empty() {
            return Err(InvalidOid::new("OID cannot be empty"));
        }
        let mut arcs = Vec::new();
        for part in text.split('.') {
            if part.starts_with('-') {
                return Err(InvalidOid::new(format!("OID contains a negative arc: {s}")));
            }
            let arc: u128 = part
                .parse()
                .map_err(|_| InvalidOid::new(format!("OID contains a non-numeric arc: {s}")))?;
            let arc: u32 = u32::try_from(arc).map_err(|_| {
                InvalidOid::new(format!("OID arc {arc} exceeds maximum {OID_ARC_MAX}"))
            })?;
            arcs.push(arc);
        }
        Self::from_arcs(&arcs)
    }

    /// The arcs of this OID.
    #[must_use]
    pub fn arcs(&self) -> &[u32] {
        &self.0
    }

    /// True when `prefix`'s arcs are a prefix of this OID's arcs.
    #[must_use]
    pub fn starts_with(&self, prefix: &Oid) -> bool {
        self.0.starts_with(&prefix.0)
    }

    /// Dotted-decimal string form, byte-identical to the reference
    /// (`".".join(str(arc) for arc in oid)`).
    #[must_use]
    pub fn display(&self) -> String {
        self.0
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(".")
    }

    /// Builds an empty OID (Phase 6 MIB suffix marker; the reference's
    /// `OidMatch.suffix` defaults to an empty tuple, registry.py:194–206).
    pub(crate) fn empty() -> Self {
        Self(Vec::new())
    }

    /// Builds an OID without arc-shape validation. Internal-only: the MIB
    /// registry needs arbitrary arc-slice keys (`prefix`/`suffix` markers,
    /// single-arc prefixes) that Python tuples never validate — Python's
    /// `parse_oid`/tuple slices accept any non-negative arc sequence
    /// (registry.py:77–100).
    pub(crate) fn from_arcs_unchecked(arcs: Vec<u32>) -> Self {
        Self(arcs)
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display())
    }
}

impl AsnType for Oid {
    const TAG: Tag = Tag::OBJECT_IDENTIFIER;
    const IDENTIFIER: Identifier = Identifier::OBJECT_IDENTIFIER;
    const TAG_TREE: TagTree = TagTree::Leaf(Tag::OBJECT_IDENTIFIER);
}

impl Decode for Oid {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        _tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        use rasn::de::Error as _;
        let codec = decoder.codec();
        // Capture the raw TLV under the active (DER) decoder so indefinite
        // lengths are rejected, then hand-parse it for reference-flavored
        // error messages (the reference walks decode_tlv + tag check).
        let any = Any::decode_with_tag_and_constraints(decoder, Tag::EOC, constraints)?;
        let tlv = any.as_bytes();
        let (tag, content, end) =
            crate::codec::decode_tlv(tlv, 0).map_err(|e| D::Error::custom(e.message, codec))?;
        if tag != 0x06 {
            return Err(D::Error::custom(
                format!("Expected OBJECT IDENTIFIER, found 0x{tag:02x}"),
                codec,
            ));
        }
        if end != tlv.len() {
            return Err(D::Error::custom("Unexpected trailing BER content", codec));
        }
        decode_oid_content(content).map_err(|e| D::Error::custom(e.message, codec))
    }
}

impl Encode for Oid {
    fn encode_with_tag_and_constraints<'b, EN: Encoder<'b>>(
        &self,
        encoder: &mut EN,
        _tag: Tag,
        _constraints: Constraints,
        identifier: Identifier,
    ) -> Result<(), EN::Error> {
        use rasn::enc::Error as _;
        let codec = encoder.codec();
        let content =
            encode_oid_content(&self.0).map_err(|e| EN::Error::custom(e.message, codec))?;
        let mut tlv = vec![0x06];
        tlv.extend(
            crate::codec::encode_length(content.len())
                .map_err(|e| EN::Error::custom(e.message, codec))?,
        );
        tlv.extend(content);
        encoder
            .encode_any(Tag::EOC, &Any::new(tlv), identifier)
            .map(drop)
    }
}

/// Base-128 (sub-identifier) encoding, matching asn1.py `_encode_base128`.
pub(crate) fn encode_base128(mut value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }
    let mut chunks = Vec::new();
    while value != 0 {
        chunks.push((value & 0x7F) as u8);
        value >>= 7;
    }
    chunks.reverse();
    let last = chunks.len() - 1;
    for chunk in &mut chunks[..last] {
        *chunk |= 0x80;
    }
    chunks
}

/// Base-128 (sub-identifier) decoding, matching asn1.py `_decode_base128`.
/// Returns the value and the offset just past the value.
pub(crate) fn decode_base128(content: &[u8], offset: usize) -> Result<(u64, usize), ProtocolError> {
    let mut value = 0u64;
    let mut offset = offset;
    loop {
        if offset >= content.len() {
            return Err(ProtocolError::new("Truncated base-128 value"));
        }
        let byte = content[offset];
        offset += 1;
        value = value.saturating_mul(128) | u64::from(byte & 0x7F);
        if byte & 0x80 == 0 {
            return Ok((value, offset));
        }
    }
}

/// Encodes an OID's arcs to OBJECT IDENTIFIER *content* bytes
/// (asn1.py `_encode_oid`: first two arcs packed into one subidentifier).
pub(crate) fn encode_oid_content(arcs: &[u32]) -> Result<Vec<u8>, ProtocolError> {
    if arcs.len() < 2 {
        return Err(ProtocolError::new(
            "OBJECT IDENTIFIER requires at least two arcs",
        ));
    }
    if arcs[0] > 2 {
        return Err(ProtocolError::new("First OID arc must be 0, 1, or 2"));
    }
    if arcs[0] < 2 && arcs[1] >= 40 {
        return Err(ProtocolError::new(
            "Second OID arc must be < 40 when the first arc is 0 or 1",
        ));
    }
    let combined = if arcs[0] < 2 {
        u64::from(arcs[0]) * 40 + u64::from(arcs[1])
    } else {
        80 + u64::from(arcs[1])
    };
    let mut content = encode_base128(combined);
    for &arc in &arcs[2..] {
        content.extend(encode_base128(u64::from(arc)));
    }
    Ok(content)
}

/// Decodes OBJECT IDENTIFIER *content* bytes into an `Oid`
/// (asn1.py `_decode_oid`: first subidentifier split into arcs 0 and 1,
/// every arc bounded to u32).
pub(crate) fn decode_oid_content(content: &[u8]) -> Result<Oid, ProtocolError> {
    if content.is_empty() {
        return Err(ProtocolError::new(
            "OBJECT IDENTIFIER content cannot be empty",
        ));
    }
    let (first, mut offset) = decode_base128(content, 0)?;
    let (first_arc, second_arc) = if first < 40 {
        (0, first)
    } else if first < 80 {
        (1, first - 40)
    } else {
        (2, first - 80)
    };
    if second_arc > u64::from(OID_ARC_MAX) {
        return Err(ProtocolError::new(format!(
            "OID subidentifier {second_arc} exceeds maximum {OID_ARC_MAX}"
        )));
    }
    let mut arcs = vec![first_arc, second_arc as u32];
    while offset < content.len() {
        let (arc, next) = decode_base128(content, offset)?;
        if arc > u64::from(OID_ARC_MAX) {
            return Err(ProtocolError::new(format!(
                "OID subidentifier {arc} exceeds maximum {OID_ARC_MAX}"
            )));
        }
        arcs.push(arc as u32);
        offset = next;
    }
    Ok(Oid(arcs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arcs(oid: &Oid) -> Vec<u32> {
        oid.arcs().to_vec()
    }

    #[test]
    fn from_arcs_rejects_invalid_shapes() {
        // asn1.py `_encode_oid` rejections, moved to construction time (§8).
        let err = Oid::from_arcs(&[1]).unwrap_err();
        assert_eq!(err.0, "OBJECT IDENTIFIER requires at least two arcs");
        let err = Oid::from_arcs(&[3, 0]).unwrap_err();
        assert_eq!(err.0, "First OID arc must be 0, 1, or 2");
        let err = Oid::from_arcs(&[1, 40]).unwrap_err();
        assert_eq!(
            err.0,
            "Second OID arc must be < 40 when the first arc is 0 or 1"
        );
        let err = Oid::from_arcs(&[0, 40]).unwrap_err();
        assert_eq!(
            err.0,
            "Second OID arc must be < 40 when the first arc is 0 or 1"
        );
    }

    #[test]
    fn from_arcs_accepts_boundary_shapes() {
        assert_eq!(arcs(&Oid::from_arcs(&[0, 39]).unwrap()), [0, 39]);
        assert_eq!(arcs(&Oid::from_arcs(&[1, 39]).unwrap()), [1, 39]);
        assert_eq!(arcs(&Oid::from_arcs(&[2, 39]).unwrap()), [2, 39]);
        assert_eq!(arcs(&Oid::from_arcs(&[2, 40]).unwrap()), [2, 40]);
        assert_eq!(
            arcs(&Oid::from_arcs(&[2, u32::MAX]).unwrap()),
            [2, u32::MAX]
        );
    }

    #[test]
    fn parse_normalizes_and_validates() {
        assert_eq!(arcs(&Oid::parse("1.3.6.1").unwrap()), [1, 3, 6, 1]);
        assert_eq!(arcs(&Oid::parse(" .1.3.6.1 ").unwrap()), [1, 3, 6, 1]);
        assert_eq!(arcs(&Oid::parse(".1.3.6.1").unwrap()), [1, 3, 6, 1]);
        assert_eq!(Oid::parse("").unwrap_err().0, "OID cannot be empty");
        assert_eq!(Oid::parse("...").unwrap_err().0, "OID cannot be empty");
        assert!(Oid::parse("1.3.x").unwrap_err().0.contains("non-numeric"));
        assert!(Oid::parse("1.3.-1").unwrap_err().0.contains("negative"));
        // Early single-arc rejection (§8): the reference accepts it at parse
        // time and fails only at encode.
        assert_eq!(
            Oid::parse("1").unwrap_err().0,
            "OBJECT IDENTIFIER requires at least two arcs"
        );
    }

    #[test]
    fn starts_with_and_display() {
        let base = Oid::from_arcs(&[1, 3, 6, 1]).unwrap();
        let child = Oid::from_arcs(&[1, 3, 6, 1, 2, 1]).unwrap();
        assert!(child.starts_with(&base));
        assert!(!base.starts_with(&child));
        assert!(base.starts_with(&base));
        assert_eq!(base.display(), "1.3.6.1");
    }

    #[test]
    fn encode_and_decode_base128_values() {
        assert_eq!(encode_base128(0), vec![0x00]);
        assert_eq!(encode_base128(128), vec![0x81, 0x00]);
        assert_eq!(decode_base128(&[0x81, 0x00], 0).unwrap(), (128, 2));
        assert_eq!(encode_base128(99999), vec![0x86, 0x8D, 0x1F]);
        assert_eq!(decode_base128(&[0x86, 0x8D, 0x1F], 0).unwrap(), (99999, 3));
    }

    #[test]
    fn decode_base128_rejects_truncation() {
        let err = decode_base128(&[0x81], 0).unwrap_err();
        assert_eq!(err.message, "Truncated base-128 value");
    }

    #[test]
    fn decode_oid_handles_all_first_arc_ranges_and_rejects_empty_content() {
        assert_eq!(arcs(&decode_oid_content(&[0x03]).unwrap()), [0, 3]);
        assert_eq!(arcs(&decode_oid_content(&[0x2D]).unwrap()), [1, 5]);
        assert_eq!(arcs(&decode_oid_content(&[0x51]).unwrap()), [2, 1]);
        assert_eq!(arcs(&decode_oid_content(&[0x81, 0x34]).unwrap()), [2, 100]);
        let err = decode_oid_content(&[]).unwrap_err();
        assert_eq!(err.message, "OBJECT IDENTIFIER content cannot be empty");
    }

    #[test]
    fn decode_oid_matches_external_ber_vector_for_second_arc_over_39() {
        assert_eq!(arcs(&decode_oid_content(&[0x81, 0x34]).unwrap()), [2, 100]);
        assert_eq!(
            arcs(&decode_oid_content(&[0x81, 0x34, 0x03]).unwrap()),
            [2, 100, 3]
        );
        assert_eq!(
            encode_oid_content(&[2, 100, 3]).unwrap(),
            vec![0x81, 0x34, 0x03]
        );
    }

    #[test]
    fn encode_oid_accepts_second_arc_39_under_first_arc_zero_or_one() {
        assert_eq!(encode_oid_content(&[0, 39]).unwrap(), vec![0x27]);
        assert_eq!(arcs(&decode_oid_content(&[0x27]).unwrap()), [0, 39]);
        assert_eq!(encode_oid_content(&[1, 39]).unwrap(), vec![0x4F]);
        assert_eq!(arcs(&decode_oid_content(&[0x4F]).unwrap()), [1, 39]);
    }

    #[test]
    fn encode_oid_accepts_second_arc_over_39_under_first_arc_two() {
        assert_eq!(encode_oid_content(&[2, 39]).unwrap(), vec![0x77]);
        assert_eq!(encode_oid_content(&[2, 40]).unwrap(), vec![0x78]);
        assert_eq!(encode_oid_content(&[2, 100]).unwrap(), vec![0x81, 0x34]);
    }

    #[test]
    fn oid_round_trips_second_arc_over_39_under_first_arc_two() {
        for oid in [&[2u32, 39][..], &[2, 40], &[2, 47], &[2, 48], &[2, 100]] {
            assert_eq!(
                arcs(&decode_oid_content(&encode_oid_content(oid).unwrap()).unwrap()),
                oid
            );
        }
    }

    #[test]
    fn oid_accepts_second_arc_up_to_uint32_bound_under_first_arc_two() {
        let encoded = encode_base128(80 + u64::from(u32::MAX));
        assert_eq!(encode_oid_content(&[2, u32::MAX]).unwrap(), encoded);
        assert_eq!(arcs(&decode_oid_content(&encoded).unwrap()), [2, u32::MAX]);
    }

    #[test]
    fn decode_oid_rejects_oversized_first_subidentifier() {
        // 80 + 2**32: the split second arc exceeds the u32 bound.
        let err = decode_oid_content(&encode_base128(80 + (1u64 << 32))).unwrap_err();
        assert_eq!(
            err.message,
            format!("OID subidentifier 4294967296 exceeds maximum {OID_ARC_MAX}")
        );
    }

    #[test]
    fn decode_oid_rejects_truncated_first_subidentifier() {
        let err = decode_oid_content(&[0x81]).unwrap_err();
        assert_eq!(err.message, "Truncated base-128 value");
    }

    #[test]
    fn oid_accepts_large_arc_up_to_uint32_bound() {
        let encoded = encode_base128(u64::from(u32::MAX));
        assert_eq!(
            decode_base128(&encoded, 0).unwrap(),
            (u64::from(u32::MAX), encoded.len())
        );
        let mut content = vec![0x2B];
        content.extend(encoded);
        assert_eq!(
            arcs(&decode_oid_content(&content).unwrap()),
            [1, 3, u32::MAX]
        );
    }

    #[test]
    fn decode_oid_rejects_arc_beyond_uint32_bound() {
        let mut content = vec![0x2B];
        content.extend(encode_base128(1u64 << 32));
        let err = decode_oid_content(&content).unwrap_err();
        assert_eq!(
            err.message,
            format!("OID subidentifier 4294967296 exceeds maximum {OID_ARC_MAX}")
        );
    }
}
