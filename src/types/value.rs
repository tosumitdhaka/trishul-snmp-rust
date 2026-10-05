//! SnmpValue enum, Display (← types.py:41–185)

use std::fmt;
use std::net::Ipv4Addr;

use rasn::prelude::*;
use rasn::types::{Any, Constraints, Identifier, Tag, TagTree};

use crate::error::ProtocolError;
use crate::types::oid::{Oid, decode_oid_content, encode_oid_content};

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OBJECT_IDENTIFIER: u8 = 0x06;
const TAG_IP_ADDRESS: u8 = 0x40;
const TAG_COUNTER32: u8 = 0x41;
const TAG_GAUGE32: u8 = 0x42;
const TAG_TIMETICKS: u8 = 0x43;
const TAG_OPAQUE: u8 = 0x44;
const TAG_COUNTER64: u8 = 0x46;
const TAG_NO_SUCH_OBJECT: u8 = 0x80;
const TAG_NO_SUCH_INSTANCE: u8 = 0x81;
const TAG_END_OF_MIB_VIEW: u8 = 0x82;

/// An SNMP value, one variant per wire type.
///
/// The enum-of-payload replaces the reference's 13 value dataclasses
/// (types.py:41–185); `Display` output is byte-identical to the reference's
/// `to_display_string`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SnmpValue {
    /// BER INTEGER (signed; magnitude beyond i64 → Malformed on decode).
    Integer(i64),
    /// OCTET STRING.
    OctetString(Vec<u8>),
    /// NULL.
    Null,
    /// OBJECT IDENTIFIER.
    ObjectIdentifier(Oid),
    /// IpAddress — `Ipv4Addr` internally, display identical to the reference.
    IpAddress(Ipv4Addr),
    /// Counter32.
    Counter32(u32),
    /// Gauge32 (shares the Unsigned32 wire format).
    Gauge32(u32),
    /// TimeTicks.
    TimeTicks(u32),
    /// Opaque.
    Opaque(Vec<u8>),
    /// Counter64.
    Counter64(u64),
    /// noSuchObject exception.
    NoSuchObject,
    /// noSuchInstance exception.
    NoSuchInstance,
    /// endOfMibView exception.
    EndOfMibView,
}

impl SnmpValue {
    /// The reference's `type_name` per dataclass (types.py:41–185).
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Integer(_) => "integer",
            Self::OctetString(_) => "octet-string",
            Self::Null => "null",
            Self::ObjectIdentifier(_) => "object-identifier",
            Self::IpAddress(_) => "ip-address",
            Self::Counter32(_) => "counter32",
            Self::Gauge32(_) => "gauge32",
            Self::TimeTicks(_) => "timeticks",
            Self::Opaque(_) => "opaque",
            Self::Counter64(_) => "counter64",
            Self::NoSuchObject => "no-such-object",
            Self::NoSuchInstance => "no-such-instance",
            Self::EndOfMibView => "end-of-mib-view",
        }
    }

    fn encode_tlv(&self) -> Result<Vec<u8>, ProtocolError> {
        let (tag, content): (u8, Vec<u8>) = match self {
            Self::Integer(v) => (TAG_INTEGER, encode_signed(*v)),
            Self::OctetString(bytes) => (TAG_OCTET_STRING, bytes.clone()),
            Self::Null => (TAG_NULL, Vec::new()),
            Self::ObjectIdentifier(oid) => (TAG_OBJECT_IDENTIFIER, encode_oid_content(oid.arcs())?),
            Self::IpAddress(addr) => (TAG_IP_ADDRESS, addr.octets().to_vec()),
            Self::Counter32(v) => (TAG_COUNTER32, encode_unsigned(u64::from(*v), "Counter32")?),
            Self::Gauge32(v) => (TAG_GAUGE32, encode_unsigned(u64::from(*v), "Gauge32")?),
            Self::TimeTicks(v) => (TAG_TIMETICKS, encode_unsigned(u64::from(*v), "TimeTicks")?),
            Self::Opaque(bytes) => (TAG_OPAQUE, bytes.clone()),
            Self::Counter64(v) => (TAG_COUNTER64, encode_unsigned(*v, "Counter64")?),
            Self::NoSuchObject => (TAG_NO_SUCH_OBJECT, Vec::new()),
            Self::NoSuchInstance => (TAG_NO_SUCH_INSTANCE, Vec::new()),
            Self::EndOfMibView => (TAG_END_OF_MIB_VIEW, Vec::new()),
        };
        let mut tlv = vec![tag];
        tlv.extend(crate::codec::encode_length(content.len())?);
        tlv.extend(content);
        Ok(tlv)
    }
}

impl fmt::Display for SnmpValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Integer(v) => write!(f, "{v}"),
            Self::OctetString(bytes) => f.write_str(&octet_string_display(bytes)),
            Self::Null => f.write_str("null"),
            Self::ObjectIdentifier(oid) => f.write_str(&oid.display()),
            Self::IpAddress(addr) => write!(f, "{addr}"),
            Self::Counter32(v) => write!(f, "{v}"),
            Self::Gauge32(v) => write!(f, "{v}"),
            Self::TimeTicks(v) => write!(f, "{v}"),
            Self::Opaque(bytes) => f.write_str(&hex(bytes)),
            Self::Counter64(v) => write!(f, "{v}"),
            Self::NoSuchObject => f.write_str("noSuchObject"),
            Self::NoSuchInstance => f.write_str("noSuchInstance"),
            Self::EndOfMibView => f.write_str("endOfMibView"),
        }
    }
}

impl AsnType for SnmpValue {
    const TAG: Tag = Tag::EOC;
    const IDENTIFIER: Identifier = Identifier::EMPTY;
    const TAG_TREE: TagTree = TagTree::Choice(&[
        TagTree::Leaf(Tag::INTEGER),
        TagTree::Leaf(Tag::OCTET_STRING),
        TagTree::Leaf(Tag::NULL),
        TagTree::Leaf(Tag::OBJECT_IDENTIFIER),
        TagTree::Leaf(Tag::new(Class::Application, 0)), // IpAddress
        TagTree::Leaf(Tag::new(Class::Application, 1)), // Counter32
        TagTree::Leaf(Tag::new(Class::Application, 2)), // Gauge32
        TagTree::Leaf(Tag::new(Class::Application, 3)), // TimeTicks
        TagTree::Leaf(Tag::new(Class::Application, 4)), // Opaque
        TagTree::Leaf(Tag::new(Class::Application, 6)), // Counter64
        TagTree::Leaf(Tag::new(Class::Context, 0)),     // noSuchObject
        TagTree::Leaf(Tag::new(Class::Context, 1)),     // noSuchInstance
        TagTree::Leaf(Tag::new(Class::Context, 2)),     // endOfMibView
    ]);
}

/// Manual `Decode` (docs/architecture.md §5.3a item 3): rasn accepts
/// non-minimal unsigned content and silently corrupts over-wide values, so the
/// value layer hand-applies asn1.py:132–182 (unsigned minimality via
/// re-encode compare, u32/u64 width bounds, empty-content rejection, and the
/// 4-octet IpAddress rule). The outer TLV is read under the active (DER)
/// decoder, which already rejects indefinite lengths.
impl Decode for SnmpValue {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        _tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        use rasn::de::Error as _;
        let codec = decoder.codec();
        let any = Any::decode_with_tag_and_constraints(decoder, Tag::EOC, constraints)?;
        decode_value_tlv(any.as_bytes()).map_err(|e| D::Error::custom(e.message, codec))
    }
}

/// Decodes a full value TLV (tag + length + content) into an `SnmpValue`.
///
/// The reference's `decode_value` (asn1.py:86–129) reads the TLV with its own
/// `decode_tlv`, which treats the first octet as the complete tag (SNMP has no
/// long-form tags) and rejects trailing content; this shared path is used both
/// by the in-structure `Decode` impl (after rasn captures the raw TLV) and by
/// the standalone `codec::decode_value` entry point.
pub(crate) fn decode_value_tlv(tlv: &[u8]) -> Result<SnmpValue, ProtocolError> {
    if tlv.is_empty() {
        return Err(ProtocolError::new("BER tag is truncated"));
    }
    let (tag, content, end) = crate::codec::decode_tlv(tlv, 0)?;
    if end != tlv.len() {
        return Err(ProtocolError::new("Unexpected trailing BER content"));
    }
    let value = match tag {
        TAG_INTEGER => SnmpValue::Integer(decode_signed_content(content)?),
        TAG_OCTET_STRING => SnmpValue::OctetString(content.to_vec()),
        TAG_NULL => {
            require_empty(content, tag)?;
            SnmpValue::Null
        }
        TAG_OBJECT_IDENTIFIER => SnmpValue::ObjectIdentifier(decode_oid_content(content)?),
        TAG_IP_ADDRESS => SnmpValue::IpAddress(decode_ip_address(content)?),
        TAG_COUNTER32 => {
            SnmpValue::Counter32(decode_unsigned(content, u64::from(u32::MAX), "Counter32")? as u32)
        }
        TAG_GAUGE32 => {
            SnmpValue::Gauge32(decode_unsigned(content, u64::from(u32::MAX), "Gauge32")? as u32)
        }
        TAG_TIMETICKS => {
            SnmpValue::TimeTicks(decode_unsigned(content, u64::from(u32::MAX), "TimeTicks")? as u32)
        }
        TAG_OPAQUE => SnmpValue::Opaque(content.to_vec()),
        TAG_COUNTER64 => SnmpValue::Counter64(decode_unsigned(content, u64::MAX, "Counter64")?),
        TAG_NO_SUCH_OBJECT => {
            require_empty(content, tag)?;
            SnmpValue::NoSuchObject
        }
        TAG_NO_SUCH_INSTANCE => {
            require_empty(content, tag)?;
            SnmpValue::NoSuchInstance
        }
        TAG_END_OF_MIB_VIEW => {
            require_empty(content, tag)?;
            SnmpValue::EndOfMibView
        }
        other => {
            return Err(ProtocolError::new(format!(
                "Unsupported SNMP value tag 0x{other:02x}"
            )));
        }
    };
    Ok(value)
}

/// Manual `Encode` (the §5.3a “encoder parity is byte-exact” contract). A
/// derived `Encode` cannot be used: rasn encodes `Vec<u8>` as SEQUENCE OF, not
/// OCTET STRING, and `Oid` needs its own OBJECT IDENTIFIER encoding.
impl Encode for SnmpValue {
    fn encode_with_tag_and_constraints<'b, EN: Encoder<'b>>(
        &self,
        encoder: &mut EN,
        _tag: Tag,
        _constraints: Constraints,
        identifier: Identifier,
    ) -> Result<(), EN::Error> {
        use rasn::enc::Error as _;
        let codec = encoder.codec();
        let tlv = self
            .encode_tlv()
            .map_err(|e| EN::Error::custom(e.message, codec))?;
        encoder
            .encode_any(Tag::EOC, &Any::new(tlv), identifier)
            .map(drop)
    }
}

/// Signed INTEGER *content* encoding, byte-identical to asn1.py
/// `_encode_signed_integer` (minimal length, leading `00`/`FF` trimmed).
pub(crate) fn encode_signed(value: i64) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }
    let bit_len = (64 - value.unsigned_abs().leading_zeros()) as usize;
    let len = ((bit_len + 8) / 8).clamp(1, 8);
    let mut encoded = value.to_be_bytes()[8 - len..].to_vec();
    while encoded.len() > 1
        && ((encoded[0] == 0x00 && encoded[1] & 0x80 == 0)
            || (encoded[0] == 0xFF && encoded[1] & 0x80 == 0x80))
    {
        encoded.remove(0);
    }
    encoded
}

/// Signed INTEGER *content* decoding (asn1.py `_decode_signed_integer`); empty
/// content is rejected, and magnitudes beyond i64 are Malformed (§8).
pub(crate) fn decode_signed_content(content: &[u8]) -> Result<i64, ProtocolError> {
    if content.is_empty() {
        return Err(ProtocolError::new("INTEGER content cannot be empty"));
    }
    if content.len() > 8 {
        return Err(ProtocolError::new("INTEGER content exceeds i64 bounds"));
    }
    let mut buf = [if content[0] & 0x80 != 0 { 0xFF } else { 0x00 }; 8];
    buf[8 - content.len()..].copy_from_slice(content);
    Ok(i64::from_be_bytes(buf))
}

/// Unsigned INTEGER *content* encoding (asn1.py `_encode_unsigned_integer`):
/// minimal length with a leading `00` when the MSB would be set.
pub(crate) fn encode_unsigned(value: u64, _field: &str) -> Result<Vec<u8>, ProtocolError> {
    if value == 0 {
        return Ok(vec![0]);
    }
    let len = ((64 - value.leading_zeros()) + 7) as usize / 8;
    let mut bytes = value.to_be_bytes()[8 - len..].to_vec();
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    Ok(bytes)
}

/// Unsigned INTEGER *content* decoding (asn1.py `_decode_unsigned_integer`):
/// empty content rejected, non-minimal encoding rejected (re-encode compare),
/// value beyond `max` rejected.
pub(crate) fn decode_unsigned(content: &[u8], max: u64, field: &str) -> Result<u64, ProtocolError> {
    if content.is_empty() {
        return Err(ProtocolError::new(
            "Unsigned integer content cannot be empty",
        ));
    }
    let mut value = 0u128;
    for &byte in content {
        value = (value << 8) | u128::from(byte);
    }
    if value > u128::from(u64::MAX) {
        return Err(ProtocolError::new(format!(
            "{field} value {value} exceeds maximum {max}"
        )));
    }
    let value = value as u64;
    if content != encode_unsigned(value, field)? {
        return Err(ProtocolError::new(format!(
            "{field} content is not minimally encoded"
        )));
    }
    if value > max {
        return Err(ProtocolError::new(format!(
            "{field} value {value} exceeds maximum {max}"
        )));
    }
    Ok(value)
}

fn decode_ip_address(content: &[u8]) -> Result<Ipv4Addr, ProtocolError> {
    if content.len() != 4 {
        return Err(ProtocolError::new(
            "IpAddress values must contain exactly four octets",
        ));
    }
    Ok(Ipv4Addr::new(
        content[0], content[1], content[2], content[3],
    ))
}

fn require_empty(content: &[u8], tag: u8) -> Result<(), ProtocolError> {
    if content.is_empty() {
        Ok(())
    } else {
        Err(ProtocolError::new(format!(
            "Zero-length value expected for tag 0x{tag:02x}"
        )))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// OCTET STRING display per types.py:60–73: empty → `""`; valid UTF-8 that is
/// fully printable → the decoded text; otherwise hex. Rust has no
/// `isprintable()`; `!is_control()` is the close approximation (documented
/// divergence for exotic format/line-separator code points).
fn octet_string_display(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    match std::str::from_utf8(bytes) {
        Ok(text) if text.chars().all(|c| !c.is_control()) => text.to_string(),
        _ => hex(bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_signed_integer_handles_negative_trim_case() {
        // asn1.py `_encode_signed_integer(-128) == b"\x80"`.
        assert_eq!(encode_signed(-128), vec![0x80]);
        assert_eq!(encode_signed(-32768), vec![0x80, 0x00]);
        assert_eq!(encode_signed(0), vec![0x00]);
        assert_eq!(encode_signed(128), vec![0x00, 0x80]);
        assert_eq!(encode_signed(-1), vec![0xFF]);
        assert_eq!(encode_signed(i64::MIN), vec![0x80, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn decode_signed_integer_rejects_empty_content() {
        let err = decode_signed_content(&[]).unwrap_err();
        assert_eq!(err.message, "INTEGER content cannot be empty");
    }

    #[test]
    fn encode_unsigned_integer_handles_zero_and_leading_sign_bit() {
        assert_eq!(encode_unsigned(0, "u").unwrap(), vec![0x00]);
        assert_eq!(encode_unsigned(128, "u").unwrap(), vec![0x00, 0x80]);
    }

    #[test]
    fn decode_unsigned_integer_rejects_empty_content() {
        let err = decode_unsigned(&[], u32::MAX.into(), "Counter32").unwrap_err();
        assert_eq!(err.message, "Unsigned integer content cannot be empty");
    }

    #[test]
    fn encode_unsigned_integer_accepts_exact_bound() {
        assert_eq!(
            encode_unsigned(u64::from(u32::MAX), "Counter32").unwrap(),
            vec![0x00, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        assert_eq!(
            encode_unsigned(u64::MAX, "Counter64").unwrap(),
            [vec![0x00], vec![0xFF; 8]].concat()
        );
    }

    #[test]
    fn decode_unsigned_integer_rejects_non_minimal_encoding() {
        for content in [
            &[0x00u8, 0x01][..],
            &[0x00, 0x00],
            &[0x00, 0x00, 0x80],
            &[0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF],
        ] {
            let err = decode_unsigned(content, u64::MAX, "Unsigned integer").unwrap_err();
            assert_eq!(
                err.message,
                "Unsigned integer content is not minimally encoded"
            );
        }
    }

    #[test]
    fn decode_unsigned_integer_rejects_value_beyond_uint64() {
        // 2**64 needs nine content octets.
        let content = (1u128 << 64).to_be_bytes();
        let err = decode_unsigned(&content, u64::MAX, "Counter64").unwrap_err();
        assert_eq!(
            err.message,
            "Counter64 value 18446744073709551616 exceeds maximum 18446744073709551615"
        );
    }

    #[test]
    fn decode_unsigned_integer_rejects_non_minimal_counter32() {
        // `41 02 00 01` — value 1 padded with a leading zero.
        let err = decode_unsigned(&[0x00, 0x01], u64::from(u32::MAX), "Counter32").unwrap_err();
        assert_eq!(err.message, "Counter32 content is not minimally encoded");
    }

    #[test]
    fn decode_ip_address_rejects_invalid_length() {
        let err = decode_ip_address(&[0x7F, 0x00, 0x00]).unwrap_err();
        assert_eq!(
            err.message,
            "IpAddress values must contain exactly four octets"
        );
        assert_eq!(
            decode_ip_address(&[0x7F, 0x00, 0x00, 0x01]).unwrap(),
            Ipv4Addr::new(127, 0, 0, 1)
        );
    }

    #[test]
    fn require_empty_rejects_non_empty_content() {
        let err = require_empty(&[0x00], 0x80).unwrap_err();
        assert_eq!(err.message, "Zero-length value expected for tag 0x80");
    }

    #[test]
    fn display_strings_match_reference() {
        use std::net::Ipv4Addr;
        assert_eq!(SnmpValue::Integer(-42).to_string(), "-42");
        assert_eq!(SnmpValue::OctetString(b"eth0".to_vec()).to_string(), "eth0");
        assert_eq!(SnmpValue::OctetString(vec![0xFF, 0xFE]).to_string(), "fffe");
        assert_eq!(SnmpValue::OctetString(Vec::new()).to_string(), "");
        assert_eq!(SnmpValue::Null.to_string(), "null");
        assert_eq!(
            SnmpValue::ObjectIdentifier(Oid::from_arcs(&[1, 3, 6]).unwrap()).to_string(),
            "1.3.6"
        );
        assert_eq!(
            SnmpValue::IpAddress(Ipv4Addr::new(192, 0, 2, 1)).to_string(),
            "192.0.2.1"
        );
        assert_eq!(SnmpValue::Counter32(7).to_string(), "7");
        assert_eq!(SnmpValue::Gauge32(7).to_string(), "7");
        assert_eq!(SnmpValue::TimeTicks(12345).to_string(), "12345");
        assert_eq!(SnmpValue::Opaque(vec![0x00, 0xFF]).to_string(), "00ff");
        assert_eq!(
            SnmpValue::Counter64(2_u64.pow(40)).to_string(),
            "1099511627776"
        );
        assert_eq!(SnmpValue::NoSuchObject.to_string(), "noSuchObject");
        assert_eq!(SnmpValue::NoSuchInstance.to_string(), "noSuchInstance");
        assert_eq!(SnmpValue::EndOfMibView.to_string(), "endOfMibView");
    }

    #[test]
    fn type_names_match_reference() {
        assert_eq!(SnmpValue::Integer(1).type_name(), "integer");
        assert_eq!(SnmpValue::OctetString(vec![]).type_name(), "octet-string");
        assert_eq!(SnmpValue::Null.type_name(), "null");
        assert_eq!(
            SnmpValue::ObjectIdentifier(Oid::from_arcs(&[1, 3]).unwrap()).type_name(),
            "object-identifier"
        );
        assert_eq!(
            SnmpValue::IpAddress(Ipv4Addr::LOCALHOST).type_name(),
            "ip-address"
        );
        assert_eq!(SnmpValue::Counter32(0).type_name(), "counter32");
        assert_eq!(SnmpValue::Gauge32(0).type_name(), "gauge32");
        assert_eq!(SnmpValue::TimeTicks(0).type_name(), "timeticks");
        assert_eq!(SnmpValue::Opaque(vec![]).type_name(), "opaque");
        assert_eq!(SnmpValue::Counter64(0).type_name(), "counter64");
        assert_eq!(SnmpValue::NoSuchObject.type_name(), "no-such-object");
        assert_eq!(SnmpValue::NoSuchInstance.type_name(), "no-such-instance");
        assert_eq!(SnmpValue::EndOfMibView.type_name(), "end-of-mib-view");
    }
}
