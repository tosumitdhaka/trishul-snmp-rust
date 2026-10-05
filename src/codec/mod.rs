//! rasn DER-mode config + remainder shim (← ber.py; see docs/architecture.md §5.3a)

use rasn::de::Decode;

use crate::error::ProtocolError;
use crate::types::value::SnmpValue;

pub mod message;
pub mod pdu;
pub mod v3;
pub mod validate;

/// Encodes a BER length field (← ber.py:8–15). `usize` cannot be negative,
/// so the reference's negative rejection is unrepresentable.
pub(crate) fn encode_length(length: usize) -> Result<Vec<u8>, ProtocolError> {
    if length < 0x80 {
        return Ok(vec![length as u8]);
    }
    let mut bytes = Vec::new();
    let mut remaining = length;
    while remaining > 0 {
        bytes.push((remaining & 0xFF) as u8);
        remaining >>= 8;
    }
    bytes.reverse();
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend(bytes);
    Ok(out)
}

/// Decodes a BER length field (← ber.py:18–33). Indefinite form (0x80) and
/// truncated long-form payloads are rejected; non-canonical (long-form for a
/// short value) octets are accepted — required by test_v3_wire.py:302–327.
pub(crate) fn decode_length(data: &[u8], offset: usize) -> Result<(usize, usize), ProtocolError> {
    if offset >= data.len() {
        return Err(ProtocolError::new("BER length is truncated"));
    }
    let first = data[offset];
    let offset = offset + 1;
    if first < 0x80 {
        return Ok((usize::from(first), offset));
    }
    let count = usize::from(first & 0x7F);
    if count == 0 {
        return Err(ProtocolError::new(
            "Indefinite BER lengths are not supported",
        ));
    }
    let end = offset.saturating_add(count);
    if end > data.len() {
        return Err(ProtocolError::new("BER length payload is truncated"));
    }
    let mut value = 0usize;
    for &byte in &data[offset..end] {
        value = value.saturating_mul(256) | usize::from(byte);
    }
    Ok((value, end))
}

/// Decodes a BER TLV (single-octet tag), returning `(tag, content, end)`
/// (← ber.py:36–50).
pub(crate) fn decode_tlv(data: &[u8], offset: usize) -> Result<(u8, &[u8], usize), ProtocolError> {
    if offset >= data.len() {
        return Err(ProtocolError::new("BER tag is truncated"));
    }
    let tag = data[offset];
    let (length, content_offset) = decode_length(data, offset + 1)?;
    let end = content_offset.saturating_add(length);
    if end > data.len() {
        return Err(ProtocolError::new("BER content is truncated"));
    }
    Ok((tag, &data[content_offset..end], end))
}

/// Requires `offset` to point at the end of `data` (← ber.py:53–56).
pub(crate) fn expect_end(data: &[u8], offset: usize) -> Result<(), ProtocolError> {
    if offset != data.len() {
        return Err(ProtocolError::new("Unexpected trailing BER content"));
    }
    Ok(())
}

/// Decodes `T` under rasn's DER decoder options, rejecting trailing content.
///
/// DER mode (docs/architecture.md §5.3a item 1) rejects indefinite lengths and
/// constructed OCTET STRINGs — both accepted by rasn's BER mode and both
/// rejected by the reference. The remainder shim (item 2) matches the
/// reference's `expect_end` top-level check (ber.py:53–56), which
/// `der::decode` alone does not provide.
pub(crate) fn decode_der<T: Decode>(data: &[u8]) -> Result<T, ProtocolError> {
    let mut decoder = rasn::ber::de::Decoder::new(data, rasn::ber::de::DecoderOptions::der());
    let value = T::decode(&mut decoder)
        .map_err(|e| ProtocolError::at(decoder.decoded_len(), e.to_string()))?;
    let offset = decoder.decoded_len();
    if !decoder.remaining().is_empty() {
        return Err(ProtocolError::at(offset, "Unexpected trailing BER content"));
    }
    Ok(value)
}

/// Encodes a bare `SnmpValue` to its BER TLV (← asn1.py:encode_value).
pub fn encode_value(value: &SnmpValue) -> Result<Vec<u8>, ProtocolError> {
    rasn::ber::encode(value).map_err(|e| ProtocolError::new(e.to_string()))
}

/// Decodes a bare BER-encoded `SnmpValue`, applying the asn1.py:132–182
/// strictness rules and rejecting trailing content (← asn1.py:decode_value).
///
/// The TLV framing is read with this module's own helpers rather than a rasn
/// `Any` decode: the reference's `decode_tlv` treats the first octet as the
/// complete tag (SNMP has no long-form tags), whereas rasn's identifier parser
/// would consume continuation octets for high-bit tags.
pub fn decode_value(data: &[u8]) -> Result<SnmpValue, ProtocolError> {
    crate::types::value::decode_value_tlv(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_length_supports_short_and_long_forms() {
        // The reference's negative rejection is unrepresentable with usize.
        assert_eq!(encode_length(0).unwrap(), vec![0x00]);
        assert_eq!(encode_length(127).unwrap(), vec![0x7F]);
        assert_eq!(encode_length(128).unwrap(), vec![0x81, 0x80]);
        assert_eq!(encode_length(256).unwrap(), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn decode_length_supports_short_and_long_forms_and_rejects_truncation() {
        assert_eq!(decode_length(&[0x7F], 0).unwrap(), (127, 1));
        assert_eq!(decode_length(&[0x81, 0x80], 0).unwrap(), (128, 2));
        assert_eq!(decode_length(&[0x82, 0x01, 0x00], 0).unwrap(), (256, 3));
        let err = decode_length(&[], 0).unwrap_err();
        assert_eq!(err.message, "BER length is truncated");
        let err = decode_length(&[0x82, 0x01], 0).unwrap_err();
        assert_eq!(err.message, "BER length payload is truncated");
    }

    #[test]
    fn decode_length_rejects_indefinite_form() {
        let err = decode_length(&[0x80], 0).unwrap_err();
        assert_eq!(err.message, "Indefinite BER lengths are not supported");
    }

    #[test]
    fn decode_tlv_rejects_truncated_content() {
        let err = decode_tlv(&[0x02, 0x02, 0x01], 0).unwrap_err();
        assert_eq!(err.message, "BER content is truncated");
    }

    #[test]
    fn decode_tlv_and_expect_end_reject_invalid_framing() {
        assert_eq!(
            decode_tlv(&[0x04, 0x03, b'a', b'b', b'c'], 0).unwrap(),
            (0x04, &b"abc"[..], 5)
        );
        let err = decode_tlv(&[], 0).unwrap_err();
        assert_eq!(err.message, "BER tag is truncated");
        let err = expect_end(&[0x00], 0).unwrap_err();
        assert_eq!(err.message, "Unexpected trailing BER content");
    }

    #[test]
    fn decode_tlv_accepts_maximum_short_form_length() {
        let data = [vec![0x04, 0x7F], vec![0x00; 127]].concat();
        assert_eq!(decode_tlv(&data, 0).unwrap().1.len(), 127);
    }

    #[test]
    fn decode_tlv_accepts_minimal_long_form_length() {
        let data = [vec![0x04, 0x81, 0x80], vec![0x00; 128]].concat();
        let (tag, content, offset) = decode_tlv(&data, 0).unwrap();
        assert_eq!(tag, 0x04);
        assert_eq!(content.len(), 128);
        assert_eq!(offset, 131);
    }

    #[test]
    fn decode_tlv_rejects_length_claim_beyond_payload() {
        // Long-form length claims 16 content bytes but only 1 is present.
        let err = decode_tlv(&[0x04, 0x83, 0x00, 0x00, 0x10, 0xAA], 0).unwrap_err();
        assert_eq!(err.message, "BER content is truncated");
    }
}
