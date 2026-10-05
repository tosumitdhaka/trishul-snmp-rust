//! V3Message, UsmSecurityParameters, ScopedPdu, locate_auth_params() (← v3message.py)
//!
//! Phase 1 ships only `locate_auth_params`; the V3Message codec gates in
//! Phase 3 (docs/plan.md Phase 1).

use crate::codec::{decode_tlv, expect_end};
use crate::error::ProtocolError;

/// Walks the fixed outer structure of a BER-encoded SNMPv3 message and returns
/// the byte offset (within `data`) of the `msgAuthenticationParameters` OCTET
/// STRING *content* — the position USM verification zero-fills before
/// recomputing the HMAC (v3message.py:113–120, usm.py:622–645).
///
/// Structure: outer SEQ → version INTEGER → msgGlobalData SEQ →
/// msgSecurityParameters OCTET STRING → UsmSecurityParameters SEQ → 5th field.
///
/// Offsets are derived from parser state (`len(data) - len(content)`), never
/// from re-encoded lengths, so non-canonical long-form BER length octets do
/// not shift the result (test_v3_wire.py:302–327).
pub fn locate_auth_params(data: &[u8]) -> Result<usize, ProtocolError> {
    let (tag, outer_content, end) = decode_tlv(data, 0)?;
    if tag != 0x30 {
        return Err(ProtocolError::new(format!(
            "Expected SNMPv3 message SEQUENCE, found 0x{tag:02x}"
        )));
    }
    expect_end(data, end)?;

    let mut offset = 0;
    // version INTEGER
    let (version_tag, _, next) = decode_tlv(outer_content, offset)?;
    if version_tag != 0x02 {
        return Err(ProtocolError::new(format!(
            "Expected INTEGER, found 0x{version_tag:02x}"
        )));
    }
    offset = next;
    // msgGlobalData SEQUENCE
    let (header_tag, _, next) = decode_tlv(outer_content, offset)?;
    if header_tag != 0x30 {
        return Err(ProtocolError::new(format!(
            "Expected msgGlobalData SEQUENCE, found 0x{header_tag:02x}"
        )));
    }
    offset = next;
    // msgSecurityParameters OCTET STRING
    let (sp_tag, sp_content, next) = decode_tlv(outer_content, offset)?;
    if sp_tag != 0x04 {
        return Err(ProtocolError::new(format!(
            "Expected msgSecurityParameters OCTET STRING, found 0x{sp_tag:02x}"
        )));
    }
    offset = next; // msgData follows; not needed here

    // UsmSecurityParameters SEQUENCE inside the security parameters octets.
    let (usm_tag, usm_content, usm_end) = decode_tlv(sp_content, 0)?;
    if usm_tag != 0x30 {
        return Err(ProtocolError::new(format!(
            "Expected UsmSecurityParameters SEQUENCE, found 0x{usm_tag:02x}"
        )));
    }
    expect_end(sp_content, usm_end)?;

    let mut inner = 0;
    // engine_id OCTET STRING
    let (t, _, next) = decode_tlv(usm_content, inner)?;
    if t != 0x04 {
        return Err(ProtocolError::new(format!(
            "Expected OCTET STRING, found 0x{t:02x}"
        )));
    }
    inner = next;
    // engine_boots INTEGER
    let (t, _, next) = decode_tlv(usm_content, inner)?;
    if t != 0x02 {
        return Err(ProtocolError::new(format!(
            "Expected INTEGER, found 0x{t:02x}"
        )));
    }
    inner = next;
    // engine_time INTEGER
    let (t, _, next) = decode_tlv(usm_content, inner)?;
    if t != 0x02 {
        return Err(ProtocolError::new(format!(
            "Expected INTEGER, found 0x{t:02x}"
        )));
    }
    inner = next;
    // username OCTET STRING
    let (t, _, next) = decode_tlv(usm_content, inner)?;
    if t != 0x04 {
        return Err(ProtocolError::new(format!(
            "Expected OCTET STRING, found 0x{t:02x}"
        )));
    }
    inner = next;
    // auth_params OCTET STRING — the 5th field.
    let (auth_tag, auth_content, auth_end) = decode_tlv(usm_content, inner)?;
    if auth_tag != 0x04 {
        return Err(ProtocolError::new(format!(
            "Expected msgAuthenticationParameters OCTET STRING, found 0x{auth_tag:02x}"
        )));
    }

    // All offsets derive from parser state, never from re-encoded lengths.
    let outer_content_start = data.len() - outer_content.len();
    let sp_content_start = outer_content_start + offset - sp_content.len();
    let usm_content_start = sp_content_start + (sp_content.len() - usm_content.len());
    Ok(usm_content_start + auth_end - auth_content.len())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn usm_params(auth: &[u8]) -> Vec<u8> {
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
        let sp = etlv(0x04, &usm_params(auth));
        // msgData — the walker never parses it; a minimal ScopedPDU suffices.
        let scoped = etlv(
            0x30,
            &[etlv(0x04, &[]), etlv(0x04, &[]), etlv(0x30, &[])].concat(),
        );
        etlv(0x30, &[sint(3), header, sp, scoped].concat())
    }

    #[test]
    fn offset_points_at_auth_params_content() {
        let sentinel = [
            0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        let raw = v3_message(&sentinel);
        let offset = locate_auth_params(&raw).unwrap();
        assert_eq!(&raw[offset..offset + sentinel.len()], &sentinel);
    }

    #[test]
    fn offset_is_stable_under_non_canonical_outer_length() {
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

    #[test]
    fn rejects_wrong_outer_tag() {
        let err = locate_auth_params(&[0x04, 0x01, 0x00]).unwrap_err();
        assert_eq!(err.message, "Expected SNMPv3 message SEQUENCE, found 0x04");
    }

    #[test]
    fn rejects_trailing_content() {
        let mut raw = v3_message(&[]);
        raw.push(0x00);
        let err = locate_auth_params(&raw).unwrap_err();
        assert_eq!(err.message, "Unexpected trailing BER content");
    }
}
