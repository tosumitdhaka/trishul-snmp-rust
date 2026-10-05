//! V3Message, UsmSecurityParameters, ScopedPdu, locate_auth_params() (← v3message.py)

use crate::codec::pdu::{Pdu, decode_pdu, encode_pdu};
use crate::codec::{decode_tlv, encode_tlv, expect_end};
use crate::error::ProtocolError;
use crate::types::value::{decode_signed_content, encode_signed};

// msgFlags bits (RFC 3412 §7.1.9)
pub const MSG_FLAG_AUTH: u8 = 0x01;
pub const MSG_FLAG_PRIV: u8 = 0x02;
pub const MSG_FLAG_REPORTABLE: u8 = 0x04;

const SEQUENCE_TAG: u8 = 0x30;
const INTEGER_TAG: u8 = 0x02;
const OCTET_STRING_TAG: u8 = 0x04;
const SNMP_V3_VERSION: i64 = 3;
const SECURITY_MODEL_USM: i64 = 3;

/// Decoded USM security parameters (msgSecurityParameters).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsmSecurityParameters {
    /// Authoritative engine identifier.
    pub engine_id: Vec<u8>,
    /// Authoritative engine boots counter.
    pub engine_boots: i64,
    /// Authoritative engine time.
    pub engine_time: i64,
    /// User name.
    pub username: Vec<u8>,
    /// Message authentication parameters (truncated HMAC tag).
    pub auth_params: Vec<u8>,
    /// Privacy parameters (salt).
    pub priv_params: Vec<u8>,
}

/// Decoded SNMPv3 outer message (← v3message.py:V3MessageView).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V3Message {
    /// Message id.
    pub msg_id: i64,
    /// Maximum message size the sender can accept.
    pub msg_max_size: i64,
    /// msgFlags octet (auth/priv/reportable bits).
    pub msg_flags: u8,
    /// Security model (must be USM = 3).
    pub msg_security_model: i64,
    /// Decoded USM security parameters.
    pub usm_params: UsmSecurityParameters,
    /// Raw msgData bytes: ScopedPDU SEQUENCE when priv is off, encryptedPDU
    /// OCTET STRING when on.
    pub msg_data_bytes: Vec<u8>,
    /// Byte offset within the full message where the auth_params *content*
    /// starts — the verifier zero-fills exactly `tag_len` bytes there before
    /// recomputing the HMAC (usm.py:622–645).
    pub auth_params_offset: usize,
}

/// Encodes a full SNMPv3 message (← v3message.py:encode_v3_message).
///
/// `msg_data_bytes` must be a ScopedPDU SEQUENCE when privacy is off, or an
/// encryptedPDU OCTET STRING when the PRIV flag is set. The caller fills
/// `auth_params` with the HMAC (or a protocol-length zero placeholder).
pub fn encode_v3_message(
    msg_id: i64,
    msg_max_size: i64,
    flags: u8,
    usm_params: &UsmSecurityParameters,
    msg_data_bytes: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let header_data = encode_header_data(msg_id, msg_max_size, flags)?;
    let usm_bytes = encode_usm_params(usm_params)?;
    let security_params = encode_tlv(OCTET_STRING_TAG, &usm_bytes)?;

    let mut content = encode_tlv(INTEGER_TAG, &encode_signed(SNMP_V3_VERSION))?;
    content.extend(header_data);
    content.extend(security_params);
    content.extend_from_slice(msg_data_bytes);
    encode_tlv(SEQUENCE_TAG, &content)
}

/// Decodes a full SNMPv3 outer message, deriving `auth_params_offset` from
/// parser state so non-canonical BER length forms do not shift it
/// (← v3message.py:decode_v3_message, v3message.py:113–120).
pub fn decode_v3_message(data: &[u8]) -> Result<V3Message, ProtocolError> {
    let (tag, content, end) = decode_tlv(data, 0)?;
    if tag != SEQUENCE_TAG {
        return Err(ProtocolError::new(format!(
            "Expected SNMPv3 message SEQUENCE, found 0x{tag:02x}"
        )));
    }
    expect_end(data, end)?;

    let mut offset = 0usize;

    let version = decode_integer(content, &mut offset)?;
    if version != SNMP_V3_VERSION {
        return Err(ProtocolError::new(format!(
            "Expected SNMPv3 version 3, found {version}"
        )));
    }

    let (msg_id, msg_max_size, msg_flags, msg_security_model) =
        decode_header_data(content, &mut offset)?;
    if msg_security_model != SECURITY_MODEL_USM {
        return Err(ProtocolError::new(format!(
            "Expected USM security model (3), found {msg_security_model}"
        )));
    }

    // security parameters: OCTET STRING wrapping BER-encoded UsmSecurityParameters
    let (sp_tag, sp_content, sp_offset) = decode_tlv(content, offset)?;
    if sp_tag != OCTET_STRING_TAG {
        return Err(ProtocolError::new(format!(
            "Expected msgSecurityParameters OCTET STRING, found 0x{sp_tag:02x}"
        )));
    }
    offset = sp_offset;

    // Offsets come from parser state, not re-encoded lengths
    // (v3message.py:113–120). Since expect_end verified the outer SEQUENCE
    // spans all of data, the outer content starts at len(data) - len(content).
    let (usm_params, auth_offset_in_sp) = decode_usm_params_with_offset(sp_content)?;
    let outer_content_start = data.len() - content.len();
    let sp_content_start = outer_content_start + sp_offset - sp_content.len();
    let auth_params_offset = sp_content_start + auth_offset_in_sp;

    // Validate and capture msgData: tag must match the PRIV flag.
    let priv_set = msg_flags & MSG_FLAG_PRIV != 0;
    let expected_data_tag = if priv_set {
        OCTET_STRING_TAG
    } else {
        SEQUENCE_TAG
    };
    let msg_data_start = offset;
    let (msg_data_tag, _msg_data_content, offset) = decode_tlv(content, offset)?;
    if msg_data_tag != expected_data_tag {
        let label = if priv_set {
            "encryptedPDU OCTET STRING"
        } else {
            "ScopedPDU SEQUENCE"
        };
        return Err(ProtocolError::new(format!(
            "Expected msgData as {label} (0x{expected_data_tag:02x}), found 0x{msg_data_tag:02x}"
        )));
    }
    expect_end(content, offset)?;
    let msg_data_bytes = content[msg_data_start..offset].to_vec();

    Ok(V3Message {
        msg_id,
        msg_max_size,
        msg_flags,
        msg_security_model,
        usm_params,
        msg_data_bytes,
        auth_params_offset,
    })
}

/// Encodes a ScopedPDU (← v3message.py:encode_scoped_pdu).
pub fn encode_scoped_pdu(
    engine_id: &[u8],
    context_name: &[u8],
    pdu: &Pdu,
) -> Result<Vec<u8>, ProtocolError> {
    let mut content = encode_tlv(OCTET_STRING_TAG, engine_id)?;
    content.extend(encode_tlv(OCTET_STRING_TAG, context_name)?);
    content.extend(encode_pdu(pdu)?);
    encode_tlv(SEQUENCE_TAG, &content)
}

/// Decodes a ScopedPDU into `(engine_id, context_name, pdu)`
/// (← v3message.py:decode_scoped_pdu). REPORT PDUs (0xA8) decode through the
/// standard PDU codec (`PduKind::Report` is first-class here).
pub fn decode_scoped_pdu(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Pdu), ProtocolError> {
    let (tag, content, end) = decode_tlv(data, 0)?;
    if tag != SEQUENCE_TAG {
        return Err(ProtocolError::new(format!(
            "Expected ScopedPDU SEQUENCE, found 0x{tag:02x}"
        )));
    }
    expect_end(data, end)?;

    let mut offset = 0usize;
    let engine_id = decode_octet_bytes(content, &mut offset)?;
    let context_name = decode_octet_bytes(content, &mut offset)?;

    let (pdu_tag, _pdu_content, pdu_end) = decode_tlv(content, offset)?;
    // The tag is implicitly checked by decode_pdu's tag range.
    let pdu = decode_pdu(&content[offset..pdu_end]).map_err(|error| {
        ProtocolError::new(format!("Expected PDU tag 0x{pdu_tag:02x}: {error}"))
    })?;
    expect_end(content, pdu_end)?;
    Ok((engine_id, context_name, pdu))
}

/// Walks the fixed outer structure of a BER-encoded SNMPv3 message and returns
/// the byte offset (within `data`) of the `msgAuthenticationParameters` OCTET
/// STRING *content* — the position USM verification zero-fills before
/// recomputing the HMAC (v3message.py:113–120, usm.py:622–645).
///
/// Offsets are derived from parser state (`len(data) - len(content)`), never
/// from re-encoded lengths, so non-canonical long-form BER length octets do
/// not shift the result (test_v3_wire.py:302–327).
pub fn locate_auth_params(data: &[u8]) -> Result<usize, ProtocolError> {
    let (tag, outer_content, end) = decode_tlv(data, 0)?;
    if tag != SEQUENCE_TAG {
        return Err(ProtocolError::new(format!(
            "Expected SNMPv3 message SEQUENCE, found 0x{tag:02x}"
        )));
    }
    expect_end(data, end)?;

    let mut offset = 0;
    // version INTEGER
    let (version_tag, _, next) = decode_tlv(outer_content, offset)?;
    if version_tag != INTEGER_TAG {
        return Err(ProtocolError::new(format!(
            "Expected INTEGER, found 0x{version_tag:02x}"
        )));
    }
    offset = next;
    // msgGlobalData SEQUENCE
    let (header_tag, _, next) = decode_tlv(outer_content, offset)?;
    if header_tag != SEQUENCE_TAG {
        return Err(ProtocolError::new(format!(
            "Expected msgGlobalData SEQUENCE, found 0x{header_tag:02x}"
        )));
    }
    offset = next;
    // msgSecurityParameters OCTET STRING
    let (sp_tag, sp_content, next) = decode_tlv(outer_content, offset)?;
    if sp_tag != OCTET_STRING_TAG {
        return Err(ProtocolError::new(format!(
            "Expected msgSecurityParameters OCTET STRING, found 0x{sp_tag:02x}"
        )));
    }
    offset = next;

    let (usm_tag, usm_content, usm_end) = decode_tlv(sp_content, 0)?;
    if usm_tag != SEQUENCE_TAG {
        return Err(ProtocolError::new(format!(
            "Expected UsmSecurityParameters SEQUENCE, found 0x{usm_tag:02x}"
        )));
    }
    expect_end(sp_content, usm_end)?;

    let mut inner = 0;
    // engine_id OCTET STRING
    let (t, _, next) = decode_tlv(usm_content, inner)?;
    if t != OCTET_STRING_TAG {
        return Err(ProtocolError::new(format!(
            "Expected OCTET STRING, found 0x{t:02x}"
        )));
    }
    inner = next;
    // engine_boots INTEGER
    let (t, _, next) = decode_tlv(usm_content, inner)?;
    if t != INTEGER_TAG {
        return Err(ProtocolError::new(format!(
            "Expected INTEGER, found 0x{t:02x}"
        )));
    }
    inner = next;
    // engine_time INTEGER
    let (t, _, next) = decode_tlv(usm_content, inner)?;
    if t != INTEGER_TAG {
        return Err(ProtocolError::new(format!(
            "Expected INTEGER, found 0x{t:02x}"
        )));
    }
    inner = next;
    // username OCTET STRING
    let (t, _, next) = decode_tlv(usm_content, inner)?;
    if t != OCTET_STRING_TAG {
        return Err(ProtocolError::new(format!(
            "Expected OCTET STRING, found 0x{t:02x}"
        )));
    }
    inner = next;
    // auth_params OCTET STRING
    let (auth_tag, auth_content, auth_end) = decode_tlv(usm_content, inner)?;
    if auth_tag != OCTET_STRING_TAG {
        return Err(ProtocolError::new(format!(
            "Expected msgAuthenticationParameters OCTET STRING, found 0x{auth_tag:02x}"
        )));
    }

    let outer_content_start = data.len() - outer_content.len();
    let sp_content_start = outer_content_start + offset - sp_content.len();
    let usm_content_start = sp_content_start + (sp_content.len() - usm_content.len());
    Ok(usm_content_start + auth_end - auth_content.len())
}

// ── internal helpers ─────────────────────────────────────────────────────────

fn encode_header_data(msg_id: i64, msg_max_size: i64, flags: u8) -> Result<Vec<u8>, ProtocolError> {
    let mut content = encode_tlv(INTEGER_TAG, &encode_signed(msg_id))?;
    content.extend(encode_tlv(INTEGER_TAG, &encode_signed(msg_max_size))?);
    content.extend(encode_tlv(OCTET_STRING_TAG, &[flags])?);
    content.extend(encode_tlv(INTEGER_TAG, &encode_signed(SECURITY_MODEL_USM))?);
    encode_tlv(SEQUENCE_TAG, &content)
}

fn decode_header_data(
    data: &[u8],
    offset: &mut usize,
) -> Result<(i64, i64, u8, i64), ProtocolError> {
    let (tag, content, end) = decode_tlv(data, *offset)?;
    if tag != SEQUENCE_TAG {
        return Err(ProtocolError::new(format!(
            "Expected msgGlobalData SEQUENCE, found 0x{tag:02x}"
        )));
    }
    *offset = end;

    let mut inner = 0usize;
    let msg_id = decode_integer(content, &mut inner)?;
    let msg_max_size = decode_integer(content, &mut inner)?;
    let (flags_tag, flags_content, flags_end) = decode_tlv(content, inner)?;
    if flags_tag != OCTET_STRING_TAG {
        return Err(ProtocolError::new(format!(
            "Expected msgFlags OCTET STRING, found 0x{flags_tag:02x}"
        )));
    }
    if flags_content.len() != 1 {
        return Err(ProtocolError::new("msgFlags must be exactly one octet"));
    }
    inner = flags_end;
    let security_model = decode_integer(content, &mut inner)?;
    expect_end(content, inner)?;
    Ok((msg_id, msg_max_size, flags_content[0], security_model))
}

fn encode_usm_params(p: &UsmSecurityParameters) -> Result<Vec<u8>, ProtocolError> {
    let mut content = encode_tlv(OCTET_STRING_TAG, &p.engine_id)?;
    content.extend(encode_tlv(INTEGER_TAG, &encode_signed(p.engine_boots))?);
    content.extend(encode_tlv(INTEGER_TAG, &encode_signed(p.engine_time))?);
    content.extend(encode_tlv(OCTET_STRING_TAG, &p.username)?);
    content.extend(encode_tlv(OCTET_STRING_TAG, &p.auth_params)?);
    content.extend(encode_tlv(OCTET_STRING_TAG, &p.priv_params)?);
    encode_tlv(SEQUENCE_TAG, &content)
}

/// Decodes UsmSecurityParameters plus the byte offset (within `data`) of the
/// auth_params *content* (← v3message.py:_decode_usm_params_with_offset).
fn decode_usm_params_with_offset(
    data: &[u8],
) -> Result<(UsmSecurityParameters, usize), ProtocolError> {
    let (tag, content, end) = decode_tlv(data, 0)?;
    if tag != SEQUENCE_TAG {
        return Err(ProtocolError::new(format!(
            "Expected UsmSecurityParameters SEQUENCE, found 0x{tag:02x}"
        )));
    }
    expect_end(data, end)?;

    // content starts at len(data) - len(content); derive offsets from parser
    // state so non-canonical length encodings do not shift the pointer.
    let content_start = data.len() - content.len();

    let mut offset = 0usize;
    let engine_id = decode_octet_bytes(content, &mut offset)?;
    let engine_boots = decode_integer(content, &mut offset)?;
    let engine_time = decode_integer(content, &mut offset)?;
    let username = decode_octet_bytes(content, &mut offset)?;

    let (auth_tag, auth_content, auth_end) = decode_tlv(content, offset)?;
    if auth_tag != OCTET_STRING_TAG {
        return Err(ProtocolError::new(format!(
            "Expected msgAuthenticationParameters OCTET STRING, found 0x{auth_tag:02x}"
        )));
    }
    let auth_offset_in_data = content_start + auth_end - auth_content.len();
    offset = auth_end;

    let priv_params = decode_octet_bytes(content, &mut offset)?;
    expect_end(content, offset)?;

    Ok((
        UsmSecurityParameters {
            engine_id,
            engine_boots,
            engine_time,
            username,
            auth_params: auth_content.to_vec(),
            priv_params,
        },
        auth_offset_in_data,
    ))
}

fn decode_integer(data: &[u8], offset: &mut usize) -> Result<i64, ProtocolError> {
    let (tag, content, end) = decode_tlv(data, *offset)?;
    if tag != INTEGER_TAG {
        return Err(ProtocolError::new(format!(
            "Expected INTEGER, found 0x{tag:02x}"
        )));
    }
    if content.is_empty() {
        return Err(ProtocolError::new("INTEGER content cannot be empty"));
    }
    let value = decode_signed_content(content)?;
    *offset = end;
    Ok(value)
}

fn decode_octet_bytes(data: &[u8], offset: &mut usize) -> Result<Vec<u8>, ProtocolError> {
    let (tag, content, end) = decode_tlv(data, *offset)?;
    if tag != OCTET_STRING_TAG {
        return Err(ProtocolError::new(format!(
            "Expected OCTET STRING, found 0x{tag:02x}"
        )));
    }
    *offset = end;
    Ok(content.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::oid::Oid;
    use crate::types::value::SnmpValue;
    use crate::types::varbind::VarBind;

    fn oid(arcs: &[u32]) -> Oid {
        Oid::from_arcs(arcs).unwrap()
    }

    fn get_pdu(request_id: i64) -> Pdu {
        Pdu {
            kind: crate::codec::pdu::PduKind::GetRequest,
            request_id: request_id as u32,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                SnmpValue::Null,
            )],
            v1_trap: None,
        }
    }

    fn sample_usm(auth: &[u8], priv_params: &[u8]) -> UsmSecurityParameters {
        UsmSecurityParameters {
            engine_id: vec![
                0x80, 0x00, 0x1f, 0x88, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            engine_boots: 5,
            engine_time: 12345,
            username: b"simulator".to_vec(),
            auth_params: auth.to_vec(),
            priv_params: priv_params.to_vec(),
        }
    }

    #[test]
    fn usm_params_and_v3_message_roundtrip() {
        let usm = sample_usm(&[0u8; 12], &[]);
        let scoped = encode_scoped_pdu(&usm.engine_id, b"", &get_pdu(7)).unwrap();
        let raw = encode_v3_message(101, 65507, MSG_FLAG_REPORTABLE, &usm, &scoped).unwrap();
        let view = decode_v3_message(&raw).unwrap();
        assert_eq!(view.msg_id, 101);
        assert_eq!(view.msg_max_size, 65507);
        assert_eq!(view.msg_flags, MSG_FLAG_REPORTABLE);
        assert_eq!(view.msg_security_model, 3);
        assert_eq!(view.usm_params, usm);
        let (eid, ctx, pdu) = decode_scoped_pdu(&view.msg_data_bytes).unwrap();
        assert_eq!(eid, usm.engine_id);
        assert!(ctx.is_empty());
        assert_eq!(pdu.request_id, 7);
    }

    #[test]
    fn locate_auth_params_matches_decode_offset() {
        let usm = sample_usm(&[0u8; 24], &[]);
        let scoped = encode_scoped_pdu(&usm.engine_id, b"ctx", &get_pdu(1)).unwrap();
        let raw = encode_v3_message(1, 65507, MSG_FLAG_AUTH | MSG_FLAG_REPORTABLE, &usm, &scoped)
            .unwrap();
        assert_eq!(
            locate_auth_params(&raw).unwrap(),
            decode_v3_message(&raw).unwrap().auth_params_offset
        );
    }

    #[test]
    fn decode_v3_message_rejects_wrong_version() {
        let usm = sample_usm(&[], &[]);
        let scoped = encode_scoped_pdu(&usm.engine_id, b"", &get_pdu(1)).unwrap();
        let raw = encode_v3_message(1, 65507, 0, &usm, &scoped).unwrap();
        // Rewrite the version INTEGER content to 2.
        let mut bytes = raw.clone();
        bytes[4] = 0x02; // version value 3 -> 2 (content starts at index 4)
        let err = decode_v3_message(&bytes).unwrap_err();
        assert!(
            err.to_string()
                .contains("Expected SNMPv3 version 3, found 2")
        );
    }

    #[test]
    fn decode_v3_message_rejects_wrong_outer_tag() {
        let err = decode_v3_message(&[0x02, 0x01, 0x03]).unwrap_err();
        assert!(
            err.to_string()
                .contains("Expected SNMPv3 message SEQUENCE, found 0x02")
        );
    }

    #[test]
    fn decode_scoped_pdu_rejects_trailing_bytes() {
        let usm = sample_usm(&[], &[]);
        let scoped = encode_scoped_pdu(&usm.engine_id, b"", &get_pdu(1)).unwrap();
        let mut bytes = scoped.clone();
        bytes.push(0x00);
        let err = decode_scoped_pdu(&bytes).unwrap_err();
        assert!(err.to_string().contains("Unexpected trailing"));
    }
}
