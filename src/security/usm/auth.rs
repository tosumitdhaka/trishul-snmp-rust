//! Truncated HMAC stamp/verify, zero-fill semantics (← usm.py:622–645)

use subtle::ConstantTimeEq;

use crate::codec::v3::locate_auth_params;
use crate::error::Error;
use crate::security::usm::kdf::{AuthProtocol, auth_enabled, auth_tag_length, hmac_digest};

/// Zero-fill semantics are byte-exact (usm.py:640–644): verification zeroes
/// **exactly `tag_len` bytes** at the located offset — not the received
/// field's length — and compares only the first `tag_len` bytes of the
/// received value. Consequences to replicate: an over-long received auth field
/// contributes its extra bytes raw to the MAC input but they are ignored for
/// comparison; an under-long field lets zeros spill into the following TLV
/// (framing altered, MAC fails).
///
/// Computes the truncated HMAC tag over `raw` (usm.py:_compute_auth_tag).
///
/// Callers must zero the auth_params placeholder at the located offset before
/// calling: the MAC input is the full message as given.
pub fn compute_auth_tag(raw: &[u8], key: &[u8], protocol: AuthProtocol) -> Vec<u8> {
    let digest = hmac_digest(key, raw, protocol);
    digest[..auth_tag_length(protocol)].to_vec()
}

/// Send side: the placeholder is exactly `tag_len` zero bytes before splicing
/// the computed HMAC (usm.py:622–629). Locates the offset itself.
pub fn stamp_auth(raw: &[u8], key: &[u8], protocol: AuthProtocol) -> Result<Vec<u8>, Error> {
    let offset = locate_auth_params(raw)?;
    let tag = compute_auth_tag(raw, key, protocol);
    let tag_len = auth_tag_length(protocol);
    let mut out = raw[..offset].to_vec();
    out.extend_from_slice(&tag);
    out.extend_from_slice(&raw[offset + tag_len..]);
    Ok(out)
}

/// Verification (usm.py:_verify_auth). Returns `Error::Authentication` on
/// HMAC mismatch via a constant-time comparison of the first `tag_len` bytes.
pub fn verify_auth(
    raw: &[u8],
    offset: usize,
    received_tag: &[u8],
    key: &[u8],
    protocol: AuthProtocol,
) -> Result<(), Error> {
    if !auth_enabled(protocol) {
        return Ok(());
    }
    let tag_len = auth_tag_length(protocol);
    let zeroed = zero_fill(raw, offset, tag_len);
    let expected = compute_auth_tag(&zeroed, key, protocol);
    let received = &received_tag[..received_tag.len().min(tag_len)];
    let matches = expected.len() == received.len() && expected.ct_eq(received).unwrap_u8() == 1;
    if !matches {
        return Err(Error::Authentication);
    }
    Ok(())
}

/// Zeroes exactly `tag_len` bytes at `offset` (not the received field length).
fn zero_fill(raw: &[u8], offset: usize, tag_len: usize) -> Vec<u8> {
    let mut out = raw.to_vec();
    let end = (offset + tag_len).min(out.len());
    if offset < out.len() {
        for slot in &mut out[offset..end] {
            *slot = 0;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::usm::kdf::localize_key;
    use crate::types::oid::Oid;
    use crate::types::value::SnmpValue;
    use crate::types::varbind::VarBind;

    fn engine_id() -> Vec<u8> {
        vec![
            0x80, 0x00, 0x1f, 0x88, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }

    fn get_pdu() -> crate::codec::pdu::Pdu {
        crate::codec::pdu::Pdu {
            kind: crate::codec::pdu::PduKind::GetRequest,
            request_id: 7,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                Oid::from_arcs(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap(),
                SnmpValue::Null,
            )],
            v1_trap: None,
        }
    }

    fn wrapped(protocol: AuthProtocol) -> Vec<u8> {
        let usm = crate::codec::v3::UsmSecurityParameters {
            engine_id: engine_id(),
            engine_boots: 2,
            engine_time: 500,
            username: b"parity".to_vec(),
            auth_params: vec![0u8; auth_tag_length(protocol)],
            priv_params: Vec::new(),
        };
        let scoped = crate::codec::v3::encode_scoped_pdu(&usm.engine_id, b"", &get_pdu()).unwrap();
        crate::codec::v3::encode_v3_message(
            1,
            65507,
            crate::codec::v3::MSG_FLAG_AUTH | crate::codec::v3::MSG_FLAG_REPORTABLE,
            &usm,
            &scoped,
        )
        .unwrap()
    }

    #[test]
    fn verify_accepts_stamped_message() {
        for protocol in [
            crate::security::usm::kdf::AuthProtocol::Md5,
            AuthProtocol::Sha1,
            AuthProtocol::Sha224,
            AuthProtocol::Sha256,
            AuthProtocol::Sha384,
            AuthProtocol::Sha512,
        ] {
            let key = localize_key(b"maplesyrup", &engine_id(), protocol).unwrap();
            let stamped = stamp_auth(&wrapped(protocol), &key, protocol).unwrap();
            let offset = locate_auth_params(&stamped).unwrap();
            let view = crate::codec::v3::decode_v3_message(&stamped).unwrap();
            verify_auth(
                &stamped,
                offset,
                &view.usm_params.auth_params,
                &key,
                protocol,
            )
            .unwrap();
        }
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let protocol = AuthProtocol::Sha256;
        let key = localize_key(b"maplesyrup", &engine_id(), protocol).unwrap();
        let mut stamped = stamp_auth(&wrapped(protocol), &key, protocol).unwrap();
        let offset = locate_auth_params(&stamped).unwrap();
        // Flip a bit in the PDU area.
        let last = stamped.len() - 1;
        stamped[last] ^= 0x01;
        let view = crate::codec::v3::decode_v3_message(&stamped).unwrap();
        let err = verify_auth(
            &stamped,
            offset,
            &view.usm_params.auth_params,
            &key,
            protocol,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Authentication));
    }

    #[test]
    fn verify_ignores_extra_bytes_of_overlong_field_but_keeps_them_in_mac() {
        // An over-long auth field: extra bytes stay raw in the MAC input, the
        // comparison uses only the first tag_len bytes (usm.py:640–644).
        let protocol = AuthProtocol::Sha256;
        let key = localize_key(b"maplesyrup", &engine_id(), protocol).unwrap();
        let tag_len = auth_tag_length(protocol);
        let base_usm = crate::codec::v3::UsmSecurityParameters {
            engine_id: engine_id(),
            engine_boots: 2,
            engine_time: 500,
            username: b"parity".to_vec(),
            auth_params: vec![0u8; tag_len + 1],
            priv_params: Vec::new(),
        };
        let scoped =
            crate::codec::v3::encode_scoped_pdu(&base_usm.engine_id, b"", &get_pdu()).unwrap();
        // Messages whose auth field is tag_len+1 bytes with a varying extra byte.
        let message = |extra: u8| {
            let mut auth_params = vec![0u8; tag_len + 1];
            auth_params[tag_len] = extra;
            crate::codec::v3::encode_v3_message(
                1,
                65507,
                crate::codec::v3::MSG_FLAG_AUTH | crate::codec::v3::MSG_FLAG_REPORTABLE,
                &crate::codec::v3::UsmSecurityParameters {
                    auth_params,
                    ..base_usm.clone()
                },
                &scoped,
            )
            .unwrap()
        };
        let msg_extra_zero = message(0x00);
        let msg_extra_one = message(0x01);
        let offset = locate_auth_params(&msg_extra_zero).unwrap();
        assert_eq!(locate_auth_params(&msg_extra_one).unwrap(), offset);
        // Tag computed over the zeroed field — the extra byte is part of the
        // MAC input.
        let tag = compute_auth_tag(&msg_extra_zero, &key, protocol);
        assert_eq!(tag.len(), tag_len);
        // A legitimate over-long datagram (tag || extra) verifies: only the
        // first tag_len bytes are compared.
        let mut signed = msg_extra_zero.clone();
        signed[offset..offset + tag_len].copy_from_slice(&tag);
        assert!(
            verify_auth(
                &signed,
                offset,
                &signed[offset..offset + tag_len + 1],
                &key,
                protocol
            )
            .is_ok()
        );
        // The extra byte is in the MAC input: msg_extra_one with the same tag
        // fails even though its first tag_len field bytes match exactly.
        let mut forged = msg_extra_one.clone();
        forged[offset..offset + tag_len].copy_from_slice(&tag);
        assert!(
            verify_auth(
                &forged,
                offset,
                &forged[offset..offset + tag_len + 1],
                &key,
                protocol
            )
            .is_err()
        );
    }
}
