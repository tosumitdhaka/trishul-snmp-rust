//! Probe detect, REPORT encode, inform ack, v3 receive decode (← notify/v3.py rest)
//!
//! The listener-side SNMPv3 helpers: the decoded-datagram wrapper, the
//! notification envelope, the fine-grained receive decode (auth verify, priv
//! decrypt, security-level and reportable-flag validation), discovery-probe
//! detection, the discovery REPORT encoder, and the inform RESPONSE encoder.

use crate::codec::pdu::{Pdu, PduKind, decode_pdu};
use crate::codec::v3::{
    MSG_FLAG_AUTH, MSG_FLAG_PRIV, MSG_FLAG_REPORTABLE, UsmSecurityParameters, V3Message,
    decode_v3_message, encode_scoped_pdu, encode_v3_message,
};
use crate::codec::{decode_tlv, encode_length, expect_end};
use crate::error::{Error, ProtocolError};
use crate::notify::replay::DropReason;
use crate::security::usm::kdf::{PrivProtocol, auth_enabled, auth_tag_length};
use crate::security::usm::{UsmLocalEngine, UsmModel, UsmUser};
use crate::types::oid::Oid;
use crate::types::value::SnmpValue;
use crate::types::varbind::VarBind;

/// Maximum message size declared by outbound listener messages.
const MAX_MSG_SIZE: i64 = 65507;
const SEQUENCE_TAG: u8 = 0x30;
const OCTET_STRING_TAG: u8 = 0x04;
const GET_REQUEST_TAG: u8 = 0xA0;
/// usmStatsUnknownUserNames.0 — the discovery probe target.
const DISCOVERY_PROBE_OID: [u32; 11] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0];
const NOTIFICATION_PDU_TAGS: [u8; 2] = [0xA6, 0xA7]; // INFORM, SNMPV2-TRAP

/// `(context_engine_id, context_name, pdu_tag, pdu_content)` from the
/// ScopedPDU walk (notify/v3.py:590–601).
type ScopedFields = (Vec<u8>, Vec<u8>, u8, Vec<u8>);

/// `(context_engine_id, context_name, pdu)` for a decoded notification
/// (notify/v3.py:583–587).
type NotificationScoped = (Vec<u8>, Vec<u8>, Pdu);

/// Decoded SNMPv3 message header plus its raw datagram bytes
/// (notify/v3.py:53–68).
///
/// The notification consume path decodes the message header exactly once at
/// the listener boundary and threads this structure through the verification
/// helpers so no helper re-decodes the header of the same datagram.
#[derive(Clone, Debug)]
pub struct V3DecodedDatagram {
    /// The raw datagram bytes (needed for HMAC verification).
    pub data: Vec<u8>,
    /// The decoded message header.
    pub view: V3Message,
}

impl V3DecodedDatagram {
    /// Decodes the header of `data` into a shared decoded structure.
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            data: data.to_vec(),
            view: decode_v3_message(data)?,
        })
    }
}

/// Decoded inbound SNMPv3 notification plus v3 metadata (notify/v3.py:42–51).
#[derive(Clone, Debug)]
pub struct V3NotificationEnvelope {
    /// The decoded outer message.
    pub view: V3Message,
    /// The decoded notification PDU.
    pub pdu: Pdu,
    /// ScopedPDU contextEngineID.
    pub context_engine_id: Vec<u8>,
    /// ScopedPDU contextName.
    pub context_name: Vec<u8>,
    /// `"noAuthNoPriv"` | `"authNoPriv"` | `"authPriv"`.
    pub security_level: String,
}

/// Whether `decoded` is the empty-engineID discovery probe used by
/// `V3Notifier` (notify/v3.py:355–372).
#[must_use]
pub fn is_discovery_probe(decoded: &V3DecodedDatagram) -> bool {
    if !has_probe_header(&decoded.view) {
        return false;
    }
    let Ok((context_engine_id, context_name, pdu_tag, pdu_content)) =
        decode_scoped_fields(&decoded.view.msg_data_bytes)
    else {
        return false;
    };
    let Ok(probe) = decode_pdu_bytes(pdu_tag, &pdu_content) else {
        return false;
    };
    has_probe_payload(&context_engine_id, &context_name, pdu_tag, &probe)
}

/// Decodes an inbound SNMPv3 trap or inform for a single configured user
/// (notify/v3.py:288–352).
///
/// Returns `Ok(None)` for wrong-user or non-notification messages. Returns
/// `Err(Error::Protocol)` for malformed messages that otherwise target the
/// configured user, and `Err(Error::Authentication)` for HMAC failures.
///
/// `codec` supplies a persistent [`UsmModel`] whose localized-key caches
/// survive across datagrams — the listener hot path passes its own codec so
/// the RFC 3414 key derivations run once per engine instead of once per
/// packet. Offline/CLI use builds a fresh one-shot model.
pub fn decode_v3_notification_message(
    decoded: &V3DecodedDatagram,
    user: &UsmUser,
    codec: &UsmModel,
) -> Result<Option<V3NotificationEnvelope>, Error> {
    let view = &decoded.view;
    if view.usm_params.username != user.username.as_bytes() {
        return Ok(None);
    }
    let flags = view.msg_flags;
    validate_security_level(flags, user)?;

    if flags & MSG_FLAG_AUTH != 0 {
        let expected_auth_len = codec.auth_tag_len();
        if view.usm_params.auth_params.len() != expected_auth_len {
            return Err(Error::Protocol(ProtocolError::new(format!(
                "USM auth parameters must be exactly {expected_auth_len} octets for {}, \
                 got {}",
                user.auth_protocol.name(),
                view.usm_params.auth_params.len()
            ))));
        }
        codec.verify_auth(
            &decoded.data,
            view.auth_params_offset,
            &view.usm_params.auth_params,
            &view.usm_params.engine_id,
        )?;
    }

    let mut msg_data = view.msg_data_bytes.clone();
    if flags & MSG_FLAG_PRIV != 0 {
        msg_data = codec.decrypt_scoped_pdu(
            &msg_data,
            &view.usm_params.priv_params,
            &view.usm_params.engine_id,
            view.usm_params.engine_boots,
            view.usm_params.engine_time,
        )?;
    }

    let Some((context_engine_id, context_name, pdu)) = decode_notification_scoped_pdu(&msg_data)?
    else {
        return Ok(None);
    };
    validate_notification_reportable_flag(flags, pdu.kind)?;

    Ok(Some(V3NotificationEnvelope {
        view: view.clone(),
        pdu,
        context_engine_id,
        context_name,
        security_level: security_level_from_flags(flags).to_string(),
    }))
}

/// Classifies a v3 datagram that decoded to no notification for `user`
/// (notify/v3.py:121–135).
///
/// `decode_v3_notification_message` returns `None` both when the message names
/// a different user and when it is a well-formed message that is not a
/// notification PDU; this helper picks the drop reason between the two.
#[must_use]
pub fn classify_v3_unmatched(decoded: &V3DecodedDatagram, user: &UsmUser) -> DropReason {
    if decoded.view.usm_params.username != user.username.as_bytes() {
        DropReason::WrongUser
    } else {
        DropReason::NotNotification
    }
}

/// Encodes a minimal discovery REPORT for an empty-engineID probe
/// (notify/v3.py:403–438).
///
/// `engine_time` overrides `local_engine.engine_time` — the listener passes
/// its monotonic-advanced current engine time so successive REPORTs stay
/// inside the probe sender's ±150 s acceptance window. When omitted (offline
/// use) the configured value is used verbatim.
pub fn encode_discovery_report(
    decoded: &V3DecodedDatagram,
    local_engine: &UsmLocalEngine,
    engine_time: Option<u32>,
) -> Result<Vec<u8>, ProtocolError> {
    let (view, context_engine_id, context_name, probe) = decode_discovery_probe(decoded)?;
    let effective_engine_time = engine_time.unwrap_or(local_engine.engine_time);
    let report_pdu = Pdu {
        kind: PduKind::Report,
        request_id: probe.request_id,
        error_status: 0,
        error_index: 0,
        varbinds: vec![VarBind::new(
            Oid::from_arcs(&DISCOVERY_PROBE_OID).expect("fixed OID"),
            SnmpValue::Counter32(1),
        )],
        v1_trap: None,
    };
    let scoped = encode_scoped_pdu(&context_engine_id, &context_name, &report_pdu)?;
    let usm = UsmSecurityParameters {
        engine_id: local_engine.engine_id.clone(),
        engine_boots: i64::from(local_engine.engine_boots),
        engine_time: i64::from(effective_engine_time),
        username: Vec::new(),
        auth_params: Vec::new(),
        priv_params: Vec::new(),
    };
    encode_v3_message(view.msg_id, MAX_MSG_SIZE, 0, &usm, &scoped)
}

/// Encodes a USM RESPONSE that acknowledges an INFORM request
/// (notify/v3.py:441–508).
///
/// `codec` supplies a persistent [`UsmModel`] so the listener hot path reuses
/// its localized-key caches across informs (a fresh one-shot model is built
/// when omitted, as in offline use). `engine_time` overrides
/// `local_engine.engine_time` — the listener passes its monotonic-advanced
/// current engine time; it is used both for the message header and for the
/// privacy IV, so the receiver can decrypt the response.
pub fn encode_inform_response(
    envelope: &V3NotificationEnvelope,
    user: &UsmUser,
    local_engine: &UsmLocalEngine,
    codec: &UsmModel,
    engine_time: Option<u32>,
) -> Result<Vec<u8>, Error> {
    if envelope.pdu.kind != PduKind::InformRequest {
        return Err(Error::Protocol(ProtocolError::new(format!(
            "Inform response requires INFORM-REQUEST, found {:?}",
            envelope.pdu.kind
        ))));
    }
    let flags = envelope.view.msg_flags;
    validate_security_level(flags, user)?;

    let response_pdu = Pdu {
        kind: PduKind::Response,
        request_id: envelope.pdu.request_id,
        error_status: 0,
        error_index: 0,
        varbinds: envelope.pdu.varbinds.clone(),
        v1_trap: None,
    };
    let msg_data = encode_scoped_pdu(
        &envelope.context_engine_id,
        &envelope.context_name,
        &response_pdu,
    )?;

    let effective_engine_time = engine_time.unwrap_or(local_engine.engine_time);
    let outbound_engine = UsmLocalEngine {
        engine_id: local_engine.engine_id.clone(),
        engine_boots: local_engine.engine_boots,
        engine_time: effective_engine_time,
    };
    let (priv_params, msg_data) = if flags & MSG_FLAG_PRIV != 0 {
        codec.encrypt_scoped_pdu(&msg_data, &outbound_engine)?
    } else {
        (Vec::new(), msg_data)
    };
    let auth_params = if flags & MSG_FLAG_AUTH != 0 {
        vec![0u8; auth_tag_length(user.auth_protocol)]
    } else {
        Vec::new()
    };
    let usm = UsmSecurityParameters {
        engine_id: outbound_engine.engine_id.clone(),
        engine_boots: i64::from(outbound_engine.engine_boots),
        engine_time: i64::from(outbound_engine.engine_time),
        username: user.username.as_bytes().to_vec(),
        auth_params,
        priv_params,
    };
    let raw = encode_v3_message(
        envelope.view.msg_id,
        MAX_MSG_SIZE,
        flags & (MSG_FLAG_AUTH | MSG_FLAG_PRIV),
        &usm,
        &msg_data,
    )?;
    if flags & MSG_FLAG_AUTH != 0 {
        codec.stamp_auth(&raw, &outbound_engine.engine_id)
    } else {
        Ok(raw)
    }
}

/// The security-level label for a msgFlags octet (notify/v3.py:511–516).
#[must_use]
pub fn security_level_from_flags(flags: u8) -> &'static str {
    if flags & MSG_FLAG_PRIV != 0 {
        "authPriv"
    } else if flags & MSG_FLAG_AUTH != 0 {
        "authNoPriv"
    } else {
        "noAuthNoPriv"
    }
}

/// Validates that the received msgFlags match the user's configured level
/// (notify/v3.py:519–538).
pub(crate) fn validate_security_level(flags: u8, user: &UsmUser) -> Result<(), ProtocolError> {
    if flags & MSG_FLAG_PRIV != 0 && flags & MSG_FLAG_AUTH == 0 {
        return Err(ProtocolError::new("SNMPv3 privacy requires authentication"));
    }
    let actual = flags & (MSG_FLAG_AUTH | MSG_FLAG_PRIV);
    let expected = expected_security_flags(user);
    if actual != expected {
        return Err(ProtocolError::new(format!(
            "Configured user requires {} messages, received {}",
            security_level_from_flags(expected),
            security_level_from_flags(actual)
        )));
    }
    Ok(())
}

fn expected_security_flags(user: &UsmUser) -> u8 {
    let mut expected = 0;
    if auth_enabled(user.auth_protocol) {
        expected |= MSG_FLAG_AUTH;
    }
    if user.priv_protocol != PrivProtocol::None_ {
        expected |= MSG_FLAG_PRIV;
    }
    expected
}

/// trap/inform reportable-flag rules (notify/v3.py:541–547).
fn validate_notification_reportable_flag(flags: u8, kind: PduKind) -> Result<(), ProtocolError> {
    let reportable = flags & MSG_FLAG_REPORTABLE != 0;
    if kind == PduKind::SnmpV2Trap && reportable {
        return Err(ProtocolError::new(
            "SNMPv3 trap notifications must clear reportableFlag",
        ));
    }
    if kind == PduKind::InformRequest && !reportable {
        return Err(ProtocolError::new(
            "SNMPv3 inform notifications must set reportableFlag",
        ));
    }
    Ok(())
}

fn has_probe_header(view: &V3Message) -> bool {
    if view.msg_flags != MSG_FLAG_REPORTABLE {
        return false;
    }
    let p = &view.usm_params;
    !(!p.engine_id.is_empty()
        || p.engine_boots != 0
        || p.engine_time != 0
        || !p.username.is_empty()
        || !p.auth_params.is_empty()
        || !p.priv_params.is_empty())
}

fn has_probe_payload(
    context_engine_id: &[u8],
    context_name: &[u8],
    pdu_tag: u8,
    probe: &Pdu,
) -> bool {
    if !context_engine_id.is_empty() || !context_name.is_empty() || pdu_tag != GET_REQUEST_TAG {
        return false;
    }
    if probe.varbinds.len() != 1 {
        return false;
    }
    let varbind = &probe.varbinds[0];
    varbind.oid.arcs() == DISCOVERY_PROBE_OID && varbind.value == SnmpValue::Null
}

fn decode_discovery_probe(
    decoded: &V3DecodedDatagram,
) -> Result<(V3Message, Vec<u8>, Vec<u8>, Pdu), ProtocolError> {
    if !has_probe_header(&decoded.view) {
        return Err(ProtocolError::new("Invalid discovery probe"));
    }
    let (context_engine_id, context_name, pdu_tag, pdu_content) =
        decode_scoped_fields(&decoded.view.msg_data_bytes)
            .map_err(|error| ProtocolError::new(format!("Invalid discovery probe: {error}")))?;
    let probe = decode_pdu_bytes(pdu_tag, &pdu_content)
        .map_err(|error| ProtocolError::new(format!("Invalid discovery probe: {error}")))?;
    if !has_probe_payload(&context_engine_id, &context_name, pdu_tag, &probe) {
        return Err(ProtocolError::new("Invalid discovery probe"));
    }
    Ok((decoded.view.clone(), context_engine_id, context_name, probe))
}

/// Decodes the ScopedPDU and returns the PDU only when its tag is a
/// notification tag (notify/v3.py:583–587).
///
/// The tag check happens BEFORE the PDU content is decoded, exactly as in the
/// reference: a well-formed non-notification PDU (even a malformed one) yields
/// `Ok(None)` rather than a decode error.
fn decode_notification_scoped_pdu(
    data: &[u8],
) -> Result<Option<NotificationScoped>, ProtocolError> {
    let (context_engine_id, context_name, pdu_tag, pdu_content) = decode_scoped_fields(data)?;
    if !NOTIFICATION_PDU_TAGS.contains(&pdu_tag) {
        return Ok(None);
    }
    let pdu = decode_pdu_bytes(pdu_tag, &pdu_content)?;
    Ok(Some((context_engine_id, context_name, pdu)))
}

/// Walks the ScopedPDU SEQUENCE into `(context_engine_id, context_name,
/// pdu_tag, pdu_content)` (notify/v3.py:590–601).
fn decode_scoped_fields(data: &[u8]) -> Result<ScopedFields, ProtocolError> {
    let (tag, content, end) = decode_tlv(data, 0)?;
    if tag != SEQUENCE_TAG {
        return Err(ProtocolError::new(format!(
            "Expected ScopedPDU SEQUENCE, found 0x{tag:02x}"
        )));
    }
    expect_end(data, end)?;

    let mut offset = 0usize;
    let (context_engine_id, next) = decode_octets(content, offset, "contextEngineID")?;
    offset = next;
    let (context_name, next) = decode_octets(content, offset, "contextName")?;
    offset = next;
    let (pdu_tag, pdu_content, next) = decode_tlv(content, offset)?;
    expect_end(content, next)?;
    Ok((
        context_engine_id,
        context_name,
        pdu_tag,
        pdu_content.to_vec(),
    ))
}

fn decode_octets(
    data: &[u8],
    offset: usize,
    label: &str,
) -> Result<(Vec<u8>, usize), ProtocolError> {
    let (tag, content, end) = decode_tlv(data, offset)?;
    if tag != OCTET_STRING_TAG {
        return Err(ProtocolError::new(format!(
            "Expected {label} OCTET STRING, found 0x{tag:02x}"
        )));
    }
    Ok((content.to_vec(), end))
}

/// Reassembles and decodes a PDU from its tag + content bytes
/// (notify/v3.py:611–612).
fn decode_pdu_bytes(tag: u8, content: &[u8]) -> Result<Pdu, ProtocolError> {
    let mut tlv = vec![tag];
    tlv.extend(encode_length(content.len())?);
    tlv.extend_from_slice(content);
    decode_pdu(&tlv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::v3::{MSG_FLAG_REPORTABLE, decode_scoped_pdu, decode_v3_message};
    use crate::security::usm::kdf::AuthProtocol;
    use crate::security::usm::{AuthKey, PrivKey};
    use crate::time::{Clock, Rng, SystemClock};
    use std::sync::Arc;
    use zeroize::Zeroizing;

    fn clock() -> Arc<dyn Clock> {
        Arc::new(SystemClock)
    }

    fn rng() -> Arc<dyn Rng> {
        Arc::new(crate::time::SystemRng)
    }

    fn user(username: &str) -> UsmUser {
        UsmUser::new(
            username.to_string(),
            AuthProtocol::None_,
            AuthKey::Passphrase(Vec::new()),
            PrivProtocol::None_,
            PrivKey::Passphrase(Vec::new()),
        )
        .unwrap()
    }

    fn oid(arcs: &[u32]) -> Oid {
        Oid::from_arcs(arcs).unwrap()
    }

    #[test]
    fn security_level_labels_match_reference() {
        assert_eq!(security_level_from_flags(0), "noAuthNoPriv");
        assert_eq!(security_level_from_flags(MSG_FLAG_AUTH), "authNoPriv");
        assert_eq!(
            security_level_from_flags(MSG_FLAG_AUTH | MSG_FLAG_PRIV),
            "authPriv"
        );
    }

    #[test]
    fn probe_oid_constant_is_valid() {
        assert_eq!(
            oid(&DISCOVERY_PROBE_OID).display(),
            "1.3.6.1.6.3.15.1.1.4.0"
        );
    }

    #[test]
    fn scoped_fields_decode_rejects_wrong_first_tag() {
        let err = decode_scoped_fields(&[0x04, 0x00]).unwrap_err();
        assert!(err.message.contains("ScopedPDU SEQUENCE"), "{err}");
    }

    #[test]
    fn discovery_report_rejects_non_probe() {
        // A noAuth trap wrapped through a fresh model is not a probe.
        let model = UsmModel::new(
            user("x"),
            Vec::new(),
            Some(UsmLocalEngine {
                engine_id: vec![0xaa; 11],
                engine_boots: 1,
                engine_time: 2,
            }),
            clock(),
            rng(),
        );
        let trap = Pdu {
            kind: PduKind::SnmpV2Trap,
            request_id: 9,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                SnmpValue::Null,
            )],
            v1_trap: None,
        };
        let raw = model.wrap_pdu(&trap).unwrap();
        let decoded = V3DecodedDatagram::decode(&raw).unwrap();
        assert!(!is_discovery_probe(&decoded));
        let err = encode_discovery_report(
            &decoded,
            &UsmLocalEngine {
                engine_id: vec![0xbb; 11],
                engine_boots: 1,
                engine_time: 2,
            },
            None,
        )
        .unwrap_err();
        assert!(err.message.contains("discovery probe"), "{err}");
    }

    #[test]
    fn discovery_probe_detected_and_report_shape() {
        // The report echoes the probe's msg_id and request_id, carries the
        // local engine, and reports usmStatsUnknownUserNames.0 = 1.
        let model = UsmModel::new(user("probe"), Vec::new(), None, clock(), rng());
        let probe = model.build_discovery_probe().unwrap();
        let probe_view = decode_v3_message(&probe).unwrap();
        let decoded = V3DecodedDatagram::decode(&probe).unwrap();
        assert!(is_discovery_probe(&decoded));

        let local = UsmLocalEngine {
            engine_id: [vec![0x80, 0x00, 0x01, 0x02, 0x03], vec![0xcc; 12]].concat(),
            engine_boots: 12,
            engine_time: 345,
        };
        let report = encode_discovery_report(&decoded, &local, None).unwrap();
        let view = decode_v3_message(&report).unwrap();
        assert_eq!(view.msg_id, probe_view.msg_id);
        assert_eq!(view.msg_flags, 0);
        assert_eq!(view.usm_params.engine_id, local.engine_id);
        assert_eq!(view.usm_params.engine_boots, 12);
        assert_eq!(view.usm_params.engine_time, 345);
        assert!(view.usm_params.username.is_empty());
        let (ctx_eid, ctx_name, pdu) = decode_scoped_pdu(&view.msg_data_bytes).unwrap();
        assert!(ctx_eid.is_empty());
        assert!(ctx_name.is_empty());
        assert_eq!(pdu.kind, PduKind::Report);
        assert_eq!(pdu.request_id, probe_view.msg_id as u32);
        assert_eq!(pdu.varbinds.len(), 1);
        assert_eq!(pdu.varbinds[0].value, SnmpValue::Counter32(1));
    }

    #[test]
    fn probe_variants_are_rejected() {
        // Flags alone are not enough: the payload must be the exact probe.
        let model = UsmModel::new(user("probe"), Vec::new(), None, clock(), rng());
        let probe = model.build_discovery_probe().unwrap();
        let view = decode_v3_message(&probe).unwrap();
        let p = &view.usm_params;

        // Same header but a non-empty contextEngineID.
        let scoped = encode_scoped_pdu(
            b"\x80\x00\x01",
            b"",
            &Pdu {
                kind: PduKind::GetRequest,
                request_id: 1,
                error_status: 0,
                error_index: 0,
                varbinds: vec![VarBind::new(oid(&DISCOVERY_PROBE_OID), SnmpValue::Null)],
                v1_trap: None,
            },
        )
        .unwrap();
        let with_context = encode_v3_message(
            view.msg_id,
            view.msg_max_size,
            view.msg_flags,
            &UsmSecurityParameters {
                engine_id: p.engine_id.clone(),
                engine_boots: p.engine_boots,
                engine_time: p.engine_time,
                username: p.username.clone(),
                auth_params: p.auth_params.clone(),
                priv_params: p.priv_params.clone(),
            },
            &scoped,
        )
        .unwrap();
        assert!(!is_discovery_probe(
            &V3DecodedDatagram::decode(&with_context).unwrap()
        ));

        // Two varbinds.
        let scoped = encode_scoped_pdu(
            b"",
            b"",
            &Pdu {
                kind: PduKind::GetRequest,
                request_id: 1,
                error_status: 0,
                error_index: 0,
                varbinds: vec![
                    VarBind::new(oid(&DISCOVERY_PROBE_OID), SnmpValue::Null),
                    VarBind::new(oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]), SnmpValue::Null),
                ],
                v1_trap: None,
            },
        )
        .unwrap();
        let too_many = encode_v3_message(
            view.msg_id,
            view.msg_max_size,
            view.msg_flags,
            &UsmSecurityParameters {
                engine_id: p.engine_id.clone(),
                engine_boots: p.engine_boots,
                engine_time: p.engine_time,
                username: p.username.clone(),
                auth_params: p.auth_params.clone(),
                priv_params: p.priv_params.clone(),
            },
            &scoped,
        )
        .unwrap();
        assert!(!is_discovery_probe(
            &V3DecodedDatagram::decode(&too_many).unwrap()
        ));

        assert!(is_discovery_probe(&decoded_safe(&probe)));
    }

    fn decoded_safe(data: &[u8]) -> V3DecodedDatagram {
        V3DecodedDatagram::decode(data).unwrap()
    }

    #[test]
    fn security_level_mismatch_rejected() {
        let auth_user = UsmUser::new(
            "u".to_string(),
            AuthProtocol::Md5,
            AuthKey::Localized(Zeroizing::new(vec![0xaa; 16])),
            PrivProtocol::None_,
            PrivKey::Passphrase(Vec::new()),
        )
        .unwrap();
        let err = validate_security_level(0, &auth_user).unwrap_err();
        assert!(err.message.contains("requires authNoPriv"), "{err}");
        let priv_user = UsmUser::new(
            "u".to_string(),
            AuthProtocol::Md5,
            AuthKey::Localized(Zeroizing::new(vec![0xaa; 16])),
            PrivProtocol::Aes128,
            PrivKey::Passphrase(b"privpassword12345".to_vec()),
        )
        .unwrap();
        let err = validate_security_level(MSG_FLAG_AUTH, &priv_user).unwrap_err();
        assert!(err.message.contains("requires authPriv"), "{err}");
        let err = validate_security_level(MSG_FLAG_PRIV, &auth_user).unwrap_err();
        assert!(
            err.message.contains("privacy requires authentication"),
            "{err}"
        );
    }

    #[test]
    fn reportable_flag_rules() {
        assert!(validate_notification_reportable_flag(0, PduKind::SnmpV2Trap).is_ok());
        let err = validate_notification_reportable_flag(MSG_FLAG_REPORTABLE, PduKind::SnmpV2Trap)
            .unwrap_err();
        assert!(
            err.message
                .contains("trap notifications must clear reportableFlag"),
            "{err}"
        );
        assert!(
            validate_notification_reportable_flag(MSG_FLAG_REPORTABLE, PduKind::InformRequest)
                .is_ok()
        );
        let err = validate_notification_reportable_flag(0, PduKind::InformRequest).unwrap_err();
        assert!(
            err.message
                .contains("inform notifications must set reportableFlag"),
            "{err}"
        );
    }
}
