//! v3 notification decode tests (ported from test_v3_notification_decode.py):
//! `decode_v3_notification_message` security-level / auth / priv / reportable
//! rules, `decode_notification` v3, and `encode_inform_response` shapes.

mod common;

use std::sync::Arc;

use common::notify::{make_local_engine, make_raw_notification, make_v3_user};

use trishul_snmp::codec::pdu::{Pdu, PduKind};
use trishul_snmp::codec::v3::{
    MSG_FLAG_AUTH, MSG_FLAG_PRIV, MSG_FLAG_REPORTABLE, UsmSecurityParameters, decode_v3_message,
    encode_v3_message,
};
use trishul_snmp::error::{Error, UnwrapOutcome};
use trishul_snmp::notify::event::decode_notification;
use trishul_snmp::notify::v3_path::{
    V3DecodedDatagram, V3NotificationEnvelope, decode_v3_notification_message,
    encode_inform_response,
};
use trishul_snmp::security::usm::kdf::{AuthProtocol, PrivProtocol};
use trishul_snmp::security::usm::{AuthKey, PrivKey, UsmModel, UsmUser};
use trishul_snmp::types::oid::Oid;
use trishul_snmp::types::value::SnmpValue;
use trishul_snmp::types::varbind::VarBind;
use zeroize::Zeroizing;

fn oid(arcs: &[u32]) -> Oid {
    Oid::from_arcs(arcs).unwrap()
}

/// A fresh one-shot codec (notify/v3.py `_usm_codec` when `codec` omitted).
fn one_shot(user: &UsmUser) -> UsmModel {
    UsmModel::new(
        user.clone(),
        Vec::new(),
        None,
        Arc::new(trishul_snmp::time::SystemClock),
        common::notify::fixture_rng(),
    )
}

fn decode(raw: &[u8], user: &UsmUser) -> Result<Option<V3NotificationEnvelope>, Error> {
    let decoded = V3DecodedDatagram::decode(raw)?;
    decode_v3_notification_message(&decoded, user, &one_shot(user))
}

/// `_make_notification_pdu` (test_v3_notification_decode.py:76–83).
fn notification_pdu(pdu_type: PduKind, request_id: u32) -> Pdu {
    Pdu {
        kind: pdu_type,
        request_id,
        error_status: 0,
        error_index: 0,
        varbinds: vec![VarBind::new(
            oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
            SnmpValue::Null,
        )],
        v1_trap: None,
    }
}

/// `_make_message` (test_v3_notification_decode.py:86–99).
fn make_message(
    user: &UsmUser,
    pdu: &Pdu,
    context_name: &[u8],
    local_engine: Option<trishul_snmp::security::usm::UsmLocalEngine>,
    peer_engine: Option<trishul_snmp::security::usm::UsmLocalEngine>,
) -> Vec<u8> {
    let model = UsmModel::new(
        user.clone(),
        context_name.to_vec(),
        local_engine,
        Arc::new(trishul_snmp::time::SystemClock),
        common::notify::fixture_rng(),
    );
    if let Some(peer) = peer_engine {
        model.adopt_engine_state(peer.engine_id, peer.engine_boots, peer.engine_time);
    }
    model.wrap_pdu(pdu).unwrap()
}

fn sha256_user(username: &str) -> UsmUser {
    UsmUser::new(
        username.to_string(),
        AuthProtocol::Sha256,
        AuthKey::Localized(Zeroizing::new(vec![0xaa; 32])),
        PrivProtocol::None_,
        PrivKey::Passphrase(Vec::new()),
    )
    .unwrap()
}

fn restamp_auth(raw: &[u8], user: &UsmUser, engine_id: &[u8]) -> Vec<u8> {
    one_shot(user).stamp_auth(raw, engine_id).unwrap()
}

#[test]
fn decode_v3_trap_noauthnopriv() {
    let user = make_v3_user("noAuthNoPriv", "notifyuser");
    let sender_engine = make_local_engine(0x11, 3, 22);
    let pdu = notification_pdu(PduKind::SnmpV2Trap, 101);
    let raw = make_message(&user, &pdu, b"trapctx", Some(sender_engine.clone()), None);

    let envelope = decode(&raw, &user).unwrap().expect("envelope");
    assert_eq!(envelope.pdu, pdu);
    assert_eq!(envelope.context_engine_id, sender_engine.engine_id);
    assert_eq!(envelope.context_name, b"trapctx");
    assert_eq!(envelope.security_level, "noAuthNoPriv");
    assert_eq!(envelope.view.usm_params.engine_id, sender_engine.engine_id);
}

#[test]
fn decode_v3_inform_authnopriv() {
    let user = make_v3_user("authNoPriv", "notifyuser");
    let receiver_engine = make_local_engine(0x22, 4, 33);
    let pdu = notification_pdu(PduKind::InformRequest, 102);
    let raw = make_message(
        &user,
        &pdu,
        b"informctx",
        None,
        Some(receiver_engine.clone()),
    );

    let envelope = decode(&raw, &user).unwrap().expect("envelope");
    assert_eq!(envelope.pdu, pdu);
    assert_eq!(envelope.context_engine_id, receiver_engine.engine_id);
    assert_eq!(envelope.context_name, b"informctx");
    assert_eq!(envelope.security_level, "authNoPriv");
    assert_ne!(envelope.view.msg_flags & MSG_FLAG_AUTH, 0);
    assert_eq!(envelope.view.msg_flags & MSG_FLAG_PRIV, 0);
}

#[test]
fn decode_v3_notification_accepts_sha256_protocol_correct_tag() {
    let user = sha256_user("sha256user");
    let sender_engine = make_local_engine(0x2A, 4, 33);
    let pdu = notification_pdu(PduKind::SnmpV2Trap, 108);
    let raw = make_message(&user, &pdu, b"", Some(sender_engine), None);

    let view = decode_v3_message(&raw).unwrap();
    assert_eq!(view.usm_params.auth_params.len(), 24); // RFC 7860 truncation

    let envelope = decode(&raw, &user).unwrap().expect("envelope");
    assert_eq!(envelope.pdu, pdu);
    assert_eq!(envelope.security_level, "authNoPriv");
}

#[test]
fn decode_v3_notification_rejects_legacy_12_byte_tag_for_sha256() {
    let user = sha256_user("sha256user");
    let sender_engine = make_local_engine(0x2B, 4, 33);
    let raw = make_message(
        &user,
        &notification_pdu(PduKind::SnmpV2Trap, 109),
        b"",
        Some(sender_engine),
        None,
    );
    let view = decode_v3_message(&raw).unwrap();
    let p = &view.usm_params;
    let legacy = encode_v3_message(
        view.msg_id,
        view.msg_max_size,
        view.msg_flags,
        &UsmSecurityParameters {
            engine_id: p.engine_id.clone(),
            engine_boots: p.engine_boots,
            engine_time: p.engine_time,
            username: p.username.clone(),
            auth_params: vec![0u8; 12], // pre-RFC 7860 legacy length
            priv_params: p.priv_params.clone(),
        },
        &view.msg_data_bytes,
    )
    .unwrap();

    let err = decode(&legacy, &user).unwrap_err();
    assert!(err.to_string().contains("24 octets for SHA256"), "{err}");
}

#[test]
fn decode_v3_trap_authpriv() {
    let user = make_v3_user("authPriv", "notifyuser");
    let sender_engine = make_local_engine(0x33, 5, 44);
    let pdu = notification_pdu(PduKind::SnmpV2Trap, 103);
    let raw = make_message(&user, &pdu, b"privctx", Some(sender_engine.clone()), None);

    let envelope = decode(&raw, &user).unwrap().expect("envelope");
    assert_eq!(envelope.pdu, pdu);
    assert_eq!(envelope.context_engine_id, sender_engine.engine_id);
    assert_eq!(envelope.context_name, b"privctx");
    assert_eq!(envelope.security_level, "authPriv");
    assert_ne!(envelope.view.msg_flags & MSG_FLAG_AUTH, 0);
    assert_ne!(envelope.view.msg_flags & MSG_FLAG_PRIV, 0);
}

#[test]
fn decode_v3_notification_returns_none_for_wrong_user() {
    let sender = make_v3_user("noAuthNoPriv", "alice");
    let receiver = make_v3_user("noAuthNoPriv", "bob");
    let sender_engine = make_local_engine(0x44, 7, 111);
    let raw = make_message(
        &sender,
        &notification_pdu(PduKind::SnmpV2Trap, 104),
        b"",
        Some(sender_engine),
        None,
    );

    assert!(decode(&raw, &receiver).unwrap().is_none());
}

#[test]
fn decode_v3_notification_returns_none_for_non_notification_pdu() {
    let user = make_v3_user("noAuthNoPriv", "notifyuser");
    let peer_engine = make_local_engine(0x55, 7, 111);
    let raw = make_message(
        &user,
        &notification_pdu(PduKind::GetRequest, 104),
        b"",
        None,
        Some(peer_engine),
    );

    assert!(decode(&raw, &user).unwrap().is_none());
}

#[test]
fn decode_v3_notification_rejects_noauth_for_auth_user() {
    let receiver = make_v3_user("authNoPriv", "notifyuser");
    let sender = make_v3_user("noAuthNoPriv", "notifyuser");
    let raw = make_message(
        &sender,
        &notification_pdu(PduKind::SnmpV2Trap, 119),
        b"",
        Some(make_local_engine(0x59, 7, 111)),
        None,
    );

    let err = decode(&raw, &receiver).unwrap_err();
    assert!(err.to_string().contains("requires authNoPriv"), "{err}");
}

#[test]
fn decode_v3_notification_rejects_authnopriv_for_authpriv_user() {
    let receiver = make_v3_user("authPriv", "notifyuser");
    let sender = make_v3_user("authNoPriv", "notifyuser");
    let raw = make_message(
        &sender,
        &notification_pdu(PduKind::InformRequest, 119),
        b"",
        None,
        Some(make_local_engine(0x5A, 7, 111)),
    );

    let err = decode(&raw, &receiver).unwrap_err();
    assert!(err.to_string().contains("requires authPriv"), "{err}");
}

#[test]
fn decode_v3_notification_rejects_trap_with_reportable_flag_set() {
    let user = make_v3_user("noAuthNoPriv", "notifyuser");
    let raw = make_message(
        &user,
        &notification_pdu(PduKind::SnmpV2Trap, 119),
        b"",
        Some(make_local_engine(0x5B, 7, 111)),
        None,
    );
    let view = decode_v3_message(&raw).unwrap();
    let p = &view.usm_params;
    let mutated = encode_v3_message(
        view.msg_id,
        view.msg_max_size,
        view.msg_flags | MSG_FLAG_REPORTABLE,
        &UsmSecurityParameters {
            engine_id: p.engine_id.clone(),
            engine_boots: p.engine_boots,
            engine_time: p.engine_time,
            username: p.username.clone(),
            auth_params: p.auth_params.clone(),
            priv_params: p.priv_params.clone(),
        },
        &view.msg_data_bytes,
    )
    .unwrap();

    let err = decode(&mutated, &user).unwrap_err();
    assert!(
        err.to_string()
            .contains("trap notifications must clear reportableFlag"),
        "{err}"
    );
}

#[test]
fn decode_v3_notification_rejects_inform_with_reportable_flag_clear() {
    let user = make_v3_user("noAuthNoPriv", "notifyuser");
    let raw = make_message(
        &user,
        &notification_pdu(PduKind::InformRequest, 120),
        b"",
        None,
        Some(make_local_engine(0x5C, 7, 111)),
    );
    let view = decode_v3_message(&raw).unwrap();
    let p = &view.usm_params;
    let mutated = encode_v3_message(
        view.msg_id,
        view.msg_max_size,
        view.msg_flags & !MSG_FLAG_REPORTABLE,
        &UsmSecurityParameters {
            engine_id: p.engine_id.clone(),
            engine_boots: p.engine_boots,
            engine_time: p.engine_time,
            username: p.username.clone(),
            auth_params: p.auth_params.clone(),
            priv_params: p.priv_params.clone(),
        },
        &view.msg_data_bytes,
    )
    .unwrap();

    let err = decode(&mutated, &user).unwrap_err();
    assert!(
        err.to_string()
            .contains("inform notifications must set reportableFlag"),
        "{err}"
    );
}

#[test]
fn decode_notification_v3_builds_public_event() {
    let user = make_v3_user("authNoPriv", "notifyuser");
    let receiver_engine = make_local_engine(0x5A, 9, 123);
    let raw = make_message(
        &user,
        &notification_pdu(PduKind::InformRequest, 120),
        b"alerts",
        None,
        Some(receiver_engine.clone()),
    );

    let event = decode_notification(
        &raw,
        Some("127.0.0.1:40162".parse().unwrap()),
        Some(&user),
        None,
    )
    .unwrap();
    assert_eq!(event.community, None);
    assert_eq!(event.snmp_version.as_deref(), Some("3"));
    assert_eq!(event.username.as_deref(), Some("notifyuser"));
    assert_eq!(event.security_level.as_deref(), Some("authNoPriv"));
    assert_eq!(
        event.context_engine_id.as_deref(),
        Some(receiver_engine.engine_id.as_slice())
    );
    assert_eq!(event.context_name.as_deref(), Some(b"alerts".as_slice()));
    assert_eq!(
        event.authoritative_engine_id.as_deref(),
        Some(receiver_engine.engine_id.as_slice())
    );
    assert_eq!(event.authoritative_engine_boots, Some(9));
    assert_eq!(event.authoritative_engine_time, Some(123));
    assert_eq!(
        event.source_address,
        Some("127.0.0.1:40162".parse().unwrap())
    );
}

#[test]
fn decode_v3_notification_raises_on_bad_hmac() {
    let user = make_v3_user("authNoPriv", "notifyuser");
    let receiver_engine = make_local_engine(0x66, 7, 111);
    let raw = make_message(
        &user,
        &notification_pdu(PduKind::InformRequest, 105),
        b"",
        None,
        Some(receiver_engine),
    );
    let view = decode_v3_message(&raw).unwrap();
    let mut tampered = raw.clone();
    tampered[view.auth_params_offset] ^= 0xFF;

    let err = decode(&tampered, &user).unwrap_err();
    assert!(matches!(err, Error::Authentication), "{err:?}");
}

#[test]
fn decode_notification_v3_raises_on_bad_hmac() {
    let user = make_v3_user("authNoPriv", "notifyuser");
    let receiver_engine = make_local_engine(0x5C, 7, 111);
    let raw = make_message(
        &user,
        &notification_pdu(PduKind::InformRequest, 122),
        b"",
        None,
        Some(receiver_engine),
    );
    let view = decode_v3_message(&raw).unwrap();
    let mut tampered = raw.clone();
    tampered[view.auth_params_offset] ^= 0xFF;

    let err = decode_notification(&tampered, None, Some(&user), None).unwrap_err();
    assert!(matches!(err, Error::Authentication), "{err:?}");
}

#[test]
fn decode_v3_notification_raises_on_bad_priv_params_length() {
    let user = make_v3_user("authPriv", "notifyuser");
    let sender_engine = make_local_engine(0x77, 7, 111);
    let raw = make_message(
        &user,
        &notification_pdu(PduKind::SnmpV2Trap, 106),
        b"",
        Some(sender_engine.clone()),
        None,
    );
    let view = decode_v3_message(&raw).unwrap();
    let p = &view.usm_params;
    let reencoded = encode_v3_message(
        view.msg_id,
        view.msg_max_size,
        view.msg_flags,
        &UsmSecurityParameters {
            engine_id: p.engine_id.clone(),
            engine_boots: p.engine_boots,
            engine_time: p.engine_time,
            username: p.username.clone(),
            auth_params: vec![0u8; 12],
            priv_params: [p.priv_params.as_slice(), &[0x99]].concat(),
        },
        &view.msg_data_bytes,
    )
    .unwrap();
    let restamped = restamp_auth(&reencoded, &user, &sender_engine.engine_id);

    let err = decode(&restamped, &user).unwrap_err();
    assert!(err.to_string().contains("8 octets"), "{err}");
}

#[test]
fn decode_v3_notification_raises_on_malformed_ciphertext() {
    let user = make_v3_user("authPriv", "notifyuser");
    let sender_engine = make_local_engine(0x88, 7, 111);
    let raw = make_message(
        &user,
        &notification_pdu(PduKind::SnmpV2Trap, 107),
        b"",
        Some(sender_engine.clone()),
        None,
    );
    let view = decode_v3_message(&raw).unwrap();
    let p = &view.usm_params;
    let reencoded = encode_v3_message(
        view.msg_id,
        view.msg_max_size,
        view.msg_flags,
        &UsmSecurityParameters {
            engine_id: p.engine_id.clone(),
            engine_boots: p.engine_boots,
            engine_time: p.engine_time,
            username: p.username.clone(),
            auth_params: vec![0u8; 12],
            priv_params: p.priv_params.clone(),
        },
        &[0x04, 0x00], // an OCTET STRING with no ciphertext
    )
    .unwrap();
    let restamped = restamp_auth(&reencoded, &user, &sender_engine.engine_id);

    let err = decode(&restamped, &user).unwrap_err();
    assert!(matches!(err, Error::Protocol(_)), "{err:?}");
}

#[test]
fn is_discovery_probe_matches_usm_probe() {
    let user = make_v3_user("noAuthNoPriv", "notifyuser");
    let probe = one_shot(&user).build_discovery_probe().unwrap();
    assert!(trishul_snmp::notify::v3_path::is_discovery_probe(
        &V3DecodedDatagram::decode(&probe).unwrap()
    ));
}

#[test]
fn is_discovery_probe_rejects_regular_notification() {
    let user = make_v3_user("noAuthNoPriv", "notifyuser");
    let sender_engine = make_local_engine(0x99, 7, 111);
    let raw = make_message(
        &user,
        &notification_pdu(PduKind::SnmpV2Trap, 108),
        b"",
        Some(sender_engine),
        None,
    );
    assert!(!trishul_snmp::notify::v3_path::is_discovery_probe(
        &V3DecodedDatagram::decode(&raw).unwrap()
    ));
}

#[test]
fn decode_notification_with_user_rejects_v2c_message() {
    let user = make_v3_user("noAuthNoPriv", "notifyuser");
    let v2c =
        trishul_snmp::codec::message::encode_message(&trishul_snmp::codec::message::SnmpMessage {
            version: trishul_snmp::codec::message::SnmpVersion::V2c,
            community: b"public".to_vec(),
            pdu: notification_pdu(PduKind::SnmpV2Trap, 123),
        })
        .unwrap();

    let err = decode_notification(&v2c, None, Some(&user), None).unwrap_err();
    assert!(err.to_string().contains("version 3"), "{err}");
}

#[test]
fn encode_inform_response_authpriv_shape() {
    let user = make_v3_user("authPriv", "notifyuser");
    let receiver_engine = make_local_engine(0xBA, 13, 456);
    let inform_pdu = notification_pdu(PduKind::InformRequest, 110);
    let raw = make_message(
        &user,
        &inform_pdu,
        b"ctx-name",
        None,
        Some(receiver_engine.clone()),
    );
    let envelope = decode(&raw, &user).unwrap().expect("envelope");

    let response =
        encode_inform_response(&envelope, &user, &receiver_engine, &one_shot(&user), None).unwrap();
    let view = decode_v3_message(&response).unwrap();

    // The response unwraps under a model adopting the receiver's engine.
    let response_model = one_shot(&user);
    response_model.adopt_engine_state(
        receiver_engine.engine_id.clone(),
        receiver_engine.engine_boots,
        receiver_engine.engine_time,
    );
    let unwrapped = response_model.unwrap_message(&response);
    match unwrapped {
        UnwrapOutcome::Ok(pdu) => {
            assert_eq!(pdu.kind, PduKind::Response);
            assert_eq!(pdu.request_id, inform_pdu.request_id);
            assert_eq!(pdu.varbinds, inform_pdu.varbinds);
        }
        other => panic!("expected Ok, got {other:?}"),
    }

    assert_eq!(view.msg_id, envelope.view.msg_id);
    assert_ne!(view.msg_flags & MSG_FLAG_AUTH, 0);
    assert_ne!(view.msg_flags & MSG_FLAG_PRIV, 0);
    assert_eq!(view.msg_flags & MSG_FLAG_REPORTABLE, 0);
    assert_eq!(view.usm_params.engine_id, receiver_engine.engine_id);
    assert_eq!(view.usm_params.engine_boots, 13);
    assert_eq!(view.usm_params.engine_time, 456);
}

#[test]
fn encode_inform_response_rejects_non_inform() {
    let user = make_v3_user("noAuthNoPriv", "notifyuser");
    let sender_engine = make_local_engine(0xBB, 7, 111);
    let raw = make_message(
        &user,
        &notification_pdu(PduKind::SnmpV2Trap, 111),
        b"",
        Some(sender_engine),
        None,
    );
    let envelope = decode(&raw, &user).unwrap().expect("envelope");

    let err = encode_inform_response(
        &envelope,
        &user,
        &make_local_engine(0xBC, 7, 111),
        &one_shot(&user),
        None,
    )
    .unwrap_err();
    assert!(err.to_string().contains("INFORM-REQUEST"), "{err}");
}

#[test]
fn make_raw_notification_and_make_message_agree() {
    // The listener suite builds raw notifications via make_raw_notification;
    // the decode suite via make_message. They must produce equivalent
    // decodable messages for the same user/pdu/engine.
    let user = make_v3_user("noAuthNoPriv", "listener");
    let engine = make_local_engine(0x77, 7, 111);
    let raw = make_raw_notification(&user, PduKind::SnmpV2Trap, 7, Some(engine.clone()), None);
    let envelope = decode(&raw, &user).unwrap().expect("envelope");
    assert_eq!(envelope.pdu.request_id, 7);
    assert_eq!(envelope.view.usm_params.engine_id, engine.engine_id);
}
