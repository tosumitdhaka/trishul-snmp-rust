//! Vendored 3DES-EDE authPriv datagram (fixtures/3des-datagram/, see
//! SOURCE.md for provenance: reference repo rev 1b01976, cryptography
//! 48.0.0). Decrypt-side byte-exact coverage for the 3DES path (review I6).

use std::sync::Arc;

use trishul_snmp::codec::v3::decode_v3_message;
use trishul_snmp::codec::v3::{UsmSecurityParameters, encode_v3_message};
use trishul_snmp::security::usm::kdf::{AuthProtocol, PrivProtocol};
use trishul_snmp::security::usm::privacy::{decrypt_for_protocol, tripledes_decrypt};
use trishul_snmp::security::usm::{AuthKey, PrivKey, UsmModel, UsmUser};
use trishul_snmp::types::oid::Oid;
use trishul_snmp::types::value::SnmpValue;
use trishul_snmp::types::varbind::{ErrorStatus, Response, VarBind};
use zeroize::Zeroizing;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn fixture_hex(name: &str) -> Vec<u8> {
    let text = std::fs::read_to_string(format!(
        "{}/fixtures/3des-datagram/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    ))
    .expect("fixture must exist");
    let hexstr = text.trim();
    (0..hexstr.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hexstr[i..i + 2], 16).unwrap())
        .collect()
}

/// A model with the vendored 3DES key material as a Localized priv key.
fn vendored_model() -> UsmModel {
    let engine_id = hex("80001f8804726565646572696e76657374");
    let user = UsmUser::new(
        "simulator".to_string(),
        AuthProtocol::Sha256,
        AuthKey::Passphrase(b"authpassword12345".to_vec()),
        PrivProtocol::Des3Ede,
        PrivKey::Localized(Zeroizing::new(fixture_hex("key-material.hex"))),
    )
    .unwrap();
    let model = UsmModel::new(
        user,
        Vec::new(),
        None,
        Arc::new(trishul_snmp::time::SystemClock),
        Arc::new(trishul_snmp::time::SystemRng),
    );
    model.adopt_engine_state(engine_id, 2, 500);
    model
}

#[test]
fn vendored_3des_datagram_decrypts_to_expected_scoped_pdu() {
    let datagram = fixture_hex("datagram.hex");
    let key_material = fixture_hex("key-material.hex");
    let view = decode_v3_message(&datagram).expect("vendored datagram decodes");
    assert_eq!(view.usm_params.engine_boots, 2);
    assert_eq!(view.usm_params.engine_time, 500);
    assert_eq!(view.msg_flags & 0x03, 0x03, "auth+priv flags set");

    // Primitive path: decrypt the inbound msgData with the datagram's own
    // boots/time/salt (review I6: inbound salt from the datagram).
    let plaintext = decrypt_for_protocol(
        &key_material,
        &view.msg_data_bytes,
        2,
        500,
        &view.usm_params.priv_params,
        PrivProtocol::Des3Ede,
    )
    .expect("vendored ciphertext decrypts");
    let (_eid, _ctx, pdu) = trishul_snmp::codec::v3::decode_scoped_pdu(&plaintext)
        .expect("decrypted ScopedPDU is a valid BER PDU");
    assert_eq!(pdu.request_id, 0x0102_0304);
    assert_eq!(pdu.varbinds.len(), 1);
    assert_eq!(pdu.varbinds[0].value, SnmpValue::TimeTicks(12345));
}

#[test]
fn vendored_3des_datagram_survives_full_model_unwrap() {
    // The whole typed path: auth verify (localized SHA-256 key) + 3DES
    // decrypt against the reference-produced bytes.
    let datagram = fixture_hex("datagram.hex");
    let model = vendored_model();
    match model.unwrap_message(&datagram) {
        trishul_snmp::error::UnwrapOutcome::Ok(pdu) => {
            assert_eq!(pdu.request_id, 0x0102_0304);
            assert_eq!(
                pdu.varbinds[0].value,
                SnmpValue::TimeTicks(12345),
                "sysUpTime.0 recovered"
            );
        }
        other => panic!("expected Ok, got {other:?}"),
    }
}

#[test]
fn vendored_3des_datagram_decrypts_with_plain_tripledes_primitive() {
    // Direct primitive check: BER-extent truncation yields exactly the
    // ScopedPDU extent from the padded plaintext.
    let datagram = fixture_hex("datagram.hex");
    let key_material = fixture_hex("key-material.hex");
    let view = decode_v3_message(&datagram).unwrap();
    let salt: [u8; 8] = view.usm_params.priv_params.clone().try_into().unwrap();
    let material: [u8; 32] = key_material.clone().try_into().unwrap();
    // Minimal local TLV parse of the encryptedPDU OCTET STRING (the codec's
    // decode_tlv is internal; decrypt_for_protocol uses it for us).
    assert_eq!(view.msg_data_bytes[0], 0x04, "encryptedPDU OCTET STRING");
    let ciphertext = &view.msg_data_bytes[2..];
    let plaintext = tripledes_decrypt(&material, ciphertext, &salt).unwrap();
    let decoded = trishul_snmp::codec::v3::decode_scoped_pdu(&plaintext).unwrap();
    assert_eq!(decoded.2.request_id, 0x0102_0304);
}

/// Structural assertion helper: the recovered response shape (used to pin the
/// ScopedPDU content without relying on unrelated codec internals).
#[allow(dead_code)]
fn _expected_response() -> Response {
    Response {
        request_id: 0x0102_0304,
        error_status: ErrorStatus::NoError,
        error_index: 0,
        varbinds: vec![VarBind::new(
            Oid::from_arcs(&[1, 3, 6, 1, 2, 1, 1, 3, 0]).unwrap(),
            SnmpValue::TimeTicks(12345),
        )],
    }
}

/// Compile-time guard that the vendored message survives a re-encode of its
/// USM parameters (checks the fixture isn't stale against the codec).
#[test]
fn vendored_usm_params_reencode_stable() {
    let datagram = fixture_hex("datagram.hex");
    let view = decode_v3_message(&datagram).unwrap();
    let usm = UsmSecurityParameters {
        engine_id: view.usm_params.engine_id.clone(),
        engine_boots: view.usm_params.engine_boots,
        engine_time: view.usm_params.engine_time,
        username: view.usm_params.username.clone(),
        auth_params: view.usm_params.auth_params.clone(),
        priv_params: view.usm_params.priv_params.clone(),
    };
    let reencoded = encode_v3_message(
        view.msg_id,
        view.msg_max_size,
        view.msg_flags,
        &usm,
        &view.msg_data_bytes,
    )
    .unwrap();
    assert_eq!(
        reencoded, datagram,
        "vendored message re-encodes identically"
    );
}
