//! USM crypto ground-truth vectors.
//!
//! LOCKED ORDER: these tests were written FIRST against the reference's
//! vectors — they fail until the KDF exists. Sources:
//! - RFC 3414 Appendix A.2/A.3 (MD5/SHA-1 Ku + localized key);
//! - fixtures/crypto-vectors/vectors.toml — the 5 net-snmp 5.9.4 localized
//!   privacy keys (Blumenthal AES-192/256 derivation) and the 2 reeder
//!   Appendix B chains.
//!
//! The net-snmp vectors assert the full Blumenthal key. The RFC 3414
//! localization is Phase-3 KDF work; the truncate/extend step is mirrored
//! here with a test-side helper (usm.py:_extend_localized_key) and lands in
//! priv.rs in Phase 4. The reeder 3DES chains gate in Phase 4 with priv.rs
//! and are asserted there.

use std::fs;

use trishul_snmp::security::usm::kdf::PrivProtocol;
use trishul_snmp::security::usm::kdf::{AuthProtocol, localize_key, password_to_ku};
use trishul_snmp::security::usm::privacy::localized_priv_key;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// A record: `section_name -> Vec<(field, value)>`.
type TomlRecord = (String, Vec<(String, String)>);

/// Minimal parser for the fixture's known TOML subset: `[[section]]` records
/// with `key = "value"` lines and `#` comments. (No toml crate is declared;
/// the fixture format is fixed and documented in vectors.toml.)
fn parse_toml(raw: &str) -> Vec<TomlRecord> {
    let mut records = Vec::new();
    let mut current: Option<TomlRecord> = None;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(name) = trimmed
            .strip_prefix("[[")
            .and_then(|r| r.strip_suffix("]]"))
        {
            if let Some(record) = current.take() {
                records.push(record);
            }
            current = Some((name.to_string(), Vec::new()));
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=')
            && let Some(record) = current.as_mut()
        {
            let value = value.trim();
            let value = value.split('"').nth(1).unwrap_or(value);
            let value = value.split('#').next().unwrap_or(value).trim();
            record.1.push((key.trim().to_string(), value.to_string()));
        }
    }
    if let Some(record) = current.take() {
        records.push(record);
    }
    records
}

/// The fixture's records for one section.
fn records_for(section: &str) -> Vec<Vec<(String, String)>> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/crypto-vectors/vectors.toml"
    );
    let raw = fs::read_to_string(path).expect("vectors.toml must exist");
    parse_toml(&raw)
        .into_iter()
        .filter(|(name, _)| name == section)
        .map(|(_, fields)| fields)
        .collect()
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> &'a str {
    fields
        .iter()
        .find(|(key, _)| key == name)
        .unwrap_or_else(|| panic!("missing field {name}"))
        .1
        .as_str()
}

fn protocol_of(name: &str) -> AuthProtocol {
    match name {
        "MD5" => AuthProtocol::Md5,
        "SHA1" => AuthProtocol::Sha1,
        "SHA224" => AuthProtocol::Sha224,
        "SHA256" => AuthProtocol::Sha256,
        "SHA384" => AuthProtocol::Sha384,
        "SHA512" => AuthProtocol::Sha512,
        other => panic!("unknown protocol {other}"),
    }
}

// ── RFC 3414 A.2/A.3 classic vectors ───────────────────────────────────────

const RFC_ENGINE: &str = "000000000000000000000002";
const PASSWORD: &[u8] = b"maplesyrup";

#[test]
fn rfc3414_a2_md5_ku_and_localized() {
    let ku = password_to_ku(PASSWORD, AuthProtocol::Md5);
    assert_eq!(
        ku.as_slice(),
        &hex("9faf3283884e92834ebc9847d8edd963"),
        "RFC 3414 A.2.1 Ku"
    );
    let kul = localize_key(PASSWORD, &hex(RFC_ENGINE), AuthProtocol::Md5).unwrap();
    assert_eq!(
        kul.as_slice(),
        &hex("526f5eed9fcce26f8964c2930787d82b"),
        "RFC 3414 A.2.1 Kul"
    );
}

#[test]
fn rfc3414_a3_sha1_ku_and_localized() {
    let ku = password_to_ku(PASSWORD, AuthProtocol::Sha1);
    assert_eq!(
        ku.as_slice(),
        &hex("9fb5cc0381497b3793528939ff788d5d79145211"),
        "RFC 3414 A.2.2 Ku"
    );
    let kul = localize_key(PASSWORD, &hex(RFC_ENGINE), AuthProtocol::Sha1).unwrap();
    assert_eq!(
        kul.as_slice(),
        &hex("6695febc9288e36282235fc7151f128497b38f3f"),
        "RFC 3414 A.2.2 Kul"
    );
}

// ── net-snmp 5.9.4 localized privacy keys (fixtures/crypto-vectors/vectors.toml) ──

#[test]
fn netsnmp_localized_priv_key_vectors() {
    let cases = records_for("netsnmp_aes");
    assert_eq!(cases.len(), 5, "five net-snmp vectors");
    for case in &cases {
        let auth = protocol_of(field(case, "auth_protocol"));
        let engine_id = hex(field(case, "engine_id"));
        let priv_password = field(case, "priv_passphrase").as_bytes();
        let expected = hex(field(case, "expected_localized_priv_key"));
        let key_length = expected.len();

        // Production derivation (Phase 4 priv.rs): localize the digest-length
        // Ku, then truncate/extend the LOCALIZED key (net-snmp semantics).
        let protocol = if key_length == 24 {
            PrivProtocol::Aes192
        } else {
            PrivProtocol::Aes256
        };
        let key = localized_priv_key(priv_password, &engine_id, auth, protocol).unwrap();

        let name = field(case, "name");
        assert_eq!(
            key.as_slice(),
            expected.as_slice(),
            "net-snmp localized key vector {name}"
        );
    }
}

#[test]
fn netsnmp_control_case_localized_key_is_full_cipher_key() {
    // sha256-aes256-control: digest length == key length, so the localized
    // key IS the cipher key — a pure Phase-3 KDF assertion.
    let engine_id = hex("80001f8804726565646572696e76657374");
    let localized = localize_key(b"privpassword12345", &engine_id, AuthProtocol::Sha256).unwrap();
    assert_eq!(
        localized.as_slice(),
        &hex("93cbabe7564aaffcf6561be284c26e9338036d8ff742783b48366937ea608a93"),
        "sha256-aes256-control localized key"
    );
}

// ── reeder Appendix B chains (production 3DES derivation) ───────────────────

#[test]
fn reeder_appendix_b_3des_chains_byte_exact() {
    // draft-reeder-snmpv3-usm-3desede-00 Appendix B, via the production
    // chain (priv.rs localized_priv_key): K1 = RFC 3414 localized key,
    // K2 = P2K(K1) localized, key = (K1 || K2)[:32].
    let cases = records_for("reeder_3des_appendix_b");
    assert_eq!(cases.len(), 2, "two reeder vectors");
    let engine = hex("000000000000000000000002");
    for case in &cases {
        let auth = protocol_of(field(case, "auth_protocol"));
        // The fixture records the draft's full Appendix B literal; the 3DES
        // key material is its first `key_material_octets` (32).
        let chain = hex(field(case, "chain_hex"));
        let octets: usize = field(case, "key_material_octets").parse().unwrap();
        let expected = chain[..octets].to_vec();
        let key = localized_priv_key(b"maplesyrup", &engine, auth, PrivProtocol::Des3Ede).unwrap();
        let name = field(case, "name");
        assert_eq!(
            key.as_slice(),
            expected.as_slice(),
            "reeder 3DES chain vector {name}"
        );
        assert_eq!(key.len(), 32, "{name}: 3DES key material is 32 octets");
    }
}
