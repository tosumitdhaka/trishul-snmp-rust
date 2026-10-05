//! AES-CFB 128/192/256, 3DES-EDE, salt rules (← usm.py priv path)
//!
//! `priv` is a Rust reserved word, so the file `priv.rs` is declared as the
//! module `privacy` (see `usm/mod.rs`); the on-disk name matches the
//! architecture's module tree.

use std::convert::TryInto;

use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use aes::{Aes128, Aes192, Aes256};
use cfb_mode::{Decryptor as CfbDecryptor, Encryptor as CfbEncryptor};
use des::TdesEde3;
use des::cipher::generic_array::GenericArray;
use des::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use zeroize::Zeroizing;

use crate::error::{Error, ProtocolError};
use crate::security::usm::PrivProtocol;
use crate::security::usm::kdf::{
    AuthProtocol, auth_enabled, localize_key, localize_ku, password_to_ku, plain_digest,
};
use crate::time::Rng;

/// The localized privacy key length each protocol consumes (usm.py:_priv_key_length).
pub fn priv_key_length(protocol: PrivProtocol) -> Result<usize, Error> {
    Ok(match protocol {
        PrivProtocol::None_ => {
            return Err(Error::Protocol(ProtocolError::new(
                "no privacy protocol configured",
            )));
        }
        PrivProtocol::Aes128 => 16,
        PrivProtocol::Aes192 => 24,
        PrivProtocol::Aes256 => 32,
        PrivProtocol::Des3Ede => 32,
    })
}

/// Extends a LOCALIZED key to `length` octets (usm.py:_extend_localized_key,
/// draft-blumenthal-aes-usm-04 §3.1.2.2). A key already at/above the target is
/// truncated; a shorter key is extended by appending `H(buffer)` where the
/// hash input is the whole buffer built so far (`Kul || H(Kul) || H(Kul||…)`).
/// The engine-independent Ku is never extended.
pub fn extend_localized_key(
    key: &[u8],
    length: usize,
    protocol: AuthProtocol,
) -> Zeroizing<Vec<u8>> {
    if key.len() >= length {
        return Zeroizing::new(key[..length].to_vec());
    }
    let mut extended = key.to_vec();
    while extended.len() < length {
        extended.extend_from_slice(&plain_digest(&extended, protocol));
    }
    extended.truncate(length);
    Zeroizing::new(extended)
}

/// Adapts an already-localized priv key to the cipher key length (truncate;
/// Blumenthal-extend for AES-192/256). Used for `PrivKey::Localized`.
pub fn adapt_localized_key(
    key: &[u8],
    protocol: PrivProtocol,
    auth: AuthProtocol,
) -> Zeroizing<Vec<u8>> {
    match protocol {
        PrivProtocol::Aes128 => Zeroizing::new(key[..key.len().min(16)].to_vec()),
        PrivProtocol::Aes192 | PrivProtocol::Aes256 | PrivProtocol::Des3Ede => {
            extend_localized_key(key, priv_key_length(protocol).unwrap_or(32), auth)
        }
        PrivProtocol::None_ => Zeroizing::new(Vec::new()),
    }
}

/// Derives the localized privacy key for a passphrase and protocol
/// (usm.py:_localize_priv_key_* + _priv_key).
pub fn localized_priv_key(
    passphrase: &[u8],
    engine_id: &[u8],
    auth: AuthProtocol,
    protocol: PrivProtocol,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if !auth_enabled(auth) {
        return Err(Error::Protocol(ProtocolError::new(
            "Cannot derive priv key without an auth protocol",
        )));
    }
    let length = priv_key_length(protocol)?;
    match protocol {
        PrivProtocol::Aes128 => {
            // RFC 3414 localized key truncated to the cipher length.
            let kul = localize_key(passphrase, engine_id, auth)?;
            Ok(Zeroizing::new(kul[..length].to_vec()))
        }
        PrivProtocol::Aes192 | PrivProtocol::Aes256 => {
            // net-snmp's default: localize the digest-length Ku, then extend
            // the LOCALIZED key (usm.py:_localize_priv_key_blumenthal).
            let kul = localize_key(passphrase, engine_id, auth)?;
            Ok(extend_localized_key(&kul, length, auth))
        }
        PrivProtocol::Des3Ede => {
            // draft-reeder chain: K1 = localized key; if under 32 octets,
            // K2 = P2K(K1) localized; key = (K1 || K2)[:32].
            let kul = localize_key(passphrase, engine_id, auth)?;
            if kul.len() >= 32 {
                return Ok(Zeroizing::new(kul[..32].to_vec()));
            }
            let ku_prime = password_to_ku(&kul, auth);
            let kul_prime = localize_ku(&ku_prime, engine_id, auth);
            let mut key = kul.as_slice().to_vec();
            key.extend_from_slice(&kul_prime);
            key.truncate(32);
            Ok(Zeroizing::new(key))
        }
        PrivProtocol::None_ => Err(Error::Protocol(ProtocolError::new(
            "no privacy protocol configured",
        ))),
    }
}

/// RFC 3826 §3 IV: `engineBoots(4) || engineTime(4) || salt(8)`.
fn aes_iv(boots: u32, time: u32, salt: &[u8; 8]) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..4].copy_from_slice(&boots.to_be_bytes());
    iv[4..8].copy_from_slice(&time.to_be_bytes());
    iv[8..].copy_from_slice(salt);
    iv
}

/// Full-block AES-CFB (RFC 3826). Risk #3: 8-bit CFB diverges from the
/// reference's `cryptography` `modes.CFB`; the `cfb-mode` crate is full-block
/// (`Encryptor`/`Decryptor`), and the net-snmp vectors + live snmpd are the
/// proof. The crate ships distinct encrypt/decrypt feedback (xor_set1 vs
/// xor_set2), so the directions are separate despite CFB's shared keystream.
fn aes_cfb_dispatch(
    key: &[u8],
    data: &[u8],
    boots: u32,
    time: u32,
    salt: &[u8; 8],
    key_length: usize,
    decrypt: bool,
) -> Result<Vec<u8>, Error> {
    if key.len() != key_length {
        return Err(Error::Protocol(ProtocolError::new(format!(
            "AES-{} privacy key must be {key_length} octets, got {}",
            key_length * 8,
            key.len()
        ))));
    }
    let iv = aes_iv(boots, time, salt);
    let mut buf = data.to_vec();
    match (key_length, decrypt) {
        (16, false) => {
            CfbEncryptor::<Aes128>::new_from_slices(key, &iv)
                .map_err(|_| Error::Protocol(ProtocolError::new("invalid AES-128 key/iv")))?
                .encrypt(&mut buf);
        }
        (16, true) => {
            CfbDecryptor::<Aes128>::new_from_slices(key, &iv)
                .map_err(|_| Error::Protocol(ProtocolError::new("invalid AES-128 key/iv")))?
                .decrypt(&mut buf);
        }
        (24, false) => {
            CfbEncryptor::<Aes192>::new_from_slices(key, &iv)
                .map_err(|_| Error::Protocol(ProtocolError::new("invalid AES-192 key/iv")))?
                .encrypt(&mut buf);
        }
        (24, true) => {
            CfbDecryptor::<Aes192>::new_from_slices(key, &iv)
                .map_err(|_| Error::Protocol(ProtocolError::new("invalid AES-192 key/iv")))?
                .decrypt(&mut buf);
        }
        (32, false) => {
            CfbEncryptor::<Aes256>::new_from_slices(key, &iv)
                .map_err(|_| Error::Protocol(ProtocolError::new("invalid AES-256 key/iv")))?
                .encrypt(&mut buf);
        }
        (32, true) => {
            CfbDecryptor::<Aes256>::new_from_slices(key, &iv)
                .map_err(|_| Error::Protocol(ProtocolError::new("invalid AES-256 key/iv")))?
                .decrypt(&mut buf);
        }
        _ => {
            return Err(Error::Protocol(ProtocolError::new(format!(
                "unsupported AES key length {key_length}"
            ))));
        }
    }
    Ok(buf)
}

/// AES-CFB encryption (RFC 3826).
pub fn aes_cfb_encrypt(
    key: &[u8],
    plaintext: &[u8],
    boots: u32,
    time: u32,
    salt: &[u8; 8],
    key_length: usize,
) -> Result<Vec<u8>, Error> {
    aes_cfb_dispatch(key, plaintext, boots, time, salt, key_length, false)
}

/// AES-CFB decryption (RFC 3826).
pub fn aes_cfb_decrypt(
    key: &[u8],
    ciphertext: &[u8],
    boots: u32,
    time: u32,
    salt: &[u8; 8],
    key_length: usize,
) -> Result<Vec<u8>, Error> {
    aes_cfb_dispatch(key, ciphertext, boots, time, salt, key_length, true)
}

/// 8-octet random salt (RFC 3826; usm.py:os.urandom(8)).
pub fn fresh_aes_salt(rng: &dyn Rng) -> [u8; 8] {
    let mut salt = [0u8; 8];
    rng.fill_bytes(&mut salt);
    salt
}

/// CBC (3DES) salt with the first-octet change rule (usm.py:_fresh_cbc_salt,
/// lines 955–969): if the random first octet equals the previous message's,
/// XOR it with 0x01 so the IV (pre-IV XOR salt) cannot be reused.
pub fn fresh_cbc_salt(rng: &dyn Rng, last_first_octet: &mut Option<u8>) -> [u8; 8] {
    let mut salt = [0u8; 8];
    rng.fill_bytes(&mut salt);
    if let Some(last) = *last_first_octet
        && salt[0] == last
    {
        salt[0] ^= 0x01;
    }
    *last_first_octet = Some(salt[0]);
    salt
}

/// PKCS#7 padding to an 8-octet block (the draft's CBC scheme; usm.py pads
/// via `cryptography`'s PKCS7(64)).
fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let pad_len = 8 - (data.len() % 8);
    let mut out = data.to_vec();
    out.extend(std::iter::repeat_n(pad_len as u8, pad_len));
    out
}

/// 3DES-EDE-CBC encrypt (RFC 3414 §1.5 / draft-reeder): `C[i] = E(P[i] ^ C[i-1])`.
fn cbc_ede_encrypt(key: &[u8; 24], iv: &[u8; 8], data: &[u8]) -> Vec<u8> {
    let cipher = TdesEde3::new_from_slice(key).expect("24-octet 3DES key");
    let mut prev = GenericArray::clone_from_slice(iv);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(8) {
        let mut block = GenericArray::clone_from_slice(chunk);
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        cipher.encrypt_block(&mut block);
        prev = block;
        out.extend_from_slice(&block);
    }
    out
}

/// 3DES-EDE-CBC decrypt: `P[i] = D(C[i]) ^ C[i-1]`.
fn cbc_ede_decrypt(key: &[u8; 24], iv: &[u8; 8], data: &[u8]) -> Vec<u8> {
    let cipher = TdesEde3::new_from_slice(key).expect("24-octet 3DES key");
    let mut prev = GenericArray::clone_from_slice(iv);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(8) {
        let mut block = GenericArray::clone_from_slice(chunk);
        let ciphertext_block = block;
        cipher.decrypt_block(&mut block);
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        prev = ciphertext_block;
        out.extend_from_slice(&block);
    }
    out
}

/// 3DES-EDE encrypt: the 32-octet key material splits into a 24-octet 3DES
/// key and an 8-octet pre-IV; `iv = pre-IV XOR salt`; PKCS#7 padded
/// (usm.py:_encrypt_3des_ede).
pub fn tripledes_encrypt(
    key_material: &[u8; 32],
    plaintext: &[u8],
    salt: &[u8; 8],
) -> Result<Vec<u8>, Error> {
    let des_key: [u8; 24] = key_material[..24]
        .try_into()
        .map_err(|_| Error::Protocol(ProtocolError::new("3DES key material truncated")))?;
    let iv = xor8(&key_material[24..32], salt);
    let padded = pkcs7_pad(plaintext);
    Ok(cbc_ede_encrypt(&des_key, &iv, &padded))
}

/// 3DES-EDE decrypt, padding-lenient (draft-reeder §5.1.3: "the padding is
/// ignored"): the plaintext is a BER ScopedPDU whose own length declares its
/// extent, so truncate to that extent instead of requiring a padding scheme.
/// RFC 3414 senders zero-pad and never emit PKCS#7 (usm.py:_decrypt_3des_ede,
/// risk #4).
pub fn tripledes_decrypt(
    key_material: &[u8; 32],
    ciphertext: &[u8],
    salt: &[u8; 8],
) -> Result<Vec<u8>, Error> {
    let des_key: [u8; 24] = key_material[..24]
        .try_into()
        .map_err(|_| Error::Protocol(ProtocolError::new("3DES key material truncated")))?;
    let iv = xor8(&key_material[24..32], salt);
    let padded = cbc_ede_decrypt(&des_key, &iv, ciphertext);
    match ber_extent(&padded) {
        Some(extent) if extent <= padded.len() => Ok(padded[..extent].to_vec()),
        _ => Ok(padded),
    }
}

fn xor8(a: &[u8], b: &[u8; 8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// The BER extent of `data`: tag(1) + length header + declared content
/// (usm.py:_ber_extent). `None` when `data` does not begin with a well-formed
/// definite-length header.
pub fn ber_extent(data: &[u8]) -> Option<usize> {
    if data.is_empty() {
        return None;
    }
    let (length, content_offset) = crate::codec::decode_length(data, 1).ok()?;
    Some(content_offset + length)
}

/// Dispatch: encrypt `plaintext` (a ScopedPDU) under `protocol`; returns the
/// ciphertext for use as the msgData OCTET STRING.
pub fn encrypt_for_protocol(
    key: &[u8],
    plaintext: &[u8],
    boots: u32,
    time: u32,
    salt: &[u8; 8],
    protocol: PrivProtocol,
) -> Result<Vec<u8>, Error> {
    match protocol {
        PrivProtocol::Aes128 | PrivProtocol::Aes192 | PrivProtocol::Aes256 => aes_cfb_encrypt(
            key,
            plaintext,
            boots,
            time,
            salt,
            priv_key_length(protocol)?,
        ),
        PrivProtocol::Des3Ede => {
            let material: [u8; 32] = key.try_into().map_err(|_| {
                Error::Protocol(ProtocolError::new("3DES-EDE privacy key must be 32 octets"))
            })?;
            tripledes_encrypt(&material, plaintext, salt)
        }
        PrivProtocol::None_ => Err(Error::Protocol(ProtocolError::new(
            "no privacy protocol configured",
        ))),
    }
}

/// Dispatch: decrypt the inbound msgData OCTET STRING under `protocol`.
pub fn decrypt_for_protocol(
    key: &[u8],
    msg_data: &[u8],
    boots: u32,
    time: u32,
    priv_params: &[u8],
    protocol: PrivProtocol,
) -> Result<Vec<u8>, Error> {
    if priv_params.len() != 8 {
        return Err(Error::Protocol(ProtocolError::new(format!(
            "{protocol:?} privacyParameters must be exactly 8 octets, got {}",
            priv_params.len()
        ))));
    }
    let (tag, ciphertext, end) = crate::codec::decode_tlv(msg_data, 0)?;
    if end != msg_data.len() {
        return Err(Error::Protocol(ProtocolError::new(
            "Unexpected trailing BER content after encryptedPDU",
        )));
    }
    if tag != 0x04 {
        return Err(Error::Protocol(ProtocolError::new(format!(
            "Expected encryptedPDU OCTET STRING, found 0x{tag:02x}"
        ))));
    }
    let salt: [u8; 8] = priv_params.try_into().expect("length checked above");
    match protocol {
        PrivProtocol::Aes128 | PrivProtocol::Aes192 | PrivProtocol::Aes256 => aes_cfb_decrypt(
            key,
            ciphertext,
            boots,
            time,
            &salt,
            priv_key_length(protocol)?,
        ),
        PrivProtocol::Des3Ede => {
            let material: [u8; 32] = key.try_into().map_err(|_| {
                Error::Protocol(ProtocolError::new("3DES-EDE privacy key must be 32 octets"))
            })?;
            tripledes_decrypt(&material, ciphertext, &salt)
        }
        PrivProtocol::None_ => Err(Error::Protocol(ProtocolError::new(
            "no privacy protocol configured",
        ))),
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_cfb_roundtrips_all_key_lengths() {
        let plaintext = b"scoped pdu bytes here";
        for (length, salt) in [(16u8, 1u8), (24, 2), (32, 3)] {
            let key = vec![0x42u8; length as usize];
            let salt_bytes = [salt; 8];
            let ct =
                aes_cfb_encrypt(&key, plaintext, 2, 500, &salt_bytes, length as usize).unwrap();
            let pt = aes_cfb_decrypt(&key, &ct, 2, 500, &salt_bytes, length as usize).unwrap();
            assert_eq!(pt, plaintext, "AES-{} roundtrip", length * 8);
        }
    }

    #[test]
    fn tripledes_roundtrip_primitive() {
        let material = [0x11u8; 32];
        let salt = [0x22u8; 8];
        // A real ScopedPDU TLV whose own length declares its extent, so the
        // padding-lenient decrypt truncates the PKCS#7 pad away.
        let plaintext = crate::codec::encode_tlv(0x30, b"scoped pdu payload").unwrap();
        let ct = tripledes_encrypt(&material, &plaintext, &salt).unwrap();
        let pt = tripledes_decrypt(&material, &ct, &salt).unwrap();
        assert_eq!(pt, plaintext);
        assert_eq!(ct.len() % 8, 0, "PKCS#7 padded to a block boundary");
    }

    #[test]
    fn ber_extent_parses_scoped_pdu() {
        let data = crate::codec::encode_tlv(0x30, b"payload").unwrap();
        assert_eq!(ber_extent(&data), Some(data.len()));
        assert_eq!(ber_extent(b""), None);
        assert_eq!(ber_extent(&[0x30]), None);
    }
}
