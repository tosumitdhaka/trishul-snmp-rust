//! Ku/localize, RFC 3414 §2.6 + RFC 7860 §2.2 (← usm.py:499–953 KDF region)

use hmac::{Mac, SimpleHmac};
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

use crate::error::{Error, ProtocolError};

/// USM authentication protocols (RFC 3414 MD5/SHA-1 + RFC 7860 SHA-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthProtocol {
    /// No authentication.
    None_,
    /// HMAC-MD5-96.
    Md5,
    /// HMAC-SHA-1-96.
    Sha1,
    /// HMAC-SHA-224-128 (RFC 7860).
    Sha224,
    /// HMAC-SHA-256-192 (RFC 7860).
    Sha256,
    /// HMAC-SHA-384-256 (RFC 7860).
    Sha384,
    /// HMAC-SHA-512-384 (RFC 7860).
    Sha512,
}

/// USM privacy protocols. DES-CBC is locked out (architecture §1); the AES
/// and 3DES variants gate in Phase 4 (priv.rs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrivProtocol {
    /// No privacy.
    None_,
    /// AES-128-CFB (RFC 3826).
    Aes128,
    /// AES-192-CFB (Blumenthal derivation).
    Aes192,
    /// AES-256-CFB (Blumenthal derivation).
    Aes256,
    /// 3DES-EDE (draft-reeder).
    Des3Ede,
}

/// Required length of an already-localized auth key per protocol: the hash
/// digest length (RFC 3414 / RFC 7860).
#[must_use]
pub fn auth_localized_key_length(protocol: AuthProtocol) -> usize {
    match protocol {
        AuthProtocol::None_ => 0,
        AuthProtocol::Md5 => 16,
        AuthProtocol::Sha1 => 20,
        AuthProtocol::Sha224 => 28,
        AuthProtocol::Sha256 => 32,
        AuthProtocol::Sha384 => 48,
        AuthProtocol::Sha512 => 64,
    }
}

/// Truncated HMAC tag length per protocol (RFC 3414 §3.3.2 / RFC 7860 §3.1).
#[must_use]
pub fn auth_tag_length(protocol: AuthProtocol) -> usize {
    match protocol {
        AuthProtocol::None_ => 0,
        AuthProtocol::Md5 => 12,
        AuthProtocol::Sha1 => 12,
        AuthProtocol::Sha224 => 16,
        AuthProtocol::Sha256 => 24,
        AuthProtocol::Sha384 => 32,
        AuthProtocol::Sha512 => 48,
    }
}

/// Whether the protocol authenticates.
#[must_use]
pub fn auth_enabled(protocol: AuthProtocol) -> bool {
    protocol != AuthProtocol::None_
}

/// RFC 3414 §2.6 step 1: engine-independent user key Ku — hash *password*
/// repeated into a 1 MiB buffer (usm.py:_password_to_ku).
pub fn password_to_ku(password: &[u8], protocol: AuthProtocol) -> Zeroizing<Vec<u8>> {
    let mut buf = vec![0u8; 1_048_576];
    let plen = password.len();
    if plen > 0 {
        for (i, slot) in buf.iter_mut().enumerate() {
            *slot = password[i % plen];
        }
    }
    let digest = hash_digest(&buf, protocol);
    Zeroizing::new(digest.to_vec())
}

/// RFC 3414 §2.6 step 2 / RFC 7860 §2.2: localized key
/// `Kul = H(Ku || engine_id || Ku)` (usm.py:_localize_key).
///
/// No caching here — the model's state cache owns caching.
pub fn localize_key(
    password: &[u8],
    engine_id: &[u8],
    protocol: AuthProtocol,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if !auth_enabled(protocol) {
        return Err(Error::Protocol(ProtocolError::new(
            "Cannot localize key without an auth protocol",
        )));
    }
    let ku = password_to_ku(password, protocol);
    Ok(localize_ku(&ku, engine_id, protocol))
}

/// RFC 3414 §2.6 step 2: `Kul = H(Ku || engine_id || Ku)` (plain digest, not
/// HMAC). Shared by the auth KDF and the 3DES chain's second block.
pub fn localize_ku(ku: &[u8], engine_id: &[u8], protocol: AuthProtocol) -> Zeroizing<Vec<u8>> {
    let mut input = ku.to_vec();
    input.extend_from_slice(engine_id);
    input.extend_from_slice(ku);
    Zeroizing::new(plain_digest(&input, protocol))
}

/// Plain hash digest (the RFC 3414 KDF steps use `H`, not HMAC).
pub fn plain_digest(data: &[u8], protocol: AuthProtocol) -> Vec<u8> {
    match protocol {
        AuthProtocol::Md5 => digest_of::<md5::Md5>(data),
        AuthProtocol::Sha1 => digest_of::<sha1::Sha1>(data),
        AuthProtocol::Sha224 => digest_of::<sha2::Sha224>(data),
        AuthProtocol::Sha256 => digest_of::<sha2::Sha256>(data),
        AuthProtocol::Sha384 => digest_of::<sha2::Sha384>(data),
        AuthProtocol::Sha512 => digest_of::<sha2::Sha512>(data),
        AuthProtocol::None_ => Vec::new(),
    }
}

/// The full HMAC digest over `msg` with the localized `key` (usm.py:_compute_auth_tag).
pub fn hmac_digest(key: &[u8], msg: &[u8], protocol: AuthProtocol) -> Vec<u8> {
    match protocol {
        AuthProtocol::None_ => Vec::new(),
        AuthProtocol::Md5 => hmac_of::<Md5>(key, msg),
        AuthProtocol::Sha1 => hmac_of::<Sha1>(key, msg),
        AuthProtocol::Sha224 => hmac_of::<Sha224>(key, msg),
        AuthProtocol::Sha256 => hmac_of::<Sha256>(key, msg),
        AuthProtocol::Sha384 => hmac_of::<Sha384>(key, msg),
        AuthProtocol::Sha512 => hmac_of::<Sha512>(key, msg),
    }
}

fn hmac_of<D>(key: &[u8], msg: &[u8]) -> Vec<u8>
where
    D: hmac::digest::Digest + hmac::digest::core_api::BlockSizeUser,
{
    let mut mac = <SimpleHmac<D> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// Plain digest of `data` under the protocol's hash (KDF internals).
fn hash_digest(data: &[u8], protocol: AuthProtocol) -> Vec<u8> {
    match protocol {
        AuthProtocol::None_ => Vec::new(),
        AuthProtocol::Md5 => digest_of::<Md5>(data),
        AuthProtocol::Sha1 => digest_of::<Sha1>(data),
        AuthProtocol::Sha224 => digest_of::<Sha224>(data),
        AuthProtocol::Sha256 => digest_of::<Sha256>(data),
        AuthProtocol::Sha384 => digest_of::<Sha384>(data),
        AuthProtocol::Sha512 => digest_of::<Sha512>(data),
    }
}

fn digest_of<D>(data: &[u8]) -> Vec<u8>
where
    D: hmac::digest::Digest,
{
    let mut hasher = D::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3414_a2_md5_vectors() {
        let ku = password_to_ku(b"maplesyrup", AuthProtocol::Md5);
        assert_eq!(ku.as_slice(), &hex("9faf3283884e92834ebc9847d8edd963"));
        let kul = localize_key(
            b"maplesyrup",
            &hex("000000000000000000000002"),
            AuthProtocol::Md5,
        )
        .unwrap();
        assert_eq!(kul.as_slice(), &hex("526f5eed9fcce26f8964c2930787d82b"));
    }

    #[test]
    fn rfc3414_a3_sha1_vectors() {
        let ku = password_to_ku(b"maplesyrup", AuthProtocol::Sha1);
        assert_eq!(
            ku.as_slice(),
            &hex("9fb5cc0381497b3793528939ff788d5d79145211")
        );
        let kul = localize_key(
            b"maplesyrup",
            &hex("000000000000000000000002"),
            AuthProtocol::Sha1,
        )
        .unwrap();
        assert_eq!(
            kul.as_slice(),
            &hex("6695febc9288e36282235fc7151f128497b38f3f")
        );
    }

    #[test]
    fn localized_key_length_equals_digest_size() {
        for protocol in [
            AuthProtocol::Md5,
            AuthProtocol::Sha1,
            AuthProtocol::Sha224,
            AuthProtocol::Sha256,
            AuthProtocol::Sha384,
            AuthProtocol::Sha512,
        ] {
            let kul = localize_key(b"maplesyrup", &[0x80, 0x00], protocol).unwrap();
            assert_eq!(kul.len(), auth_localized_key_length(protocol));
        }
    }

    #[test]
    fn tag_lengths_follow_rfc() {
        assert_eq!(auth_tag_length(AuthProtocol::Md5), 12);
        assert_eq!(auth_tag_length(AuthProtocol::Sha1), 12);
        assert_eq!(auth_tag_length(AuthProtocol::Sha224), 16);
        assert_eq!(auth_tag_length(AuthProtocol::Sha256), 24);
        assert_eq!(auth_tag_length(AuthProtocol::Sha384), 32);
        assert_eq!(auth_tag_length(AuthProtocol::Sha512), 48);
    }

    #[test]
    fn localize_requires_auth_protocol() {
        let err = localize_key(b"pw", &[1], AuthProtocol::None_).unwrap_err();
        assert!(err.to_string().contains("Cannot localize key"));
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
