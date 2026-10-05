//! CommunityModel (← community.py)

use std::sync::Arc;
use std::time::Duration;

use crate::codec::message::{SnmpMessage, SnmpVersion, decode_message, encode_message};
use crate::codec::pdu::Pdu;
use crate::error::{Error, ProtocolError, UnwrapOutcome};
use crate::mib::MibBundle;
use crate::time::{Rng, SystemRng};

/// Shared community-security client configuration
/// (← client.py:V1Config/V2cConfig, notify/client.py:V1NotifierConfig/V2cNotifierConfig).
///
/// The manager's `V1Config`/`V2cConfig` and the notifier's
/// `V1NotifierConfig`/`V2cNotifierConfig` are aliases of this type, keeping
/// the architecture §5.5 names public (§5.5 constructor-shape note). The
/// shared default port is the manager's 161; trap senders should set `port`
/// explicitly (SNMP trap default 162).
#[derive(Clone)]
pub struct CommunityConfig {
    /// Remote host.
    pub host: String,
    /// Remote UDP port.
    pub port: u16,
    /// Community string.
    pub community: String,
    /// Optional MIB bundle for symbolic targets and response enrichment.
    pub bundle: Option<Arc<MibBundle>>,
    /// Per-attempt response timeout (default 2s).
    pub timeout: Duration,
    /// Retries after the initial attempt (default 1).
    pub retries: u32,
    /// Randomness seam (default SystemRng).
    pub rng: Arc<dyn Rng>,
}

impl Default for CommunityConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 161,
            community: "public".to_string(),
            bundle: None,
            timeout: Duration::from_secs(2),
            retries: 1,
            rng: Arc::new(SystemRng),
        }
    }
}

/// Community-based security model for v1/v2c (← community.py:CommunityModel).
///
/// The community string is bytewise (locked decision: no latin-1 fallback).
/// Version and community mismatches yield [`UnwrapOutcome::NotForUs`] so the
/// dispatcher skips foreign datagrams instead of failing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommunityModel {
    community: Vec<u8>,
    version: SnmpVersion,
}

impl CommunityModel {
    /// Creates a community model for a specific SNMP version. The version is
    /// part of the identity: an agent answering a v1 request with a v2c
    /// response is not for us (community.py:39–49).
    pub fn new(community: Vec<u8>, version: SnmpVersion) -> Result<Self, ProtocolError> {
        if version == SnmpVersion::V3 {
            // A community model is meaningless for v3 (usm.py is the v3 path).
            return Err(ProtocolError::new(
                "CommunityModel cannot be constructed for SNMPv3",
            ));
        }
        let model = Self { community, version };
        Ok(model)
    }

    /// The community bytes.
    #[must_use]
    pub fn community(&self) -> &[u8] {
        &self.community
    }

    /// The SNMP version this model wraps.
    #[must_use]
    pub fn version(&self) -> SnmpVersion {
        self.version
    }

    /// Wraps a PDU into a v1/v2c message datagram.
    pub fn wrap_pdu(&self, pdu: &Pdu) -> Result<Vec<u8>, Error> {
        let message = SnmpMessage {
            version: self.version,
            community: self.community.clone(),
            pdu: pdu.clone(),
        };
        encode_message(&message).map_err(Error::Protocol)
    }

    /// Validates an inbound datagram against this community and version.
    pub fn unwrap_message(&self, data: &[u8]) -> UnwrapOutcome {
        let message = match decode_message(data) {
            Ok(message) => message,
            Err(error) => return UnwrapOutcome::Malformed(error),
        };
        if message.version != self.version {
            return UnwrapOutcome::NotForUs;
        }
        if message.community != self.community {
            return UnwrapOutcome::NotForUs;
        }
        UnwrapOutcome::Ok(message.pdu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::message::SnmpVersion;
    use crate::types::oid::Oid;
    use crate::types::value::SnmpValue;
    use crate::types::varbind::VarBind;

    fn test_oid(arcs: &[u32]) -> Oid {
        Oid::from_arcs(arcs).unwrap()
    }

    fn get_pdu(request_id: u32) -> Pdu {
        Pdu {
            kind: crate::codec::pdu::PduKind::GetRequest,
            request_id,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                test_oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]),
                SnmpValue::Null,
            )],
            v1_trap: None,
        }
    }

    #[test]
    fn wrap_and_unwrap_roundtrip() {
        let model = CommunityModel::new(b"public".to_vec(), SnmpVersion::V2c).unwrap();
        let wrapped = model.wrap_pdu(&get_pdu(7)).unwrap();
        match model.unwrap_message(&wrapped) {
            UnwrapOutcome::Ok(pdu) => assert_eq!(pdu.request_id, 7),
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn wrong_community_is_not_for_us() {
        let model = CommunityModel::new(b"public".to_vec(), SnmpVersion::V2c).unwrap();
        let other = CommunityModel::new(b"private".to_vec(), SnmpVersion::V2c).unwrap();
        let wrapped = other.wrap_pdu(&get_pdu(7)).unwrap();
        assert_eq!(model.unwrap_message(&wrapped), UnwrapOutcome::NotForUs);
    }

    #[test]
    fn wrong_version_is_not_for_us() {
        let v1 = CommunityModel::new(b"public".to_vec(), SnmpVersion::V1).unwrap();
        let v2c = CommunityModel::new(b"public".to_vec(), SnmpVersion::V2c).unwrap();
        let wrapped = v2c.wrap_pdu(&get_pdu(7)).unwrap();
        assert_eq!(v1.unwrap_message(&wrapped), UnwrapOutcome::NotForUs);
    }

    #[test]
    fn malformed_datagram_is_malformed() {
        let model = CommunityModel::new(b"public".to_vec(), SnmpVersion::V2c).unwrap();
        match model.unwrap_message(b"\x02\x01\x01") {
            UnwrapOutcome::Malformed(_) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn wrap_is_byte_identical_to_codec_message() {
        let model = CommunityModel::new(b"public".to_vec(), SnmpVersion::V2c).unwrap();
        let pdu = get_pdu(123);
        let wrapped = model.wrap_pdu(&pdu).unwrap();
        let direct = encode_message(&SnmpMessage {
            version: SnmpVersion::V2c,
            community: b"public".to_vec(),
            pdu,
        })
        .unwrap();
        assert_eq!(wrapped, direct);
    }

    #[test]
    fn rejects_v3_construction() {
        // SnmpVersion::V3 is the USM path; a community model for v3 is
        // meaningless (review batch; message.rs has the same invariant).
        let err = CommunityModel::new(b"public".to_vec(), SnmpVersion::V3).unwrap_err();
        assert!(
            err.message.contains("cannot be constructed for SNMPv3"),
            "{err}"
        );
    }
}
