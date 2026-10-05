//! v1/v2c SnmpMessage (← message.py)

use rasn::prelude::*;
use rasn::types::OctetString;

use crate::codec::pdu::{Pdu, RawPdu};
use crate::error::ProtocolError;

/// SNMP message version (wire integers 0 | 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnmpVersion {
    /// SNMPv1.
    V1,
    /// SNMPv2c.
    V2c,
}

impl SnmpVersion {
    /// The wire version integer.
    #[must_use]
    pub fn to_wire(self) -> i64 {
        match self {
            Self::V1 => 0,
            Self::V2c => 1,
        }
    }
}

/// Low-level SNMP v1/v2c message.
///
/// The community is bytewise (`Vec<u8>`): there is no latin-1 fallback
/// (locked decision, docs/architecture.md §1 and §8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnmpMessage {
    /// The message version.
    pub version: SnmpVersion,
    /// The community string, bytewise.
    pub community: Vec<u8>,
    /// The enclosed PDU.
    pub pdu: Pdu,
}

/// rasn wire model of the message: INTEGER version, OCTET STRING community,
/// PDU choice.
#[derive(AsnType, Decode, Encode)]
struct RawMessage {
    version: i64,
    community: OctetString,
    pdu: RawPdu,
}

/// Encodes a v1/v2c message to BER bytes (← message.py:encode_message).
pub fn encode_message(message: &SnmpMessage) -> Result<Vec<u8>, ProtocolError> {
    let raw = RawMessage {
        version: message.version.to_wire(),
        community: OctetString::from(message.community.clone()),
        pdu: message.pdu.to_raw()?,
    };
    rasn::ber::encode(&raw).map_err(|e| ProtocolError::new(e.to_string()))
}

/// Decodes a BER-encoded v1/v2c message under DER options (indefinite-length
/// and constructed-OCTET-STRING rejection) with a trailing-content shim
/// (← message.py:decode_message, §5.3a).
pub fn decode_message(data: &[u8]) -> Result<SnmpMessage, ProtocolError> {
    if data.is_empty() {
        return Err(ProtocolError::new("BER tag is truncated"));
    }
    let tag = data[0];
    if tag != 0x30 {
        return Err(ProtocolError::new(format!(
            "Expected SNMP message SEQUENCE, found 0x{tag:02x}"
        )));
    }
    let raw = crate::codec::decode_der::<RawMessage>(data)?;
    let version = match raw.version {
        0 => SnmpVersion::V1,
        1 => SnmpVersion::V2c,
        other => {
            return Err(ProtocolError::new(format!(
                "Unsupported SNMP version {other}"
            )));
        }
    };
    Ok(SnmpMessage {
        version,
        community: raw.community.as_ref().to_vec(),
        pdu: raw.pdu.into_pdu()?,
    })
}
