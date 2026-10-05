//! SecurityModel enum (← model.py)

pub mod community;

use crate::codec::message::SnmpVersion;
use crate::codec::pdu::Pdu;
use crate::error::{EngineReport, Error, UnwrapOutcome};
use crate::security::community::CommunityModel;
use crate::transport::dispatcher::RequestDispatcher;

/// The security layer behind the dispatcher's send/receive loop
/// (← model.py:SecurityModel protocol; §5.4).
///
/// `wrap_pdu` serializes an outbound PDU into the authenticated datagram;
/// `unwrap_message` validates an inbound datagram and reports
/// [`UnwrapOutcome`]. The USM variant (`SecurityModel::Usm`) lands in Phase 3;
/// until then only community security is constructible.
#[derive(Clone)]
pub enum SecurityModel {
    /// Community-based security for v1/v2c (← community.py).
    Community(CommunityModel),
}

impl SecurityModel {
    /// Wraps a PDU into a ready-to-send datagram (community: message wrapper).
    pub fn wrap_pdu(&self, pdu: &Pdu) -> Result<Vec<u8>, Error> {
        match self {
            SecurityModel::Community(model) => model.wrap_pdu(pdu),
        }
    }

    /// Validates an inbound datagram and extracts the PDU, if any.
    pub fn unwrap_message(&self, data: &[u8]) -> UnwrapOutcome {
        match self {
            SecurityModel::Community(model) => model.unwrap_message(data),
        }
    }

    /// Prepares the security layer (USM discovery/report exchange in Phase 3;
    /// no-op for community).
    pub async fn prepare(&self, _dispatcher: &RequestDispatcher) -> Result<(), Error> {
        match self {
            SecurityModel::Community(_) => Ok(()),
        }
    }

    /// Claims a pending engine-recovery report (community: never).
    #[must_use]
    pub fn take_recovery(&self) -> Option<EngineReport> {
        match self {
            SecurityModel::Community(_) => None,
        }
    }

    /// The SNMP version this security model speaks.
    #[must_use]
    pub fn version(&self) -> SnmpVersion {
        match self {
            SecurityModel::Community(model) => model.version(),
        }
    }
}

impl From<CommunityModel> for SecurityModel {
    fn from(model: CommunityModel) -> Self {
        SecurityModel::Community(model)
    }
}
