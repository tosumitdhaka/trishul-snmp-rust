//! SecurityModel enum (← model.py)

pub mod community;
pub mod usm;

use crate::codec::message::SnmpVersion;
use crate::codec::pdu::Pdu;
use crate::error::{EngineReport, Error, UnwrapOutcome};
use crate::security::community::CommunityModel;
use crate::security::usm::UsmModel;
use crate::transport::dispatcher::RequestDispatcher;

/// The security layer behind the dispatcher's send/receive loop
/// (← model.py:SecurityModel protocol; §5.4).
///
/// `wrap_pdu` serializes an outbound PDU into the authenticated datagram;
/// `unwrap_message` validates an inbound datagram and reports
/// [`UnwrapOutcome`]. USM lands in Phase 3.
#[derive(Clone)]
#[allow(clippy::large_enum_variant)] // Usm carries a Mutex<UsmEngineState>; the arms are a plain 2-way dispatch
pub enum SecurityModel {
    /// Community-based security for v1/v2c (← community.py).
    Community(CommunityModel),
    /// USM security for v3 (← usm.py).
    Usm(UsmModel),
}

impl SecurityModel {
    /// Wraps a PDU into a ready-to-send datagram.
    pub fn wrap_pdu(&self, pdu: &Pdu) -> Result<Vec<u8>, Error> {
        match self {
            SecurityModel::Community(model) => model.wrap_pdu(pdu),
            SecurityModel::Usm(model) => model.wrap_pdu(pdu),
        }
    }

    /// Validates an inbound datagram and extracts the PDU, if any.
    pub fn unwrap_message(&self, data: &[u8]) -> UnwrapOutcome {
        match self {
            SecurityModel::Community(model) => model.unwrap_message(data),
            SecurityModel::Usm(model) => model.unwrap_message(data),
        }
    }

    /// Prepares the security layer: USM performs RFC 3414 discovery;
    /// community is a no-op.
    pub async fn prepare(&self, dispatcher: &RequestDispatcher) -> Result<(), Error> {
        match self {
            SecurityModel::Community(_) => Ok(()),
            SecurityModel::Usm(model) => model.prepare(dispatcher).await,
        }
    }

    /// Claims a pending engine-recovery report (community: never).
    #[must_use]
    pub fn take_recovery(&self) -> Option<EngineReport> {
        match self {
            SecurityModel::Community(_) => None,
            SecurityModel::Usm(model) => model.take_recovery(),
        }
    }

    /// The SNMP version this security model speaks.
    #[must_use]
    pub fn version(&self) -> SnmpVersion {
        match self {
            SecurityModel::Community(model) => model.version(),
            SecurityModel::Usm(model) => model.version(),
        }
    }
}

impl From<CommunityModel> for SecurityModel {
    fn from(model: CommunityModel) -> Self {
        SecurityModel::Community(model)
    }
}
