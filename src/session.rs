//! SnmpSession (← session.py)

use std::sync::Arc;
use std::time::Duration;

use crate::error::Error;
use crate::security::SecurityModel;
use crate::time::Rng;
use crate::transport::dispatcher::RequestDispatcher;
use crate::transport::udp::{UdpClient, UdpTransport};

/// Wire configuration shared by the session constructors.
#[derive(Clone)]
pub struct SessionConfig {
    /// Remote host.
    pub host: String,
    /// Remote UDP port.
    pub port: u16,
    /// The security model wrapping the session.
    pub security: Arc<SecurityModel>,
    /// Per-attempt response timeout.
    pub timeout: Duration,
    /// Retries after the initial attempt.
    pub retries: u32,
    /// Request-id randomness source.
    pub rng: Arc<dyn Rng>,
}

/// An open SNMP session: security model + transport + dispatcher
/// (← session.py:SnmpSession; §5.5).
///
/// # Lock discipline
///
/// `request_lock` serializes request/response exchanges through the session so
/// concurrent callers cannot interleave responses (the reference's
/// `_request_lock`; session.py:70–74). Lock discipline: `get`/`get_next`/
/// `get_bulk` acquire it once around a single exchange; `walk`/`bulkwalk` and
/// the V1 GETBULK downgrade acquire it **per request** so one long walk cannot
/// starve other callers. The lock guard must never be held across a wait that
/// could deadlock a concurrent close; use `Drop` teardown for cancellation.
pub struct SnmpSession {
    /// The security model (shared with the dispatcher; §5.4 ownership).
    pub security: Arc<SecurityModel>,
    /// The underlying transport.
    pub client: Arc<dyn UdpTransport>,
    /// The request dispatcher.
    pub dispatcher: RequestDispatcher,
    /// Serializes request/response exchanges.
    pub request_lock: tokio::sync::Mutex<()>,
}

impl SnmpSession {
    /// Connects: opens the transport, then lets the security model prepare
    /// (community: no-op).
    pub async fn connect(config: SessionConfig) -> Result<Self, Error> {
        let client: Arc<dyn UdpTransport> = Arc::new(UdpClient::new(config.host, config.port));
        let dispatcher = RequestDispatcher::new(
            Arc::clone(&client),
            Arc::clone(&config.security),
            config.timeout,
            config.retries,
            Arc::clone(&config.rng),
        )?;
        client.open().await.map_err(Error::Transport)?;
        config.security.prepare(&dispatcher).await?;
        Ok(Self {
            security: config.security,
            client,
            dispatcher,
            request_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Closes the underlying transport.
    pub async fn close(&self) -> Result<(), Error> {
        self.client.close().await.map_err(Error::Transport)
    }

    /// Builds a session over a caller-supplied transport (test seam; the
    /// transport is not opened here).
    pub fn from_parts(
        security: Arc<SecurityModel>,
        client: Arc<dyn UdpTransport>,
        dispatcher: RequestDispatcher,
    ) -> Self {
        Self {
            security,
            client,
            dispatcher,
            request_lock: tokio::sync::Mutex::new(()),
        }
    }
}
