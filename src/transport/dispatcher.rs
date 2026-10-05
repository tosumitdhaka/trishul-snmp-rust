//! RequestDispatcher, request-id pool (← dispatcher.py)

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

use crate::codec::pdu::{Pdu, PduKind};
use crate::error::{Error, ProtocolError};
use crate::security::SecurityModel;
use crate::time::Rng;
use crate::transport::udp::UdpTransport;

/// A prepared (wrapped) request datagram with a reserved request id
/// (← dispatcher.py:PreparedRequest).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedRequest {
    /// The reserved, encoded request id (or the v1 trap timestamp).
    pub request_id: u32,
    /// The wrapped, ready-to-send datagram.
    pub encoded_message: Vec<u8>,
}

/// RAII guard releasing a reserved request id on drop — including when the
/// enclosing future is cancelled at an await point. Without it a dropped
/// request would leak its id for the dispatcher's lifetime.
struct IdGuard<'a> {
    dispatcher: &'a RequestDispatcher,
    request_id: u32,
}

impl Drop for IdGuard<'_> {
    fn drop(&mut self) {
        self.dispatcher.release_request(self.request_id);
    }
}

/// The 31-bit request-id space reserved by SNMPv2 (RFC 3416 §4.1.5).
const REQUEST_ID_MASK: u32 = 0x7FFF_FFFF;

/// Dispatches request/response flows over a `UdpTransport`, owning the
/// request-id pool and the retry/timeout loop (tokio::time, §7).
///
/// Holds the `Arc<SecurityModel>` so `unwrap_message` runs here (the
/// dispatcher is the only owner of the receive loop; §5.4).
pub struct RequestDispatcher {
    client: Arc<dyn UdpTransport>,
    security: Arc<SecurityModel>,
    timeout: Duration,
    retries: u32,
    issued: Mutex<HashSet<u32>>,
    rng: Arc<dyn Rng>,
}

impl RequestDispatcher {
    /// Creates a dispatcher. `timeout` must be non-zero.
    pub fn new(
        client: Arc<dyn UdpTransport>,
        security: Arc<SecurityModel>,
        timeout: Duration,
        retries: u32,
        rng: Arc<dyn Rng>,
    ) -> Result<Self, Error> {
        if timeout.is_zero() {
            return Err(Error::InvalidInput(
                "RequestDispatcher timeout must be greater than 0".to_string(),
            ));
        }
        Ok(Self {
            client,
            security,
            timeout,
            retries,
            issued: Mutex::new(HashSet::new()),
            rng,
        })
    }

    /// Currently reserved request ids (test/diagnostic surface).
    #[must_use]
    pub fn issued_request_ids(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = self
            .issued
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .copied()
            .collect();
        ids.sort_unstable();
        ids
    }

    /// Generates a fresh request id: 31-bit (never zero), Rng-backed, and
    /// collision-checked against the reserved set (dispatcher.py:46–52).
    fn new_request_id(&self) -> u32 {
        let mut issued = self
            .issued
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            let mut buf = [0u8; 4];
            self.rng.fill_bytes(&mut buf);
            let id = u32::from_be_bytes(buf) & REQUEST_ID_MASK;
            if id != 0 && !issued.contains(&id) {
                issued.insert(id);
                return id;
            }
        }
    }

    /// Releases a request id back to the pool (idempotent).
    pub fn release_request(&self, request_id: u32) {
        self.issued
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&request_id);
    }

    /// Reserves an id, builds the PDU, and wraps it through the security model
    /// (dispatcher.py:prepare_request). The id is released if wrapping fails.
    pub fn prepare_request(
        &self,
        kind: PduKind,
        varbinds: Vec<crate::types::varbind::VarBind>,
        error_status: i32,
        error_index: i32,
    ) -> Result<PreparedRequest, Error> {
        let request_id = self.new_request_id();
        let pdu = Pdu {
            kind,
            request_id,
            error_status,
            error_index,
            varbinds,
            v1_trap: None,
        };
        match self.security.wrap_pdu(&pdu) {
            Ok(encoded_message) => Ok(PreparedRequest {
                request_id,
                encoded_message,
            }),
            Err(error) => {
                self.release_request(request_id);
                Err(error)
            }
        }
    }

    /// Sends a prepared request datagram without waiting (dispatcher.py:send_only).
    pub async fn send_only(&self, request: &PreparedRequest) -> Result<(), Error> {
        self.client
            .send(&request.encoded_message)
            .await
            .map_err(Error::Transport)
    }

    /// Sends a prepared request and waits for its matching response, retrying
    /// up to `retries + 1` times. The request id is released on every exit
    /// path — including caller cancellation, via the `IdGuard` held across
    /// the whole exchange.
    pub async fn send_prepared_request(&self, request: PreparedRequest) -> Result<Pdu, Error> {
        let _guard = IdGuard {
            dispatcher: self,
            request_id: request.request_id,
        };
        self.send_prepared_request_inner(&request).await
    }

    async fn send_prepared_request_inner(&self, request: &PreparedRequest) -> Result<Pdu, Error> {
        let attempts = self.retries + 1;
        let mut saw_timeout = false;
        for _ in 0..attempts {
            self.send_only(request).await?;
            match self.receive_response(request.request_id).await {
                Ok(pdu) => return Ok(pdu),
                Err(Error::Timeout { .. }) => saw_timeout = true,
                Err(error) => return Err(error),
            }
        }
        debug_assert!(saw_timeout || attempts == 0);
        Err(Error::Timeout {
            attempts: u8::try_from(attempts).unwrap_or(u8::MAX),
        })
    }

    /// Waits for a response matching `request_id`, releasing the id on exit
    /// (including cancellation, via the `IdGuard`).
    pub async fn receive_response(&self, request_id: u32) -> Result<Pdu, Error> {
        let _guard = IdGuard {
            dispatcher: self,
            request_id,
        };
        self.receive_matching_response(request_id).await
    }

    async fn receive_matching_response(&self, request_id: u32) -> Result<Pdu, Error> {
        let deadline = Instant::now() + self.timeout;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::Timeout { attempts: 1 });
            }
            let remaining = deadline - now;
            let data = match self.client.receive(remaining).await {
                Err(crate::error::TransportError::Timeout) => {
                    return Err(Error::Timeout { attempts: 1 });
                }
                Err(other) => return Err(Error::Transport(other)),
                Ok(data) => data,
            };
            match self.security.unwrap_message(&data) {
                crate::error::UnwrapOutcome::Ok(pdu) => {
                    if pdu.kind != PduKind::Response {
                        return Err(Error::Protocol(ProtocolError::new(format!(
                            "Expected RESPONSE PDU, received {:?}",
                            pdu.kind
                        ))));
                    }
                    if pdu.request_id != request_id {
                        continue;
                    }
                    return Ok(pdu);
                }
                crate::error::UnwrapOutcome::NotForUs
                | crate::error::UnwrapOutcome::Malformed(_) => continue,
                crate::error::UnwrapOutcome::AuthFailed => {
                    return Err(Error::Authentication);
                }
                crate::error::UnwrapOutcome::EngineRecoveryPending => {
                    if let Some(report) = self.security.take_recovery() {
                        return Err(Error::EngineRecovery(report));
                    }
                    continue;
                }
            }
        }
    }

    /// Sends a raw datagram and returns the first decoded response (or the
    /// raw bytes for USM discovery), retrying on timeout
    /// (dispatcher.py:send_raw_and_receive).
    pub async fn send_raw_and_receive(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let attempts = self.retries + 1;
        for _ in 0..attempts {
            self.client.send(data).await.map_err(Error::Transport)?;
            match self.client.receive(self.timeout).await {
                Err(crate::error::TransportError::Timeout) => {}
                Err(other) => return Err(Error::Transport(other)),
                Ok(reply) => return Ok(reply),
            }
        }
        Err(Error::Timeout {
            attempts: u8::try_from(attempts).unwrap_or(u8::MAX),
        })
    }

    /// Full request/response cycle for a manager-style PDU
    /// (dispatcher.py:send_pdu).
    pub async fn send_pdu(
        &self,
        kind: PduKind,
        varbinds: Vec<crate::types::varbind::VarBind>,
        error_status: i32,
        error_index: i32,
    ) -> Result<Pdu, Error> {
        let request = self.prepare_request(kind, varbinds, error_status, error_index)?;
        self.send_prepared_request(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::community::CommunityModel;
    use crate::types::oid::Oid;
    use crate::types::value::SnmpValue;
    use crate::types::varbind::VarBind;

    struct DeterministicRng {
        next: Mutex<u32>,
    }

    impl Rng for DeterministicRng {
        fn fill_bytes(&self, buf: &mut [u8]) {
            let mut next = self.next.lock().unwrap();
            let value = *next;
            *next = next.wrapping_add(1);
            buf.copy_from_slice(&value.to_be_bytes());
        }
    }

    fn test_oid(arcs: &[u32]) -> Oid {
        Oid::from_arcs(arcs).unwrap()
    }

    fn test_varbind() -> Vec<VarBind> {
        vec![VarBind::new(
            test_oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]),
            SnmpValue::Null,
        )]
    }

    fn test_security() -> Arc<SecurityModel> {
        Arc::new(SecurityModel::Community(
            CommunityModel::new(b"public".to_vec(), crate::codec::message::SnmpVersion::V2c)
                .unwrap(),
        ))
    }

    #[test]
    fn new_request_ids_are_31_bit_nonzero_and_unique() {
        let dispatcher = RequestDispatcher::new(
            Arc::new(crate::transport::udp::UdpClient::new(
                "127.0.0.1".into(),
                161,
            )),
            test_security(),
            Duration::from_secs(1),
            1,
            Arc::new(DeterministicRng {
                next: Mutex::new(0),
            }),
        )
        .unwrap();
        let a = dispatcher.new_request_id();
        let b = dispatcher.new_request_id();
        assert_ne!(a, b);
        assert_ne!(a, 0);
        assert_ne!(b, 0);
        assert!(a & REQUEST_ID_MASK == a);
        assert!(b & REQUEST_ID_MASK == b);
    }

    #[test]
    fn request_ids_avoid_collisions_with_reserved_ids() {
        // A sequence of 0xFFFFFFFF, 0x00000000, 0x00000001 must produce 1
        // after the first (0xFFFFFFFF -> 0x7FFFFFFF). Zero is never returned.
        let dispatcher = RequestDispatcher::new(
            Arc::new(crate::transport::udp::UdpClient::new(
                "127.0.0.1".into(),
                161,
            )),
            test_security(),
            Duration::from_secs(1),
            1,
            Arc::new(DeterministicRng {
                next: Mutex::new(0),
            }),
        )
        .unwrap();
        let mut seen = HashSet::new();
        for _ in 0..100 {
            let id = dispatcher.new_request_id();
            assert_ne!(id, 0);
            assert!(seen.insert(id), "collision: {id}");
        }
    }

    #[test]
    fn rejects_zero_timeout() {
        let err = RequestDispatcher::new(
            Arc::new(crate::transport::udp::UdpClient::new(
                "127.0.0.1".into(),
                161,
            )),
            test_security(),
            Duration::ZERO,
            1,
            Arc::new(DeterministicRng {
                next: Mutex::new(0),
            }),
        )
        .err()
        .expect("zero timeout must fail");
        assert!(matches!(err, Error::InvalidInput(_)));
    }

    #[test]
    fn prepare_request_reserves_an_id_and_release_frees_it() {
        let dispatcher = RequestDispatcher::new(
            Arc::new(crate::transport::udp::UdpClient::new(
                "127.0.0.1".into(),
                161,
            )),
            test_security(),
            Duration::from_secs(1),
            1,
            Arc::new(DeterministicRng {
                next: Mutex::new(1),
            }),
        )
        .unwrap();
        let request = dispatcher
            .prepare_request(PduKind::GetRequest, test_varbind(), 0, 0)
            .unwrap();
        assert_eq!(request.request_id, 1);
        assert_eq!(dispatcher.issued_request_ids(), vec![1]);
        dispatcher.release_request(request.request_id);
        assert!(dispatcher.issued_request_ids().is_empty());
    }

    #[test]
    fn release_request_is_idempotent() {
        let dispatcher = RequestDispatcher::new(
            Arc::new(crate::transport::udp::UdpClient::new(
                "127.0.0.1".into(),
                161,
            )),
            test_security(),
            Duration::from_secs(1),
            1,
            Arc::new(DeterministicRng {
                next: Mutex::new(1),
            }),
        )
        .unwrap();
        let request = dispatcher
            .prepare_request(PduKind::GetRequest, test_varbind(), 0, 0)
            .unwrap();
        dispatcher.release_request(request.request_id);
        dispatcher.release_request(request.request_id);
        assert!(dispatcher.issued_request_ids().is_empty());
    }
}
