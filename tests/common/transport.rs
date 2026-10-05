//! In-memory `UdpTransport` for dispatcher-level tests (shared by the
//! dispatcher suite and the v3 engine-recovery suite).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use trishul_snmp::codec::message::{SnmpMessage, decode_message, encode_message};
use trishul_snmp::codec::pdu::{Pdu, PduKind};
use trishul_snmp::error::TransportError;
use trishul_snmp::transport::udp::UdpTransport;
use trishul_snmp::types::varbind::VarBind;

/// A send hook: given the raw request bytes, returns datagrams to queue for
/// subsequent receives (empty = do not reply).
pub type SendHook = Box<dyn Fn(&[u8]) -> Vec<Vec<u8>> + Send>;

/// A configurable in-memory transport for dispatcher tests.
pub struct FakeTransport {
    on_send: Mutex<SendHook>,
    /// extra datagrams queued ahead of the send callback output.
    queued: Mutex<VecDeque<Vec<u8>>>,
    /// sent datagrams (for assertions).
    sent: Mutex<Vec<Vec<u8>>>,
    /// when set, receive always times out without consuming the queue.
    force_timeout: AtomicBool,
    /// number of receives to consume silently (drop) before the queue.
    drop_receives: AtomicUsize,
}

impl FakeTransport {
    /// Creates a transport whose send hook computes replies.
    pub fn new(on_send: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static) -> Arc<Self> {
        Arc::new(Self {
            on_send: Mutex::new(Box::new(on_send)),
            queued: Mutex::new(VecDeque::new()),
            sent: Mutex::new(Vec::new()),
            force_timeout: AtomicBool::new(false),
            drop_receives: AtomicUsize::new(0),
        })
    }

    /// Number of datagrams sent through this transport.
    #[must_use]
    pub fn sent_count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }

    /// Every datagram sent through this transport.
    #[must_use]
    pub fn sent_datagrams(&self) -> Vec<Vec<u8>> {
        self.sent.lock().unwrap().clone()
    }
}

impl UdpTransport for FakeTransport {
    fn open(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + '_>>
    {
        Box::pin(async { Ok(()) })
    }

    fn close(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + '_>>
    {
        Box::pin(async { Ok(()) })
    }

    fn send(
        &self,
        data: &[u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + '_>>
    {
        let owned = data.to_vec();
        let transport = self;
        Box::pin(async move {
            transport.sent.lock().unwrap().push(owned.clone());
            let replies = (transport.on_send.lock().unwrap())(&owned);
            let mut queued = transport.queued.lock().unwrap();
            for reply in replies {
                queued.push_back(reply);
            }
            Ok(())
        })
    }

    fn receive(
        &self,
        timeout: Duration,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<u8>, TransportError>> + Send + '_>,
    > {
        let transport = self;
        Box::pin(async move {
            if transport.force_timeout.load(Ordering::SeqCst) {
                tokio::time::sleep(timeout).await;
                return Err(TransportError::Timeout);
            }
            if transport.drop_receives.load(Ordering::SeqCst) > 0 {
                transport.drop_receives.fetch_sub(1, Ordering::SeqCst);
                tokio::time::sleep(timeout).await;
                return Err(TransportError::Timeout);
            }
            if let Some(data) = transport.queued.lock().unwrap().pop_front() {
                return Ok(data);
            }
            tokio::time::sleep(timeout).await;
            Err(TransportError::Timeout)
        })
    }
}

/// Builds a RESPONSE datagram echoing the request's version/community/id.
pub fn reply_for(request: &[u8], varbinds: Vec<VarBind>) -> Option<Vec<u8>> {
    let message = decode_message(request).ok()?;
    let pdu = Pdu {
        kind: PduKind::Response,
        request_id: message.pdu.request_id,
        error_status: 0,
        error_index: 0,
        varbinds,
        v1_trap: None,
    };
    encode_message(&SnmpMessage {
        version: message.version,
        community: message.community,
        pdu,
    })
    .ok()
}

/// Builds a RESPONSE with an explicitly overridden request id (for mismatch
/// tests; a request id of zero is never used by the dispatcher).
pub fn reply_for_with_id(
    request: &[u8],
    request_id: u32,
    varbinds: Vec<VarBind>,
) -> Option<Vec<u8>> {
    let message = decode_message(request).ok()?;
    let pdu = Pdu {
        kind: PduKind::Response,
        request_id,
        error_status: 0,
        error_index: 0,
        varbinds,
        v1_trap: None,
    };
    encode_message(&SnmpMessage {
        version: message.version,
        community: message.community,
        pdu,
    })
    .ok()
}

/// Unsizes a concrete FakeTransport into the trait object the dispatcher takes.
pub fn upcast(transport: Arc<FakeTransport>) -> Arc<dyn UdpTransport> {
    transport
}
