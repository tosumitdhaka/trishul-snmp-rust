//! Runtime tests: dispatcher semantics (in-memory transport) and v1/v2c
//! manager operations (loopback UDP agent).
//!
//! Ported from the reference's `test_dispatcher.py` and `test_manager_operations.py`
//! plus the v1 GETBULK behavior in `test_v1_manager.py` (rewritten against
//! scripted loopback agents instead of injected fake clients).

mod common;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::agent::{FakeAgent, object_logic, scripted_logic};
use common::{hex, oid, vb};

use trishul_snmp::codec::message::{SnmpMessage, SnmpVersion, decode_message, encode_message};
use trishul_snmp::codec::pdu::{Pdu, PduKind};
use trishul_snmp::error::{Error, TransportError};
use trishul_snmp::manager::{Manager, V1Config, V2cConfig};
use trishul_snmp::security::SecurityModel;
use trishul_snmp::security::community::CommunityModel;
use trishul_snmp::time::Rng;
use trishul_snmp::transport::dispatcher::RequestDispatcher;
use trishul_snmp::transport::udp::UdpTransport;
use trishul_snmp::types::value::SnmpValue;
use trishul_snmp::types::varbind::{ErrorStatus, VarBind};

/// A send hook: given the raw request bytes, returns datagrams to queue for
/// subsequent receives (empty = do not reply).
type SendHook = Box<dyn Fn(&[u8]) -> Vec<Vec<u8>> + Send>;

/// A configurable in-memory transport for dispatcher tests.
struct FakeTransport {
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
    fn new(on_send: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static) -> Arc<Self> {
        Arc::new(Self {
            on_send: Mutex::new(Box::new(on_send)),
            queued: Mutex::new(VecDeque::new()),
            sent: Mutex::new(Vec::new()),
            force_timeout: AtomicBool::new(false),
            drop_receives: AtomicUsize::new(0),
        })
    }

    fn sent_count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }

    fn sent_datagrams(&self) -> Vec<Vec<u8>> {
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
fn reply_for(request: &[u8], varbinds: Vec<VarBind>) -> Option<Vec<u8>> {
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

/// A request id of zero is never used, so an id mismatch is easy to build.
fn reply_for_with_id(request: &[u8], request_id: u32, varbinds: Vec<VarBind>) -> Option<Vec<u8>> {
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

fn test_security() -> Arc<SecurityModel> {
    Arc::new(SecurityModel::Community(
        CommunityModel::new(b"public".to_vec(), SnmpVersion::V2c).unwrap(),
    ))
}

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

fn upcast(transport: Arc<FakeTransport>) -> Arc<dyn UdpTransport> {
    transport
}

fn dispatcher(
    transport: Arc<dyn UdpTransport>,
    timeout: Duration,
    retries: u32,
) -> RequestDispatcher {
    RequestDispatcher::new(
        transport,
        test_security(),
        timeout,
        retries,
        Arc::new(DeterministicRng {
            next: Mutex::new(7),
        }),
    )
    .unwrap()
}

fn sys_uptime_varbind() -> Vec<VarBind> {
    vec![vb(&[1, 3, 6, 1, 2, 1, 1, 3, 0], SnmpValue::Null)]
}

fn sys_uptime_reply() -> Vec<VarBind> {
    vec![vb(&[1, 3, 6, 1, 2, 1, 1, 3, 0], SnmpValue::TimeTicks(42))]
}

#[tokio::test]
async fn dispatcher_retries_then_succeeds() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let transport = FakeTransport::new({
        let attempts = Arc::clone(&attempts);
        move |request: &[u8]| {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst) + 1;
            if attempt == 1 {
                vec![] // first attempt times out
            } else {
                vec![reply_for(request, sys_uptime_reply()).unwrap()]
            }
        }
    });
    let d = dispatcher(upcast(Arc::clone(&transport)), Duration::from_millis(20), 1);
    let pdu = d
        .send_pdu(PduKind::GetRequest, sys_uptime_varbind(), 0, 0)
        .await
        .unwrap();
    assert_eq!(pdu.request_id, 7);
    assert_eq!(pdu.varbinds.len(), 1);
    assert_eq!(transport.sent_count(), 2);
    assert!(d.issued_request_ids().is_empty(), "id released after send");
}

#[tokio::test]
async fn dispatcher_ignores_unmatched_responses() {
    let transport = FakeTransport::new(move |request: &[u8]| {
        // First a response for an unrelated request id, then the real one.
        let wrong = reply_for_with_id(request, 1, sys_uptime_reply()).unwrap();
        let right = reply_for(request, sys_uptime_reply()).unwrap();
        vec![wrong, right]
    });
    let d = dispatcher(upcast(Arc::clone(&transport)), Duration::from_millis(50), 0);
    let pdu = d
        .send_pdu(PduKind::GetRequest, sys_uptime_varbind(), 0, 0)
        .await
        .unwrap();
    assert_eq!(pdu.request_id, 7);
    assert!(d.issued_request_ids().is_empty());
}

#[tokio::test]
async fn dispatcher_skips_malformed_datagrams() {
    let transport = FakeTransport::new(move |request: &[u8]| {
        let good = reply_for(request, sys_uptime_reply()).unwrap();
        vec![vec![0xde, 0xad, 0xbe, 0xef], good]
    });
    let d = dispatcher(upcast(Arc::clone(&transport)), Duration::from_millis(50), 0);
    let pdu = d
        .send_pdu(PduKind::GetRequest, sys_uptime_varbind(), 0, 0)
        .await
        .unwrap();
    assert_eq!(pdu.varbinds[0].value, SnmpValue::TimeTicks(42));
}

#[tokio::test]
async fn dispatcher_raises_protocol_error_for_non_response_pdu() {
    let transport = FakeTransport::new(move |request: &[u8]| {
        let message = decode_message(request).unwrap();
        let pdu = Pdu {
            kind: PduKind::GetRequest,
            request_id: message.pdu.request_id,
            error_status: 0,
            error_index: 0,
            varbinds: sys_uptime_reply(),
            v1_trap: None,
        };
        encode_message(&SnmpMessage {
            version: message.version,
            community: message.community,
            pdu,
        })
        .ok()
        .into_iter()
        .collect()
    });
    let d = dispatcher(upcast(Arc::clone(&transport)), Duration::from_millis(50), 0);
    let err = d
        .send_pdu(PduKind::GetRequest, sys_uptime_varbind(), 0, 0)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
    assert!(d.issued_request_ids().is_empty());
}

#[tokio::test]
async fn dispatcher_raises_after_retry_budget_exhausted() {
    let transport = FakeTransport::new(|_request| vec![]);
    let d = dispatcher(upcast(Arc::clone(&transport)), Duration::from_millis(15), 2);
    let err = d
        .send_pdu(PduKind::GetRequest, sys_uptime_varbind(), 0, 0)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Timeout { attempts: 3 }), "got {err:?}");
    assert!(
        d.issued_request_ids().is_empty(),
        "id released after exhaustion"
    );
}

#[tokio::test]
async fn dispatcher_reuses_same_request_id_across_retries() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let transport = FakeTransport::new({
        let attempts = Arc::clone(&attempts);
        move |request: &[u8]| {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst) + 1;
            if attempt == 1 {
                vec![]
            } else {
                vec![reply_for(request, sys_uptime_reply()).unwrap()]
            }
        }
    });
    let d = dispatcher(upcast(Arc::clone(&transport)), Duration::from_millis(20), 2);
    let _ = d
        .send_pdu(PduKind::GetRequest, sys_uptime_varbind(), 0, 0)
        .await
        .unwrap();
    let datagrams = transport.sent_datagrams();
    assert_eq!(datagrams.len(), 2);
    let first_id = decode_message(&datagrams[0]).unwrap().pdu.request_id;
    let second_id = decode_message(&datagrams[1]).unwrap().pdu.request_id;
    assert_eq!(first_id, second_id, "same id across retries");
}

#[tokio::test]
async fn dispatcher_send_failure_releases_request_id() {
    // A transport whose send always fails.
    let transport: Arc<dyn UdpTransport> = Arc::new(TransportSendFail);
    let d = dispatcher(Arc::clone(&transport), Duration::from_millis(20), 1);
    let err = d
        .send_pdu(PduKind::GetRequest, sys_uptime_varbind(), 0, 0)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Transport(_)), "got {err:?}");
    assert!(
        d.issued_request_ids().is_empty(),
        "id released after send failure"
    );
}

struct TransportSendFail;

impl UdpTransport for TransportSendFail {
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
        _data: &[u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + '_>>
    {
        Box::pin(async { Err(TransportError::Io("send failed".to_string())) })
    }
    fn receive(
        &self,
        timeout: Duration,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<u8>, TransportError>> + Send + '_>,
    > {
        Box::pin(async move {
            tokio::time::sleep(timeout).await;
            Err(TransportError::Timeout)
        })
    }
}

#[tokio::test]
async fn dispatcher_wrong_community_response_is_skipped() {
    let transport = FakeTransport::new(move |request: &[u8]| {
        // Reply with a different community: not for us, then the real reply.
        let message = decode_message(request).unwrap();
        let wrong = encode_message(&SnmpMessage {
            version: message.version,
            community: b"private".to_vec(),
            pdu: Pdu {
                kind: PduKind::Response,
                request_id: message.pdu.request_id,
                error_status: 0,
                error_index: 0,
                varbinds: sys_uptime_reply(),
                v1_trap: None,
            },
        })
        .unwrap();
        let right = reply_for(request, sys_uptime_reply()).unwrap();
        vec![wrong, right]
    });
    let d = dispatcher(upcast(Arc::clone(&transport)), Duration::from_millis(50), 0);
    let pdu = d
        .send_pdu(PduKind::GetRequest, sys_uptime_varbind(), 0, 0)
        .await
        .unwrap();
    assert_eq!(pdu.varbinds[0].value, SnmpValue::TimeTicks(42));
}

#[tokio::test]
async fn prepare_request_reserves_and_release_frees() {
    let d = dispatcher(FakeTransport::new(|_| vec![]), Duration::from_millis(20), 1);
    let request = d
        .prepare_request(PduKind::GetRequest, sys_uptime_varbind(), 0, 0)
        .unwrap();
    assert_eq!(request.request_id, 7);
    assert_eq!(d.issued_request_ids(), vec![7]);
    d.release_request(request.request_id);
    assert!(d.issued_request_ids().is_empty());
}

// ───────────────────────────── manager operations ─────────────────────────────

fn v2c_manager_config(port: u16, community: &str) -> V2cConfig {
    V2cConfig {
        host: "127.0.0.1".to_string(),
        port,
        community: community.to_string(),
        timeout: Duration::from_millis(300),
        retries: 0,
        ..Default::default()
    }
}

fn v1_manager_config(port: u16, community: &str) -> V1Config {
    V1Config {
        host: "127.0.0.1".to_string(),
        port,
        community: community.to_string(),
        timeout: Duration::from_millis(300),
        retries: 0,
        ..Default::default()
    }
}

const SYS_UPTIME: [u32; 9] = [1, 3, 6, 1, 2, 1, 1, 3, 0];

#[tokio::test]
async fn v2c_get_roundtrip() {
    let objects = vec![(oid(&SYS_UPTIME), SnmpValue::TimeTicks(12345))];
    let (agent, port) = FakeAgent::spawn(object_logic(objects, false)).await;
    let manager = Manager::connect_v2c(v2c_manager_config(port, "public"))
        .await
        .unwrap();
    let response = manager.get(vec!["1.3.6.1.2.1.1.3.0"]).await.unwrap();
    assert_eq!(response.error_status, ErrorStatus::NoError);
    assert_ne!(response.request_id, 0);
    assert_eq!(response.varbinds.len(), 1);
    assert_eq!(response.varbinds[0].value, SnmpValue::TimeTicks(12345));
    agent.stop();
}

#[tokio::test]
async fn v1_get_roundtrip() {
    let objects = vec![(
        oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
        SnmpValue::OctetString(b"v1 agent".to_vec()),
    )];
    let (agent, port) = FakeAgent::spawn(object_logic(objects, true)).await;
    let manager = Manager::connect_v1(v1_manager_config(port, "public"))
        .await
        .unwrap();
    let response = manager.get(vec!["1.3.6.1.2.1.1.1.0"]).await.unwrap();
    assert_eq!(response.error_status, ErrorStatus::NoError);
    assert_eq!(
        response.varbinds[0].value,
        SnmpValue::OctetString(b"v1 agent".to_vec())
    );
    agent.stop();
}

#[tokio::test]
async fn v2c_get_next_roundtrip() {
    let objects = vec![
        (
            oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
            SnmpValue::OctetString(b"descr".to_vec()),
        ),
        (oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]), SnmpValue::TimeTicks(1)),
    ];
    let (agent, port) = FakeAgent::spawn(object_logic(objects, false)).await;
    let manager = Manager::connect_v2c(v2c_manager_config(port, "public"))
        .await
        .unwrap();
    let response = manager.get_next(vec!["1.3.6.1.2.1.1.1.0"]).await.unwrap();
    assert_eq!(response.varbinds[0].oid, oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]));
    assert_eq!(response.varbinds[0].value, SnmpValue::TimeTicks(1));
    agent.stop();
}

#[tokio::test]
async fn v2c_get_bulk_sends_max_repetitions_and_returns_rows() {
    // GETBULK from sysUpTime.0 lands on the only table object after it.
    let objects = vec![(oid(&[1, 3, 6, 1, 2, 1, 2, 1, 0]), SnmpValue::Integer(2))];
    let (agent, port) = FakeAgent::spawn(object_logic(objects, false)).await;
    let manager = Manager::connect_v2c(v2c_manager_config(port, "public"))
        .await
        .unwrap();
    let response = manager
        .get_bulk(vec!["1.3.6.1.2.1.1.3.0"], 0, 5)
        .await
        .unwrap();
    assert_eq!(response.error_status, ErrorStatus::NoError);
    assert_eq!(response.varbinds[0].value, SnmpValue::Integer(2));
    assert_eq!(agent.requested_max_repetitions(), vec![5]);
    assert_eq!(agent.requested_kinds(), vec![PduKind::GetBulkRequest]);
    agent.stop();
}

#[tokio::test]
async fn v1_get_bulk_treats_no_such_name_as_end_of_mib_walk() {
    // Port of test_v1_manager.py:388: the noSuchName agent walks four rows
    // then an EndOfMibView slot marks the exhausted column.
    let objects = vec![
        (
            oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]),
            SnmpValue::TimeTicks(12345),
        ),
        (
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1]),
            SnmpValue::OctetString(b"1".to_vec()),
        ),
        (
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 2]),
            SnmpValue::OctetString(b"2".to_vec()),
        ),
        (
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1]),
            SnmpValue::OctetString(b"eth0".to_vec()),
        ),
        (
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 2]),
            SnmpValue::OctetString(b"eth1".to_vec()),
        ),
    ];
    let (agent, port) = FakeAgent::spawn(object_logic(objects, true)).await;
    let manager = Manager::connect_v1(v1_manager_config(port, "public"))
        .await
        .unwrap();
    let response = manager
        .get_bulk(vec!["1.3.6.1.2.1.2.2"], 0, 10)
        .await
        .unwrap();
    assert_eq!(response.error_status, ErrorStatus::NoError);
    assert_eq!(response.error_index, 0);
    let slots: Vec<(String, bool)> = response
        .varbinds
        .iter()
        .map(|v| (v.oid.display(), v.value == SnmpValue::EndOfMibView))
        .collect();
    assert_eq!(
        slots,
        vec![
            ("1.3.6.1.2.1.2.2.1.1.1".to_string(), false),
            ("1.3.6.1.2.1.2.2.1.1.2".to_string(), false),
            ("1.3.6.1.2.1.2.2.1.2.1".to_string(), false),
            ("1.3.6.1.2.1.2.2.1.2.2".to_string(), false),
            ("1.3.6.1.2.1.2.2.1.2.2".to_string(), true),
        ]
    );
    assert_eq!(agent.request_count(), 5);
    // Every request went out as GETNEXT.
    assert!(
        agent
            .requested_kinds()
            .iter()
            .all(|kind| *kind == PduKind::GetNextRequest)
    );
    agent.stop();
}

#[tokio::test]
async fn v1_get_bulk_ends_columns_on_no_such_name() {
    let objects = vec![
        (
            oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
            SnmpValue::OctetString(b"a".to_vec()),
        ),
        (oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]), SnmpValue::TimeTicks(1)),
        (
            oid(&[1, 3, 6, 1, 2, 1, 1, 5, 0]),
            SnmpValue::OctetString(b"n".to_vec()),
        ),
    ];
    let (agent, port) = FakeAgent::spawn(object_logic(objects, true)).await;
    let manager = Manager::connect_v1(v1_manager_config(port, "public"))
        .await
        .unwrap();
    let response = manager
        .get_bulk(vec!["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.6.0"], 0, 10)
        .await
        .unwrap();
    assert_eq!(response.error_status, ErrorStatus::NoError);
    // The exhausted column contributes an EndOfMibView slot.
    assert!(
        response
            .varbinds
            .iter()
            .any(|v| v.value == SnmpValue::EndOfMibView)
    );
    agent.stop();
}

#[tokio::test]
async fn v1_get_bulk_non_repeaters() {
    // Port of test_v1_manager.py:437: a non_repeaters=1 split sends one
    // GETNEXT for the non-repeater column, then the repeater column.
    let objects = vec![
        (
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1]),
            SnmpValue::OctetString(b"eth0".to_vec()),
        ),
        (
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 2]),
            SnmpValue::OctetString(b"eth1".to_vec()),
        ),
        (
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1]),
            SnmpValue::OctetString(b"1".to_vec()),
        ),
        (
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 2]),
            SnmpValue::OctetString(b"2".to_vec()),
        ),
    ];
    let (agent, port) = FakeAgent::spawn(object_logic(objects, true)).await;
    let manager = Manager::connect_v1(v1_manager_config(port, "public"))
        .await
        .unwrap();
    let response = manager
        .get_bulk(vec!["1.3.6.1.2.1.2.2.1.2.1", "1.3.6.1.2.1.2.2.1.1.1"], 1, 2)
        .await
        .unwrap();
    assert_eq!(response.error_status, ErrorStatus::NoError);
    let oids: Vec<String> = response.varbinds.iter().map(|v| v.oid.display()).collect();
    assert_eq!(
        oids,
        vec![
            "1.3.6.1.2.1.2.2.1.2.2".to_string(), // single successor of ifDescr.1
            "1.3.6.1.2.1.2.2.1.1.2".to_string(), // successor of ifIndex.1
            "1.3.6.1.2.1.2.2.1.2.1".to_string(), // successor of ifIndex.2
        ]
    );
    assert_eq!(agent.request_count(), 3);
    agent.stop();
}

#[tokio::test]
async fn v1_get_bulk_error_response_carries_status_and_collected() {
    let script = vec![(
        oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]),
        vec![vb(&[1, 3, 6, 1, 2, 1, 1, 3, 0], SnmpValue::TimeTicks(1))],
    )];
    let errors = std::collections::HashMap::from([(oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]), (5, 1))]);
    let (agent, port) =
        FakeAgent::spawn(scripted_logic(script.into_iter().collect(), errors, false)).await;
    let manager = Manager::connect_v1(v1_manager_config(port, "public"))
        .await
        .unwrap();
    let response = manager
        .get_bulk(vec!["1.3.6.1.2.1.1.3.0"], 0, 5)
        .await
        .unwrap();
    assert_eq!(response.error_status, ErrorStatus::GenErr);
    assert_eq!(response.error_index, 1);
    agent.stop();
}

#[tokio::test]
async fn get_rejects_symbolic_target_without_bundle() {
    let (agent, port) = FakeAgent::spawn(scripted_logic(
        Default::default(),
        Default::default(),
        false,
    ))
    .await;
    let manager = Manager::connect_v2c(v2c_manager_config(port, "public"))
        .await
        .unwrap();
    let err = manager.get(vec!["IF-MIB::ifDescr.1"]).await.unwrap_err();
    assert!(err.to_string().contains("requires a loaded bundle"));
    agent.stop();
}

#[tokio::test]
async fn get_rejects_unrecognized_target() {
    let (agent, port) = FakeAgent::spawn(scripted_logic(
        Default::default(),
        Default::default(),
        false,
    ))
    .await;
    let manager = Manager::connect_v2c(v2c_manager_config(port, "public"))
        .await
        .unwrap();
    let err = manager.get(vec!["not-an-oid"]).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("Unrecognized target format: not-an-oid")
    );
    agent.stop();
}

#[tokio::test]
async fn get_rejects_empty_targets() {
    let (agent, port) = FakeAgent::spawn(scripted_logic(
        Default::default(),
        Default::default(),
        false,
    ))
    .await;
    let manager = Manager::connect_v2c(v2c_manager_config(port, "public"))
        .await
        .unwrap();
    let err = manager.get(Vec::<&str>::new()).await.unwrap_err();
    assert!(err.to_string().contains("At least one target is required"));
    agent.stop();
}

#[tokio::test]
async fn v2c_manager_wrong_community_times_out() {
    let (agent, port) = FakeAgent::spawn(scripted_logic(
        Default::default(),
        Default::default(),
        false,
    ))
    .await;
    let manager = Manager::connect_v2c(v2c_manager_config(port, "wrong"))
        .await
        .unwrap();
    let err = manager.get(vec!["1.3.6.1.2.1.1.3.0"]).await.unwrap_err();
    assert!(matches!(err, Error::Timeout { attempts: 1 }), "got {err:?}");
    agent.stop();
}

#[tokio::test]
async fn manager_walk_uses_getnext_for_v1() {
    let objects = vec![
        (
            oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
            SnmpValue::OctetString(b"a".to_vec()),
        ),
        (oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]), SnmpValue::TimeTicks(1)),
    ];
    let (agent, port) = FakeAgent::spawn(object_logic(objects, true)).await;
    let manager = Manager::connect_v1(v1_manager_config(port, "public"))
        .await
        .unwrap();
    let results = manager
        .walk(
            "1.3.6.1.2.1.1",
            trishul_snmp::manager::walk::WalkOptions::default(),
        )
        .await
        .unwrap();
    assert!(!results.is_empty());
    assert!(
        agent
            .requested_kinds()
            .iter()
            .all(|kind| *kind == PduKind::GetNextRequest)
    );
    agent.stop();
}

#[tokio::test]
async fn bulkwalk_uses_getbulk_with_max_repetitions() {
    let objects = vec![
        (
            oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
            SnmpValue::OctetString(b"a".to_vec()),
        ),
        (oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]), SnmpValue::TimeTicks(1)),
    ];
    let (agent, port) = FakeAgent::spawn(object_logic(objects, false)).await;
    let manager = Manager::connect_v2c(v2c_manager_config(port, "public"))
        .await
        .unwrap();
    let results = manager
        .walk(
            "1.3.6.1.2.1.1",
            trishul_snmp::manager::walk::WalkOptions {
                bulk: true,
                max_repetitions: 7,
            },
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 2);
    assert!(
        agent
            .requested_kinds()
            .iter()
            .all(|kind| *kind == PduKind::GetBulkRequest)
    );
    assert!(agent.requested_max_repetitions().iter().all(|n| *n == 7));
    agent.stop();
}

#[test]
fn response_error_status_rejects_unknown_values() {
    let err = trishul_snmp::codec::pdu::response_error_status(999).unwrap_err();
    assert!(
        err.to_string()
            .contains("Unsupported SNMP error-status value 999")
    );
}

#[test]
fn hex_helper_is_available() {
    assert_eq!(hex("020105"), vec![0x02, 0x01, 0x05]);
}
