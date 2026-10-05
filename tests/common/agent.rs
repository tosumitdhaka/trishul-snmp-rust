//! Loopback UDP fake agents that decode requests and script responses.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use tokio::net::UdpSocket;

use trishul_snmp::codec::message::{SnmpMessage, decode_message, encode_message};
use trishul_snmp::codec::pdu::{Pdu, PduKind};
use trishul_snmp::types::oid::Oid;
use trishul_snmp::types::value::SnmpValue;
use trishul_snmp::types::varbind::VarBind;

use super::{oid, vb};

/// The reply an agent script produces for one request.
#[derive(Clone, Debug, Default)]
pub struct AgentReply {
    /// Response varbinds (the first varbind's OID answers the request).
    pub varbinds: Vec<VarBind>,
    /// Raw error-status for the response.
    pub error_status: i32,
    /// Raw error-index for the response.
    pub error_index: i32,
}

impl AgentReply {
    /// A clean response carrying the given varbinds.
    #[must_use]
    pub fn ok(varbinds: Vec<VarBind>) -> Self {
        Self {
            varbinds,
            error_status: 0,
            error_index: 0,
        }
    }

    /// A single endOfMibView varbind at the requested OID (normal walk end).
    #[must_use]
    pub fn eomv(requested: &Oid) -> Self {
        Self::ok(vec![vb(requested.arcs(), SnmpValue::EndOfMibView)])
    }

    /// An error response.
    #[must_use]
    pub fn error(status: i32, index: i32) -> Self {
        Self {
            varbinds: Vec::new(),
            error_status: status,
            error_index: index,
        }
    }
}

/// Response logic: given the requested (first-varbind) OID and PDU kind,
/// produce the reply.
pub type AgentLogic = Box<dyn Fn(&Oid, PduKind) -> AgentReply + Send + Sync>;

/// A loopback UDP fake agent.
///
/// Decodes inbound messages, records what was requested, computes a reply via
/// the injected logic, and echoes back the request's version/community/
/// request-id. Use [`FakeAgent::stop`] or drop the handle to end it.
pub struct FakeAgent {
    socket: Arc<UdpSocket>,
    logic: AgentLogic,
    requested_oids: Mutex<Vec<Oid>>,
    requested_kinds: Mutex<Vec<PduKind>>,
    requested_max_repetitions: Mutex<Vec<i32>>,
    received: Mutex<Vec<Vec<u8>>>,
    shutdown: tokio::sync::watch::Sender<bool>,
    port: u16,
}

impl FakeAgent {
    /// Spawns an agent on an ephemeral loopback port. Returns the agent and
    /// the port to point clients at.
    pub async fn spawn(logic: AgentLogic) -> (Arc<FakeAgent>, u16) {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind loopback"));
        let port = socket.local_addr().expect("bound").port();
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let agent = Arc::new(FakeAgent {
            socket: Arc::clone(&socket),
            logic,
            requested_oids: Mutex::new(Vec::new()),
            requested_kinds: Mutex::new(Vec::new()),
            requested_max_repetitions: Mutex::new(Vec::new()),
            received: Mutex::new(Vec::new()),
            shutdown: shutdown_tx,
            port,
        });
        let task_agent = Arc::clone(&agent);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                tokio::select! {
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    recv = task_agent.socket.recv_from(&mut buf) => {
                        let (n, peer) = match recv {
                            Ok(result) => result,
                            Err(_) => break,
                        };
                        let data = buf[..n].to_vec();
                        task_agent.record_received(data.clone());
                        if let Ok(message) = decode_message(&data) {
                            let requested = message
                                .pdu
                                .varbinds
                                .first()
                                .map(|v| v.oid.clone())
                                .unwrap_or_else(|| oid(&[0, 0]));
                            task_agent.record_request(&requested, message.pdu.kind, message.pdu.error_index);
                            let reply = (task_agent.logic)(&requested, message.pdu.kind);
                            // A real agent answers with its own (fixed) community;
                            // only the version and request id are echoed.
                            let response = SnmpMessage {
                                version: message.version,
                                community: b"public".to_vec(),
                                pdu: Pdu {
                                    kind: PduKind::Response,
                                    request_id: message.pdu.request_id,
                                    error_status: reply.error_status,
                                    error_index: reply.error_index,
                                    varbinds: reply.varbinds,
                                    v1_trap: None,
                                },
                            };
                            if let Ok(bytes) = encode_message(&response) {
                                let _ = task_agent.socket.send_to(&bytes, peer).await;
                            }
                        }
                    }
                }
            }
        });
        (agent, port)
    }

    fn record_received(&self, data: Vec<u8>) {
        self.received.lock().unwrap().push(data);
    }

    fn record_request(&self, requested: &Oid, kind: PduKind, max_repetitions: i32) {
        self.requested_oids.lock().unwrap().push(requested.clone());
        self.requested_kinds.lock().unwrap().push(kind);
        self.requested_max_repetitions
            .lock()
            .unwrap()
            .push(max_repetitions);
    }

    /// Stops the agent task.
    pub fn stop(&self) {
        let _ = self.shutdown.send(true);
    }

    /// The bound port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Every OID carried by the first varbind of each decoded request.
    #[must_use]
    pub fn requested_oids(&self) -> Vec<Oid> {
        self.requested_oids.lock().unwrap().clone()
    }

    /// The PDU kind of each decoded request.
    #[must_use]
    pub fn requested_kinds(&self) -> Vec<PduKind> {
        self.requested_kinds.lock().unwrap().clone()
    }

    /// The raw error-index (GETBULK max-repetitions) of each decoded request.
    #[must_use]
    pub fn requested_max_repetitions(&self) -> Vec<i32> {
        self.requested_max_repetitions.lock().unwrap().clone()
    }

    /// Every raw datagram received.
    #[must_use]
    pub fn received(&self) -> Vec<Vec<u8>> {
        self.received.lock().unwrap().clone()
    }

    /// The number of decoded requests.
    #[must_use]
    pub fn request_count(&self) -> usize {
        self.requested_oids.lock().unwrap().len()
    }
}

/// Polls until the agent has recorded at least `count` datagrams or the
/// deadline passes (used after fire-and-forget sends).
pub async fn wait_for_datagrams(agent: &FakeAgent, count: usize) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    while agent.received().len() < count && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// Scripted logic: a per-OID response map plus optional error responses and an
/// echo-request mode (← test_walk_quirks.py:QuirkAgent).
pub fn scripted_logic(
    script: HashMap<Oid, Vec<VarBind>>,
    error_script: HashMap<Oid, (i32, i32)>,
    echo_requests: bool,
) -> AgentLogic {
    Box::new(move |requested, _kind| {
        if echo_requests {
            return AgentReply::ok(vec![vb(requested.arcs(), SnmpValue::Null)]);
        }
        if let Some((status, index)) = error_script.get(requested) {
            return AgentReply::error(*status, *index);
        }
        match script.get(requested) {
            Some(varbinds) => AgentReply::ok(varbinds.clone()),
            None => AgentReply::eomv(requested),
        }
    })
}

/// In-memory object-table logic: GET looks up exactly, GETNEXT returns the
/// next OID in table order, and past the end either answers endOfMibView or
/// (v1) noSuchName.
pub fn object_logic(mut objects: Vec<(Oid, SnmpValue)>, v1_no_such_name: bool) -> AgentLogic {
    // A real agent's object table is OID-ordered; the linear successor lookup
    // below relies on it (matching the reference's ordered `_objects`).
    objects.sort_by(|a, b| a.0.cmp(&b.0));
    Box::new(move |requested, kind| match kind {
        PduKind::GetRequest => match objects.iter().find(|(oid, _)| oid == requested) {
            Some((_, value)) => AgentReply::ok(vec![vb(requested.arcs(), value.clone())]),
            None => {
                if v1_no_such_name {
                    AgentReply::error(2, 1)
                } else {
                    AgentReply::eomv(requested)
                }
            }
        },
        PduKind::GetNextRequest => match objects.iter().find(|(oid, _)| oid > requested) {
            Some((next_oid, value)) => AgentReply::ok(vec![vb(next_oid.arcs(), value.clone())]),
            None => {
                if v1_no_such_name {
                    AgentReply::error(2, 1)
                } else {
                    AgentReply::eomv(requested)
                }
            }
        },
        PduKind::GetBulkRequest => match objects.iter().find(|(oid, _)| oid > requested) {
            Some((next_oid, value)) => AgentReply::ok(vec![vb(next_oid.arcs(), value.clone())]),
            None => AgentReply::eomv(requested),
        },
        _ => AgentReply::eomv(requested),
    })
}

/// An agent that never answers (drops inbound datagrams).
pub async fn silent_agent() -> (Arc<FakeAgent>, u16) {
    // A logic that produces a reply is still required by the harness; instead
    // of a reply we use a dedicated socket that absorbs datagrams.
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind loopback"));
    let port = socket.local_addr().expect("bound").port();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let agent = Arc::new(FakeAgent {
        socket: Arc::clone(&socket),
        logic: Box::new(|_, _| AgentReply::default()),
        requested_oids: Mutex::new(Vec::new()),
        requested_kinds: Mutex::new(Vec::new()),
        requested_max_repetitions: Mutex::new(Vec::new()),
        received: Mutex::new(Vec::new()),
        shutdown: shutdown_tx,
        port,
    });
    let task_agent = Arc::clone(&agent);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                recv = task_agent.socket.recv_from(&mut buf) => {
                    let Ok((n, _peer)) = recv else { break };
                    task_agent.record_received(buf[..n].to_vec());
                }
            }
        }
    });
    (agent, port)
}
