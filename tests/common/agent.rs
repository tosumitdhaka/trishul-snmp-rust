//! Loopback UDP fake agents that decode requests and script responses.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use tokio::net::UdpSocket;

use trishul_snmp::codec::message::{SnmpMessage, decode_message, encode_message};
use trishul_snmp::codec::pdu::{Pdu, PduKind};
use trishul_snmp::codec::v3::{
    UsmSecurityParameters, decode_v3_message, encode_scoped_pdu, encode_v3_message,
};
use trishul_snmp::error::UnwrapOutcome;
use trishul_snmp::security::usm::UsmModel;
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
pub type AgentLogic = Arc<dyn Fn(&Oid, PduKind) -> AgentReply + Send + Sync>;

/// v3-side agent identity: the reply UsmModel (peer = the agent's own engine)
/// plus the authoritative engine parameters used for discovery REPORTs.
pub struct AgentUsm {
    /// The reply model; its peer state is the agent's own engine.
    pub model: Arc<UsmModel>,
    /// Authoritative engine id.
    pub engine_id: Vec<u8>,
    /// Authoritative engine boots.
    pub engine_boots: u32,
    /// Authoritative engine time.
    pub engine_time: u32,
}

/// A loopback UDP fake agent.
///
/// Decodes inbound messages, records what was requested, computes a reply via
/// the injected logic, and echoes back the request's version/community/
/// request-id. Teardown is automatic: dropping the last [`FakeAgent`] handle
/// signals the pump task to exit (also on test panics). Use [`FakeAgent::stop`]
/// for mid-test teardown.
pub struct FakeAgent {
    socket: Arc<UdpSocket>,
    logic: AgentLogic,
    requested_oids: Arc<Mutex<Vec<Oid>>>,
    requested_kinds: Arc<Mutex<Vec<PduKind>>>,
    requested_max_repetitions: Arc<Mutex<Vec<i32>>>,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    shutdown: tokio::sync::watch::Sender<bool>,
    port: u16,
}

impl FakeAgent {
    /// Spawns an agent on an ephemeral loopback port. Returns the agent and
    /// the port to point clients at.
    pub async fn spawn(logic: AgentLogic) -> (Arc<FakeAgent>, u16) {
        Self::spawn_with(logic, None).await
    }

    /// Spawns a v3-capable agent: answers RFC 3414 discovery probes with a
    /// noAuth REPORT carrying `usm`'s authoritative engine parameters, verifies
    /// inbound auth via `usm.model`, and replies with model-wrapped RESPONSEs.
    pub async fn spawn_v3(logic: AgentLogic, usm: AgentUsm) -> (Arc<FakeAgent>, u16) {
        Self::spawn_with(logic, Some(usm)).await
    }

    /// The shared spawn path.
    async fn spawn_with(logic: AgentLogic, usm: Option<AgentUsm>) -> (Arc<FakeAgent>, u16) {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind loopback"));
        let port = socket.local_addr().expect("bound").port();
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let requested_oids = Arc::new(Mutex::new(Vec::new()));
        let requested_kinds = Arc::new(Mutex::new(Vec::new()));
        let requested_max_repetitions = Arc::new(Mutex::new(Vec::new()));
        let received = Arc::new(Mutex::new(Vec::new()));
        let agent = Arc::new(FakeAgent {
            socket: Arc::clone(&socket),
            logic: Arc::clone(&logic),
            requested_oids: Arc::clone(&requested_oids),
            requested_kinds: Arc::clone(&requested_kinds),
            requested_max_repetitions: Arc::clone(&requested_max_repetitions),
            received: Arc::clone(&received),
            shutdown: shutdown_tx,
            port,
        });
        let task_socket = Arc::clone(&socket);
        let task_logic = logic;
        let task_usm: Option<AgentUsm> = usm;
        let task_oids = Arc::clone(&requested_oids);
        let task_kinds = Arc::clone(&requested_kinds);
        let task_max_rep = Arc::clone(&requested_max_repetitions);
        let task_received = Arc::clone(&received);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                tokio::select! {
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    recv = task_socket.recv_from(&mut buf) => {
                        let (n, peer) = match recv {
                            Ok(result) => result,
                            Err(_) => break,
                        };
                        let data = buf[..n].to_vec();
                        task_received.lock().unwrap().push(data.clone());
                        if let Ok(message) = decode_message(&data) {
                            let requested = message
                                .pdu
                                .varbinds
                                .first()
                                .map(|v| v.oid.clone())
                                .unwrap_or_else(|| oid(&[0, 0]));
                            task_oids.lock().unwrap().push(requested.clone());
                            task_kinds.lock().unwrap().push(message.pdu.kind);
                            task_max_rep.lock().unwrap().push(message.pdu.error_index);
                            let reply = (task_logic)(&requested, message.pdu.kind);
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
                                let _ = task_socket.send_to(&bytes, peer).await;
                            }
                        } else if let Some(agent_usm) = &task_usm {
                            handle_v3_datagram(
                                &data,
                                agent_usm,
                                &task_logic,
                                &AgentRecords {
                                    oids: &task_oids,
                                    kinds: &task_kinds,
                                    max_repetitions: &task_max_rep,
                                },
                                &task_socket,
                                peer,
                            )
                            .await;
                        }
                    }
                }
            }
        });
        (agent, port)
    }

    /// Spawns a plain agent that answers every request with an endOfMibView
    /// response (for tests that only need a listening socket).
    pub async fn spawn_plain() -> (Arc<FakeAgent>, u16) {
        Self::spawn(scripted_logic(
            Default::default(),
            Default::default(),
            false,
        ))
        .await
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

impl Drop for FakeAgent {
    fn drop(&mut self) {
        // Signals the pump task to exit so a dropped (or panicked) test handle
        // cannot leave an agent task running.
        let _ = self.shutdown.send(true);
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
    Arc::new(move |requested, _kind| {
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
    Arc::new(move |requested, kind| match kind {
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
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind loopback"));
    let port = socket.local_addr().expect("bound").port();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let received = Arc::new(Mutex::new(Vec::new()));
    let agent = Arc::new(FakeAgent {
        socket: Arc::clone(&socket),
        logic: Arc::new(|_, _| AgentReply::default()),
        requested_oids: Arc::new(Mutex::new(Vec::new())),
        requested_kinds: Arc::new(Mutex::new(Vec::new())),
        requested_max_repetitions: Arc::new(Mutex::new(Vec::new())),
        received: Arc::clone(&received),
        shutdown: shutdown_tx,
        port,
    });
    let task_socket = Arc::clone(&socket);
    let task_received = Arc::clone(&received);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                recv = task_socket.recv_from(&mut buf) => {
                    let Ok((n, _peer)) = recv else { break };
                    task_received.lock().unwrap().push(buf[..n].to_vec());
                }
            }
        }
    });
    (agent, port)
}

/// Shared record buffers for the v3 reply path.
struct AgentRecords<'a> {
    oids: &'a Arc<Mutex<Vec<Oid>>>,
    kinds: &'a Arc<Mutex<Vec<PduKind>>>,
    max_repetitions: &'a Arc<Mutex<Vec<i32>>>,
}

/// Handles one v3 datagram: discovery probes get a noAuth REPORT; authed
/// requests are verified and answered with a model-wrapped RESPONSE.
async fn handle_v3_datagram(
    data: &[u8],
    agent_usm: &AgentUsm,
    logic: &AgentLogic,
    records: &AgentRecords<'_>,
    socket: &Arc<UdpSocket>,
    peer: std::net::SocketAddr,
) {
    let view = match decode_v3_message(data) {
        Ok(view) => view,
        Err(_) => return,
    };
    if view.usm_params.engine_id.is_empty() {
        // RFC 3414 discovery probe: reply with a noAuth REPORT carrying our
        // authoritative engine parameters.
        let report = discovery_report(view.msg_id, agent_usm);
        if let Ok(bytes) = report {
            let _ = socket.send_to(&bytes, peer).await;
        }
        return;
    }
    if let UnwrapOutcome::Ok(pdu) = agent_usm.model.unwrap_message(data) {
        let requested = pdu
            .varbinds
            .first()
            .map(|v| v.oid.clone())
            .unwrap_or_else(|| oid(&[0, 0]));
        records.oids.lock().unwrap().push(requested.clone());
        records.kinds.lock().unwrap().push(pdu.kind);
        records
            .max_repetitions
            .lock()
            .unwrap()
            .push(pdu.error_index);
        let reply = (logic)(&requested, pdu.kind);
        let response = Pdu {
            kind: PduKind::Response,
            request_id: pdu.request_id,
            error_status: reply.error_status,
            error_index: reply.error_index,
            varbinds: reply.varbinds,
            v1_trap: None,
        };
        if let Ok(bytes) = agent_usm.model.wrap_pdu(&response) {
            let _ = socket.send_to(&bytes, peer).await;
        }
    }
}

/// Builds a noAuth discovery REPORT carrying the agent's engine parameters.
fn discovery_report(msg_id: i64, agent_usm: &AgentUsm) -> Result<Vec<u8>, String> {
    let report = Pdu {
        kind: PduKind::Report,
        request_id: 1,
        error_status: 0,
        error_index: 0,
        varbinds: vec![vb(
            &[1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0],
            SnmpValue::Counter32(1),
        )],
        v1_trap: None,
    };
    let scoped =
        encode_scoped_pdu(&agent_usm.engine_id, b"", &report).map_err(|e| e.to_string())?;
    let usm = UsmSecurityParameters {
        engine_id: agent_usm.engine_id.clone(),
        engine_boots: i64::from(agent_usm.engine_boots),
        engine_time: i64::from(agent_usm.engine_time),
        username: Vec::new(),
        auth_params: Vec::new(),
        priv_params: Vec::new(),
    };
    encode_v3_message(msg_id, 65507, 0, &usm, &scoped).map_err(|e| e.to_string())
}

/// Builds a noAuth `usmStatsNotInTimeWindows` REPORT datagram — the
/// engine-recovery test helper (← test_engine_recovery.py:_build_report_bytes).
pub fn build_recovery_report(
    engine_id: &[u8],
    engine_boots: u32,
    engine_time: u32,
    username: &[u8],
) -> Vec<u8> {
    let report = Pdu {
        kind: PduKind::Report,
        request_id: 1,
        error_status: 0,
        error_index: 0,
        varbinds: vec![vb(
            &[1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0],
            SnmpValue::Counter32(1),
        )],
        v1_trap: None,
    };
    let scoped = encode_scoped_pdu(engine_id, b"", &report).expect("scoped pdu encodes");
    let usm = UsmSecurityParameters {
        engine_id: engine_id.to_vec(),
        engine_boots: i64::from(engine_boots),
        engine_time: i64::from(engine_time),
        username: username.to_vec(),
        auth_params: Vec::new(),
        priv_params: Vec::new(),
    };
    encode_v3_message(1, 65507, 0, &usm, &scoped).expect("report encodes")
}

/// Builds an agent-side UsmModel with its own engine adopted as peer state —
/// the model used to wrap RESPONSEs and verify inbound auth
/// (engine-recovery / v3 client tests).
pub fn usm_agent_model(
    user: trishul_snmp::security::usm::UsmUser,
    engine_id: Vec<u8>,
    engine_boots: u32,
    engine_time: u32,
) -> UsmModel {
    use std::sync::Arc;
    use trishul_snmp::time::SystemClock;
    let model = UsmModel::new(user, Vec::new(), None, Arc::new(SystemClock));
    model.adopt_engine_state(engine_id, engine_boots, engine_time);
    model
}
