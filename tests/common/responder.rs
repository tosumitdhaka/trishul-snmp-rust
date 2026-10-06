//! Shared responder harness: spawn/config builders, request datagram builders,
//! and a request/reply exchange helper.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;

use trishul_snmp::codec::message::{SnmpMessage, SnmpVersion, encode_message};
use trishul_snmp::codec::pdu::{Pdu, PduKind};
use trishul_snmp::responder::{ObjectInput, ObjectValue, ResponderConfig, SnmpResponder};
use trishul_snmp::security::usm::kdf::{AuthProtocol, PrivProtocol};
use trishul_snmp::security::usm::{AuthKey, PrivKey, UsmLocalEngine, UsmUser};
use trishul_snmp::target::Target;
use trishul_snmp::types::oid::Oid;
use trishul_snmp::types::value::SnmpValue;
use trishul_snmp::types::varbind::VarBind;

use super::oid;

/// The engine identity the v3 loopback tests share on both sides.
pub const ENGINE_ID: [u8; 11] = [
    0x80, 0x00, 0x1f, 0x88, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Binds a responder on an ephemeral loopback port; returns it and the port.
pub async fn spawn(config: ResponderConfig) -> (Arc<SnmpResponder>, u16) {
    let responder = Arc::new(
        SnmpResponder::bind(config)
            .await
            .expect("bind loopback responder"),
    );
    let port = responder.local_addr().port();
    (responder, port)
}

/// The standard loopback config: ephemeral port, optional community
/// allow-list, optional object seeds.
pub fn config(communities: Option<&[&str]>, objects: Vec<ObjectInput>) -> ResponderConfig {
    ResponderConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        communities: communities.map(|list| list.iter().map(|s| s.as_bytes().to_vec()).collect()),
        objects,
        ..Default::default()
    }
}

/// A static object seed.
pub fn object(arcs: &[u32], value: SnmpValue) -> ObjectInput {
    (Target::from(arcs), ObjectValue::Static(value))
}

/// A rule object seed.
pub fn rule_object(
    arcs: &[u32],
    rule: impl trishul_snmp::responder::SimulationRule + 'static,
) -> ObjectInput {
    (Target::from(arcs), ObjectValue::Rule(Box::new(rule)))
}

/// A v3-auth user (authNoPriv).
pub fn v3_auth_user(username: &str) -> UsmUser {
    UsmUser::new(
        username.to_string(),
        AuthProtocol::Sha256,
        AuthKey::Passphrase(b"authpassword12345".to_vec()),
        PrivProtocol::None_,
        PrivKey::Passphrase(Vec::new()),
    )
    .expect("valid v3 user")
}

/// A v3-auth+priv user (authPriv).
pub fn v3_priv_user(username: &str) -> UsmUser {
    UsmUser::new(
        username.to_string(),
        AuthProtocol::Sha256,
        AuthKey::Passphrase(b"authpassword12345".to_vec()),
        PrivProtocol::Aes128,
        PrivKey::Passphrase(b"privpassword12345".to_vec()),
    )
    .expect("valid v3 user")
}

/// The responder's authoritative local engine for the v3 tests.
pub fn local_engine(engine_time: u32) -> UsmLocalEngine {
    UsmLocalEngine {
        engine_id: ENGINE_ID.to_vec(),
        engine_boots: 1,
        engine_time,
    }
}

/// A GET request PDU.
pub fn get_pdu(request_id: u32, arcs: &[u32]) -> Pdu {
    request_pdu(
        PduKind::GetRequest,
        request_id,
        0,
        0,
        vec![VarBind::new(oid(arcs), SnmpValue::Null)],
    )
}

/// A GETNEXT request PDU.
pub fn get_next_pdu(request_id: u32, arcs: &[u32]) -> Pdu {
    request_pdu(
        PduKind::GetNextRequest,
        request_id,
        0,
        0,
        vec![VarBind::new(oid(arcs), SnmpValue::Null)],
    )
}

/// A GETBULK request PDU (`error_status`/`error_index` double as
/// non-repeaters/max-repetitions).
pub fn get_bulk_pdu(
    request_id: u32,
    non_repeaters: i32,
    max_repetitions: i32,
    arcs: &[u32],
) -> Pdu {
    request_pdu(
        PduKind::GetBulkRequest,
        request_id,
        non_repeaters,
        max_repetitions,
        vec![VarBind::new(oid(arcs), SnmpValue::Null)],
    )
}

/// A multi-varbind GETBULK request PDU.
pub fn get_bulk_pdu_multi(
    request_id: u32,
    non_repeaters: i32,
    max_repetitions: i32,
    arcs: &[&[u32]],
) -> Pdu {
    request_pdu(
        PduKind::GetBulkRequest,
        request_id,
        non_repeaters,
        max_repetitions,
        arcs.iter()
            .map(|arcs| VarBind::new(oid(arcs), SnmpValue::Null))
            .collect(),
    )
}

/// A SET request PDU carrying one varbind with `value`.
pub fn set_pdu(request_id: u32, arcs: &[u32], value: SnmpValue) -> Pdu {
    request_pdu(
        PduKind::SetRequest,
        request_id,
        0,
        0,
        vec![VarBind::new(oid(arcs), value)],
    )
}

fn request_pdu(
    kind: PduKind,
    request_id: u32,
    error_status: i32,
    error_index: i32,
    varbinds: Vec<VarBind>,
) -> Pdu {
    Pdu {
        kind,
        request_id,
        error_status,
        error_index,
        varbinds,
        v1_trap: None,
    }
}

/// Encodes a v1/v2c request message.
pub fn message(version: SnmpVersion, community: &str, pdu: Pdu) -> Vec<u8> {
    encode_message(&SnmpMessage {
        version,
        community: community.as_bytes().to_vec(),
        pdu,
    })
    .expect("request message encodes")
}

/// Sends `data` to the responder and waits for one reply (timeout → `None`).
pub async fn exchange(responder: &SnmpResponder, data: &[u8]) -> Option<Vec<u8>> {
    exchange_from(responder.local_addr(), data).await
}

/// Sends `data` to `addr` and waits for one reply (timeout → `None`).
pub async fn exchange_from(addr: SocketAddr, data: &[u8]) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind loopback client");
    socket.send_to(data, addr).await.expect("send request");
    let mut buf = vec![0u8; 65535];
    match tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await {
        Ok(Ok((n, _peer))) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

/// A numeric OID literal.
pub fn oid_arcs(arcs: &[u32]) -> Oid {
    oid(arcs)
}
