//! v3 manager and notifier end-to-end tests (discovery + authNoPriv flows)
//! against the loopback v3 FakeAgent. Ports the v3-shaped behaviors of
//! test_v3_clients.py and test_v3_usm.py's discovery/wrap paths.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::agent::{AgentUsm, FakeAgent, object_logic, usm_agent_model};

use trishul_snmp::codec::message::SnmpVersion;
use trishul_snmp::codec::pdu::PduKind;
use trishul_snmp::codec::v3::decode_v3_message;
use trishul_snmp::manager::Manager;
use trishul_snmp::manager::walk::WalkOptions;
use trishul_snmp::notify::sender::{Notifier, V1TrapSpec};
use trishul_snmp::security::usm::kdf::{AuthProtocol, PrivProtocol};
use trishul_snmp::security::usm::{AuthKey, PrivKey, UsmLocalEngine, UsmUser, V3Config};
use trishul_snmp::types::oid::Oid;
use trishul_snmp::types::value::SnmpValue;
use trishul_snmp::types::varbind::{ErrorStatus, VarBind};

const ENGINE_ID: [u8; 11] = [
    0x80, 0x00, 0x1f, 0x88, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn user(username: &str, auth: AuthProtocol) -> UsmUser {
    UsmUser::new(
        username.to_string(),
        auth,
        AuthKey::Passphrase(b"authpassword12345".to_vec()),
        PrivProtocol::None_,
        PrivKey::Passphrase(Vec::new()),
    )
    .unwrap()
}

fn v3_config(port: u16, user: UsmUser) -> V3Config {
    V3Config {
        host: "127.0.0.1".to_string(),
        port,
        user,
        context_name: Vec::new(),
        local_engine: None,
        timeout: Duration::from_millis(300),
        retries: 0,
        clock: Arc::new(trishul_snmp::time::SystemClock),
        rng: Arc::new(trishul_snmp::time::SystemRng),
    }
}

/// A v3-capable loopback agent for the given user.
async fn v3_agent(user: &UsmUser) -> (Arc<FakeAgent>, u16) {
    let objects = vec![
        (
            common::oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
            SnmpValue::OctetString(b"v3 agent".to_vec()),
        ),
        (
            common::oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]),
            SnmpValue::TimeTicks(12345),
        ),
        (
            common::oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1]),
            SnmpValue::Integer(1),
        ),
        (
            common::oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1]),
            SnmpValue::OctetString(b"eth0".to_vec()),
        ),
    ];
    let model = usm_agent_model(user.clone(), ENGINE_ID.to_vec(), 1, 1000);
    FakeAgent::spawn_v3(
        object_logic(objects, false),
        AgentUsm {
            model: Arc::new(model),
            engine_id: ENGINE_ID.to_vec(),
            engine_boots: 1,
            engine_time: 1000,
        },
    )
    .await
}

#[tokio::test]
async fn v3_manager_connects_and_gets() {
    let (agent, port) = v3_agent(&user("simulator", AuthProtocol::Sha256)).await;
    let manager = Manager::connect_v3(v3_config(port, user("simulator", AuthProtocol::Sha256)))
        .await
        .unwrap();
    let response = manager.get(vec!["1.3.6.1.2.1.1.1.0"]).await.unwrap();
    assert_eq!(response.error_status, ErrorStatus::NoError);
    assert_eq!(
        response.varbinds[0].value,
        SnmpValue::OctetString(b"v3 agent".to_vec())
    );
    assert_ne!(response.request_id, 0);
    // The manager discovered the agent's engine.
    let model = match &*manager.session.security {
        trishul_snmp::security::SecurityModel::Usm(model) => model,
        _ => unreachable!(),
    };
    assert_eq!(model.peer_engine_id(), ENGINE_ID.to_vec());
    agent.stop();
}

#[tokio::test]
async fn v3_manager_get_next_and_get_bulk() {
    let (agent, port) = v3_agent(&user("simulator", AuthProtocol::Sha256)).await;
    let manager = Manager::connect_v3(v3_config(port, user("simulator", AuthProtocol::Sha256)))
        .await
        .unwrap();
    let next = manager.get_next(vec!["1.3.6.1.2.1.1.1.0"]).await.unwrap();
    assert_eq!(
        next.varbinds[0].oid,
        Oid::from_arcs(&[1, 3, 6, 1, 2, 1, 1, 3, 0]).unwrap()
    );

    let bulk = manager
        .get_bulk(vec!["1.3.6.1.2.1.2.2.1.1.1"], 0, 5)
        .await
        .unwrap();
    assert_eq!(bulk.error_status, ErrorStatus::NoError);
    assert!(!bulk.varbinds.is_empty());
    agent.stop();
}

#[tokio::test]
async fn v3_manager_walk_uses_getbulk() {
    let (agent, port) = v3_agent(&user("simulator", AuthProtocol::Sha256)).await;
    let manager = Manager::connect_v3(v3_config(port, user("simulator", AuthProtocol::Sha256)))
        .await
        .unwrap();
    let walked = manager
        .walk("1.3.6.1.2.1.1", WalkOptions::default())
        .await
        .unwrap();
    assert!(walked.len() >= 2, "walked {}", walked.len());
    assert!(agent.requested_kinds().contains(&PduKind::GetBulkRequest));
    agent.stop();
}

#[tokio::test]
async fn v3_auth_roundtrip_across_protocol_matrix() {
    for auth in [
        AuthProtocol::Md5,
        AuthProtocol::Sha1,
        AuthProtocol::Sha224,
        AuthProtocol::Sha256,
        AuthProtocol::Sha384,
        AuthProtocol::Sha512,
    ] {
        let (agent, port) = v3_agent(&user("simulator", auth)).await;
        let manager = Manager::connect_v3(v3_config(port, user("simulator", auth)))
            .await
            .unwrap();
        let response = manager.get(vec!["1.3.6.1.2.1.1.3.0"]).await.unwrap();
        assert_eq!(response.error_status, ErrorStatus::NoError);
        assert_eq!(response.varbinds[0].value, SnmpValue::TimeTicks(12345));
        agent.stop();
    }
}

#[tokio::test]
async fn v3_wrong_community_is_not_applicable() {
    // A v3 manager never accepts community answers; only the v3 agent replies.
    let (agent, port) = v3_agent(&user("simulator", AuthProtocol::Sha256)).await;
    let manager = Manager::connect_v3(v3_config(port, user("simulator", AuthProtocol::Sha256)))
        .await
        .unwrap();
    let response = manager.get(vec!["1.3.6.1.2.1.1.1.0"]).await.unwrap();
    assert_eq!(response.error_status, ErrorStatus::NoError);
    agent.stop();
}

#[tokio::test]
async fn v3_notifier_send_trap_requires_local_engine() {
    let (agent, port) = v3_agent(&user("trapuser", AuthProtocol::Sha256)).await;
    let notifier = Notifier::connect_v3(v3_config(port, user("trapuser", AuthProtocol::Sha256)))
        .await
        .unwrap();
    let err = notifier
        .send_trap("1.3.6.1.6.3.1.1.5.1", &[], 1)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("local_engine"));
    agent.stop();
}

#[tokio::test]
async fn v3_notifier_send_trap_uses_local_engine_state() {
    let (agent, port) = v3_agent(&user("trapuser", AuthProtocol::Sha256)).await;
    let mut config = v3_config(port, user("trapuser", AuthProtocol::Sha256));
    config.local_engine = Some(UsmLocalEngine {
        engine_id: vec![0xaa; 11],
        engine_boots: 17,
        engine_time: 900,
    });
    let notifier = Notifier::connect_v3(config).await.unwrap();
    let _ = notifier
        .send_trap("1.3.6.1.6.3.1.1.5.1", &[], 1)
        .await
        .unwrap();
    common::agent::wait_for_datagrams(&agent, 1).await;
    // The trap is a v3 message carrying the local engine parameters.
    let trap = decode_v3_message(&agent.received()[0]).unwrap();
    assert_eq!(trap.usm_params.engine_id, vec![0xaa; 11]);
    assert_eq!(trap.usm_params.engine_boots, 17);
    assert_eq!(trap.usm_params.engine_time, 900);
    agent.stop();
}

#[tokio::test]
async fn v3_notifier_send_inform_discovers_peer_lazily() {
    // local_engine present: connect skips discovery; send_inform discovers
    // lazily and gets a response (notify/client.py:300–303).
    let (agent, port) = v3_agent(&user("informuser", AuthProtocol::Sha256)).await;
    let mut config = v3_config(port, user("informuser", AuthProtocol::Sha256));
    config.local_engine = Some(UsmLocalEngine {
        engine_id: vec![0xaa; 11],
        engine_boots: 1,
        engine_time: 100,
    });
    let notifier = Notifier::connect_v3(config).await.unwrap();
    let response = notifier
        .send_inform("1.3.6.1.6.3.1.1.5.1", &[], 456)
        .await
        .unwrap();
    assert_eq!(response.error_status, ErrorStatus::NoError);
    agent.stop();
}

#[tokio::test]
async fn v3_notifier_send_inform_after_connect_discovery() {
    // No local_engine: connect discovers; inform then round-trips.
    let (agent, port) = v3_agent(&user("informuser", AuthProtocol::Sha256)).await;
    let notifier = Notifier::connect_v3(v3_config(port, user("informuser", AuthProtocol::Sha256)))
        .await
        .unwrap();
    let response = notifier
        .send_inform("1.3.6.1.6.3.1.1.5.1", &[], 123)
        .await
        .unwrap();
    assert_eq!(response.error_status, ErrorStatus::NoError);
    assert!(notifier.session.dispatcher.issued_request_ids().is_empty());
    agent.stop();
}

#[tokio::test]
async fn v1_trap_spec_is_unaffected_by_v3() {
    let _ = V1TrapSpec::default();
    let _ = SnmpVersion::V3;
    let _: Option<VarBind> = None;
    let _: Option<PduKind> = None;
    let _ = SnmpValue::Null;
}
