//! Notification tests (v1/v2c sender): ported from the reference's
//! `test_notification_send.py` and `test_v1_notifications.py`, run against
//! loopback fake agents.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::agent::{FakeAgent, scripted_logic, wait_for_datagrams};
use common::{oid, snmp_trap_oid_instance, sys_uptime_instance};

use std::str::FromStr;
use trishul_snmp::codec::message::{SnmpVersion, decode_message};
use trishul_snmp::codec::pdu::PduKind;
use trishul_snmp::error::Error;
use trishul_snmp::types::varbind::ErrorStatus;

use trishul_snmp::notify::sender::{Notifier, V1NotifierConfig, V1TrapSpec, V2cNotifierConfig};
use trishul_snmp::types::value::SnmpValue;

fn v1_config(port: u16) -> V1NotifierConfig {
    V1NotifierConfig {
        host: "127.0.0.1".to_string(),
        port,
        community: "public".to_string(),
        timeout: Duration::from_millis(300),
        retries: 0,
        ..Default::default()
    }
}

fn v2c_config(port: u16) -> V2cNotifierConfig {
    V2cNotifierConfig {
        host: "127.0.0.1".to_string(),
        port,
        community: "public".to_string(),
        timeout: Duration::from_millis(300),
        retries: 0,
        ..Default::default()
    }
}

/// A notifier over a session whose dispatcher we can inspect.
fn varbind_target(arcs: &[u32]) -> trishul_snmp::target::Target {
    trishul_snmp::target::Target::Numeric(oid(arcs))
}

#[tokio::test]
async fn v2c_send_trap_roundtrip_and_message_shape() {
    let (agent, port) = FakeAgent::spawn(scripted_logic(
        Default::default(),
        Default::default(),
        false,
    ))
    .await;
    let notifier = Notifier::connect_v2c(v2c_config(port)).await.unwrap();

    let extra = vec![
        (
            varbind_target(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 7]),
            SnmpValue::Integer(1),
        ),
        (
            varbind_target(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 8]),
            SnmpValue::Integer(1),
        ),
    ];
    let request_id = notifier
        .send_trap("1.3.6.1.6.3.1.1.5.1", &extra, 123)
        .await
        .unwrap();
    assert_ne!(request_id, 0);

    wait_for_datagrams(&agent, 1).await;
    let received = agent.received();
    assert_eq!(received.len(), 1);
    let message = decode_message(&received[0]).unwrap();
    assert_eq!(message.version, SnmpVersion::V2c);
    assert_eq!(message.community, b"public");
    assert_eq!(message.pdu.kind, PduKind::SnmpV2Trap);
    assert_eq!(message.pdu.varbinds.len(), 4);
    assert_eq!(message.pdu.varbinds[0].oid, sys_uptime_instance());
    assert_eq!(message.pdu.varbinds[0].value, SnmpValue::TimeTicks(123));
    assert_eq!(message.pdu.varbinds[1].oid, snmp_trap_oid_instance());
    assert_eq!(
        message.pdu.varbinds[1].value,
        SnmpValue::ObjectIdentifier(oid(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 1]))
    );
    assert_eq!(
        message.pdu.varbinds[2].oid,
        oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 7])
    );
    assert_eq!(
        message.pdu.varbinds[3].oid,
        oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 8])
    );
    agent.stop();
}

#[tokio::test]
async fn v2c_send_trap_leaves_no_reserved_request_ids() {
    let (agent, port) = FakeAgent::spawn(scripted_logic(
        Default::default(),
        Default::default(),
        false,
    ))
    .await;
    let notifier = Notifier::connect_v2c(v2c_config(port)).await.unwrap();
    for _ in 0..3 {
        let _ = notifier
            .send_trap("1.3.6.1.6.3.1.1.5.1", &[], 1)
            .await
            .unwrap();
    }
    assert!(
        notifier.session.dispatcher.issued_request_ids().is_empty(),
        "every trap released its request id"
    );
    agent.stop();
}

#[tokio::test]
async fn v2c_send_trap_applies_explicit_sys_uptime_and_trap_oid() {
    let (agent, port) = FakeAgent::spawn(scripted_logic(
        Default::default(),
        Default::default(),
        false,
    ))
    .await;
    let notifier = Notifier::connect_v2c(v2c_config(port)).await.unwrap();
    let explicit_trap_oid = oid(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 9]);
    let varbinds = vec![
        (
            varbind_target(&[1, 3, 6, 1, 2, 1, 1, 3, 0]),
            SnmpValue::TimeTicks(999),
        ),
        (
            varbind_target(&[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0]),
            SnmpValue::ObjectIdentifier(explicit_trap_oid.clone()),
        ),
    ];
    let _ = notifier
        .send_trap("1.3.6.1.6.3.1.1.5.1", &varbinds, 123)
        .await
        .unwrap();
    wait_for_datagrams(&agent, 1).await;
    let message = decode_message(&agent.received()[0]).unwrap();
    assert_eq!(message.pdu.varbinds[0].value, SnmpValue::TimeTicks(999));
    assert_eq!(
        message.pdu.varbinds[1].value,
        SnmpValue::ObjectIdentifier(explicit_trap_oid)
    );
    assert_eq!(message.pdu.varbinds.len(), 2);
    agent.stop();
}

#[tokio::test]
async fn v1_send_trap_roundtrip() {
    let (agent, port) = FakeAgent::spawn(scripted_logic(
        Default::default(),
        Default::default(),
        false,
    ))
    .await;
    let notifier = Notifier::connect_v1(v1_config(port)).await.unwrap();
    let spec = V1TrapSpec {
        enterprise: varbind_target(&[1, 3, 6, 1, 4, 1, 999]),
        agent_addr: "192.0.2.1".parse().unwrap(),
        generic_trap: 0,
        specific_trap: 5,
        timestamp: 654321,
        varbinds: vec![(
            varbind_target(&[1, 3, 6, 1, 2, 1, 1, 3, 0]),
            SnmpValue::TimeTicks(654321),
        )],
    };
    let effective = notifier.send_v1_trap(spec).await.unwrap();
    assert_eq!(effective, 654321);

    wait_for_datagrams(&agent, 1).await;
    let received = agent.received();
    assert_eq!(received.len(), 1);
    let message = decode_message(&received[0]).unwrap();
    assert_eq!(message.version, SnmpVersion::V1);
    assert_eq!(message.pdu.kind, PduKind::Trap);
    let trap = message.pdu.v1_trap.as_ref().unwrap();
    assert_eq!(trap.enterprise, oid(&[1, 3, 6, 1, 4, 1, 999]));
    assert_eq!(trap.agent_addr.to_string(), "192.0.2.1");
    assert_eq!(trap.generic_trap, 0);
    assert_eq!(trap.specific_trap, 5);
    assert_eq!(trap.timestamp, 654321);
    assert_eq!(message.pdu.varbinds[0].value, SnmpValue::TimeTicks(654321));
    agent.stop();
}

#[tokio::test]
async fn v1_send_trap_default_spec_uses_enterprise_specific() {
    let (agent, port) = FakeAgent::spawn(scripted_logic(
        Default::default(),
        Default::default(),
        false,
    ))
    .await;
    let notifier = Notifier::connect_v1(v1_config(port)).await.unwrap();
    let spec = V1TrapSpec::default();
    let effective = notifier.send_v1_trap(spec).await.unwrap();
    assert_eq!(effective, 0);
    wait_for_datagrams(&agent, 1).await;
    let message = decode_message(&agent.received()[0]).unwrap();
    let trap = message.pdu.v1_trap.as_ref().unwrap();
    assert_eq!(trap.generic_trap, 6);
    assert_eq!(trap.specific_trap, 0);
    assert_eq!(trap.enterprise, oid(&[1, 3, 6, 1, 4, 1]));
    assert_eq!(trap.timestamp, 0);
    agent.stop();
}

#[tokio::test]
async fn v2c_notifier_rejects_v1_trap_method() {
    let (agent, port) = FakeAgent::spawn(scripted_logic(
        Default::default(),
        Default::default(),
        false,
    ))
    .await;
    let notifier = Notifier::connect_v2c(v2c_config(port)).await.unwrap();
    let err = notifier
        .send_v1_trap(V1TrapSpec::default())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("requires a v1 notifier"));
    agent.stop();
}

#[tokio::test]
async fn v1_notifier_rejects_inform() {
    let (agent, port) = FakeAgent::spawn(scripted_logic(
        Default::default(),
        Default::default(),
        false,
    ))
    .await;
    let notifier = Notifier::connect_v1(v1_config(port)).await.unwrap();
    let err = notifier
        .send_inform("1.3.6.1.6.3.1.1.5.1", &[], 1)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("SNMPv1 does not support informs"));
    agent.stop();
}

#[tokio::test]
async fn v2c_send_inform_roundtrip() {
    let (agent, port) = FakeAgent::spawn(scripted_logic(
        Default::default(),
        Default::default(),
        false,
    ))
    .await;
    let notifier = Notifier::connect_v2c(v2c_config(port)).await.unwrap();
    let response = notifier
        .send_inform("1.3.6.1.6.3.1.1.5.1", &[], 456)
        .await
        .unwrap();
    assert_eq!(response.error_status, ErrorStatus::NoError);
    assert_ne!(response.request_id, 0);
    // The inform left no reserved request id behind.
    assert!(notifier.session.dispatcher.issued_request_ids().is_empty());
    agent.stop();
}

#[tokio::test]
async fn v2c_send_inform_waiting_for_response_times_out_when_agent_is_silent() {
    // An agent that absorbs datagrams without replying.
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let port = socket.local_addr().unwrap().port();
    let shutdown = Arc::new(tokio::sync::watch::Sender::new(false));
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let task_socket = Arc::clone(&socket);
    let absorb = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                recv = task_socket.recv_from(&mut buf) => {
                    let Ok(_) = recv else { break };
                }
            }
        }
    });
    let _ = shutdown;
    let notifier = Notifier::connect_v2c(V2cNotifierConfig {
        host: "127.0.0.1".to_string(),
        port,
        timeout: Duration::from_millis(100),
        retries: 0,
        ..Default::default()
    })
    .await
    .unwrap();
    let err = notifier
        .send_inform("1.3.6.1.6.3.1.1.5.1", &[], 1)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Timeout { attempts: 1 }), "got {err:?}");
    assert!(notifier.session.dispatcher.issued_request_ids().is_empty());
    let _ = shutdown_tx.send(true);
    absorb.abort();
}

#[tokio::test]
async fn v1_send_trap_applies_sys_uptime_override() {
    let (agent, port) = FakeAgent::spawn(scripted_logic(
        Default::default(),
        Default::default(),
        false,
    ))
    .await;
    let notifier = Notifier::connect_v1(v1_config(port)).await.unwrap();
    let spec = V1TrapSpec {
        enterprise: varbind_target(&[1, 3, 6, 1, 4, 1, 999]),
        timestamp: 0,
        varbinds: vec![(
            varbind_target(&[1, 3, 6, 1, 2, 1, 1, 3, 0]),
            SnmpValue::TimeTicks(777),
        )],
        ..Default::default()
    };
    let effective = notifier.send_v1_trap(spec).await.unwrap();
    assert_eq!(effective, 777);
    wait_for_datagrams(&agent, 1).await;
    let message = decode_message(&agent.received()[0]).unwrap();
    let trap = message.pdu.v1_trap.as_ref().unwrap();
    assert_eq!(trap.timestamp, 777);
    assert_eq!(message.pdu.varbinds[0].value, SnmpValue::TimeTicks(777));
    agent.stop();
}

#[tokio::test]
async fn send_trap_rejects_symbolic_varbind_targets_without_bundle() {
    let (agent, port) = FakeAgent::spawn(scripted_logic(
        Default::default(),
        Default::default(),
        false,
    ))
    .await;
    let notifier = Notifier::connect_v2c(v2c_config(port)).await.unwrap();
    let symbolic = trishul_snmp::target::Target::from_str("IF-MIB::ifDescr.1").unwrap();
    let varbinds = vec![(symbolic, SnmpValue::Integer(1))];
    let err = notifier
        .send_trap("1.3.6.1.6.3.1.1.5.1", &varbinds, 1)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("requires a loaded bundle"));
    agent.stop();
}

#[test]
fn sys_uptime_and_trap_oid_instances_are_exposed() {
    use trishul_snmp::notify::sender::{SNMP_TRAP_OID, SYS_UPTIME_OID};
    assert_eq!(sys_uptime_instance(), oid(&SYS_UPTIME_OID));
    assert_eq!(snmp_trap_oid_instance(), oid(&SNMP_TRAP_OID));
}
