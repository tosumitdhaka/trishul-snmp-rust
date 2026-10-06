//! Listener integration tests: v1/v2c + v3 listeners over loopback sockets,
//! drop accounting, replay windows, discovery REPORT, inform acks, teardown
//! semantics (ported from the reference's test_notification_listener.py,
//! test_v3_notification_listener.py, and test_notification_to_dict.py).

mod common;

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use common::notify::{
    FrozenClock, make_local_engine, make_passphrase_user, make_raw_notification, make_v3_user,
};
use tokio::net::UdpSocket;

use trishul_snmp::codec::message::{SnmpMessage, SnmpVersion, encode_message};
use trishul_snmp::codec::pdu::{Pdu, PduKind};
use trishul_snmp::notify::listener::{
    ListenerConfig, NotificationListener, V3NotificationListener,
};
use trishul_snmp::notify::replay::DropReason;
use trishul_snmp::security::usm::V3Config;
use trishul_snmp::security::usm::{UsmModel, UsmUser};
use trishul_snmp::types::oid::Oid;
use trishul_snmp::types::value::SnmpValue;
use trishul_snmp::types::varbind::{ErrorStatus, VarBind};

fn oid(arcs: &[u32]) -> Oid {
    Oid::from_arcs(arcs).unwrap()
}

fn varbind_target(arcs: &[u32]) -> trishul_snmp::target::Target {
    trishul_snmp::target::Target::Numeric(oid(arcs))
}

/// A v1/v2c message builder matching the reference's `_v2c_message`.
fn v2c_message(community: &str, request_id: u32, version: u8, pdu_type: PduKind) -> Vec<u8> {
    let version = match version {
        0 => SnmpVersion::V1,
        1 => SnmpVersion::V2c,
        other => {
            // Unsupported versions cannot round-trip through the codec; build
            // the raw SEQUENCE like the reference's encoder would.
            let pdu = Pdu {
                kind: pdu_type,
                request_id,
                error_status: 0,
                error_index: 0,
                varbinds: vec![VarBind::new(
                    oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                    SnmpValue::Integer(7),
                )],
                v1_trap: None,
            };
            let message = SnmpMessage {
                version: SnmpVersion::V2c,
                community: community.as_bytes().to_vec(),
                pdu,
            };
            let encoded = encode_message(&message).unwrap();
            // Rewrite the version INTEGER content (offset 4) to `other`.
            let mut bytes = encoded;
            bytes[4] = other;
            return bytes;
        }
    };
    encode_message(&SnmpMessage {
        version,
        community: community.as_bytes().to_vec(),
        pdu: Pdu {
            kind: pdu_type,
            request_id,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                SnmpValue::Integer(7),
            )],
            v1_trap: None,
        },
    })
    .unwrap()
}

/// Sends raw datagrams to `addr` from one loopback socket.
async fn send_datagrams(addr: std::net::SocketAddr, datagrams: &[Vec<u8>]) -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for datagram in datagrams {
        socket.send_to(datagram, addr).await.unwrap();
    }
    socket
}

/// Receives the next datagram into the socket (for acks and reports).
async fn recv_datagram(socket: &UdpSocket) -> Vec<u8> {
    let mut buf = vec![0u8; 65535];
    let (n, _from) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .expect("expected a datagram within 2s")
        .expect("recv ok");
    buf[..n].to_vec()
}

/// A listener config on 127.0.0.1 with an ephemeral port and a frozen clock.
fn config(clock: Arc<FrozenClock>) -> ListenerConfig {
    ListenerConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        clock,
        ..Default::default()
    }
}

/// Receives one event from the listener (asserting the channel stays open).
async fn recv_event(
    listener: &NotificationListener,
) -> trishul_snmp::notify::event::NotificationEvent {
    listener
        .recv()
        .await
        .expect("channel open")
        .expect("no listener-side error")
}

#[tokio::test]
async fn v2c_listener_receives_trap_event() {
    let listener = NotificationListener::bind(ListenerConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        communities: Some(vec![b"public".to_vec()]),
        ..Default::default()
    })
    .await
    .unwrap();
    let port = listener.local_addr().port();

    let notifier = common::test_v2c_notifier(port).await;
    let extra = vec![(
        varbind_target(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 7]),
        SnmpValue::Integer(7),
    )];
    let send_task = tokio::spawn(async move {
        notifier
            .send_trap("1.3.6.1.6.3.1.1.5.3", &extra, 123)
            .await
            .unwrap()
    });

    let event = recv_event(&listener).await;
    let request_id = send_task.await.unwrap();

    assert_eq!(event.pdu_type, "snmpv2-trap");
    assert_eq!(event.community.as_deref(), Some(b"public".as_slice()));
    assert_eq!(event.source_host().as_deref(), Some("127.0.0.1"));
    assert!(event.source_port().unwrap() > 0);
    assert_eq!(event.request_id, request_id);
    // Auto sysUpTime + snmpTrapOID + the extra varbind.
    assert_eq!(event.varbinds[0].value, SnmpValue::TimeTicks(123));
    assert_eq!(
        event.varbinds[1].value,
        SnmpValue::ObjectIdentifier(oid(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 3]))
    );
    assert_eq!(
        event.varbinds[2].oid,
        oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 7])
    );
    assert_eq!(
        event.notification_oid.as_ref().map(Oid::display).as_deref(),
        Some("1.3.6.1.6.3.1.1.5.3")
    );
    assert_eq!(event.uptime, Some(123));
    drop(listener);
}

#[tokio::test]
async fn v2c_listener_acknowledges_informs() {
    let listener = NotificationListener::bind(ListenerConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        communities: Some(vec![b"public".to_vec()]),
        ..Default::default()
    })
    .await
    .unwrap();
    let port = listener.local_addr().port();

    let notifier = common::test_v2c_notifier_with(port, "public", Duration::from_secs(1), 0).await;
    let inform_task = tokio::spawn(async move {
        notifier
            .send_inform("1.3.6.1.6.3.1.1.5.3", &[], 55)
            .await
            .unwrap()
    });

    let event = recv_event(&listener).await;
    let response = inform_task.await.unwrap();

    assert!(event.is_inform());
    assert_eq!(response.error_status, ErrorStatus::NoError);
    assert_eq!(response.request_id, event.request_id);
    drop(listener);
}

#[tokio::test]
async fn v2c_listener_v1_trap_carries_trap_metadata() {
    let listener = NotificationListener::bind(ListenerConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        ..Default::default()
    })
    .await
    .unwrap();
    let addr = listener.local_addr();
    let v1_trap = encode_message(&SnmpMessage {
        version: SnmpVersion::V1,
        community: b"public".to_vec(),
        pdu: Pdu {
            kind: PduKind::Trap,
            request_id: 0,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]),
                SnmpValue::TimeTicks(10),
            )],
            v1_trap: Some(trishul_snmp::codec::pdu::V1TrapFields {
                enterprise: oid(&[1, 3, 6, 1, 4, 1, 999]),
                agent_addr: "192.0.2.1".parse().unwrap(),
                generic_trap: 0,
                specific_trap: 5,
                timestamp: 10,
            }),
        },
    })
    .unwrap();
    send_datagrams(addr, &[v1_trap]).await;

    let event = recv_event(&listener).await;
    assert_eq!(event.pdu_type, "trap");
    assert_eq!(
        event.enterprise.as_ref().map(Oid::display).as_deref(),
        Some("1.3.6.1.4.1.999")
    );
    assert_eq!(event.agent_addr.as_deref(), Some("192.0.2.1"));
    assert_eq!(event.generic_trap, Some(0));
    assert_eq!(event.specific_trap, Some(5));
    assert_eq!(event.timestamp, Some(10));
    drop(listener);
}

#[tokio::test]
async fn v2c_listener_community_allowlist_filters_events() {
    let listener = NotificationListener::bind(ListenerConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        communities: Some(vec![b"private".to_vec()]),
        ..Default::default()
    })
    .await
    .unwrap();
    let port = listener.local_addr().port();

    // A wrong-community trap is dropped; recv() stays pending.
    let bad_notifier =
        common::test_v2c_notifier_with(port, "public", Duration::from_millis(200), 0).await;
    bad_notifier
        .send_trap("1.3.6.1.6.3.1.1.5.3", &[], 1)
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.recv())
            .await
            .is_err(),
        "wrong-community trap must not surface"
    );
    assert_eq!(listener.drop_counts().total(), 1);
    assert_eq!(listener.drop_counts().get(DropReason::WrongCommunity), 1);

    // The matching-community trap surfaces.
    let good_notifier =
        common::test_v2c_notifier_with(port, "private", Duration::from_millis(200), 0).await;
    let send_task = tokio::spawn(async move {
        good_notifier
            .send_trap("1.3.6.1.6.3.1.1.5.3", &[], 1)
            .await
            .unwrap()
    });
    let event = recv_event(&listener).await;
    send_task.await.unwrap();
    assert_eq!(event.community.as_deref(), Some(b"private".as_slice()));
    drop(listener);
}

#[tokio::test]
async fn v2c_listener_skips_invalid_and_non_notification_messages() {
    let listener = NotificationListener::bind(config(FrozenClock::new(1000)))
        .await
        .unwrap();
    let addr = listener.local_addr();
    let get = v2c_message("public", 8, 1, PduKind::GetRequest);
    let valid = v2c_message("public", 9, 1, PduKind::SnmpV2Trap);
    send_datagrams(addr, &[b"not-snmp".to_vec(), get, valid]).await;

    let event = recv_event(&listener).await;
    assert_eq!(event.request_id, 9);
    assert_eq!(listener.drop_counts().total(), 2);
    assert_eq!(listener.drop_counts().get(DropReason::UndecodableBer), 1);
    assert_eq!(listener.drop_counts().get(DropReason::NotNotification), 1);
    drop(listener);
}

#[tokio::test]
async fn v2c_listener_drop_totals_reconcile_with_per_reason_counts() {
    let listener = NotificationListener::bind(ListenerConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        communities: Some(vec![b"private".to_vec()]),
        clock: FrozenClock::new(1000),
        ..Default::default()
    })
    .await
    .unwrap();
    let addr = listener.local_addr();
    let datagrams = vec![
        b"not-snmp".to_vec(),
        v2c_message("public", 1, 2, PduKind::SnmpV2Trap),
        v2c_message("public", 2, 1, PduKind::SnmpV2Trap),
        v2c_message("private", 3, 1, PduKind::GetRequest),
        v2c_message("private", 4, 1, PduKind::SnmpV2Trap),
    ];
    send_datagrams(addr, &datagrams).await;

    let event = recv_event(&listener).await;
    assert_eq!(event.request_id, 4);
    assert_eq!(listener.drop_counts().total(), 4);
    assert_eq!(listener.drop_counts().get(DropReason::UndecodableBer), 1);
    assert_eq!(
        listener.drop_counts().get(DropReason::UnsupportedVersion),
        1
    );
    assert_eq!(listener.drop_counts().get(DropReason::WrongCommunity), 1);
    assert_eq!(listener.drop_counts().get(DropReason::NotNotification), 1);
    let sum: u64 = listener.drop_counts().iter().map(|(_, c)| c).sum();
    assert_eq!(sum, listener.drop_counts().total());
    drop(listener);
}

#[tokio::test]
async fn v2c_listener_undecodable_ber_drops_are_counted() {
    let listener = NotificationListener::bind(config(FrozenClock::new(1000)))
        .await
        .unwrap();
    let addr = listener.local_addr();
    let datagrams = vec![
        b"not-snmp".to_vec(),
        vec![0x30, 0x05, 0x02, 0x01, 0x01], // version-only fragment
        v2c_message("public", 7, 1, PduKind::SnmpV2Trap),
    ];
    send_datagrams(addr, &datagrams).await;

    let event = recv_event(&listener).await;
    assert_eq!(event.request_id, 7);
    assert_eq!(listener.drop_counts().total(), 2);
    assert_eq!(listener.drop_counts().get(DropReason::UndecodableBer), 2);
    drop(listener);
}

#[tokio::test]
async fn listener_drop_signals_task_exit_and_recv_returns_none() {
    // Teardown semantics: dropping the listener wakes the receive task, which
    // exits and drops the channel sender; a pending recv() resolves to None.
    let listener = NotificationListener::bind(config(FrozenClock::new(1000)))
        .await
        .unwrap();
    let recv_future = listener.recv();
    drop(listener);

    let result = tokio::time::timeout(Duration::from_secs(2), recv_future)
        .await
        .expect("recv resolves after drop");
    assert!(
        result.is_none(),
        "pending recv() observes the closed channel"
    );
}

#[tokio::test]
async fn listener_drop_closes_channel_for_spawned_recv() {
    // The same teardown with the pending recv running in its own task: the
    // 'static future does not borrow the listener, so drop cancels the task
    // and the spawned recv completes with None.
    let listener = NotificationListener::bind(config(FrozenClock::new(1000)))
        .await
        .unwrap();
    let recv_handle = tokio::spawn(listener.recv());
    drop(listener);
    let result = tokio::time::timeout(Duration::from_secs(2), recv_handle)
        .await
        .expect("recv task finishes")
        .expect("recv future did not panic");
    assert!(result.is_none());
}

#[tokio::test]
async fn v2c_listener_local_addr_returns_bound_socket() {
    let listener = NotificationListener::bind(ListenerConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        ..Default::default()
    })
    .await
    .unwrap();
    let addr = listener.local_addr();
    assert_eq!(addr.ip().to_string(), "127.0.0.1");
    assert_ne!(addr.port(), 0);
    drop(listener);
}

#[tokio::test]
async fn decode_notification_exposes_metadata_without_source_address() {
    // Port of test_notification_listener.py's decode_notification metadata
    // test without the bundle-dependent name/description/member assertions
    // (bundle enrichment lands in Phase 6).
    let encoded = encode_message(&SnmpMessage {
        version: SnmpVersion::V2c,
        community: b"public".to_vec(),
        pdu: Pdu {
            kind: PduKind::SnmpV2Trap,
            request_id: 42,
            error_status: 0,
            error_index: 0,
            varbinds: vec![
                VarBind::new(oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]), SnmpValue::TimeTicks(123)),
                VarBind::new(
                    oid(&[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0]),
                    SnmpValue::ObjectIdentifier(oid(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 3])),
                ),
                VarBind::new(
                    oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 7]),
                    SnmpValue::Integer(7),
                ),
            ],
            v1_trap: None,
        },
    })
    .unwrap();

    let event =
        trishul_snmp::notify::event::decode_notification(&encoded, None, None, None).unwrap();
    assert!(event.source_address.is_none());
    assert_eq!(event.source_host(), None);
    assert_eq!(event.source_port(), None);
    assert_eq!(
        event.notification_oid.as_ref().map(Oid::display).as_deref(),
        Some("1.3.6.1.6.3.1.1.5.3")
    );
    assert_eq!(event.uptime, Some(123));
    assert_eq!(event.varbinds.len(), 3);
}

#[tokio::test]
async fn notification_event_helper_rejects_non_notification() {
    let message = SnmpMessage {
        version: SnmpVersion::V2c,
        community: b"public".to_vec(),
        pdu: Pdu {
            kind: PduKind::GetRequest,
            request_id: 8,
            error_status: 0,
            error_index: 0,
            varbinds: Vec::new(),
            v1_trap: None,
        },
    };
    let err = trishul_snmp::notify::event::notification_event_from_message(&message, None, None)
        .unwrap_err();
    assert!(
        err.message.contains("Unsupported notification PDU type"),
        "{err}"
    );
}

// ── SNMPv3 listener ─────────────────────────────────────────────────────────

fn v3_config(
    port: u16,
    user: UsmUser,
    local_engine: Option<trishul_snmp::security::usm::UsmLocalEngine>,
    clock: Arc<FrozenClock>,
) -> V3Config {
    V3Config {
        host: "127.0.0.1".to_string(),
        port,
        user,
        context_name: Vec::new(),
        local_engine,
        bundle: None,
        timeout: Duration::from_secs(1),
        retries: 0,
        clock,
        rng: common::notify::fixture_rng(),
    }
}

async fn recv_v3_event(
    listener: &V3NotificationListener,
) -> trishul_snmp::notify::event::NotificationEvent {
    listener
        .recv()
        .await
        .expect("channel open")
        .expect("no listener-side error")
}

#[tokio::test]
async fn v3_listener_receives_trap_event() {
    for (level, fill) in [
        ("noAuthNoPriv", 0x11u8),
        ("authNoPriv", 0x22u8),
        ("authPriv", 0x33u8),
    ] {
        let user = make_v3_user(level, "listener");
        let listener_engine = make_local_engine(fill + 1, 7, 111);
        let sender_engine = make_local_engine(fill + 2, 7, 111);
        let listener = V3NotificationListener::bind(
            config(FrozenClock::new(1000)),
            user.clone(),
            listener_engine.clone(),
        )
        .await
        .unwrap();
        let port = listener.local_addr().port();

        let notifier = trishul_snmp::notify::sender::Notifier::connect_v3(v3_config(
            port,
            user,
            Some(sender_engine.clone()),
            FrozenClock::new(1000),
        ))
        .await
        .unwrap();
        let send_task = tokio::spawn(async move {
            notifier
                .send_trap("1.3.6.1.6.3.1.1.5.3", &[], 123)
                .await
                .unwrap()
        });

        let event = recv_v3_event(&listener).await;
        let request_id = send_task.await.unwrap();

        assert_eq!(event.community, None);
        assert_eq!(event.snmp_version.as_deref(), Some("3"));
        assert_eq!(event.username.as_deref(), Some("listener"));
        assert_eq!(event.security_level.as_deref(), Some(level));
        assert_eq!(event.pdu_type, "snmpv2-trap");
        assert_eq!(event.request_id, request_id);
        assert_eq!(event.source_host().as_deref(), Some("127.0.0.1"));
        assert_eq!(
            event.authoritative_engine_id.as_deref(),
            Some(sender_engine.engine_id.as_slice())
        );
        assert_eq!(
            event.context_engine_id.as_deref(),
            Some(sender_engine.engine_id.as_slice())
        );
        drop(listener);
    }
}

#[tokio::test]
async fn v3_listener_acknowledges_authpriv_informs() {
    let user = make_v3_user("authPriv", "listener");
    let listener_engine = make_local_engine(0x44, 13, 456);
    let notifier_engine = make_local_engine(0x45, 2, 33);
    let listener = V3NotificationListener::bind(
        config(FrozenClock::new(1000)),
        user.clone(),
        listener_engine.clone(),
    )
    .await
    .unwrap();
    let port = listener.local_addr().port();

    let notifier = trishul_snmp::notify::sender::Notifier::connect_v3(v3_config(
        port,
        user,
        Some(notifier_engine),
        FrozenClock::new(1000),
    ))
    .await
    .unwrap();
    let inform_task = tokio::spawn(async move {
        notifier
            .send_inform("1.3.6.1.6.3.1.1.5.3", &[], 55)
            .await
            .unwrap()
    });

    let event = recv_v3_event(&listener).await;
    let response = inform_task.await.unwrap();

    assert!(event.is_inform());
    assert_eq!(event.security_level.as_deref(), Some("authPriv"));
    assert_eq!(
        event.authoritative_engine_id.as_deref(),
        Some(listener_engine.engine_id.as_slice())
    );
    assert_eq!(response.error_status, ErrorStatus::NoError);
    assert_eq!(response.request_id, event.request_id);
    drop(listener);
}

#[tokio::test]
async fn v3_notifier_authpriv_inform_send_full_path_roundtrip() {
    // Phase-4 parity gap: the reference has no authPriv trap/inform SEND test.
    // Full path, both sides our code — the Notifier encodes, AES-128-CFB
    // encrypts, and MD5-auths the INFORM; the listener verifies, decrypts, and
    // auto-acks; `send_inform` returns the decoded ack. Passphrase keys run
    // the RFC 3414 KDF on both ends, and the injected clock/Rng seams (frozen
    // clock + fixture RNG) keep the exchange deterministic.
    let user = make_passphrase_user();
    let listener_engine = make_local_engine(0x44, 13, 456);
    let listener = V3NotificationListener::bind(
        config(FrozenClock::new(1000)),
        user.clone(),
        listener_engine.clone(),
    )
    .await
    .unwrap();
    let port = listener.local_addr().port();

    let notifier = trishul_snmp::notify::sender::Notifier::connect_v3(v3_config(
        port,
        user,
        None,
        FrozenClock::new(1000),
    ))
    .await
    .unwrap();
    let extras = vec![
        (
            varbind_target(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 7]),
            SnmpValue::Integer(7),
        ),
        (
            varbind_target(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1]),
            SnmpValue::OctetString(b"eth0".to_vec()),
        ),
    ];
    let inform_task = tokio::spawn(async move {
        notifier
            .send_inform("1.3.6.1.6.3.1.1.5.3", &extras, 55)
            .await
            .unwrap()
    });

    let event = recv_v3_event(&listener).await;
    let response = inform_task.await.unwrap();

    assert!(event.is_inform());
    assert_eq!(event.security_level.as_deref(), Some("authPriv"));
    assert_eq!(event.uptime, Some(55));
    assert_eq!(
        event.notification_oid.as_ref(),
        Some(&oid(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 3]))
    );
    // The decoded notification carries the sent varbinds (sysUpTime.0 and
    // snmpTrapOID.0 are auto-added by the sender, then the two extras).
    let extras_received: Vec<&VarBind> = event
        .varbinds
        .iter()
        .filter(|vb| vb.oid != oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]))
        .filter(|vb| vb.oid != oid(&[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0]))
        .collect();
    assert_eq!(extras_received.len(), 2);
    assert_eq!(
        extras_received[0].oid,
        oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 7])
    );
    assert_eq!(extras_received[0].value, SnmpValue::Integer(7));
    assert_eq!(
        extras_received[1].oid,
        oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1])
    );
    assert_eq!(
        extras_received[1].value,
        SnmpValue::OctetString(b"eth0".to_vec())
    );
    // The notifier got the listener's ack.
    assert_eq!(response.error_status, ErrorStatus::NoError);
    assert_eq!(response.request_id, event.request_id);
    drop(listener);
}

#[tokio::test]
async fn v3_notifier_authpriv_trap_send_full_path_roundtrip() {
    // The trap (no-ack) half of the same parity-gap coverage: encode + AES
    // priv + auth through the Notifier, verify + decrypt through the listener,
    // matching varbinds on the wire.
    let user = make_passphrase_user();
    let notifier_engine = make_local_engine(0x46, 3, 222);
    let listener = V3NotificationListener::bind(
        config(FrozenClock::new(1000)),
        user.clone(),
        make_local_engine(0x44, 13, 456),
    )
    .await
    .unwrap();
    let port = listener.local_addr().port();

    let notifier = trishul_snmp::notify::sender::Notifier::connect_v3(v3_config(
        port,
        user,
        Some(notifier_engine),
        FrozenClock::new(1000),
    ))
    .await
    .unwrap();
    let extras = vec![(
        varbind_target(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 7]),
        SnmpValue::Integer(7),
    )];
    let send_task = tokio::spawn(async move {
        notifier
            .send_trap("1.3.6.1.6.3.1.1.5.3", &extras, 55)
            .await
            .unwrap()
    });

    let event = recv_v3_event(&listener).await;
    let request_id = send_task.await.unwrap();

    assert_eq!(event.pdu_type, "snmpv2-trap");
    assert_eq!(event.security_level.as_deref(), Some("authPriv"));
    assert_eq!(event.request_id, request_id);
    assert_eq!(event.uptime, Some(55));
    let extras_received: Vec<&VarBind> = event
        .varbinds
        .iter()
        .filter(|vb| vb.oid != oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]))
        .filter(|vb| vb.oid != oid(&[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0]))
        .collect();
    assert_eq!(extras_received.len(), 1);
    assert_eq!(
        extras_received[0].oid,
        oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 7])
    );
    assert_eq!(extras_received[0].value, SnmpValue::Integer(7));
    drop(listener);
}

#[tokio::test]
async fn v3_listener_skips_wrong_user_and_bad_auth() {
    let user = make_v3_user("authNoPriv", "good");
    let other_user = make_v3_user("authNoPriv", "other");
    let peer_engine = make_local_engine(0x55, 7, 111);

    let valid = make_raw_notification(
        &user,
        PduKind::SnmpV2Trap,
        3,
        Some(peer_engine.clone()),
        None,
    );
    let wrong_user = make_raw_notification(
        &other_user,
        PduKind::SnmpV2Trap,
        1,
        Some(peer_engine.clone()),
        None,
    );
    // A noAuth downgrade of the same user (security-level mismatch).
    let downgraded = make_raw_notification(
        &make_v3_user("noAuthNoPriv", "good"),
        PduKind::SnmpV2Trap,
        2,
        Some(peer_engine.clone()),
        None,
    );
    // A trap with reportableFlag set (re-encoded and re-stamped).
    let mut invalid_reportable = {
        let decoded = trishul_snmp::codec::v3::decode_v3_message(&valid).unwrap();
        let p = &decoded.usm_params;
        let usm = trishul_snmp::codec::v3::UsmSecurityParameters {
            engine_id: p.engine_id.clone(),
            engine_boots: p.engine_boots,
            engine_time: p.engine_time,
            username: p.username.clone(),
            auth_params: vec![0u8; 16],
            priv_params: p.priv_params.clone(),
        };
        trishul_snmp::codec::v3::encode_v3_message(
            decoded.msg_id,
            decoded.msg_max_size,
            decoded.msg_flags | trishul_snmp::codec::v3::MSG_FLAG_REPORTABLE,
            &usm,
            &decoded.msg_data_bytes,
        )
        .unwrap()
    };
    // Re-stamp the HMAC so only the reportable-flag check fails.
    let stamping_model = UsmModel::new(
        user.clone(),
        Vec::new(),
        None,
        Arc::new(trishul_snmp::time::SystemClock),
        common::notify::fixture_rng(),
    );
    invalid_reportable = stamping_model
        .stamp_auth(&invalid_reportable, &peer_engine.engine_id)
        .unwrap();
    // Bad HMAC: flip a byte in the auth params.
    let mut bad_auth = valid.clone();
    let view = trishul_snmp::codec::v3::decode_v3_message(&valid).unwrap();
    let offset = view.auth_params_offset;
    bad_auth[offset] ^= 0xFF;

    let listener = V3NotificationListener::bind(
        config(FrozenClock::new(1000)),
        user,
        make_local_engine(0x56, 7, 111),
    )
    .await
    .unwrap();
    let addr = listener.local_addr();
    send_datagrams(
        addr,
        &[wrong_user, downgraded, invalid_reportable, bad_auth, valid],
    )
    .await;

    let event = recv_v3_event(&listener).await;
    assert_eq!(event.request_id, 3);
    drop(listener);
}

#[tokio::test]
async fn v3_listener_responds_to_discovery_probe() {
    let user = make_v3_user("noAuthNoPriv", "listener");
    let listener_engine = make_local_engine(0x66, 9, 222);

    let probe_model = UsmModel::new(
        user.clone(),
        Vec::new(),
        None,
        Arc::new(trishul_snmp::time::SystemClock),
        common::notify::fixture_rng(),
    );
    let probe = probe_model.build_discovery_probe().unwrap();
    let valid = make_raw_notification(
        &user,
        PduKind::SnmpV2Trap,
        4,
        Some(make_local_engine(0x67, 7, 111)),
        None,
    );

    let listener = V3NotificationListener::bind(
        config(FrozenClock::new(1000)),
        user,
        listener_engine.clone(),
    )
    .await
    .unwrap();
    let addr = listener.local_addr();
    let socket = send_datagrams(addr, &[probe, valid]).await;

    // The REPORT arrives before the event.
    let report = recv_datagram(&socket).await;
    let view = trishul_snmp::codec::v3::decode_v3_message(&report).unwrap();
    assert_eq!(view.usm_params.engine_id, listener_engine.engine_id);
    assert_eq!(view.usm_params.engine_boots, 9);
    assert_eq!(view.usm_params.engine_time, 222);

    let event = recv_v3_event(&listener).await;
    assert_eq!(event.request_id, 4);
    assert_eq!(listener.drop_counts().total(), 0);
    drop(listener);
}

#[tokio::test]
async fn v3_listener_drops_replayed_authpriv_trap() {
    let user = make_v3_user("authPriv", "listener");
    let replayed = make_raw_notification(
        &user,
        PduKind::SnmpV2Trap,
        11,
        Some(make_local_engine(0x42, 5, 100)),
        None,
    );
    let fresh = make_raw_notification(
        &user,
        PduKind::SnmpV2Trap,
        12,
        Some(make_local_engine(0x42, 5, 101)),
        None,
    );

    let listener = V3NotificationListener::bind(
        config(FrozenClock::new(1000)),
        user,
        make_local_engine(0x43, 7, 111),
    )
    .await
    .unwrap();
    let addr = listener.local_addr();
    send_datagrams(addr, &[replayed.clone(), replayed, fresh]).await;

    let first = recv_v3_event(&listener).await;
    let second = recv_v3_event(&listener).await;
    assert_eq!(first.request_id, 11);
    assert_eq!(second.request_id, 12);
    assert_eq!(listener.drop_counts().total(), 1);
    assert_eq!(listener.drop_counts().get(DropReason::DuplicateSalt), 1);
    drop(listener);
}

#[tokio::test]
async fn v3_listener_accepts_distinct_salts_with_advancing_time() {
    let user = make_v3_user("authPriv", "listener");
    let first = make_raw_notification(
        &user,
        PduKind::SnmpV2Trap,
        21,
        Some(make_local_engine(0x51, 5, 100)),
        None,
    );
    let second = make_raw_notification(
        &user,
        PduKind::SnmpV2Trap,
        22,
        Some(make_local_engine(0x51, 5, 101)),
        None,
    );

    let listener = V3NotificationListener::bind(
        config(FrozenClock::new(1000)),
        user,
        make_local_engine(0x52, 7, 111),
    )
    .await
    .unwrap();
    let addr = listener.local_addr();
    send_datagrams(addr, &[first, second]).await;

    let first_event = recv_v3_event(&listener).await;
    let second_event = recv_v3_event(&listener).await;
    assert_eq!(first_event.request_id, 21);
    assert_eq!(second_event.request_id, 22);
    drop(listener);
}

#[tokio::test]
async fn v3_listener_drops_out_of_window_time() {
    let user = make_v3_user("authPriv", "listener");
    let first = make_raw_notification(
        &user,
        PduKind::SnmpV2Trap,
        31,
        Some(make_local_engine(0x61, 5, 100)),
        None,
    );
    let stale = make_raw_notification(
        &user,
        PduKind::SnmpV2Trap,
        32,
        Some(make_local_engine(0x61, 5, 1100)),
        None,
    );
    let fresh = make_raw_notification(
        &user,
        PduKind::SnmpV2Trap,
        33,
        Some(make_local_engine(0x61, 5, 101)),
        None,
    );

    let listener = V3NotificationListener::bind(
        config(FrozenClock::new(1000)),
        user,
        make_local_engine(0x62, 7, 111),
    )
    .await
    .unwrap();
    let addr = listener.local_addr();
    send_datagrams(addr, &[first, stale, fresh]).await;

    let first_event = recv_v3_event(&listener).await;
    let second_event = recv_v3_event(&listener).await;
    assert_eq!(first_event.request_id, 31);
    assert_eq!(second_event.request_id, 33);
    assert_eq!(listener.drop_counts().get(DropReason::OutsideTimeWindow), 1);
    drop(listener);
}

#[tokio::test]
async fn v3_listener_accepts_higher_boots_reboot() {
    let user = make_v3_user("authPriv", "listener");
    let before_reboot = make_raw_notification(
        &user,
        PduKind::SnmpV2Trap,
        41,
        Some(make_local_engine(0x71, 5, 100)),
        None,
    );
    let after_reboot = make_raw_notification(
        &user,
        PduKind::SnmpV2Trap,
        42,
        Some(make_local_engine(0x71, 6, 100)),
        None,
    );

    let listener = V3NotificationListener::bind(
        config(FrozenClock::new(1000)),
        user,
        make_local_engine(0x72, 7, 111),
    )
    .await
    .unwrap();
    let addr = listener.local_addr();
    send_datagrams(addr, &[before_reboot, after_reboot]).await;

    let first = recv_v3_event(&listener).await;
    let second = recv_v3_event(&listener).await;
    assert_eq!(first.request_id, 41);
    assert_eq!(second.request_id, 42);
    drop(listener);
}

#[tokio::test]
async fn v3_listener_does_not_ack_replayed_inform() {
    let user = make_v3_user("authPriv", "listener");
    let receiver_engine = make_local_engine(0x81, 13, 456);
    let replayed = make_raw_notification(
        &user,
        PduKind::InformRequest,
        51,
        None,
        Some(receiver_engine.clone()),
    );
    let fresh = make_raw_notification(
        &user,
        PduKind::InformRequest,
        52,
        None,
        Some(make_local_engine(0x81, 13, 457)),
    );

    let listener =
        V3NotificationListener::bind(config(FrozenClock::new(1000)), user, receiver_engine)
            .await
            .unwrap();
    let addr = listener.local_addr();
    let socket = send_datagrams(addr, &[replayed.clone(), replayed, fresh]).await;

    let first = recv_v3_event(&listener).await;
    let second = recv_v3_event(&listener).await;
    assert_eq!(first.request_id, 51);
    assert_eq!(second.request_id, 52);
    // Exactly one ack per accepted inform; the replayed one gets none.
    let _ack1 = recv_datagram(&socket).await;
    let _ack2 = recv_datagram(&socket).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), socket.recv_from(&mut [0u8; 16]))
            .await
            .is_err(),
        "no third ack"
    );
    drop(listener);
}

#[tokio::test]
async fn v3_listener_counts_replay_drops_under_shared_taxonomy() {
    let user = make_v3_user("authPriv", "listener");
    let replayed = make_raw_notification(
        &user,
        PduKind::SnmpV2Trap,
        61,
        Some(make_local_engine(0x91, 5, 100)),
        None,
    );
    let fresh = make_raw_notification(
        &user,
        PduKind::SnmpV2Trap,
        62,
        Some(make_local_engine(0x91, 5, 101)),
        None,
    );

    let listener = V3NotificationListener::bind(
        config(FrozenClock::new(1000)),
        user,
        make_local_engine(0x92, 7, 111),
    )
    .await
    .unwrap();
    let addr = listener.local_addr();
    send_datagrams(addr, &[replayed.clone(), replayed.clone(), replayed, fresh]).await;

    let first = recv_v3_event(&listener).await;
    let second = recv_v3_event(&listener).await;
    assert_eq!(first.request_id, 61);
    assert_eq!(second.request_id, 62);
    assert_eq!(listener.drop_counts().total(), 2);
    assert_eq!(listener.drop_counts().get(DropReason::DuplicateSalt), 2);
    let sum: u64 = listener.drop_counts().iter().map(|(_, c)| c).sum();
    assert_eq!(sum, listener.drop_counts().total());
    drop(listener);
}

#[tokio::test]
async fn v3_listener_counts_decode_and_auth_drops() {
    let user = make_v3_user("authNoPriv", "good");
    let other_user = make_v3_user("authNoPriv", "other");
    let peer_engine = make_local_engine(0x95, 7, 111);
    let valid = make_raw_notification(
        &user,
        PduKind::SnmpV2Trap,
        71,
        Some(peer_engine.clone()),
        None,
    );
    let mut bad_auth = valid.clone();
    let view = trishul_snmp::codec::v3::decode_v3_message(&valid).unwrap();
    bad_auth[view.auth_params_offset] ^= 0xFF;
    let wrong_user = make_raw_notification(
        &other_user,
        PduKind::SnmpV2Trap,
        72,
        Some(peer_engine),
        None,
    );

    let listener = V3NotificationListener::bind(
        config(FrozenClock::new(1000)),
        user,
        make_local_engine(0x96, 7, 111),
    )
    .await
    .unwrap();
    let addr = listener.local_addr();
    send_datagrams(addr, &[b"not-snmp".to_vec(), bad_auth, wrong_user, valid]).await;

    let event = recv_v3_event(&listener).await;
    assert_eq!(event.request_id, 71);
    assert_eq!(listener.drop_counts().total(), 3);
    assert_eq!(listener.drop_counts().get(DropReason::UndecodableBer), 1);
    assert_eq!(
        listener.drop_counts().get(DropReason::AuthenticationFailed),
        1
    );
    assert_eq!(listener.drop_counts().get(DropReason::WrongUser), 1);
    drop(listener);
}

#[tokio::test]
async fn v3_listener_drops_matching_user_non_notification() {
    let user = make_v3_user("noAuthNoPriv", "listener");
    let peer_engine = make_local_engine(0x47, 7, 111);
    // The reference wraps the GET with an empty (undiscovered) peer engine;
    // the Rust model requires adopted peer state for non-trap PDUs, so adopt
    // it here — the classification (NOT_NOTIFICATION) is identical.
    let get_message = make_raw_notification(
        &user,
        PduKind::GetRequest,
        5,
        None,
        Some(peer_engine.clone()),
    );
    let valid = make_raw_notification(&user, PduKind::SnmpV2Trap, 6, Some(peer_engine), None);

    let listener = V3NotificationListener::bind(
        config(FrozenClock::new(1000)),
        user,
        make_local_engine(0x48, 7, 111),
    )
    .await
    .unwrap();
    let addr = listener.local_addr();
    send_datagrams(addr, &[get_message, valid]).await;

    let event = recv_v3_event(&listener).await;
    assert_eq!(event.request_id, 6);
    assert_eq!(listener.drop_counts().total(), 1);
    assert_eq!(listener.drop_counts().get(DropReason::NotNotification), 1);
    drop(listener);
}

#[tokio::test]
async fn v3_listener_discovery_report_engine_time_advances() {
    // Discovery REPORTs carry configured engineTime advanced with the clock.
    let user = make_v3_user("noAuthNoPriv", "listener");
    let listener_engine = make_local_engine(0x41, 7, 100);
    let clock = FrozenClock::new(1000);
    let probe_model = UsmModel::new(
        user.clone(),
        Vec::new(),
        None,
        Arc::new(trishul_snmp::time::SystemClock),
        common::notify::fixture_rng(),
    );
    let probe = probe_model.build_discovery_probe().unwrap();

    let listener =
        V3NotificationListener::bind(config(Arc::clone(&clock)), user.clone(), listener_engine)
            .await
            .unwrap();
    let addr = listener.local_addr();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let mut report_times = Vec::new();
    for request_id in 1..=3u32 {
        socket.send_to(&probe, addr).await.unwrap();
        let report = recv_datagram(&socket).await;
        let view = trishul_snmp::codec::v3::decode_v3_message(&report).unwrap();
        report_times.push(view.usm_params.engine_time);
        let trap = make_raw_notification(
            &user,
            PduKind::SnmpV2Trap,
            request_id,
            Some(make_local_engine(0x50 + request_id as u8, 7, 111)),
            None,
        );
        socket.send_to(&trap, addr).await.unwrap();
        let _event = recv_v3_event(&listener).await;
        if request_id == 1 {
            clock.advance(149);
        } else if request_id == 2 {
            clock.advance(2);
        }
    }
    assert_eq!(report_times, vec![100, 249, 251]);
    drop(listener);
}

#[tokio::test]
async fn v3_listener_inform_response_engine_time_advances() {
    // Inform RESPONSEs carry configured engineTime advanced with the clock.
    let user = make_v3_user("noAuthNoPriv", "listener");
    let listener_engine = make_local_engine(0x61, 7, 100);
    let clock = FrozenClock::new(1000);

    let listener =
        V3NotificationListener::bind(config(Arc::clone(&clock)), user.clone(), listener_engine)
            .await
            .unwrap();
    let addr = listener.local_addr();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let mut ack_times = Vec::new();
    for request_id in 1..=3u32 {
        let inform = make_raw_notification(
            &user,
            PduKind::InformRequest,
            request_id,
            None,
            Some(make_local_engine(0x70 + request_id as u8, 7, 111)),
        );
        socket.send_to(&inform, addr).await.unwrap();
        let ack = recv_datagram(&socket).await;
        let view = trishul_snmp::codec::v3::decode_v3_message(&ack).unwrap();
        ack_times.push(view.usm_params.engine_time);
        let _event = recv_v3_event(&listener).await;
        if request_id == 1 {
            clock.advance(149);
        } else if request_id == 2 {
            clock.advance(2);
        }
    }
    assert_eq!(ack_times, vec![100, 249, 251]);
    drop(listener);
}

#[tokio::test]
async fn v3_listener_accepts_advancing_trap_engine_time() {
    // A sender advancing engineTime with the same clock stays inside the
    // ±150 s window (test_v3_notification_listener.py:1031–1073).
    let user = make_v3_user("authPriv", "listener");
    let clock = FrozenClock::new(1000);
    let listener_engine = make_local_engine(0x21, 7, 100);
    let notifier_engine = make_local_engine(0x22, 7, 100);

    let listener =
        V3NotificationListener::bind(config(Arc::clone(&clock)), user.clone(), listener_engine)
            .await
            .unwrap();
    let port = listener.local_addr().port();
    let notifier = Arc::new(
        trishul_snmp::notify::sender::Notifier::connect_v3(v3_config(
            port,
            user,
            Some(notifier_engine),
            Arc::clone(&clock),
        ))
        .await
        .unwrap(),
    );

    let mut received = Vec::new();
    for _ in 0..3 {
        let notifier = Arc::clone(&notifier);
        let send_task = tokio::spawn(async move {
            notifier
                .send_trap("1.3.6.1.6.3.1.1.5.3", &[], 1)
                .await
                .unwrap()
        });
        let event = recv_v3_event(&listener).await;
        received.push(event.request_id);
        send_task.await.unwrap();
        clock.advance(151);
    }
    assert_eq!(received.len(), 3);
    drop(listener);
}

#[tokio::test]
async fn v3_listener_wrong_user_and_bad_ber_classifications() {
    // classify_v3_unmatched parity (test_v3_notification_listener.py:764–779).
    let user = make_v3_user("noAuthNoPriv", "listener");
    let peer_engine = make_local_engine(0x46, 7, 111);
    let raw = make_raw_notification(&user, PduKind::SnmpV2Trap, 7, Some(peer_engine), None);
    let other = make_v3_user("noAuthNoPriv", "other");
    let decoded = trishul_snmp::notify::v3_path::V3DecodedDatagram::decode(&raw).unwrap();
    assert_eq!(
        trishul_snmp::notify::v3_path::classify_v3_unmatched(&decoded, &other),
        DropReason::WrongUser
    );
    // A v2c message is not decodable as v3.
    let v2c = v2c_message("public", 1, 1, PduKind::SnmpV2Trap);
    let err = trishul_snmp::notify::v3_path::V3DecodedDatagram::decode(&v2c).unwrap_err();
    assert!(err.message.contains("version 3"), "{err}");
}

// ── to_dict parity (test_notification_to_dict.py) ────────────────────────────

#[tokio::test]
async fn to_dict_is_json_serializable_without_bundle() {
    let message = SnmpMessage {
        version: SnmpVersion::V2c,
        community: b"public".to_vec(),
        pdu: Pdu {
            kind: PduKind::SnmpV2Trap,
            request_id: 42,
            error_status: 0,
            error_index: 0,
            varbinds: vec![
                VarBind::new(oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]), SnmpValue::TimeTicks(123)),
                VarBind::new(
                    oid(&[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0]),
                    SnmpValue::ObjectIdentifier(oid(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 3])),
                ),
                VarBind::new(
                    oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 7]),
                    SnmpValue::Integer(7),
                ),
            ],
            v1_trap: None,
        },
    };
    let event = trishul_snmp::notify::event::notification_event_from_message(
        &message,
        Some("10.0.0.1:12345".parse().unwrap()),
        None,
    )
    .unwrap();
    let d = event.to_dict();

    // Must round-trip through JSON without error.
    let _ = serde_json::to_string(&d).unwrap();

    assert_eq!(d["request_id"], 42);
    assert_eq!(d["community"], "public");
    assert_eq!(d["source_host"], "10.0.0.1");
    assert_eq!(d["source_port"], 12345);
    assert_eq!(d["pdu_type"], "snmpv2-trap");
    assert_eq!(d["notification_oid"], "1.3.6.1.6.3.1.1.5.3");
    assert_eq!(d["notification_name"], serde_json::Value::Null);
    assert_eq!(d["uptime"], 123);
    assert_eq!(d["varbinds"].as_array().unwrap().len(), 3);
    assert_eq!(d["member_bindings"].as_array().unwrap().len(), 0);
    // The Serialize impl produces the same shape.
    let serialized = serde_json::to_value(&event).unwrap();
    assert_eq!(serialized, d);
}

#[tokio::test]
async fn to_dict_varbind_fields() {
    let message = SnmpMessage {
        version: SnmpVersion::V2c,
        community: b"public".to_vec(),
        pdu: Pdu {
            kind: PduKind::SnmpV2Trap,
            request_id: 42,
            error_status: 0,
            error_index: 0,
            varbinds: vec![
                VarBind::new(oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]), SnmpValue::TimeTicks(123)),
                VarBind::new(
                    oid(&[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0]),
                    SnmpValue::ObjectIdentifier(oid(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 3])),
                ),
            ],
            v1_trap: None,
        },
    };
    let event =
        trishul_snmp::notify::event::notification_event_from_message(&message, None, None).unwrap();
    let d = event.to_dict();

    assert_eq!(d["source_host"], serde_json::Value::Null);
    assert_eq!(d["source_port"], serde_json::Value::Null);
    let uptime_vb = &d["varbinds"][0];
    assert_eq!(uptime_vb["oid"], "1.3.6.1.2.1.1.3.0");
    assert_eq!(uptime_vb["value_type"], "timeticks");
    assert_eq!(uptime_vb["value"], "123");
}

#[tokio::test]
async fn to_dict_with_no_source_address() {
    let message = SnmpMessage {
        version: SnmpVersion::V2c,
        community: b"mgmt".to_vec(),
        pdu: Pdu {
            kind: PduKind::SnmpV2Trap,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: Vec::new(),
            v1_trap: None,
        },
    };
    let event =
        trishul_snmp::notify::event::notification_event_from_message(&message, None, None).unwrap();
    let d = event.to_dict();
    assert_eq!(d["source_host"], serde_json::Value::Null);
    assert_eq!(d["source_port"], serde_json::Value::Null);
    assert_eq!(d["varbinds"].as_array().unwrap().len(), 0);
    assert_eq!(d["member_bindings"].as_array().unwrap().len(), 0);
    let _ = serde_json::to_string(&d).unwrap();
}

#[tokio::test]
async fn to_dict_v3_fields_are_json_safe() {
    // Port of test_notification_to_dict.py:174–203 using a noAuthNoPriv wrap.
    let user = make_v3_user("noAuthNoPriv", "notify");
    let engine = make_local_engine(0x44, 9, 321);
    let model = UsmModel::new(
        user.clone(),
        b"alerts".to_vec(),
        Some(engine.clone()),
        Arc::new(trishul_snmp::time::SystemClock),
        common::notify::fixture_rng(),
    );
    let raw = model
        .wrap_pdu(&Pdu {
            kind: PduKind::SnmpV2Trap,
            request_id: 77,
            error_status: 0,
            error_index: 0,
            varbinds: Vec::new(),
            v1_trap: None,
        })
        .unwrap();

    let d = trishul_snmp::notify::event::decode_notification(
        &raw,
        Some("10.0.0.2:40162".parse().unwrap()),
        Some(&user),
        None,
    )
    .unwrap()
    .to_dict();

    let _ = serde_json::to_string(&d).unwrap();
    assert_eq!(d["community"], serde_json::Value::Null);
    assert_eq!(d["snmp_version"], "3");
    assert_eq!(d["username"], "notify");
    assert_eq!(d["security_level"], "noAuthNoPriv");
    let engine_hex = engine
        .engine_id
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(d["context_engine_id"], engine_hex);
    assert_eq!(d["context_name"], hex(b"alerts"));
    assert_eq!(d["authoritative_engine_id"], engine_hex);
    assert_eq!(d["authoritative_engine_boots"], 9);
    assert_eq!(d["authoritative_engine_time"], 321);
}

// ── Phase 6: bundle-enriched events (deferred from Phase 5) ─────────────────

/// A v2c trap message with the reference's `_make_trap_message` varbinds
/// (test_notification_to_dict.py:59–77).
fn trap_message_with_bundle_varbinds() -> SnmpMessage {
    SnmpMessage {
        version: SnmpVersion::V2c,
        community: b"public".to_vec(),
        pdu: Pdu {
            kind: PduKind::SnmpV2Trap,
            request_id: 42,
            error_status: 0,
            error_index: 0,
            varbinds: vec![
                VarBind::new(oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]), SnmpValue::TimeTicks(123)),
                VarBind::new(
                    oid(&[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0]),
                    SnmpValue::ObjectIdentifier(oid(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 3])),
                ),
                VarBind::new(
                    oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 7]),
                    SnmpValue::Integer(7),
                ),
            ],
            v1_trap: None,
        },
    }
}

#[tokio::test]
async fn to_dict_includes_notification_metadata_with_bundle() {
    // Port of test_notification_to_dict.py:104–129 (deferred from Phase 5).
    let tmp = common::mib::TempDir::new("to_dict_bundle");
    common::mib::write_json(
        &tmp.path().join("NOTIF-MIB.json"),
        &common::mib::notif_mib_payload(),
    );
    let bundle = trishul_snmp::mib::load_bundle(tmp.path().join("NOTIF-MIB.json")).unwrap();

    let message = trap_message_with_bundle_varbinds();
    let event = trishul_snmp::notify::event::notification_event_from_message(
        &message,
        Some("192.168.1.1:161".parse().unwrap()),
        Some(&bundle),
    )
    .unwrap();
    let d = event.to_dict();

    let _ = serde_json::to_string(&d).unwrap();
    assert_eq!(d["notification_oid"], "1.3.6.1.6.3.1.1.5.3");
    assert_eq!(d["notification_name"], "NOTIF-MIB::linkDown");
    assert_eq!(d["notification_description"], "A linkDown notification.");
    assert_eq!(d["uptime"], 123);

    let bindings = d["member_bindings"].as_array().unwrap();
    assert_eq!(bindings.len(), 1);
    let member = &bindings[0];
    assert_eq!(member["symbolic"], "NOTIF-MIB::ifIndex");
    assert_eq!(member["oid"], "1.3.6.1.2.1.2.2.1.1.7");
    assert_eq!(member["value_type"], "integer");
    assert_eq!(member["value"], "7");
}

#[tokio::test]
async fn v2c_listener_receives_symbolic_trap_with_bundle() {
    // Port of test_notification_listener.py:183–225 (deferred from Phase 5):
    // a bundle-threaded listener receives an enriched symbolic trap.
    let tmp = common::mib::TempDir::new("symbolic_trap");
    common::mib::write_json(
        &tmp.path().join("NOTIF-MIB.json"),
        &common::mib::notif_mib_payload(),
    );
    let bundle =
        Arc::new(trishul_snmp::mib::load_bundle(tmp.path().join("NOTIF-MIB.json")).unwrap());
    let listener = NotificationListener::bind(ListenerConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        communities: Some(vec![b"public".to_vec()]),
        bundle: Some(Arc::clone(&bundle)),
        ..Default::default()
    })
    .await
    .unwrap();
    let port = listener.local_addr().port();

    let notifier = trishul_snmp::notify::sender::Notifier::connect_v2c(
        trishul_snmp::security::community::CommunityConfig {
            host: "127.0.0.1".to_string(),
            port,
            community: "public".to_string(),
            bundle: Some(Arc::clone(&bundle)),
            timeout: Duration::from_millis(200),
            retries: 0,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let varbinds = vec![(
        trishul_snmp::target::Target::from_str("NOTIF-MIB::ifIndex.7").unwrap(),
        SnmpValue::Integer(7),
    )];
    let send_task = tokio::spawn(async move {
        notifier
            .send_trap("NOTIF-MIB::linkDown", &varbinds, 55)
            .await
            .unwrap()
    });

    let event = recv_event(&listener).await;
    send_task.await.unwrap();

    assert_eq!(
        event.varbinds[2].display_name.as_deref(),
        Some("NOTIF-MIB::ifIndex.7")
    );
    assert_eq!(event.varbinds[2].display_value.as_deref(), Some("7"));
    assert_eq!(
        event.notification_name.as_deref(),
        Some("NOTIF-MIB::linkDown")
    );
    assert_eq!(
        event.notification_description.as_deref(),
        Some("A linkDown notification.")
    );
    assert_eq!(
        event.notification_oid.as_ref().map(Oid::display).as_deref(),
        Some("1.3.6.1.6.3.1.1.5.3")
    );
    assert_eq!(event.uptime, Some(55));
    assert_eq!(event.member_bindings.len(), 1);
    assert_eq!(event.member_bindings[0].symbolic(), "NOTIF-MIB::ifIndex");
    assert_eq!(
        event.member_bindings[0].varbind,
        Some(event.varbinds[2].clone())
    );
    drop(listener);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn drop_reason_labels_match_reference() {
    // The shared taxonomy's wire labels (notify/v3.py:90–107).
    for (reason, label) in [
        (DropReason::UndecodableBer, "undecodable-ber"),
        (DropReason::WrongCommunity, "wrong-community"),
        (DropReason::UnsupportedVersion, "unsupported-version"),
        (DropReason::WrongUser, "wrong-user"),
        (DropReason::NotNotification, "not-notification"),
        (DropReason::AuthenticationFailed, "authentication-failed"),
        (DropReason::EngineBootsReplay, "engine-boots-replay"),
        (DropReason::OutsideTimeWindow, "outside-time-window"),
        (DropReason::DuplicateSalt, "duplicate-salt"),
    ] {
        assert_eq!(reason.as_str(), label);
    }
}
