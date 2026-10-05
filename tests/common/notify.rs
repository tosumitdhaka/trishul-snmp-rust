//! Shared notification test fixtures (← test_v3_notification_listener.py
//! helpers): user/engine builders and raw notification wrapping.

use std::sync::Arc;

use trishul_snmp::codec::pdu::{Pdu, PduKind};
use trishul_snmp::security::usm::kdf::{AuthProtocol, PrivProtocol};
use trishul_snmp::security::usm::{AuthKey, PrivKey, UsmLocalEngine, UsmModel, UsmUser};
use trishul_snmp::time::{Clock, Rng, SystemClock};
use trishul_snmp::types::oid::Oid;
use trishul_snmp::types::value::SnmpValue;
use trishul_snmp::types::varbind::VarBind;
use zeroize::Zeroizing;

use super::fake::CounterRng;

/// A user for the reference's three security levels (MD5 localized auth key,
/// AES-128 passphrase priv) — `_make_user` (test_v3_notification_listener.py:
/// 38–58).
pub fn make_v3_user(level: &str, username: &str) -> UsmUser {
    match level {
        "noAuthNoPriv" => UsmUser::new(
            username.to_string(),
            AuthProtocol::None_,
            AuthKey::Passphrase(Vec::new()),
            PrivProtocol::None_,
            PrivKey::Passphrase(Vec::new()),
        )
        .unwrap(),
        "authNoPriv" => UsmUser::new(
            username.to_string(),
            AuthProtocol::Md5,
            AuthKey::Localized(Zeroizing::new(vec![0xaa; 16])),
            PrivProtocol::None_,
            PrivKey::Passphrase(Vec::new()),
        )
        .unwrap(),
        "authPriv" => UsmUser::new(
            username.to_string(),
            AuthProtocol::Md5,
            AuthKey::Localized(Zeroizing::new(vec![0xaa; 16])),
            PrivProtocol::Aes128,
            PrivKey::Passphrase(b"privpassword12345".to_vec()),
        )
        .unwrap(),
        _ => panic!("unexpected test security level: {level}"),
    }
}

/// An authPriv user with passphrases so the RFC 3414 KDF actually runs
/// (`_make_passphrase_user`, test_v3_notification_listener.py:69–77).
pub fn make_passphrase_user() -> UsmUser {
    UsmUser::new(
        "listener".to_string(),
        AuthProtocol::Md5,
        AuthKey::Passphrase(b"authpassword1".to_vec()),
        PrivProtocol::Aes128,
        PrivKey::Passphrase(b"privpassword1".to_vec()),
    )
    .unwrap()
}

/// `_make_local_engine` (test_v3_notification_listener.py:61–66): engine id
/// `80 00 01 02 03` + `fill`×12.
pub fn make_local_engine(fill: u8, boots: u32, time: u32) -> UsmLocalEngine {
    UsmLocalEngine {
        engine_id: [vec![0x80, 0x00, 0x01, 0x02, 0x03], vec![fill; 12]].concat(),
        engine_boots: boots,
        engine_time: time,
    }
}

/// Wraps a raw notification PDU for `user` (`_make_raw_notification`,
/// test_v3_notification_listener.py:121–146). `local_engine` is authoritative
/// for traps; `peer_engine` is adopted as discovered peer state (informs).
pub fn make_raw_notification(
    user: &UsmUser,
    pdu_type: PduKind,
    request_id: u32,
    local_engine: Option<UsmLocalEngine>,
    peer_engine: Option<UsmLocalEngine>,
) -> Vec<u8> {
    let model = UsmModel::new(
        user.clone(),
        Vec::new(),
        local_engine,
        Arc::new(SystemClock),
        Arc::new(CounterRng::new(7)),
    );
    if let Some(peer) = peer_engine {
        model.adopt_engine_state(peer.engine_id, peer.engine_boots, peer.engine_time);
    }
    let pdu = Pdu {
        kind: pdu_type,
        request_id,
        error_status: 0,
        error_index: 0,
        varbinds: vec![VarBind::new(
            Oid::from_arcs(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap(),
            SnmpValue::Integer(7),
        )],
        v1_trap: None,
    };
    model.wrap_pdu(&pdu).unwrap()
}

/// A frozen clock for deterministic replay windows.
pub struct FrozenClock(std::sync::Mutex<std::time::Duration>);

impl FrozenClock {
    /// Creates a clock frozen at `seconds`.
    #[must_use]
    pub fn new(seconds: u64) -> Arc<Self> {
        Arc::new(Self(std::sync::Mutex::new(std::time::Duration::from_secs(
            seconds,
        ))))
    }

    /// Advances the frozen reading.
    pub fn advance(self: &Arc<Self>, seconds: u64) {
        *self.0.lock().unwrap() += std::time::Duration::from_secs(seconds);
    }
}

impl Clock for FrozenClock {
    fn monotonic(&self) -> std::time::Duration {
        *self.0.lock().unwrap()
    }

    fn unix(&self) -> u64 {
        0
    }
}

/// The rng used by the shared fixtures (deterministic salts).
pub fn fixture_rng() -> Arc<dyn Rng> {
    Arc::new(CounterRng::new(7))
}
