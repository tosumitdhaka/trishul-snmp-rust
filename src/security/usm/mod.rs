//! UsmModel facade: wrap/unwrap/prepare, recovery (← usm.py)

pub mod auth;
pub mod engine;
pub mod kdf;
#[path = "priv.rs"]
pub mod privacy;

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::codec::message::SnmpVersion;
use crate::codec::pdu::{Pdu, PduKind};
use crate::codec::v3::{
    MSG_FLAG_AUTH, MSG_FLAG_PRIV, MSG_FLAG_REPORTABLE, UsmSecurityParameters, decode_scoped_pdu,
    decode_v3_message, encode_scoped_pdu, encode_v3_message,
};
use crate::error::{EngineReport, Error, ProtocolError, UnwrapOutcome};
use crate::mib::MibBundle;
pub use crate::security::usm::engine::UsmLocalEngine;
use crate::security::usm::engine::{KeyMaterial, UsmEngineState, advance_local_engine};
use crate::security::usm::kdf::{
    AuthProtocol, PrivProtocol, auth_enabled, auth_tag_length, password_to_ku, plain_digest,
};
use crate::time::{Clock, Rng};
use crate::transport::dispatcher::RequestDispatcher;
use crate::types::oid::Oid;
use crate::types::value::SnmpValue;
use crate::types::varbind::VarBind;

/// Maximum message size declared by this implementation's sends.
const MAX_MSG_SIZE: i64 = 65507;
/// usmStatsNotInTimeWindows.0 (RFC 3414 §5.2.3).
const NOT_IN_TIME_WINDOWS_OID: [u32; 11] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0];
/// usmStatsUnknownUserNames.0 — the discovery probe target.
const UNKNOWN_USER_NAMES_OID: [u32; 11] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0];

/// An auth key: either a passphrase to localize (RFC 3414 §2.6) or an
/// already-localized key of exactly the protocol's digest length
/// (usm.py:UsmUser.auth_key + auth_key_localized).
///
/// `Debug` is redacted — key material never appears in formatted output
/// (review NIT 9; see docs/architecture.md §8).
#[derive(Clone, PartialEq, Eq)]
pub enum AuthKey {
    /// Passphrase; localized at message time (cached per engine).
    Passphrase(Vec<u8>),
    /// Already-localized key bytes.
    Localized(Zeroizing<Vec<u8>>),
}

/// A privacy key: passphrase or already-localized bytes.
///
/// `Debug` is redacted — key material never appears in formatted output.
#[derive(Clone, PartialEq, Eq)]
pub enum PrivKey {
    /// Passphrase; localized at message time.
    Passphrase(Vec<u8>),
    /// Already-localized key bytes.
    Localized(Zeroizing<Vec<u8>>),
}

/// Construction-validated USM credentials (usm.py:UsmUser; §5.4).
///
/// `Debug` is redacted — passphrases and key material never appear in
/// formatted output (review NIT 9).
#[derive(Clone)]
pub struct UsmUser {
    /// User name.
    pub username: String,
    /// Authentication protocol.
    pub auth_protocol: AuthProtocol,
    /// Authentication key material.
    pub auth_key: AuthKey,
    /// Privacy protocol.
    pub priv_protocol: PrivProtocol,
    /// Privacy key material.
    pub priv_key: PrivKey,
}

impl std::fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Passphrase(_) => f.write_str("AuthKey::Passphrase(<redacted>)"),
            Self::Localized(_) => f.write_str("AuthKey::Localized(<redacted>)"),
        }
    }
}

impl std::fmt::Debug for PrivKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Passphrase(_) => f.write_str("PrivKey::Passphrase(<redacted>)"),
            Self::Localized(_) => f.write_str("PrivKey::Localized(<redacted>)"),
        }
    }
}

impl std::fmt::Debug for UsmUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsmUser")
            .field("username", &self.username)
            .field("auth_protocol", &self.auth_protocol)
            .field("auth_key", &"<redacted>")
            .field("priv_protocol", &self.priv_protocol)
            .field("priv_key", &"<redacted>")
            .finish()
    }
}

impl UsmUser {
    /// Validates key material at construction, mirroring the reference's
    /// `__post_init__` (usm.py): a non-NONE auth protocol requires key
    /// material, and a localized auth key must be exactly the digest length.
    pub fn new(
        username: String,
        auth_protocol: AuthProtocol,
        auth_key: AuthKey,
        priv_protocol: PrivProtocol,
        priv_key: PrivKey,
    ) -> Result<Self, Error> {
        let localized_len = crate::security::usm::kdf::auth_localized_key_length(auth_protocol);
        match &auth_key {
            AuthKey::Passphrase(passphrase) => {
                if auth_enabled(auth_protocol) && passphrase.is_empty() {
                    return Err(Error::Protocol(ProtocolError::new(format!(
                        "auth_key: empty/missing key with auth_protocol={auth_protocol:?}; \
                         supply a passphrase or a {localized_len}-octet localized key"
                    ))));
                }
            }
            AuthKey::Localized(key) => {
                if auth_enabled(auth_protocol) && key.len() != localized_len {
                    return Err(Error::Protocol(ProtocolError::new(format!(
                        "auth_key: localized key must be {localized_len} octets for \
                         auth_protocol={auth_protocol:?}, got {}",
                        key.len()
                    ))));
                }
            }
        }
        if priv_protocol != PrivProtocol::None_ {
            match &priv_key {
                PrivKey::Passphrase(passphrase) if passphrase.is_empty() => {
                    return Err(Error::Protocol(ProtocolError::new(format!(
                        "priv_key: empty/missing key with priv_protocol={priv_protocol:?}; \
                         supply a passphrase"
                    ))));
                }
                _ => {}
            }
        }
        Ok(Self {
            username,
            auth_protocol,
            auth_key,
            priv_protocol,
            priv_key,
        })
    }
}

/// Shared v3 client configuration (its own struct per the de-boilerplate
/// audit: user + context, no community fields).
#[derive(Clone)]
pub struct V3Config {
    /// Remote host.
    pub host: String,
    /// Remote UDP port.
    pub port: u16,
    /// USM user credentials.
    pub user: UsmUser,
    /// Context name carried in the ScopedPDU.
    pub context_name: Vec<u8>,
    /// Optional sender-authoritative engine for traps; `None` means peer
    /// discovery only.
    pub local_engine: Option<UsmLocalEngine>,
    /// Optional MIB bundle for symbolic targets and response enrichment.
    pub bundle: Option<Arc<MibBundle>>,
    /// Per-attempt response timeout.
    pub timeout: Duration,
    /// Retries after the initial attempt.
    pub retries: u32,
    /// Clock seam — a real consumer here: engine-time anchors advance with it.
    pub clock: Arc<dyn Clock>,
    /// Randomness seam.
    pub rng: Arc<dyn Rng>,
}

/// The USM security model (usm.py:UsmModel; §5.4).
///
/// Interior mutability: all engine state lives behind one `std::sync::Mutex`
/// and every method takes `&self`. **Module rule**: no method holds the lock
/// guard across an await point — `prepare` builds its probe under the lock,
/// drops it, then awaits the dispatcher.
pub struct UsmModel {
    /// The configured user.
    pub user: UsmUser,
    /// Context name for outbound ScopedPDUs.
    pub context_name: Vec<u8>,
    /// Optional sender-authoritative engine (traps).
    pub local_engine: Option<UsmLocalEngine>,
    /// Shared peer/local engine state.
    state: Mutex<UsmEngineState>,
    /// Clock for monotonic engine-time anchors.
    clock: Arc<dyn Clock>,
    /// RNG for privacy salts (AES salt; CBC salt first-octet tweak).
    rng: Arc<dyn Rng>,
}

impl Clone for UsmModel {
    fn clone(&self) -> Self {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        Self {
            user: self.user.clone(),
            context_name: self.context_name.clone(),
            local_engine: self.local_engine.clone(),
            state: Mutex::new(state),
            clock: Arc::clone(&self.clock),
            rng: Arc::clone(&self.rng),
        }
    }
}

impl UsmModel {
    /// Creates a model. `clock` anchors engine-time advancement; `rng` feeds
    /// privacy salt generation (§7: AES salt + the CBC salt first-octet tweak).
    #[must_use]
    pub fn new(
        user: UsmUser,
        context_name: Vec<u8>,
        local_engine: Option<UsmLocalEngine>,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
    ) -> Self {
        Self {
            user,
            context_name,
            local_engine,
            state: Mutex::new(UsmEngineState::default()),
            clock,
            rng,
        }
    }

    /// Whether peer engine discovery has populated authoritative state.
    #[must_use]
    pub fn peer_engine_discovered(&self) -> bool {
        !self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .peer_engine_id
            .is_empty()
    }

    /// Directly adopts peer engine state (used by discovery and the loopback
    /// conformance harness).
    pub fn adopt_engine_state(&self, engine_id: Vec<u8>, boots: u32, time: u32) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.adopt_engine_state(engine_id, boots, time, self.clock.monotonic());
    }

    /// The peer engine id (test/diagnostic surface).
    #[must_use]
    pub fn peer_engine_id(&self) -> Vec<u8> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .peer_engine_id
            .clone()
    }

    // ── SecurityModel protocol ────────────────────────────────────────────

    /// Encodes a PDU into an SNMPv3 USM message (usm.py:wrap_pdu).
    pub fn wrap_pdu(&self, pdu: &Pdu) -> Result<Vec<u8>, Error> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = self.clock.monotonic();
        let engine = self.select_outbound_engine(pdu.kind, &mut state, now)?;
        let flags = msg_flags(pdu.kind, self.user.auth_protocol, self.user.priv_protocol);
        let msg_id = state.next_msg_id();

        let scoped = encode_scoped_pdu(&engine.engine_id, &self.context_name, pdu)?;
        let (msg_data, priv_params) = if self.user.priv_protocol != PrivProtocol::None_ {
            // Encrypt the ScopedPDU (RFC 3826 / draft-reeder; usm.py priv path).
            let key = self.priv_key(&engine.engine_id, &mut state)?;
            let salt = if self.user.priv_protocol == PrivProtocol::Des3Ede {
                privacy::fresh_cbc_salt(&*self.rng, &mut state.last_cbc_salt_first_octet)
            } else {
                privacy::fresh_aes_salt(&*self.rng)
            };
            let encrypted = privacy::encrypt_for_protocol(
                &key,
                &scoped,
                engine.engine_boots,
                engine.engine_time,
                &salt,
                self.user.priv_protocol,
            )?;
            // msgData is the OCTET STRING wrapping the ciphertext (RFC 3826 §3).
            (crate::codec::encode_tlv(0x04, &encrypted)?, salt.to_vec())
        } else {
            (scoped, Vec::new())
        };
        let auth_params = if auth_enabled(self.user.auth_protocol) {
            vec![0u8; auth_tag_length(self.user.auth_protocol)]
        } else {
            Vec::new()
        };
        let usm = UsmSecurityParameters {
            engine_id: engine.engine_id.clone(),
            engine_boots: i64::from(engine.engine_boots),
            engine_time: i64::from(engine.engine_time),
            username: self.user.username.as_bytes().to_vec(),
            auth_params,
            priv_params,
        };
        let raw = encode_v3_message(i64::from(msg_id), MAX_MSG_SIZE, flags, &usm, &msg_data)?;

        if auth_enabled(self.user.auth_protocol) {
            let key = self.auth_key(&engine.engine_id, &mut state)?;
            drop(state);
            return auth::stamp_auth(&raw, &key, self.user.auth_protocol);
        }
        Ok(raw)
    }

    /// Validates an inbound datagram and extracts the PDU (usm.py:unwrap_message).
    ///
    /// Structurally invalid v3 datagrams, foreign users/engines, and (Phase 4)
    /// encrypted messages map to [`UnwrapOutcome::NotForUs`] — never
    /// [`UnwrapOutcome::Malformed`], which is community-codec-only (usm.py:
    /// 347–350, 382–389). HMAC failures map to [`UnwrapOutcome::AuthFailed`]
    /// (never swallowed); adopted engine-recovery reports map to
    /// [`UnwrapOutcome::EngineRecoveryPending`].
    pub fn unwrap_message(&self, data: &[u8]) -> UnwrapOutcome {
        let view = match decode_v3_message(data) {
            Ok(view) => view,
            Err(_) => return UnwrapOutcome::NotForUs,
        };
        if view.usm_params.username != self.user.username.as_bytes() {
            return UnwrapOutcome::NotForUs;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.peer_engine_id.is_empty() && view.usm_params.engine_id != state.peer_engine_id {
            return UnwrapOutcome::NotForUs;
        }
        if auth_enabled(self.user.auth_protocol) {
            let key = match self.auth_key(&view.usm_params.engine_id, &mut state) {
                Ok(key) => key,
                Err(_) => return UnwrapOutcome::NotForUs,
            };
            if auth::verify_auth(
                data,
                view.auth_params_offset,
                &view.usm_params.auth_params,
                &key,
                self.user.auth_protocol,
            )
            .is_err()
            {
                return UnwrapOutcome::AuthFailed;
            }
        }
        let msg_data = view.msg_data_bytes.clone();
        let inbound_boots = view.usm_params.engine_boots.max(0) as u32;
        let inbound_time = view.usm_params.engine_time.max(0) as u32;
        drop(state);

        let plaintext = if self.user.priv_protocol != PrivProtocol::None_ {
            // Decrypt the inbound encryptedPDU (usm.py:_decrypt_priv). A
            // missing/malformed OCTET STRING or non-8-octet salt is NotForUs.
            let key = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match self.priv_key(&view.usm_params.engine_id, &mut state) {
                    Ok(key) => key,
                    Err(_) => return UnwrapOutcome::NotForUs,
                }
            };
            match privacy::decrypt_for_protocol(
                &key,
                &msg_data,
                inbound_boots,
                inbound_time,
                &view.usm_params.priv_params,
                self.user.priv_protocol,
            ) {
                Ok(plain) => plain,
                Err(_) => return UnwrapOutcome::NotForUs,
            }
        } else {
            msg_data
        };

        let pdu = match decode_scoped_pdu(&plaintext) {
            Ok((_engine_id, _context, pdu)) => pdu,
            Err(_) => return UnwrapOutcome::NotForUs,
        };
        if pdu.kind == PduKind::Report {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if self.handle_report(&pdu, &view, data, &mut state) {
                return UnwrapOutcome::EngineRecoveryPending;
            }
            return UnwrapOutcome::NotForUs;
        }
        UnwrapOutcome::Ok(pdu)
    }

    /// Claims a pending engine-recovery report; `None` when none is pending.
    #[must_use]
    pub fn take_recovery(&self) -> Option<EngineReport> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let report = state.recovery_report.take();
        if report.is_some() {
            state.engine_recovery_needed = false;
        }
        report
    }

    /// The SNMP version for this model.
    #[must_use]
    pub fn version(&self) -> SnmpVersion {
        SnmpVersion::V3
    }

    // ── listener/offline decode support (← notify/v3.py helpers) ─────────────

    /// The truncated-HMAC tag length for the configured auth protocol
    /// (notify/v3.py:317–323 length check).
    #[must_use]
    pub fn auth_tag_len(&self) -> usize {
        auth_tag_length(self.user.auth_protocol)
    }

    /// Verifies the HMAC over a received datagram using the configured user's
    /// key for `engine_id` (notify/v3.py `codec._verify_auth`). Key derivation
    /// runs under the lock; the CPU-bound verification happens outside it.
    pub fn verify_auth(
        &self,
        data: &[u8],
        offset: usize,
        received_tag: &[u8],
        engine_id: &[u8],
    ) -> Result<(), Error> {
        if !auth_enabled(self.user.auth_protocol) {
            return Ok(());
        }
        let key = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.auth_key(engine_id, &mut state)?
        };
        auth::verify_auth(data, offset, received_tag, &key, self.user.auth_protocol)
    }

    /// Decrypts an inbound encryptedPDU for the message's authoritative engine
    /// (notify/v3.py `codec._decrypt_scoped_pdu`). Negative boots/time on the
    /// wire clamp to 0, matching `unwrap_message`.
    pub fn decrypt_scoped_pdu(
        &self,
        msg_data: &[u8],
        priv_params: &[u8],
        engine_id: &[u8],
        engine_boots: i64,
        engine_time: i64,
    ) -> Result<Vec<u8>, Error> {
        let key = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.priv_key(engine_id, &mut state)?
        };
        privacy::decrypt_for_protocol(
            &key,
            msg_data,
            engine_boots.max(0) as u32,
            engine_time.max(0) as u32,
            priv_params,
            self.user.priv_protocol,
        )
    }

    /// Encrypts an outbound ScopedPDU under `engine`'s authority, returning
    /// `(priv_params, msg_data)` where `msg_data` is the encryptedPDU OCTET
    /// STRING TLV (notify/v3.py `codec._encrypt_scoped_pdu`). Used by the
    /// listener's inform RESPONSE path.
    pub fn encrypt_scoped_pdu(
        &self,
        scoped: &[u8],
        engine: &UsmLocalEngine,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let (key, salt) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let key = self.priv_key(&engine.engine_id, &mut state)?;
            let salt = if self.user.priv_protocol == PrivProtocol::Des3Ede {
                privacy::fresh_cbc_salt(&*self.rng, &mut state.last_cbc_salt_first_octet)
            } else {
                privacy::fresh_aes_salt(&*self.rng)
            };
            (key, salt)
        };
        let ciphertext = privacy::encrypt_for_protocol(
            &key,
            scoped,
            engine.engine_boots,
            engine.engine_time,
            &salt,
            self.user.priv_protocol,
        )?;
        let msg_data = crate::codec::encode_tlv(0x04, &ciphertext)?;
        Ok((salt.to_vec(), msg_data))
    }

    /// Splices the computed HMAC into a message whose auth placeholder is
    /// already zero-filled (notify/v3.py `codec._stamp_auth`). Used by the
    /// inform RESPONSE path and loopback test fixtures.
    pub fn stamp_auth(&self, raw: &[u8], engine_id: &[u8]) -> Result<Vec<u8>, Error> {
        let key = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.auth_key(engine_id, &mut state)?
        };
        auth::stamp_auth(raw, &key, self.user.auth_protocol)
    }

    /// Builds the RFC 3414 discovery probe this model would send
    /// (← `_build_discovery_probe`); used by loopback listener fixtures to
    /// exercise the discovery REPORT path.
    pub fn build_discovery_probe(&self) -> Result<Vec<u8>, Error> {
        let msg_id = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.next_msg_id()
        };
        build_discovery_probe(msg_id)
    }

    /// Test-only: the number of passphrase→Ku derivations this model has
    /// performed (pins cross-datagram KDF reuse; cf. the reference's `_ku`
    /// monkeypatch counter).
    #[cfg(test)]
    pub(crate) fn kdf_calls(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .kdf_calls
    }

    // ── engine discovery ──────────────────────────────────────────────────

    /// Performs RFC 3414 engine discovery: sends a noAuthNoPriv probe with an
    /// empty engine_id and parses the REPORT response
    /// (usm.py:prepare, _build_discovery_probe, _parse_discovery_response).
    ///
    /// The probe is built under the lock, which is released before awaiting
    /// the dispatcher (module rule).
    pub async fn prepare(&self, dispatcher: &RequestDispatcher) -> Result<(), Error> {
        let probe = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let msg_id = state.next_msg_id();
            build_discovery_probe(msg_id)?
        };
        let response = dispatcher.send_raw_and_receive(&probe).await?;
        self.parse_discovery_response(&response)
    }

    fn parse_discovery_response(&self, data: &[u8]) -> Result<(), Error> {
        let view = decode_v3_message(data).map_err(|error| {
            Error::Protocol(ProtocolError::new(format!(
                "Engine discovery: invalid response: {error}"
            )))
        })?;
        let (_engine_id, _context, pdu) =
            decode_scoped_pdu(&view.msg_data_bytes).map_err(|error| {
                Error::Protocol(ProtocolError::new(format!(
                    "Engine discovery: cannot decode ScopedPDU: {error}"
                )))
            })?;
        if pdu.kind != PduKind::Report {
            return Err(Error::Protocol(ProtocolError::new(format!(
                "Engine discovery: expected REPORT PDU (0xa8), found 0x{:02x}",
                pdu.kind.to_raw_tag()
            ))));
        }
        let p = &view.usm_params;
        if p.engine_id.is_empty() {
            return Err(Error::Protocol(ProtocolError::new(
                "Engine discovery: REPORT contained empty engineID",
            )));
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.adopt_engine_state(
            p.engine_id.clone(),
            p.engine_boots.max(0) as u32,
            p.engine_time.max(0) as u32,
            self.clock.monotonic(),
        );
        Ok(())
    }

    // ── engine selection / recovery ────────────────────────────────────────

    fn select_outbound_engine(
        &self,
        kind: PduKind,
        state: &mut UsmEngineState,
        now: Duration,
    ) -> Result<UsmLocalEngine, Error> {
        if kind == PduKind::SnmpV2Trap {
            let local = self.local_engine.as_ref().ok_or_else(|| {
                Error::Protocol(ProtocolError::new(
                    "SNMPv3 traps require local_engine authoritative state \
                     (engine_id, engine_boots, engine_time)",
                ))
            })?;
            let (advanced, anchor) = advance_local_engine(local, state.local_engine_anchor, now);
            state.local_engine_anchor = anchor;
            return Ok(advanced);
        }
        if state.peer_engine_id.is_empty() {
            return Err(Error::Protocol(ProtocolError::new(
                "SNMPv3 USM engine discovery has not completed; cannot wrap request",
            )));
        }
        Ok(UsmLocalEngine {
            engine_id: state.peer_engine_id.clone(),
            engine_boots: state.peer_engine_boots,
            engine_time: state.current_engine_time(now),
        })
    }

    /// Adopts peer engine state from a usmStatsNotInTimeWindows REPORT and
    /// returns whether a recovery was recorded (usm.py:_handle_inbound_report).
    fn handle_report(
        &self,
        pdu: &Pdu,
        view: &crate::codec::v3::V3Message,
        data: &[u8],
        state: &mut UsmEngineState,
    ) -> bool {
        let is_time_window = pdu
            .varbinds
            .iter()
            .any(|varbind| varbind.oid.arcs() == NOT_IN_TIME_WINDOWS_OID);
        if !is_time_window {
            return false;
        }
        let engine_id = view.usm_params.engine_id.clone();
        let engine_boots = view.usm_params.engine_boots.max(0) as u32;
        let engine_time = view.usm_params.engine_time.max(0) as u32;
        state.adopt_engine_state(
            engine_id.clone(),
            engine_boots,
            engine_time,
            self.clock.monotonic(),
        );
        state.engine_recovery_needed = true;
        state.recovery_report = Some(EngineReport {
            raw: data.to_vec(),
            engine_id,
            engine_boots,
            engine_time,
        });
        true
    }

    // ── key derivation ─────────────────────────────────────────────────────

    /// The localized HMAC key for `engine_id` (cached; usm.py:_hmac_key).
    fn auth_key(
        &self,
        engine_id: &[u8],
        state: &mut UsmEngineState,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let protocol = self.user.auth_protocol;
        match &self.user.auth_key {
            AuthKey::Localized(key) => Ok(key.clone()),
            AuthKey::Passphrase(passphrase) => {
                if !auth_enabled(protocol) {
                    return Ok(Zeroizing::new(Vec::new()));
                }
                // Length-prefixed engine_id‖passphrase key (review NIT 11);
                // both halves Zeroizing on drop.
                let cache_key = KeyMaterial::new(&[engine_id, passphrase]);
                if let Some(cached) = state.localized_cache.get(&cache_key) {
                    return Ok(cached);
                }
                let ku_key = KeyMaterial::new(&[passphrase]);
                let ku = match state.ku_cache.get(&(protocol, ku_key.clone())) {
                    Some(ku) => ku.clone(),
                    None => {
                        #[cfg(test)]
                        {
                            state.kdf_calls += 1;
                        }
                        let ku = password_to_ku(passphrase, protocol);
                        state.ku_cache.insert((protocol, ku_key), ku.clone());
                        ku
                    }
                };
                // RFC 3414 §2.6 step 2 from the cached Ku:
                // Kul = H(Ku || engine_id || Ku).
                let mut input = ku.as_slice().to_vec();
                input.extend_from_slice(engine_id);
                input.extend_from_slice(&ku);
                let localized = plain_digest(&input, protocol);
                state
                    .localized_cache
                    .set(cache_key, Zeroizing::new(localized.clone()));
                Ok(Zeroizing::new(localized))
            }
        }
    }

    /// The localized privacy key for the configured protocol at its full key
    /// length (usm.py:_priv_key). Passphrases are localized against `engine_id`
    /// and cached; already-localized keys are adapted (truncate/extend) in place.
    fn priv_key(
        &self,
        engine_id: &[u8],
        state: &mut UsmEngineState,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if !auth_enabled(self.user.auth_protocol) {
            // RFC 3414 requires auth for priv; the reference raises at
            // derivation time (usm.py:874, 914, 939). This also guards the
            // Localized-key extension loop (review I1).
            return Err(Error::Protocol(ProtocolError::new(
                "Cannot derive priv key without an auth protocol",
            )));
        }
        let protocol = self.user.priv_protocol;
        if protocol == PrivProtocol::None_ {
            return Err(Error::Protocol(ProtocolError::new(
                "no privacy protocol configured",
            )));
        }
        match &self.user.priv_key {
            PrivKey::Localized(key) => {
                privacy::adapt_localized_key(key, protocol, self.user.auth_protocol)
            }
            PrivKey::Passphrase(passphrase) => {
                if passphrase.is_empty() {
                    return Err(Error::Protocol(ProtocolError::new(format!(
                        "{protocol:?} privacy requires a priv_key"
                    ))));
                }
                let cache_key = KeyMaterial::new(&[&[protocol as u8], engine_id, passphrase]);
                if let Some(cached) = state.priv_key_cache.get(&cache_key) {
                    return Ok(cached);
                }
                #[cfg(test)]
                {
                    state.kdf_calls += 1;
                }
                let key = privacy::localized_priv_key(
                    passphrase,
                    engine_id,
                    self.user.auth_protocol,
                    protocol,
                )?;
                state.priv_key_cache.set(cache_key, key.clone());
                Ok(key)
            }
        }
    }
}

/// Plain hash digest (RFC 3414 step 2 uses `H`, not HMAC).
/// msgFlags per PDU class (usm.py:_msg_flags): reportable only for confirmed
/// PDUs; traps and responses carry it cleared.
fn msg_flags(kind: PduKind, auth: AuthProtocol, priv_protocol: PrivProtocol) -> u8 {
    let unconfirmed = kind == PduKind::SnmpV2Trap || kind == PduKind::Response;
    let mut flags = if unconfirmed { 0 } else { MSG_FLAG_REPORTABLE };
    if auth_enabled(auth) {
        flags |= MSG_FLAG_AUTH;
    }
    if priv_protocol != PrivProtocol::None_ {
        flags |= MSG_FLAG_PRIV;
    }
    flags
}

/// Builds the RFC 3414 discovery probe: a noAuthNoPriv GET of
/// usmStatsUnknownUserNames.0 with empty engine parameters.
fn build_discovery_probe(msg_id: u32) -> Result<Vec<u8>, Error> {
    let pdu = Pdu {
        kind: PduKind::GetRequest,
        request_id: msg_id,
        error_status: 0,
        error_index: 0,
        varbinds: vec![VarBind::new(
            Oid::from_arcs(&UNKNOWN_USER_NAMES_OID).expect("fixed OID"),
            SnmpValue::Null,
        )],
        v1_trap: None,
    };
    let scoped = encode_scoped_pdu(b"", b"", &pdu)?;
    let usm = UsmSecurityParameters {
        engine_id: Vec::new(),
        engine_boots: 0,
        engine_time: 0,
        username: Vec::new(),
        auth_params: Vec::new(),
        priv_params: Vec::new(),
    };
    encode_v3_message(
        i64::from(msg_id),
        MAX_MSG_SIZE,
        MSG_FLAG_REPORTABLE,
        &usm,
        &scoped,
    )
    .map_err(Error::Protocol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::pdu::PduKind;
    use crate::codec::v3::{
        MSG_FLAG_REPORTABLE, UsmSecurityParameters, encode_scoped_pdu, encode_v3_message,
    };
    use crate::security::usm::kdf::{auth_localized_key_length, localize_key};
    use crate::types::value::SnmpValue;
    use crate::types::varbind::VarBind;

    fn clock() -> Arc<dyn Clock> {
        Arc::new(crate::time::SystemClock)
    }

    fn rng() -> Arc<dyn Rng> {
        Arc::new(crate::time::SystemRng)
    }

    fn priv_user(
        username: &str,
        auth: AuthProtocol,
        priv_protocol: PrivProtocol,
        priv_passphrase: &[u8],
    ) -> UsmUser {
        UsmUser::new(
            username.to_string(),
            auth,
            user(username, auth).auth_key,
            priv_protocol,
            PrivKey::Passphrase(priv_passphrase.to_vec()),
        )
        .unwrap()
    }

    fn priv_discovered(auth: AuthProtocol, priv_protocol: PrivProtocol) -> UsmModel {
        let model = UsmModel::new(
            priv_user("simulator", auth, priv_protocol, b"privpassword"),
            Vec::new(),
            None,
            clock(),
            rng(),
        );
        model.adopt_engine_state(engine_id(), 2, 500);
        model
    }

    fn user_with_key(username: &str, auth: AuthProtocol, auth_key: AuthKey) -> UsmUser {
        UsmUser::new(
            username.to_string(),
            auth,
            auth_key,
            PrivProtocol::None_,
            PrivKey::Passphrase(Vec::new()),
        )
        .unwrap()
    }

    fn user(username: &str, auth: AuthProtocol) -> UsmUser {
        let key = AuthKey::Localized(Zeroizing::new(vec![0xab; auth_localized_key_length(auth)]));
        UsmUser::new(
            username.to_string(),
            auth,
            key,
            PrivProtocol::None_,
            PrivKey::Passphrase(Vec::new()),
        )
        .unwrap()
    }

    fn engine_id() -> Vec<u8> {
        vec![
            0x80, 0x00, 0x1f, 0x88, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }

    fn get_pdu() -> Pdu {
        Pdu {
            kind: PduKind::GetRequest,
            request_id: 7,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                Oid::from_arcs(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap(),
                SnmpValue::Null,
            )],
            v1_trap: None,
        }
    }

    fn discovered() -> UsmModel {
        discovered_with(AuthProtocol::Sha256)
    }

    fn fresh_with(auth: AuthProtocol) -> UsmModel {
        UsmModel::new(user("simulator", auth), Vec::new(), None, clock(), rng())
    }

    fn discovered_with(auth: AuthProtocol) -> UsmModel {
        let model = UsmModel::new(user("simulator", auth), Vec::new(), None, clock(), rng());
        model.adopt_engine_state(engine_id(), 2, 500);
        model
    }

    #[test]
    fn wrap_unwrap_roundtrip_auth() {
        let model = discovered();
        let raw = model.wrap_pdu(&get_pdu()).unwrap();
        let outcome = model.unwrap_message(&raw);
        match outcome {
            UnwrapOutcome::Ok(pdu) => assert_eq!(pdu.request_id, 7),
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn wrap_emits_protocol_correct_auth_params_length() {
        for auth in [
            AuthProtocol::Md5,
            AuthProtocol::Sha1,
            AuthProtocol::Sha224,
            AuthProtocol::Sha256,
            AuthProtocol::Sha384,
            AuthProtocol::Sha512,
        ] {
            let model = UsmModel::new(user("simulator", auth), Vec::new(), None, clock(), rng());
            model.adopt_engine_state(engine_id(), 2, 500);
            let raw = model.wrap_pdu(&get_pdu()).unwrap();
            let view = decode_v3_message(&raw).unwrap();
            assert_eq!(view.usm_params.auth_params.len(), auth_tag_length(auth));
            assert_eq!(view.msg_flags & MSG_FLAG_AUTH, MSG_FLAG_AUTH);
        }
    }

    #[test]
    fn auth_fails_when_tag_tampered() {
        let model = discovered();
        let mut raw = model.wrap_pdu(&get_pdu()).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        assert_eq!(model.unwrap_message(&raw), UnwrapOutcome::AuthFailed);
    }

    #[test]
    fn wrong_username_is_not_for_us() {
        let model = discovered();
        let other = UsmModel::new(
            user("someone-else", AuthProtocol::Sha256),
            Vec::new(),
            None,
            clock(),
            rng(),
        );
        other.adopt_engine_state(engine_id(), 2, 500);
        let raw = other.wrap_pdu(&get_pdu()).unwrap();
        assert_eq!(model.unwrap_message(&raw), UnwrapOutcome::NotForUs);
    }

    #[test]
    fn wrong_engine_is_not_for_us() {
        let model = discovered();
        let other = UsmModel::new(
            user("simulator", AuthProtocol::Sha256),
            Vec::new(),
            None,
            clock(),
            rng(),
        );
        other.adopt_engine_state(vec![0x99; 11], 2, 500);
        let raw = other.wrap_pdu(&get_pdu()).unwrap();
        assert_eq!(model.unwrap_message(&raw), UnwrapOutcome::NotForUs);
    }

    #[test]
    fn garbage_bytes_are_not_for_us() {
        let model = discovered();
        assert_eq!(
            model.unwrap_message(b"\xde\xad\xbe\xef"),
            UnwrapOutcome::NotForUs
        );
    }

    #[test]
    fn noauthnopriv_roundtrip() {
        let model = UsmModel::new(
            UsmUser::new(
                "simulator".to_string(),
                AuthProtocol::None_,
                AuthKey::Passphrase(Vec::new()),
                PrivProtocol::None_,
                PrivKey::Passphrase(Vec::new()),
            )
            .unwrap(),
            Vec::new(),
            None,
            clock(),
            rng(),
        );
        model.adopt_engine_state(engine_id(), 2, 500);
        let raw = model.wrap_pdu(&get_pdu()).unwrap();
        let view = decode_v3_message(&raw).unwrap();
        assert_eq!(view.msg_flags & MSG_FLAG_AUTH, 0);
        match model.unwrap_message(&raw) {
            UnwrapOutcome::Ok(pdu) => assert_eq!(pdu.request_id, 7),
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn reportable_flag_cleared_for_response_and_set_for_get() {
        let model = discovered();
        let response = Pdu {
            kind: PduKind::Response,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: Vec::new(),
            v1_trap: None,
        };
        let raw = model.wrap_pdu(&response).unwrap();
        let view = decode_v3_message(&raw).unwrap();
        assert_eq!(view.msg_flags & MSG_FLAG_REPORTABLE, 0);

        let raw_get = model.wrap_pdu(&get_pdu()).unwrap();
        let view = decode_v3_message(&raw_get).unwrap();
        assert_eq!(view.msg_flags & MSG_FLAG_REPORTABLE, MSG_FLAG_REPORTABLE);
    }

    #[test]
    fn trap_wrap_requires_local_engine() {
        let model = discovered();
        let trap = Pdu {
            kind: PduKind::SnmpV2Trap,
            request_id: 0,
            error_status: 0,
            error_index: 0,
            varbinds: Vec::new(),
            v1_trap: None,
        };
        let err = model.wrap_pdu(&trap).unwrap_err();
        assert!(err.to_string().contains("local_engine"));
    }

    #[test]
    fn trap_wrap_uses_local_engine_not_peer() {
        let local = UsmLocalEngine {
            engine_id: vec![0xaa; 11],
            engine_boots: 17,
            engine_time: 900,
        };
        let model = UsmModel::new(
            user("simulator", AuthProtocol::Sha256),
            Vec::new(),
            Some(local),
            clock(),
            rng(),
        );
        model.adopt_engine_state(engine_id(), 2, 500);
        let trap = Pdu {
            kind: PduKind::SnmpV2Trap,
            request_id: 0,
            error_status: 0,
            error_index: 0,
            varbinds: Vec::new(),
            v1_trap: None,
        };
        let raw = model.wrap_pdu(&trap).unwrap();
        let view = decode_v3_message(&raw).unwrap();
        assert_eq!(view.usm_params.engine_id, vec![0xaa; 11]);
        assert_eq!(view.usm_params.engine_boots, 17);
        assert_eq!(view.usm_params.engine_time, 900);
    }

    #[test]
    fn passphrase_derivation_runs_once_per_key_material_across_wraps() {
        // Port of test_v3_notification_listener_reuses_codec_key_caches at
        // the model level: two wraps for one engine run the RFC 3414 KDF once
        // per unique derivation (the auth Ku and the priv Ku), not once per
        // packet. A regression to per-datagram KDF (cache removal, per-call
        // cache keys) fails this test.
        let user = UsmUser::new(
            "listener".to_string(),
            AuthProtocol::Md5,
            AuthKey::Passphrase(b"authpassword1".to_vec()),
            PrivProtocol::Aes128,
            PrivKey::Passphrase(b"privpassword1".to_vec()),
        )
        .unwrap();
        let local = UsmLocalEngine {
            engine_id: [vec![0x80, 0x00, 0x01, 0x02, 0x03], vec![0x31; 12]].concat(),
            engine_boots: 7,
            engine_time: 111,
        };
        let model = UsmModel::new(user, Vec::new(), Some(local), clock(), rng());
        let trap = Pdu {
            kind: PduKind::SnmpV2Trap,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                Oid::from_arcs(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap(),
                SnmpValue::Null,
            )],
            v1_trap: None,
        };
        for _ in 0..2 {
            model.wrap_pdu(&trap).unwrap();
        }
        assert_eq!(
            model.kdf_calls(),
            2,
            "auth Ku + priv Ku derived exactly once each across two wraps"
        );
    }

    #[test]
    fn passphrase_key_is_localized_against_engine() {
        let auth = AuthProtocol::Md5;
        let pw_user = UsmUser::new(
            "simulator".to_string(),
            auth,
            AuthKey::Passphrase(b"maplesyrup".to_vec()),
            PrivProtocol::None_,
            PrivKey::Passphrase(Vec::new()),
        )
        .unwrap();
        let model = UsmModel::new(pw_user, Vec::new(), None, clock(), rng());
        let engine = engine_id();
        model.adopt_engine_state(engine.clone(), 2, 500);
        let raw = model.wrap_pdu(&get_pdu()).unwrap();
        let view = decode_v3_message(&raw).unwrap();
        assert_eq!(view.usm_params.auth_params.len(), 12);
        // The HMAC verifies with the RFC 3414 localized key for this engine.
        let kul = localize_key(b"maplesyrup", &engine, auth).unwrap();
        auth::verify_auth(
            &raw,
            view.auth_params_offset,
            &view.usm_params.auth_params,
            &kul,
            auth,
        )
        .unwrap();
    }

    #[test]
    fn construction_rejects_missing_and_undersized_localized_keys() {
        let err = UsmUser::new(
            "x".to_string(),
            AuthProtocol::Sha256,
            AuthKey::Passphrase(Vec::new()),
            PrivProtocol::None_,
            PrivKey::Passphrase(Vec::new()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("empty/missing key"));

        let err = UsmUser::new(
            "x".to_string(),
            AuthProtocol::Sha256,
            AuthKey::Localized(Zeroizing::new(vec![1, 2, 3])),
            PrivProtocol::None_,
            PrivKey::Passphrase(Vec::new()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("localized key must be 32 octets"));
    }

    #[test]
    fn auth_tags_differ_across_protocols() {
        let sha256 = discovered();
        let sha224 = UsmModel::new(
            user("simulator", AuthProtocol::Sha224),
            Vec::new(),
            None,
            clock(),
            rng(),
        );
        sha224.adopt_engine_state(engine_id(), 2, 500);
        let a = sha256.wrap_pdu(&get_pdu()).unwrap();
        let b = sha224.wrap_pdu(&get_pdu()).unwrap();
        let view_a = decode_v3_message(&a).unwrap();
        let view_b = decode_v3_message(&b).unwrap();
        assert_ne!(view_a.usm_params.auth_params, view_b.usm_params.auth_params);
    }

    #[test]
    fn sha256_message_rejected_under_sha224() {
        let model256 = discovered();
        let model224 = UsmModel::new(
            user("simulator", AuthProtocol::Sha224),
            Vec::new(),
            None,
            clock(),
            rng(),
        );
        model224.adopt_engine_state(engine_id(), 2, 500);
        let raw = model256.wrap_pdu(&get_pdu()).unwrap();
        assert_eq!(model224.unwrap_message(&raw), UnwrapOutcome::AuthFailed);
    }

    // ── review batch: same-protocol wrong key + discovery failure paths ─────

    #[test]
    fn sha256_authed_message_rejected_with_wrong_same_protocol_key() {
        // Port of test_v3_crypto_parity.py:223 — protocol mismatch is not the
        // only failure mode: a different key under the SAME protocol must also
        // fail authentication.
        let model = discovered_with(AuthProtocol::Sha256);
        let other_key = UsmModel::new(
            user_with_key(
                "simulator",
                AuthProtocol::Sha256,
                AuthKey::Passphrase(b"a-different-passphrase".to_vec()),
            ),
            Vec::new(),
            None,
            clock(),
            rng(),
        );
        other_key.adopt_engine_state(engine_id(), 2, 500);
        let raw = model.wrap_pdu(&get_pdu()).unwrap();
        assert_eq!(other_key.unwrap_message(&raw), UnwrapOutcome::AuthFailed);
    }

    /// Builds a noAuth REPORT datagram for discovery/recovery parsing.
    fn discovery_report(engine_id: &[u8], boots: i64, time: i64) -> Vec<u8> {
        let report = crate::codec::pdu::Pdu {
            kind: PduKind::Report,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                crate::types::oid::Oid::from_arcs(&[1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0]).unwrap(),
                SnmpValue::Counter32(1),
            )],
            v1_trap: None,
        };
        let scoped = encode_scoped_pdu(engine_id, b"", &report).unwrap();
        let usm = UsmSecurityParameters {
            engine_id: engine_id.to_vec(),
            engine_boots: boots,
            engine_time: time,
            username: Vec::new(),
            auth_params: Vec::new(),
            priv_params: Vec::new(),
        };
        encode_v3_message(1, 65507, MSG_FLAG_REPORTABLE, &usm, &scoped).unwrap()
    }

    #[test]
    fn parse_discovery_response_accepts_valid_report() {
        let model = fresh_with(AuthProtocol::None_);
        let bytes = discovery_report(&[0x80, 0x00, 0x01, 0x02, 0x03], 7, 9876);
        model.parse_discovery_response(&bytes).unwrap();
        assert_eq!(model.peer_engine_id(), vec![0x80, 0x00, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn parse_discovery_response_rejects_non_report_pdu() {
        // Port of test_v3_usm.py:295 — a non-REPORT reply is rejected.
        let model = fresh_with(AuthProtocol::None_);
        let engine = vec![0x80, 0x00, 0x01, 0x02, 0x03];
        let pdu = crate::codec::pdu::Pdu {
            kind: PduKind::Response,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![],
            v1_trap: None,
        };
        let scoped = encode_scoped_pdu(&engine, b"", &pdu).unwrap();
        let usm = UsmSecurityParameters {
            engine_id: engine.clone(),
            engine_boots: 1,
            engine_time: 0,
            username: Vec::new(),
            auth_params: Vec::new(),
            priv_params: Vec::new(),
        };
        let bytes = encode_v3_message(1, 65507, 0, &usm, &scoped).unwrap();
        let err = model.parse_discovery_response(&bytes).unwrap_err();
        assert!(err.to_string().contains("expected REPORT PDU"), "{err}");
        // No engine state was adopted.
        assert!(model.peer_engine_id().is_empty());
    }

    #[test]
    fn parse_discovery_response_rejects_empty_engine_id() {
        // Port of test_v3_usm.py:332 — a REPORT with an empty engineID is
        // rejected (no state adopted).
        let model = fresh_with(AuthProtocol::None_);
        let bytes = discovery_report(&[], 1, 0);
        let err = model.parse_discovery_response(&bytes).unwrap_err();
        assert!(err.to_string().contains("empty engineID"), "{err}");
        assert!(model.peer_engine_id().is_empty());
    }

    #[test]
    fn parse_discovery_response_rejects_malformed_scoped_pdu() {
        // Port of test_v3_usm.py:368 (trailing bytes after the REPORT inside
        // the ScopedPDU) plus an invalid REPORT body.
        let model = fresh_with(AuthProtocol::None_);
        let engine = vec![0x80, 0x00, 0x01, 0x02, 0x03];
        // Corrupt the scoped pdu by appending a trailing NULL inside the
        // outer SEQUENCE (the reference's exact injection).
        let clean = encode_scoped_pdu(
            &engine,
            b"",
            &crate::codec::pdu::Pdu {
                kind: PduKind::Report,
                request_id: 1,
                error_status: 0,
                error_index: 0,
                varbinds: vec![],
                v1_trap: None,
            },
        )
        .unwrap();
        let (_, clean_content, _) = crate::codec::decode_tlv(&clean, 0).unwrap();
        let mut corrupted = vec![0x30];
        corrupted.extend(crate::codec::encode_length(clean_content.len() + 2).unwrap());
        corrupted.extend_from_slice(clean_content);
        corrupted.extend_from_slice(&[0x05, 0x00]); // trailing NULL
        let usm = UsmSecurityParameters {
            engine_id: engine.clone(),
            engine_boots: 1,
            engine_time: 0,
            username: Vec::new(),
            auth_params: Vec::new(),
            priv_params: Vec::new(),
        };
        let bytes = encode_v3_message(1, 65507, 0, &usm, &corrupted).unwrap();
        let err = model.parse_discovery_response(&bytes).unwrap_err();
        assert!(err.to_string().contains("cannot decode ScopedPDU"), "{err}");

        // A REPORT whose request-id INTEGER has zero-length content.
        let bad_body = b"\x02\x00\x02\x01\x00\x02\x01\x00\x30\x00";
        let usm = UsmSecurityParameters {
            engine_id: engine.clone(),
            engine_boots: 1,
            engine_time: 0,
            username: Vec::new(),
            auth_params: Vec::new(),
            priv_params: Vec::new(),
        };
        let scoped = crate::codec::encode_tlv(0x30, bad_body).unwrap();
        let bytes = encode_v3_message(1, 65507, 0, &usm, &scoped).unwrap();
        let err = model.parse_discovery_response(&bytes).unwrap_err();
        assert!(err.to_string().contains("cannot decode ScopedPDU"), "{err}");
    }

    #[test]
    fn parse_discovery_response_rejects_invalid_response_bytes() {
        let model = fresh_with(AuthProtocol::None_);
        let err = model
            .parse_discovery_response(&[0x00, 0x01, 0x02])
            .unwrap_err();
        assert!(err.to_string().contains("invalid response"), "{err}");
    }

    // ── Phase 4: privacy (← test_v3_crypto_parity.py priv matrix) ──────────

    #[test]
    fn aes_priv_roundtrips_for_each_key_length() {
        for (priv_protocol, key_length) in [
            (PrivProtocol::Aes128, 16),
            (PrivProtocol::Aes192, 24),
            (PrivProtocol::Aes256, 32),
        ] {
            let model = priv_discovered(AuthProtocol::Sha256, priv_protocol);
            let raw = model.wrap_pdu(&get_pdu()).unwrap();
            let outcome = model.unwrap_message(&raw);
            match outcome {
                UnwrapOutcome::Ok(pdu) => assert_eq!(pdu.request_id, 7),
                other => panic!("{priv_protocol:?}: expected Ok, got {other:?}"),
            }
            let view = decode_v3_message(&raw).unwrap();
            assert_eq!(
                view.msg_flags & MSG_FLAG_PRIV,
                MSG_FLAG_PRIV,
                "priv flag set"
            );
            assert_eq!(view.usm_params.priv_params.len(), 8, "8-octet salt");
            assert_eq!(
                crate::security::usm::privacy::priv_key_length(priv_protocol).unwrap(),
                key_length
            );
        }
    }

    #[test]
    fn aes_priv_key_differs_across_engine_password_and_protocol() {
        let aes128 = priv_discovered(AuthProtocol::Sha256, PrivProtocol::Aes128);
        let aes256 = priv_discovered(AuthProtocol::Sha256, PrivProtocol::Aes256);
        let mut state = UsmEngineState::default();
        let k128 = aes128.priv_key(&engine_id(), &mut state).unwrap();
        let k256 = aes256.priv_key(&engine_id(), &mut state).unwrap();
        assert_ne!(
            k128.as_slice(),
            k256.as_slice(),
            "AES-256 differs from AES-128"
        );

        let other_engine = aes256.priv_key(&[0x99; 11], &mut state).unwrap();
        assert_ne!(
            other_engine.as_slice(),
            k256.as_slice(),
            "differs across engines"
        );

        // rebuild with a different passphrase
        let different = UsmModel::new(
            priv_user(
                "simulator",
                AuthProtocol::Sha256,
                PrivProtocol::Aes256,
                b"other",
            ),
            Vec::new(),
            None,
            clock(),
            rng(),
        );
        different.adopt_engine_state(engine_id(), 2, 500);
        let k_other = different.priv_key(&engine_id(), &mut state).unwrap();
        assert_ne!(
            k_other.as_slice(),
            k256.as_slice(),
            "differs across passwords"
        );
    }

    #[test]
    fn aes256_message_fails_to_unwrap_under_aes128() {
        let aes256 = priv_discovered(AuthProtocol::Sha256, PrivProtocol::Aes256);
        let aes128 = priv_discovered(AuthProtocol::Sha256, PrivProtocol::Aes128);
        let raw = aes256.wrap_pdu(&get_pdu()).unwrap();
        assert_eq!(aes128.unwrap_message(&raw), UnwrapOutcome::NotForUs);
    }

    #[test]
    fn priv_key_mismatch_fails_to_decode() {
        let sender = priv_discovered(AuthProtocol::Sha256, PrivProtocol::Aes256);
        let receiver = UsmModel::new(
            priv_user(
                "simulator",
                AuthProtocol::Sha256,
                PrivProtocol::Aes256,
                b"wrong",
            ),
            Vec::new(),
            None,
            clock(),
            rng(),
        );
        receiver.adopt_engine_state(engine_id(), 2, 500);
        let raw = sender.wrap_pdu(&get_pdu()).unwrap();
        assert_eq!(receiver.unwrap_message(&raw), UnwrapOutcome::NotForUs);
    }

    #[test]
    fn tripledes_roundtrip_and_key_layout() {
        let model = priv_discovered(AuthProtocol::Sha256, PrivProtocol::Des3Ede);
        let raw = model.wrap_pdu(&get_pdu()).unwrap();
        match model.unwrap_message(&raw) {
            UnwrapOutcome::Ok(pdu) => assert_eq!(pdu.request_id, 7),
            other => panic!("expected Ok, got {other:?}"),
        }
        let view = decode_v3_message(&raw).unwrap();
        assert_eq!(view.usm_params.priv_params.len(), 8);
        // Key layout: first 24 octets 3DES key, last 8 pre-IV (usm.py:846–856).
        let mut state = UsmEngineState::default();
        let material = model.priv_key(&engine_id(), &mut state).unwrap();
        assert_eq!(material.len(), 32);
    }

    #[test]
    fn tripledes_short_digest_chain_structure() {
        // SHA-224: 28-octet digest, so truncation to 32 keeps all of K1 and
        // the first 4 octets of K2 (test_v3_crypto_parity.py:430).
        let model = priv_discovered(AuthProtocol::Sha224, PrivProtocol::Des3Ede);
        let mut state = UsmEngineState::default();
        let key = model.priv_key(&engine_id(), &mut state).unwrap();
        let kul = localize_key(b"privpassword", &engine_id(), AuthProtocol::Sha224).unwrap();
        assert_eq!(key.len(), 32);
        assert_eq!(&key[..28], kul.as_slice(), "K1 survives truncation");
    }

    #[test]
    fn tripledes_digest_at_least_32_uses_plain_localization() {
        let model = priv_discovered(AuthProtocol::Sha384, PrivProtocol::Des3Ede);
        let mut state = UsmEngineState::default();
        let key = model.priv_key(&engine_id(), &mut state).unwrap();
        let kul = localize_key(b"privpassword", &engine_id(), AuthProtocol::Sha384).unwrap();
        assert_eq!(
            key.as_slice(),
            &kul[..32],
            "digest >= 32 uses plain localization"
        );
    }

    #[test]
    fn tripledes_salt_first_octet_changes_between_messages() {
        let model = priv_discovered(AuthProtocol::Sha256, PrivProtocol::Des3Ede);
        let mut salts = Vec::new();
        for _ in 0..4 {
            let raw = model.wrap_pdu(&get_pdu()).unwrap();
            let view = decode_v3_message(&raw).unwrap();
            salts.push(view.usm_params.priv_params.clone());
        }
        for pair in salts.windows(2) {
            assert_ne!(pair[0][0], pair[1][0], "CBC salt first octet changes");
        }
    }

    #[test]
    fn tripledes_each_wrap_uses_fresh_salt() {
        let model = priv_discovered(AuthProtocol::Sha256, PrivProtocol::Des3Ede);
        let raw1 = model.wrap_pdu(&get_pdu()).unwrap();
        let raw2 = model.wrap_pdu(&get_pdu()).unwrap();
        assert_ne!(raw1, raw2);
        let v1 = decode_v3_message(&raw1).unwrap();
        let v2 = decode_v3_message(&raw2).unwrap();
        assert_ne!(v1.usm_params.priv_params, v2.usm_params.priv_params);
    }

    #[test]
    fn tripledes_rejects_priv_params_longer_than_8() {
        let model = priv_discovered(AuthProtocol::Sha256, PrivProtocol::Des3Ede);
        let raw = model.wrap_pdu(&get_pdu()).unwrap();
        let view = decode_v3_message(&raw).unwrap();
        let p = &view.usm_params;
        let padded_usm = crate::codec::v3::UsmSecurityParameters {
            engine_id: p.engine_id.clone(),
            engine_boots: p.engine_boots,
            engine_time: p.engine_time,
            username: p.username.clone(),
            auth_params: vec![0u8; 12],
            priv_params: [p.priv_params.as_slice(), &[0u8]].concat(),
        };
        let scoped = view.msg_data_bytes.clone();
        let reencoded = crate::codec::v3::encode_v3_message(
            view.msg_id,
            65507,
            view.msg_flags,
            &padded_usm,
            &scoped,
        )
        .unwrap();
        let restamped = crate::security::usm::auth::stamp_auth(
            &reencoded,
            &model
                .auth_key(&engine_id(), &mut UsmEngineState::default())
                .unwrap(),
            AuthProtocol::Sha256,
        )
        .unwrap();
        assert_eq!(model.unwrap_message(&restamped), UnwrapOutcome::NotForUs);
    }

    #[test]
    fn priv_key_cache_invalidated_on_boots_change() {
        // Review I5: the reference clears `_localized_priv_cache` when the
        // engine id or boots change (usm.py); the priv cache must be
        // invalidated too — the NAME says invalidated, and that is what we
        // assert (re-derivation being deterministic is a separate fact).
        let model = priv_discovered(AuthProtocol::Sha256, PrivProtocol::Aes256);
        let mut state = UsmEngineState::default();
        let k1 = model.priv_key(&engine_id(), &mut state).unwrap();
        assert_eq!(
            state.priv_key_cache.len(),
            1,
            "cached after first derivation"
        );
        // A reboot (boots change) clears the localized caches.
        state.adopt_engine_state(engine_id(), 3, 100, Duration::from_secs(0));
        assert_eq!(
            state.priv_key_cache.len(),
            0,
            "priv cache invalidated on reboot"
        );
        let k2 = model.priv_key(&engine_id(), &mut state).unwrap();
        assert_eq!(k1.as_slice(), k2.as_slice(), "derivation is deterministic");
        assert_eq!(state.priv_key_cache.len(), 1, "re-cached after reboot");
    }

    // ── review batch: extended-priv guards and cache reuse ─────────────────

    #[test]
    fn extended_priv_key_requires_auth_protocol() {
        // Port of test_v3_crypto_parity.py:357 — derivation without an auth
        // protocol must raise (RFC 3414 requires auth for priv). Construction
        // stays permissive, matching the reference (usm.py:874, 914, 939).
        for protocol in [
            PrivProtocol::Aes192,
            PrivProtocol::Aes256,
            PrivProtocol::Des3Ede,
        ] {
            let user = UsmUser::new(
                "simulator".to_string(),
                AuthProtocol::None_,
                AuthKey::Passphrase(Vec::new()),
                protocol,
                PrivKey::Passphrase(b"privpassword".to_vec()),
            )
            .unwrap();
            let model = UsmModel::new(user, Vec::new(), None, clock(), rng());
            model.adopt_engine_state(engine_id(), 2, 500);
            let err = model.wrap_pdu(&get_pdu()).unwrap_err();
            assert!(
                err.to_string()
                    .contains("Cannot derive priv key without an auth protocol"),
                "{protocol:?}: {err}"
            );
            // Same guard for a Localized priv key (no extension-loop risk).
            let localized = UsmUser::new(
                "simulator".to_string(),
                AuthProtocol::None_,
                AuthKey::Passphrase(Vec::new()),
                protocol,
                PrivKey::Localized(Zeroizing::new(vec![0x11; 32])),
            )
            .unwrap();
            let model = UsmModel::new(localized, Vec::new(), None, clock(), rng());
            model.adopt_engine_state(engine_id(), 2, 500);
            let err = model.wrap_pdu(&get_pdu()).unwrap_err();
            assert!(
                err.to_string()
                    .contains("Cannot derive priv key without an auth protocol"),
                "{protocol:?} Localized: {err}"
            );
        }
    }

    #[test]
    fn extended_priv_kdf_caches_reuse_across_wraps() {
        // Port of test_v3_crypto_parity.py:566 — repeated wraps reuse the
        // cached localized priv key (the KDF runs once per engine).
        let model = priv_discovered(AuthProtocol::Sha256, PrivProtocol::Aes256);
        for _ in 0..3 {
            model.wrap_pdu(&get_pdu()).unwrap();
        }
        let state = model.state.lock().unwrap();
        assert_eq!(
            state.priv_key_cache.len(),
            1,
            "priv KDF cached across wraps"
        );
    }
}
