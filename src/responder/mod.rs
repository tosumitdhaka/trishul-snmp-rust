//! SnmpResponder — v1/v2c/v3 read-only responder and simulator
//! (← responder/server.py; v1 and v3 answer paths are Rust extensions over
//! the reference's v2c-only `V2cResponder` — docs/architecture.md §8).
//!
//! The receive loop follows the Phase 5 listener design: a synchronous
//! per-datagram handler running under `catch_unwind` so a panic cannot kill
//! the loop, with replies moved back into the loop for the (async) send.
//! Decode/build/encode failures are per-datagram drops — exactly the
//! reference's `continue` behavior (server.py:131–152); a transport failure
//! on the reply send surfaces out of `serve()` like the reference's re-raise
//! (server.py:115–122).

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::watch;

use crate::codec::message::{SnmpMessage, SnmpVersion, decode_message, encode_message};
use crate::codec::pdu::{Pdu, PduKind};
use crate::codec::v3::{MSG_FLAG_REPORTABLE, V3Message, decode_scoped_pdu};
use crate::error::Error;
use crate::mib::MibBundle;
use crate::notify::listener::{community_allowed, peek_message_version, run_isolated_with_panic};
use crate::notify::v3_path::{
    V3DecodedDatagram, V3ResponseContext, decode_v3_auth_priv, encode_discovery_report,
    encode_v3_response, is_discovery_probe,
};
use crate::security::usm::engine::advance_local_engine;
use crate::security::usm::{NOT_IN_TIME_WINDOWS_OID, UsmLocalEngine, UsmModel, UsmUser};
use crate::target::Target;
use crate::time::{Clock, Rng, SystemClock, SystemRng};
use crate::transport::udp::{ReceivedDatagram, UdpServer};
use crate::types::oid::Oid;
use crate::types::value::SnmpValue;
use crate::types::varbind::{ErrorStatus, VarBind};

pub mod rules;
pub mod sources;

pub use crate::responder::rules::{
    CounterRule, CounterValueType, RandomNumericRule, RandomValueType, SimulationRule,
    TimestampRule, TimestampValueType, UptimeRule,
};
pub use crate::responder::sources::{
    CallbackObjectSource, InMemoryObjectSource, ObjectInput, ObjectValue, ResponderSource,
};

/// The responder's default GETBULK repetition cap (server.py:33).
const DEFAULT_MAX_BULK_REPETITIONS: u32 = 1000;
/// The responder's default maximum encoded response size (server.py:34).
const DEFAULT_MAX_RESPONSE_BYTES: usize = 65535;
/// The RFC 3414 §3.2 step-8 time-window half-width: a request's
/// msgAuthoritativeEngineTime must be within ±150 s of the local
/// snmpEngineTime (the listener's replay window, notify/replay.rs:14).
const TIME_WINDOW_SECONDS: u32 = 150;
/// Capacity of the recent-panic message drain (oldest dropped).
const RECENT_PANICS_CAP: usize = 32;

/// Responder configuration (§5.7).
pub struct ResponderConfig {
    /// Bind host (default `0.0.0.0`).
    pub host: String,
    /// Bind port (0 = ephemeral).
    pub port: u16,
    /// Community allow-list for v1/v2c; `None` allows every community.
    pub communities: Option<Vec<Vec<u8>>>,
    /// A custom lookup source; mutually exclusive with `objects`
    /// (server.py:59–60).
    pub source: Option<Arc<dyn ResponderSource>>,
    /// Object seeds for the default in-memory source.
    pub objects: Vec<ObjectInput>,
    /// MIB bundle resolving symbolic `objects`/`set_object` targets.
    pub bundle: Option<Arc<MibBundle>>,
    /// GETBULK repetition cap (server.py:33; a huge wire value never drives
    /// more than this).
    pub max_bulk_repetitions: u32,
    /// Maximum encoded response size; GETBULK responses are truncated to fit
    /// (RFC 3416 §4.2.3, server.py:34).
    pub max_response_bytes: usize,
    /// Clock seam (engine-time anchors for the v3 answer path).
    pub clock: Arc<dyn Clock>,
    /// Randomness seam (rule defaults; the v3 response salts).
    pub rng: Arc<dyn Rng>,
    /// UdpServer queue capacity (test seam).
    pub queue_capacity: usize,
    /// Optional v3 user + authoritative local engine. When present the
    /// responder answers SNMPv3 requests for `user` (including RFC 3414
    /// discovery REPORTs); v3 datagrams are dropped otherwise.
    pub v3: Option<(UsmUser, UsmLocalEngine)>,
}

impl Default for ResponderConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 161,
            communities: None,
            source: None,
            objects: Vec::new(),
            bundle: None,
            max_bulk_repetitions: DEFAULT_MAX_BULK_REPETITIONS,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            clock: Arc::new(SystemClock),
            rng: Arc::new(SystemRng),
            queue_capacity: 1024,
            v3: None,
        }
    }
}

/// The outcome of processing one datagram.
enum DatagramOutcome {
    /// An encoded reply to send back.
    Respond(Vec<u8>),
    /// The datagram was dropped without a reply.
    Dropped,
}

/// v3 answer state: the configured user, a persistent [`UsmModel`] codec
/// (localized-key caches survive across datagrams), and the responder's own
/// authoritative engine.
struct V3Responder {
    user: UsmUser,
    codec: UsmModel,
    local_engine: UsmLocalEngine,
    anchor: Duration,
    clock: Arc<dyn Clock>,
}

impl V3Responder {
    /// The monotonic-advanced current engine time (listener.py:290–301).
    fn current_engine_time(&self) -> u32 {
        advance_local_engine(
            &self.local_engine,
            Some(self.anchor),
            self.clock.monotonic(),
        )
        .0
        .engine_time
    }
}

/// Async read-only SNMP responder and simulator (← responder/server.py).
///
/// Binds over [`UdpServer`]; `serve` drives the receive loop with per-datagram
/// error isolation. Answers GET/GETNEXT (v1 and v2c/v3) and GETBULK (v2c/v3)
/// from the configured source, rejects SET with `notWritable` (v1: `readOnly`
/// — `notWritable` does not exist in RFC 1157), and answers SNMPv3 discovery
/// probes when a v3 user is configured.
pub struct SnmpResponder {
    server: Arc<UdpServer>,
    source: Arc<dyn ResponderSource>,
    in_memory: Option<Arc<InMemoryObjectSource>>,
    communities: Option<Vec<Vec<u8>>>,
    max_bulk_repetitions: u32,
    max_response_bytes: usize,
    v3: Option<V3Responder>,
    cancel: watch::Sender<bool>,
    local_addr: SocketAddr,
    /// Handler panics caught and isolated by the serve loop (§8 responder
    /// panic counter; the `responder: …` stderr branch).
    panic_count: AtomicU64,
    /// The most recent handler-panic payload texts, oldest first, bounded by
    /// `RECENT_PANICS_CAP` (see [`SnmpResponder::recent_panics`]).
    recent_panics: Mutex<VecDeque<String>>,
}

impl SnmpResponder {
    /// Binds the responder socket (port 0 = ephemeral) and validates the
    /// config (server.py:47–75 constructor validation).
    pub async fn bind(config: ResponderConfig) -> Result<Self, Error> {
        if config.source.is_some() && !config.objects.is_empty() {
            return Err(Error::InvalidInput(
                "objects cannot be used when source is provided".to_string(),
            ));
        }
        if config.max_response_bytes < 1 {
            return Err(Error::InvalidInput(
                "max_response_bytes must be at least 1".to_string(),
            ));
        }
        let server = Arc::new(
            UdpServer::bind_with(
                &config.host,
                config.port,
                config.queue_capacity,
                Arc::clone(&config.clock),
            )
            .await
            .map_err(Error::Transport)?,
        );
        let local_addr = server.local_addr();
        let (source, in_memory) = match config.source {
            Some(source) => (source, None),
            None => {
                let in_memory = Arc::new(InMemoryObjectSource::new(config.bundle, config.objects)?);
                let source: Arc<dyn ResponderSource> = in_memory.clone();
                (source, Some(in_memory))
            }
        };
        let v3 = config.v3.map(|(user, local_engine)| {
            let codec = UsmModel::new(
                user.clone(),
                Vec::new(),
                None,
                Arc::clone(&config.clock),
                Arc::clone(&config.rng),
            );
            let anchor = config.clock.monotonic();
            V3Responder {
                user,
                codec,
                local_engine,
                anchor,
                clock: Arc::clone(&config.clock),
            }
        });
        let (cancel, _) = watch::channel(false);
        Ok(Self {
            server,
            source,
            in_memory,
            communities: config
                .communities
                .as_ref()
                .map(|list| list.iter().filter(|c| !c.is_empty()).cloned().collect()),
            max_bulk_repetitions: config.max_bulk_repetitions,
            max_response_bytes: config.max_response_bytes,
            v3,
            cancel,
            local_addr,
            panic_count: AtomicU64::new(0),
            recent_panics: Mutex::new(VecDeque::with_capacity(RECENT_PANICS_CAP)),
        })
    }

    /// The bound local address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The active lookup source (server.py:94–96 `source` property).
    #[must_use]
    pub fn source(&self) -> &Arc<dyn ResponderSource> {
        &self.source
    }

    /// Whether the active source is the default in-memory source (the
    /// reference's `isinstance(responder.source, InMemoryObjectSource)`).
    #[must_use]
    pub fn is_in_memory(&self) -> bool {
        self.in_memory.is_some()
    }

    /// Number of handler panics caught and isolated by the serve loop (the
    /// `responder: …` stderr branch). No silent failure modes: a non-zero
    /// count means datagrams were dropped to a panic instead of answered —
    /// the mirror of the listener's `DropCounts` philosophy. Surfacing
    /// panics through a typed event channel is a post-1.0 candidate.
    #[must_use]
    pub fn panic_count(&self) -> u64 {
        self.panic_count.load(Ordering::Relaxed)
    }

    /// The payload texts of the most recent handler panics, oldest first,
    /// bounded by `RECENT_PANICS_CAP` (older entries are dropped). Each
    /// message corresponds to one [`SnmpResponder::panic_count`] increment —
    /// the raw `&str`/`String` the panicking handler panicked with (or a
    /// generic placeholder for non-string payloads). Returns a
    /// non-destructive snapshot (repeated calls return the same messages
    /// until newer panics push them out); intended for diagnostics: pairing
    /// the count with *what* panicked.
    #[must_use]
    pub fn recent_panics(&self) -> Vec<String> {
        self.recent_panics
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    /// Sets an object on the default in-memory source (server.py:157–159).
    pub fn set_object(&self, target: impl Into<Target>, value: ObjectValue) -> Result<Oid, Error> {
        self.require_in_memory()?.set_object(target, value)
    }

    /// Sets multiple objects on the default in-memory source
    /// (server.py:161–163).
    pub fn set_objects(&self, objects: Vec<ObjectInput>) -> Result<Vec<Oid>, Error> {
        self.require_in_memory()?.set_objects(objects)
    }

    /// Deletes an object from the default in-memory source.
    pub fn delete_object(&self, target: impl Into<Target>) -> Result<bool, Error> {
        self.require_in_memory()?.delete_object(target)
    }

    /// Clears all objects on the default in-memory source (server.py:165–167).
    pub fn clear_objects(&self) -> Result<(), Error> {
        self.require_in_memory()?.clear();
        Ok(())
    }

    /// The in-memory source handle (server.py:169–172 `_require_in_memory_source`);
    /// the reference raises `TypeError` here, mapped to `InvalidInput`.
    fn require_in_memory(&self) -> Result<&Arc<InMemoryObjectSource>, Error> {
        self.in_memory.as_ref().ok_or_else(|| {
            Error::InvalidInput("Responder is not using an InMemoryObjectSource".to_string())
        })
    }

    /// Serves up to `count` requests, or runs until the responder is closed
    /// (dropped or [`SnmpResponder::close`]) when `count` is 0
    /// (server.py:108–122 `serve`).
    ///
    /// The reference rejects a negative `count`; `usize` makes that
    /// unrepresentable. Returns the number of handled requests.
    ///
    /// A panic inside a per-datagram handler is caught, logged to stderr
    /// (`responder: …`), counted by [`SnmpResponder::panic_count`], and drained
    /// to [`SnmpResponder::recent_panics`], then the loop continues — the
    /// responder has no event channel to surface into by design (`serve` is
    /// the only consumer, unlike the listener's `recv`); surfacing panics
    /// through a typed channel is a post-1.0 candidate.
    pub async fn serve(&self, count: usize) -> Result<usize, Error> {
        let mut handled = 0usize;
        let mut cancel_rx = self.cancel.subscribe();
        while count == 0 || handled < count {
            tokio::select! {
                changed = cancel_rx.changed() => {
                    if changed.is_err() || *cancel_rx.borrow() {
                        break;
                    }
                }
                datagram = self.server.receive() => {
                    let Some(datagram) = datagram else { break; };
                    let (outcome, panic_text) =
                        run_isolated_with_panic(|| Ok(self.handle_datagram(&datagram)));
                    match outcome {
                        Ok(DatagramOutcome::Respond(bytes)) => {
                            self.server
                                .sendto(&bytes, datagram.source_address)
                                .await
                                .map_err(Error::Transport)?;
                            handled += 1;
                        }
                        Ok(DatagramOutcome::Dropped) => {}
                        Err(error) => {
                            // A handler panic is isolated per datagram; the
                            // loop stays up for the next request (Phase 5
                            // pattern). There is no event channel to surface
                            // into — the responder's `serve` has no `recv`
                            // counterpart — so the panic is logged, counted,
                            // drained to `recent_panics`, and the loop
                            // continues.
                            self.panic_count.fetch_add(1, Ordering::Relaxed);
                            if let Some(text) = panic_text {
                                let mut recent = self.recent_panics.lock().unwrap_or_else(
                                    |poisoned| poisoned.into_inner(),
                                );
                                if recent.len() >= RECENT_PANICS_CAP {
                                    recent.pop_front();
                                }
                                recent.push_back(text);
                            }
                            eprintln!("responder: {error}");
                        }
                    }
                }
            }
        }
        Ok(handled)
    }

    /// Serves requests until the responder is closed (server.py:124–126).
    pub async fn serve_forever(&self) -> Result<usize, Error> {
        self.serve(0).await
    }

    /// Signals the serve loop to stop (server.py:103–106 `close`).
    pub fn close(&self) {
        let _ = self.cancel.send(true);
    }

    // ── per-datagram dispatch ──────────────────────────────────────────────

    /// Dispatches one datagram by message version. All work is synchronous;
    /// the reply bytes are sent by the serve loop.
    fn handle_datagram(&self, datagram: &ReceivedDatagram) -> DatagramOutcome {
        match peek_message_version(&datagram.data) {
            Ok(3) => self.handle_v3(datagram),
            Ok(version) if version == 0 || version == 1 => self.handle_community(datagram),
            _ => DatagramOutcome::Dropped,
        }
    }

    /// The v1/v2c path (server.py:128–155): decode, community filter, answer,
    /// encode. Every failure is a per-datagram drop.
    fn handle_community(&self, datagram: &ReceivedDatagram) -> DatagramOutcome {
        let message = match decode_message(&datagram.data) {
            Ok(message) => message,
            Err(_) => return DatagramOutcome::Dropped,
        };
        if !community_allowed(&self.communities, &message.community) {
            return DatagramOutcome::Dropped;
        }
        let v1 = message.version == SnmpVersion::V1;
        let response_pdu = match self.build_response_pdu(&message.pdu, v1) {
            Some(pdu) => pdu,
            None => return DatagramOutcome::Dropped,
        };
        let version = message.version;
        let community = message.community.clone();
        let encoded = match self.encode_response(message.pdu.kind, response_pdu, |pdu| {
            encode_message(&SnmpMessage {
                version,
                community: community.clone(),
                pdu: pdu.clone(),
            })
            .map_err(Error::Protocol)
        }) {
            Ok(bytes) => bytes,
            Err(_) => return DatagramOutcome::Dropped,
        };
        DatagramOutcome::Respond(encoded)
    }

    /// The v3 path: discovery probes get a REPORT advertising the local
    /// engine; requests are auth-verified, priv-decrypted, window-checked,
    /// answered, and re-stamped under the local engine's authority.
    fn handle_v3(&self, datagram: &ReceivedDatagram) -> DatagramOutcome {
        let Some(v3) = &self.v3 else {
            return DatagramOutcome::Dropped;
        };
        let decoded = match V3DecodedDatagram::decode(&datagram.data) {
            Ok(decoded) => decoded,
            Err(_) => return DatagramOutcome::Dropped,
        };
        if is_discovery_probe(&decoded) {
            let engine_time = v3.current_engine_time();
            return match encode_discovery_report(&decoded, &v3.local_engine, Some(engine_time)) {
                Ok(report) => DatagramOutcome::Respond(report),
                Err(_) => DatagramOutcome::Dropped,
            };
        }
        let Some(msg_data) = (match decode_v3_auth_priv(&decoded, &v3.user, &v3.codec) {
            Ok(result) => result,
            Err(_) => return DatagramOutcome::Dropped,
        }) else {
            return DatagramOutcome::Dropped;
        };
        let (context_engine_id, context_name, pdu) = match decode_scoped_pdu(&msg_data) {
            Ok(fields) => fields,
            Err(_) => return DatagramOutcome::Dropped,
        };
        let engine_time = v3.current_engine_time();
        // RFC 3414 §3.2 step 8: an authenticated request outside the local
        // engine's time window (boots mismatch or more than ±150 s of
        // snmpEngineTime) is answered with a usmStatsNotInTimeWindows REPORT
        // — never with the data — so the sender's engine-recovery machinery
        // can rebase and retry. Only reportable messages get the REPORT;
        // unconfirmed traffic (traps) is dropped silently.
        if decoded.view.msg_flags & MSG_FLAG_REPORTABLE != 0
            && !in_time_window(&decoded.view, &v3.local_engine, engine_time)
        {
            let report_pdu = Pdu {
                kind: PduKind::Report,
                request_id: pdu.request_id,
                error_status: 0,
                error_index: 0,
                varbinds: vec![VarBind::new(
                    Oid::from_arcs(&NOT_IN_TIME_WINDOWS_OID).expect("fixed OID"),
                    SnmpValue::Counter32(1),
                )],
                v1_trap: None,
            };
            return match encode_v3_response(
                &V3ResponseContext {
                    view: &decoded.view,
                    context_engine_id: &context_engine_id,
                    context_name: &context_name,
                },
                &report_pdu,
                &v3.user,
                &v3.local_engine,
                &v3.codec,
                Some(engine_time),
            ) {
                Ok(report) => DatagramOutcome::Respond(report),
                Err(_) => DatagramOutcome::Dropped,
            };
        }
        let response_pdu = match self.build_response_pdu(&pdu, false) {
            Some(pdu) => pdu,
            None => return DatagramOutcome::Dropped,
        };
        let encoded = self.encode_response(pdu.kind, response_pdu, |pdu| {
            encode_v3_response(
                &V3ResponseContext {
                    view: &decoded.view,
                    context_engine_id: &context_engine_id,
                    context_name: &context_name,
                },
                pdu,
                &v3.user,
                &v3.local_engine,
                &v3.codec,
                Some(engine_time),
            )
        });
        match encoded {
            Ok(bytes) => DatagramOutcome::Respond(bytes),
            Err(_) => DatagramOutcome::Dropped,
        }
    }

    // ── PDU answering (shared by v1/v2c/v3) ────────────────────────────────

    /// Builds the RESPONSE PDU for a request, or `None` for PDU kinds the
    /// responder does not answer (server.py:207–236). `v1` selects RFC 1157
    /// semantics: `noSuchName` instead of v2 exception values, `readOnly`
    /// instead of `notWritable`.
    fn build_response_pdu(&self, request_pdu: &Pdu, v1: bool) -> Option<Pdu> {
        let (varbinds, error_status, error_index) = match request_pdu.kind {
            PduKind::GetRequest => {
                if v1 {
                    v1_get_varbinds(self.source.as_ref(), &request_pdu.varbinds)
                } else {
                    let varbinds = request_pdu
                        .varbinds
                        .iter()
                        .map(|varbind| {
                            let value = self
                                .source
                                .lookup_exact(&varbind.oid)
                                .unwrap_or(SnmpValue::NoSuchObject);
                            VarBind::new(varbind.oid.clone(), value)
                        })
                        .collect();
                    (varbinds, 0, 0)
                }
            }
            PduKind::GetNextRequest => {
                if v1 {
                    v1_get_next_varbinds(self.source.as_ref(), &request_pdu.varbinds)
                } else {
                    let varbinds = request_pdu
                        .varbinds
                        .iter()
                        .map(|varbind| self.lookup_next_varbind(&varbind.oid))
                        .collect();
                    (varbinds, 0, 0)
                }
            }
            PduKind::GetBulkRequest => {
                // GETBULK is a v2c/v3-only PDU (tag 0xA5 does not exist in
                // RFC 1157). The codec decodes a hand-crafted v1 message
                // carrying this tag; answering it would produce a
                // protocol-invalid v1 response (v2-only exception values),
                // so the datagram is dropped like the reference drops
                // protocol-invalid v1 at the boundary.
                if v1 {
                    return None;
                }
                let varbinds = self.build_bulk_varbinds(
                    &request_pdu.varbinds,
                    request_pdu.non_repeaters(),
                    request_pdu.max_repetitions(),
                );
                (varbinds, 0, 0)
            }
            PduKind::SetRequest => {
                let error_index = if request_pdu.varbinds.is_empty() {
                    0
                } else {
                    1
                };
                let status = if v1 {
                    // RFC 1157 has no notWritable (17); readOnly (4) is the
                    // v1 read-only rejection (§8).
                    ErrorStatus::ReadOnly.as_raw()
                } else {
                    ErrorStatus::NotWritable.as_raw()
                };
                (request_pdu.varbinds.clone(), status, error_index)
            }
            _ => return None,
        };
        Some(Pdu {
            kind: PduKind::Response,
            request_id: request_pdu.request_id,
            error_status,
            error_index,
            varbinds,
            v1_trap: None,
        })
    }

    /// One GETNEXT answer (server.py:260–265): the successor pair, or
    /// `endOfMibView` at the requested OID.
    fn lookup_next_varbind(&self, oid: &Oid) -> VarBind {
        match self.source.lookup_next(oid) {
            Some((next_oid, value)) => VarBind::new(next_oid, value),
            None => VarBind::new(oid.clone(), SnmpValue::EndOfMibView),
        }
    }

    /// GETBULK repetition expansion (server.py:267–306), verbatim: the
    /// non-repeaters are answered once; each repeater column advances until it
    /// exhausts (`endOfMibView` is emitted exactly once per frozen column);
    /// total repetition work is clamped to the configured cap.
    fn build_bulk_varbinds(
        &self,
        request_varbinds: &[VarBind],
        non_repeaters: u32,
        max_repetitions: u32,
    ) -> Vec<VarBind> {
        let max_repetitions = max_repetitions.min(self.max_bulk_repetitions);
        let request_oids: Vec<Oid> = request_varbinds.iter().map(|v| v.oid.clone()).collect();
        let split = (non_repeaters as usize).min(request_oids.len());
        let mut response_varbinds: Vec<VarBind> = request_oids[..split]
            .iter()
            .map(|oid| self.lookup_next_varbind(oid))
            .collect();
        let repeaters = &request_oids[split..];
        let mut exhausted = vec![false; repeaters.len()];
        let mut current_oids = repeaters.to_vec();
        for _ in 0..max_repetitions {
            if exhausted.iter().all(|exhausted| *exhausted) {
                // Every repeater column reached endOfMibView: no further
                // repetition can add information.
                break;
            }
            for index in 0..current_oids.len() {
                if exhausted[index] {
                    // Frozen column: endOfMibView was already emitted once.
                    continue;
                }
                let next_varbind = self.lookup_next_varbind(&current_oids[index]);
                if next_varbind.value == SnmpValue::EndOfMibView {
                    exhausted[index] = true;
                } else {
                    current_oids[index] = next_varbind.oid.clone();
                }
                response_varbinds.push(next_varbind);
            }
        }
        response_varbinds
    }

    /// Encodes the response, truncating a GETBULK response to
    /// `max_response_bytes` by halving trailing varbinds (server.py:187–205;
    /// RFC 3416 §4.2.3 — never a tooBig error). An unencodable value drops
    /// the response (server.py:144–152).
    fn encode_response(
        &self,
        request_kind: PduKind,
        response: Pdu,
        encode: impl Fn(&Pdu) -> Result<Vec<u8>, Error>,
    ) -> Result<Vec<u8>, Error> {
        let encoded = encode(&response)?;
        if request_kind != PduKind::GetBulkRequest || encoded.len() <= self.max_response_bytes {
            return Ok(encoded);
        }
        let mut pdu = response;
        loop {
            if pdu.varbinds.is_empty() {
                // An empty PDU is the smallest valid truncation.
                return encode(&pdu);
            }
            let keep = pdu.varbinds.len() / 2;
            pdu.varbinds.truncate(keep);
            let encoded = encode(&pdu)?;
            if encoded.len() <= self.max_response_bytes {
                return Ok(encoded);
            }
        }
    }
}

impl Drop for SnmpResponder {
    fn drop(&mut self) {
        // Wake any pending serve loop so it exits.
        let _ = self.cancel.send(true);
    }
}

/// Whether a request's authoritative engine state is inside the local
/// engine's RFC 3414 §3.2 step-8 time window: same boots, and the
/// msgAuthoritativeEngineTime within ±150 s of the local snmpEngineTime.
fn in_time_window(view: &V3Message, local_engine: &UsmLocalEngine, local_time: u32) -> bool {
    let boots = view.usm_params.engine_boots.max(0) as u32;
    let time = view.usm_params.engine_time.max(0) as u32;
    boots == local_engine.engine_boots && time.abs_diff(local_time) <= TIME_WINDOW_SECONDS
}

/// v1 GET answering (RFC 1157 §4.1.1): every varbind is looked up exactly;
/// the first missing one yields a `noSuchName` error echoing the request
/// varbinds (v2-only exception values do not exist in v1).
fn v1_get_varbinds(
    source: &dyn ResponderSource,
    request_varbinds: &[VarBind],
) -> (Vec<VarBind>, i32, i32) {
    let mut varbinds = Vec::with_capacity(request_varbinds.len());
    for (index, varbind) in request_varbinds.iter().enumerate() {
        match source.lookup_exact(&varbind.oid) {
            Some(value) => varbinds.push(VarBind::new(varbind.oid.clone(), value)),
            None => {
                return (
                    request_varbinds.to_vec(),
                    ErrorStatus::NoSuchName.as_raw(),
                    index as i32 + 1,
                );
            }
        }
    }
    (varbinds, 0, 0)
}

/// v1 GETNEXT answering (RFC 1157 §4.2.2): a missing successor is a
/// `noSuchName` error — the clean end signal for the v1 manager's walk.
fn v1_get_next_varbinds(
    source: &dyn ResponderSource,
    request_varbinds: &[VarBind],
) -> (Vec<VarBind>, i32, i32) {
    let mut varbinds = Vec::with_capacity(request_varbinds.len());
    for (index, varbind) in request_varbinds.iter().enumerate() {
        match source.lookup_next(&varbind.oid) {
            Some((next_oid, value)) => varbinds.push(VarBind::new(next_oid, value)),
            None => {
                return (
                    request_varbinds.to_vec(),
                    ErrorStatus::NoSuchName.as_raw(),
                    index as i32 + 1,
                );
            }
        }
    }
    (varbinds, 0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// End-to-end panic counting: a callback source whose exact lookup panics
    /// for one OID drives the `run_isolated` Err branch, which increments
    /// [`SnmpResponder::panic_count`]; a second, well-behaved request is
    /// answered so `serve(1)` terminates deterministically.
    #[tokio::test]
    async fn serve_counts_handler_panics() {
        let panicking_oid = Oid::from_arcs(&[1, 3, 6, 1, 4, 1, 4242, 1]).expect("valid OID");
        let safe_oid = Oid::from_arcs(&[1, 3, 6, 1, 4, 1, 4242, 2]).expect("valid OID");
        let panicking_oid_for_source = panicking_oid.clone();
        let exact = Arc::new(move |oid: &Oid| {
            if *oid == panicking_oid_for_source {
                panic!("injected responder panic");
            }
            Some(SnmpValue::Integer(7))
        });
        let responder = Arc::new(
            SnmpResponder::bind(ResponderConfig {
                host: "127.0.0.1".to_string(),
                port: 0,
                source: Some(Arc::new(CallbackObjectSource::new(
                    exact,
                    Arc::new(|_oid: &Oid| None),
                ))),
                ..Default::default()
            })
            .await
            .expect("bind test responder"),
        );
        let serve = {
            let responder = Arc::clone(&responder);
            tokio::spawn(async move { responder.serve(1).await })
        };
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind client socket");
        let request = |oid: &Oid| {
            encode_message(&SnmpMessage {
                version: SnmpVersion::V2c,
                community: b"public".to_vec(),
                pdu: Pdu {
                    kind: PduKind::GetRequest,
                    request_id: 1,
                    error_status: 0,
                    error_index: 0,
                    varbinds: vec![VarBind::new(oid.clone(), SnmpValue::Null)],
                    v1_trap: None,
                },
            })
            .expect("request encodes")
        };
        // The panicking request first (no reply), then a healthy one that
        // completes the count-bounded serve. `serve(1)` returns only after
        // both datagrams were processed, so the counter is final.
        client
            .send_to(&request(&panicking_oid), responder.local_addr())
            .await
            .expect("send panicking request");
        client
            .send_to(&request(&safe_oid), responder.local_addr())
            .await
            .expect("send healthy request");
        let handled = serve.await.expect("serve task").expect("serve ok");
        assert_eq!(handled, 1, "the healthy request was answered");
        assert_eq!(
            responder.panic_count(),
            1,
            "the panicking datagram was counted, not silently dropped"
        );
    }

    /// Direct test of the v2c `Err → Dropped` branch (the `Err(_) =>
    /// DatagramOutcome::Dropped` arm of `handle_community`): an unencodable
    /// response is never sent. The reference's unencodable-value case
    /// (`Counter32Value(2**32)`) is unrepresentable with the `SnmpValue`
    /// enum, so the encode failure is injected with a crafted PDU whose
    /// `to_raw` rejects it: `v1_trap` fields on a non-Trap PDU
    /// (pdu.rs:129–133).
    #[tokio::test]
    async fn encode_response_propagates_unencodable_response() {
        let responder = SnmpResponder::bind(ResponderConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            ..Default::default()
        })
        .await
        .expect("bind test responder");
        let unencodable = Pdu {
            kind: PduKind::Response,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: Vec::new(),
            v1_trap: Some(crate::codec::pdu::V1TrapFields {
                enterprise: Oid::from_arcs(&[1, 3, 6]).expect("valid OID"),
                agent_addr: std::net::Ipv4Addr::LOCALHOST,
                generic_trap: 0,
                specific_trap: 0,
                timestamp: 0,
            }),
        };
        let err = responder
            .encode_response(PduKind::GetRequest, unencodable, |pdu| {
                encode_message(&SnmpMessage {
                    version: SnmpVersion::V2c,
                    community: b"public".to_vec(),
                    pdu: pdu.clone(),
                })
                .map_err(Error::Protocol)
            })
            .expect_err("an unencodable response must surface as an error");
        assert!(
            err.to_string().contains("v1_trap"),
            "encode failure surfaced: {err}"
        );
    }

    /// The panic-count test seam in one place: a responder whose exact-lookup
    /// source panics for every OID in `100..100+count` with the message
    /// `injected panic {index}` and answers everything else.
    struct PanicSeam {
        responder: Arc<SnmpResponder>,
    }

    /// A v2c GET request for `oid` (the panic-seam test datagram).
    fn v2c_get_request(oid: &Oid) -> Vec<u8> {
        encode_message(&SnmpMessage {
            version: SnmpVersion::V2c,
            community: b"public".to_vec(),
            pdu: Pdu {
                kind: PduKind::GetRequest,
                request_id: 1,
                error_status: 0,
                error_index: 0,
                varbinds: vec![VarBind::new(oid.clone(), SnmpValue::Null)],
                v1_trap: None,
            },
        })
        .expect("request encodes")
    }

    async fn panic_seam(panic_count: u32) -> PanicSeam {
        let responder = Arc::new(
            SnmpResponder::bind(ResponderConfig {
                host: "127.0.0.1".to_string(),
                port: 0,
                source: Some(Arc::new(CallbackObjectSource::new(
                    Arc::new(move |oid: &Oid| {
                        let last = oid.arcs().last().copied().unwrap_or(0);
                        if (100..100 + panic_count).contains(&last) {
                            panic!("injected panic {}", last - 100);
                        }
                        Some(SnmpValue::Integer(7))
                    }),
                    Arc::new(|_oid: &Oid| None),
                ))),
                ..Default::default()
            })
            .await
            .expect("bind test responder"),
        );
        PanicSeam { responder }
    }

    /// Drives `serve(1)` with `panics` panicking datagrams followed by one
    /// healthy request (the only way to terminate the count-bounded serve);
    /// returns the joined responder.
    async fn serve_after_panics(seam: &PanicSeam, panics: u32) {
        let serve = {
            let responder = Arc::clone(&seam.responder);
            tokio::spawn(async move { responder.serve(1).await })
        };
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind client socket");
        for i in 0..panics {
            let oid = Oid::from_arcs(&[1, 3, 6, 1, 4, 1, 4242, 100 + i]).expect("valid OID");
            client
                .send_to(&v2c_get_request(&oid), seam.responder.local_addr())
                .await
                .expect("send panicking request");
        }
        let safe_oid = Oid::from_arcs(&[1, 3, 6, 1, 4, 1, 4242, 200]).expect("valid OID");
        client
            .send_to(&v2c_get_request(&safe_oid), seam.responder.local_addr())
            .await
            .expect("send healthy request");
        let handled = serve.await.expect("serve task").expect("serve ok");
        assert_eq!(handled, 1, "the healthy request was answered");
    }

    #[tokio::test]
    async fn recent_panics_drains_the_panicking_handlers_payload() {
        // The panic count is paired with *what* panicked: the drained message
        // is the raw payload the handler panicked with (not the prefixed
        // stderr line).
        let seam = panic_seam(1).await;
        serve_after_panics(&seam, 1).await;
        assert_eq!(seam.responder.panic_count(), 1);
        assert_eq!(seam.responder.recent_panics(), vec!["injected panic 0"]);
    }

    #[tokio::test]
    async fn recent_panics_caps_at_thirty_two_and_drops_the_oldest() {
        // 33 distinct panics: the drain keeps the newest 32, the oldest (the
        // very first) is dropped, and each remaining entry pairs one-for-one
        // with a panic_count increment.
        const PANICS: u32 = RECENT_PANICS_CAP as u32 + 1;
        let seam = panic_seam(PANICS).await;
        serve_after_panics(&seam, PANICS).await;
        assert_eq!(seam.responder.panic_count(), u64::from(PANICS));
        let drained = seam.responder.recent_panics();
        assert_eq!(drained.len(), RECENT_PANICS_CAP, "bounded drain");
        assert_eq!(drained[0], "injected panic 1", "the first panic is dropped");
        assert_eq!(
            drained[RECENT_PANICS_CAP - 1],
            format!("injected panic {}", PANICS - 1),
            "the newest panic is retained"
        );
        // Oldest-first ordering: no gaps, no reordering.
        for (index, message) in drained.iter().enumerate() {
            assert_eq!(*message, format!("injected panic {}", index + 1));
        }
    }
}
