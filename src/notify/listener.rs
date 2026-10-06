//! v1/v2c + v3 listeners, drop accounting (← notify/listener.py)
//!
//! `bind()` binds a [`UdpServer`] and spawns the receive task; `recv()` pulls
//! decoded events from an mpsc channel. **Teardown is explicit**: the listener
//! holds a cancellation watch; `Drop` signals it, the task (`select!`ing on the
//! watch in its recv loop) wakes and exits, the channel sender drops, and
//! pending `recv()` calls return `None`.
//!
//! The reference's `on_error` per-drop callback is deliberately dropped
//! (docs/architecture.md §8); `drop_counts()` polling replaces it.

use std::any::Any;
use std::future::Future;
use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::sync::watch;

use crate::codec::message::{SnmpMessage, decode_message, encode_message};
use crate::codec::pdu::{Pdu, PduKind};
use crate::error::{Error, ProtocolError, TransportError};
use crate::mib::MibBundle;
use crate::notify::event::{
    NotificationEvent, notification_event_from_message, notification_event_from_v3_envelope,
};
use crate::notify::replay::{
    DropReason, V3ReceiveVerdict, V3ReplayGuard, drop_reason_from_verdict,
};
use crate::notify::v3_path::{
    V3DecodedDatagram, classify_v3_unmatched, decode_v3_notification_message,
    encode_discovery_report, encode_inform_response, is_discovery_probe,
};
use crate::security::usm::{UsmLocalEngine, UsmModel, UsmUser};
use crate::time::{Clock, SystemClock, SystemRng};
use crate::transport::udp::{ReceivedDatagram, UdpServer};
use crate::types::value::decode_signed_content;

/// Capacity of the decoded-event channel between the receive task and
/// `recv()` callers.
const EVENT_CHANNEL_CAPACITY: usize = 64;
/// At most one drop warning per reason per this interval (listener.py:50).
const DROP_LOG_INTERVAL: Duration = Duration::from_secs(5);
/// SNMPv1 wire version.
const SNMP_V1_VERSION: i64 = 0;
/// SNMPv2c wire version.
const SNMP_V2C_VERSION: i64 = 1;
/// Signed-INTEGER maximum for engine time (usm.py:_clamp_engine_time).
const MAX_ENGINE_TIME: u32 = (1 << 31) - 1;

/// v2c/v3 listener configuration (§5.6).
#[derive(Clone)]
pub struct ListenerConfig {
    /// Bind host (default `0.0.0.0`).
    pub host: String,
    /// Bind port (0 = ephemeral).
    pub port: u16,
    /// Community allow-list for the v1/v2c listener; `None` allows every
    /// community. Ignored by the v3 listener.
    pub communities: Option<Vec<Vec<u8>>>,
    /// Optional MIB bundle enriching events with symbolic names and member
    /// bindings (← listener.py:SnmpNotificationListener(bundle=…)).
    pub bundle: Option<Arc<MibBundle>>,
    /// Clock seam for replay windows and the rate-limited drop log (§7).
    pub clock: Arc<dyn Clock>,
    /// UdpServer queue capacity (test seam).
    pub queue_capacity: usize,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 162,
            communities: None,
            bundle: None,
            clock: Arc::new(SystemClock),
            queue_capacity: 1024,
        }
    }
}

/// Per-reason drop counters, lock-free behind atomics (listener.py:68–69).
///
/// `total()` always equals the sum of `get(reason)` over all nine reasons;
/// the reference's `dropped` vs `drop_counts` reconciliation is a direct
/// consequence.
///
/// These counts cover the *listener's* per-datagram taxonomy (the reference's
/// `DropReason` set). The [`UdpServer`] maintains a separate, independent
/// overflow counter (`UdpServer::dropped`) for datagrams the socket queue
/// dropped before the listener saw them; it is not part of this taxonomy.
#[derive(Debug, Default)]
pub struct DropCounts {
    total: AtomicU64,
    per_reason: [AtomicU64; 9],
}

const ALL_DROP_REASONS: [DropReason; 9] = [
    DropReason::UndecodableBer,
    DropReason::WrongCommunity,
    DropReason::UnsupportedVersion,
    DropReason::WrongUser,
    DropReason::NotNotification,
    DropReason::AuthenticationFailed,
    DropReason::EngineBootsReplay,
    DropReason::OutsideTimeWindow,
    DropReason::DuplicateSalt,
];

impl DropCounts {
    fn record(&self, reason: DropReason) {
        self.total.fetch_add(1, Ordering::Relaxed);
        self.per_reason[reason as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Total number of datagrams dropped since the listener was created.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// The drop count for one reason.
    #[must_use]
    pub fn get(&self, reason: DropReason) -> u64 {
        self.per_reason[reason as usize].load(Ordering::Relaxed)
    }

    /// Per-reason drop counts for every reason observed so far.
    pub fn iter(&self) -> impl Iterator<Item = (DropReason, u64)> + '_ {
        ALL_DROP_REASONS
            .into_iter()
            .map(|reason| (reason, self.get(reason)))
    }
}

/// Counts, rate-limits, and formats drop warnings (listener.py:123–153).
struct DropTracker {
    counts: DropCounts,
    last_log: Mutex<std::collections::HashMap<DropReason, Duration>>,
    clock: Arc<dyn Clock>,
}

impl DropTracker {
    fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            counts: DropCounts::default(),
            last_log: Mutex::new(std::collections::HashMap::new()),
            clock,
        }
    }

    fn record(&self, reason: DropReason, source_address: SocketAddr, data: &[u8]) {
        self.counts.record(reason);
        let now = self.clock.monotonic();
        let should_log = {
            let mut last = self
                .last_log
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if last
                .get(&reason)
                .is_none_or(|last| now.saturating_sub(*last) >= DROP_LOG_INTERVAL)
            {
                last.insert(reason, now);
                true
            } else {
                false
            }
        };
        if should_log {
            let prefix = &data[..data.len().min(8)];
            eprintln!("{}", format_drop_message(reason, source_address, prefix));
        }
    }
}

/// The rate-limited drop-warning line (listener.py:148–153). Kept as a pure
/// function so the format is testable without capturing stderr.
fn format_drop_message(reason: DropReason, source_address: SocketAddr, prefix: &[u8]) -> String {
    let hex = prefix
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    format!(
        "Dropping SNMP notification from {source_address}: reason={reason}, data_prefix=0x{hex}"
    )
}

/// Shared listener state: the event channel, the drop tracker, and the
/// cancellation watch. Both public listener types wrap this. The receive task
/// owns the [`UdpServer`] Arc, so the server outlives this handle for exactly
/// as long as the task is running and drops with it on cancellation.
struct ListenerHandle {
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Result<NotificationEvent, Error>>>>,
    tracker: Arc<DropTracker>,
    cancel: watch::Sender<bool>,
    local_addr: SocketAddr,
}

/// The future returned by [`ListenerHandle::recv`] (and the public `recv`
/// methods): `'static` so a pending recv survives the listener being dropped.
type RecvFuture =
    Pin<Box<dyn Future<Output = Option<Result<NotificationEvent, Error>>> + Send + 'static>>;

impl ListenerHandle {
    fn recv(&self) -> RecvFuture {
        // The future captures only an Arc clone of the receiver, never `&self`:
        // a pending recv() survives the listener being dropped and observes the
        // channel closing as `None`.
        let rx = Arc::clone(&self.rx);
        Box::pin(async move { rx.lock().await.recv().await })
    }

    #[must_use]
    fn drop_counts(&self) -> &DropCounts {
        &self.tracker.counts
    }

    #[must_use]
    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for ListenerHandle {
    fn drop(&mut self) {
        // Wake the receive task so it exits and drops the channel sender.
        let _ = self.cancel.send(true);
    }
}

/// v1/v2c SNMP trap and inform listener (§5.6).
///
/// Serves both community-based versions: v2c traps and informs surface
/// unchanged, and v1 Trap-PDUs from legacy devices surface with their Trap-PDU
/// metadata. Community allow-listing applies to both versions. `None` from
/// [`NotificationListener::recv`] means the listener was dropped (closed).
pub struct NotificationListener {
    handle: ListenerHandle,
}

/// v2c alias (listener.py:400).
pub type V2cNotificationListener = NotificationListener;

impl NotificationListener {
    /// Binds the v1/v2c listener (port 0 = ephemeral).
    pub async fn bind(config: ListenerConfig) -> Result<Self, Error> {
        Ok(Self {
            handle: ListenerHandle::bind_community(config).await?,
        })
    }

    /// Waits for the next matching trap or inform event; `None` once the
    /// listener is closed. The future outlives the listener: after `drop` the
    /// receive task exits and pending calls resolve to `None`.
    pub fn recv(&self) -> RecvFuture {
        self.handle.recv()
    }

    /// The per-reason drop counters (polling API; replaces `on_error`).
    #[must_use]
    pub fn drop_counts(&self) -> &DropCounts {
        self.handle.drop_counts()
    }

    /// The bound local address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.handle.local_addr()
    }
}

/// SNMPv3 notification listener for one configured user (§5.6).
///
/// A persistent [`UsmModel`] codec (its localized-key caches survive across
/// datagrams), a [`V3ReplayGuard`] sharing the listener's clock, and a
/// monotonic anchor for the configured local engine's time keep discovery
/// REPORTs and inform RESPONSEs inside the ±150 s acceptance window of the
/// receiving side.
pub struct V3NotificationListener {
    handle: ListenerHandle,
}

impl V3NotificationListener {
    /// Binds the v3 listener for `user`, whose local authoritative engine
    /// (`local_engine`) is advertised in discovery REPORTs and inform acks.
    pub async fn bind(
        config: ListenerConfig,
        user: UsmUser,
        local_engine: UsmLocalEngine,
    ) -> Result<Self, Error> {
        Ok(Self {
            handle: ListenerHandle::bind_v3(config, user, local_engine).await?,
        })
    }

    /// Waits for the next matching v3 trap or inform event; `None` once the
    /// listener is closed.
    pub fn recv(&self) -> RecvFuture {
        self.handle.recv()
    }

    /// The per-reason drop counters (polling API; replaces `on_error`).
    #[must_use]
    pub fn drop_counts(&self) -> &DropCounts {
        self.handle.drop_counts()
    }

    /// The bound local address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.handle.local_addr()
    }
}

impl ListenerHandle {
    async fn bind_community(config: ListenerConfig) -> Result<Self, Error> {
        let communities = config
            .communities
            .as_ref()
            .map(|list| list.iter().filter(|c| !c.is_empty()).cloned().collect());
        let config = ListenerConfig {
            communities: None,
            ..config
        };
        Self::bind_inner(config, communities, None).await
    }

    async fn bind_v3(
        config: ListenerConfig,
        user: UsmUser,
        local_engine: UsmLocalEngine,
    ) -> Result<Self, Error> {
        Self::bind_inner(config, None, Some((user, local_engine))).await
    }

    async fn bind_inner(
        config: ListenerConfig,
        communities: Option<Vec<Vec<u8>>>,
        v3: Option<(UsmUser, UsmLocalEngine)>,
    ) -> Result<Self, Error> {
        let bundle = config.bundle.clone();
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
        let tracker = Arc::new(DropTracker::new(Arc::clone(&config.clock)));
        let (tx, rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let rx = Arc::new(tokio::sync::Mutex::new(rx));
        let (cancel_tx, cancel_rx) = watch::channel(false);

        match v3 {
            None => {
                tokio::spawn(v2c_receive_loop(
                    Arc::clone(&server),
                    communities,
                    bundle,
                    Arc::clone(&tracker),
                    tx,
                    cancel_rx,
                ));
            }
            Some((user, local_engine)) => {
                let anchor = config.clock.monotonic();
                let codec = UsmModel::new(
                    user.clone(),
                    Vec::new(),
                    Some(local_engine.clone()),
                    Arc::clone(&config.clock),
                    Arc::new(SystemRng),
                );
                let guard = V3ReplayGuard::new(Arc::clone(&config.clock));
                let ctx = V3LoopContext {
                    user,
                    local_engine,
                    codec,
                    guard,
                    anchor,
                    clock: Arc::clone(&config.clock),
                    bundle,
                    tracker: Arc::clone(&tracker),
                };
                tokio::spawn(v3_receive_loop(Arc::clone(&server), ctx, tx, cancel_rx));
            }
        }

        Ok(Self {
            rx,
            tracker,
            cancel: cancel_tx,
            local_addr,
        })
    }
}

/// Runs a synchronous per-datagram handler with panic isolation.
///
/// A panic inside the handler is converted into `Err(Error::Protocol)` — the
/// receive-loop equivalent of the reference raising the exception out of
/// `receive()`. Without this, a panic would kill the receive task and close
/// the channel, which is indistinguishable from teardown (`recv() → None`).
///
/// Shared with the responder's serve loop (the responder logs the panic and
/// keeps serving; it has no event channel to surface into).
pub(crate) fn run_isolated<T>(handler: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
    match catch_unwind(AssertUnwindSafe(handler)) {
        Ok(value) => value,
        Err(payload) => Err(Error::Protocol(ProtocolError::new(panic_message(payload)))),
    }
}

/// Human-readable text for a panic payload (a `&str` or `String` when the
/// panic carried one, otherwise a generic message).
fn panic_message(payload: Box<dyn Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        format!("listener internal panic: {message}")
    } else if let Some(message) = payload.downcast_ref::<String>() {
        format!("listener internal panic: {message}")
    } else {
        "listener internal panic".to_string()
    }
}

/// The outcome of processing one v1/v2c datagram.
enum V2cOutcome {
    /// An event to surface, with an optional INFORM ack datagram to send first.
    Event {
        /// Encoded ack (INFORM_REQUEST only); sent before the event.
        reply: Option<Vec<u8>>,
        /// The decoded notification event (boxed to keep the outcome enum
        /// small).
        event: Box<NotificationEvent>,
    },
    /// The datagram was dropped (already counted).
    Dropped,
}

/// The outcome of processing one v3 datagram.
enum V3Outcome {
    /// An event to surface, with an optional INFORM ack datagram to send first.
    Event {
        /// Encoded ack (INFORM_REQUEST only); sent before the event.
        reply: Option<Vec<u8>>,
        /// The decoded notification event (boxed to keep the outcome enum
        /// small).
        event: Box<NotificationEvent>,
    },
    /// A discovery REPORT to send back; no event.
    Reply { reply: Vec<u8> },
    /// The datagram was dropped (already counted).
    Dropped,
}

/// Whether a reply-send step finished and how the loop should continue.
#[derive(Debug, PartialEq, Eq)]
enum Dispatch {
    /// The reply was sent; proceed with the event.
    Continue,
    /// The reply failed and the `Err` event was sent; skip the event.
    ErrSent,
    /// The event channel closed; the loop must break.
    ChannelClosed,
}

/// Sends one reply datagram, surfacing a transport failure as an `Err` event
/// on the channel (the reference raises `TransportError` out of `receive()`;
/// listener.py:249, 397). `Err` responses are never silently ignored.
async fn dispatch_reply<F, Fut>(
    send: F,
    tx: &mpsc::Sender<Result<NotificationEvent, Error>>,
) -> Dispatch
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), TransportError>>,
{
    match send().await {
        Ok(()) => Dispatch::Continue,
        Err(error) => {
            if tx.send(Err(Error::Transport(error))).await.is_ok() {
                Dispatch::ErrSent
            } else {
                Dispatch::ChannelClosed
            }
        }
    }
}

/// The v1/v2c receive loop (listener.py:198–249). Every datagram that cannot
/// surface as an event is counted as a drop; a handler panic or an ack
/// encode/send failure surfaces as an `Err` event (the reference raises out
/// of `receive()`); the loop never terminates on a bad datagram.
async fn v2c_receive_loop(
    server: Arc<UdpServer>,
    communities: Option<Vec<Vec<u8>>>,
    bundle: Option<Arc<MibBundle>>,
    tracker: Arc<DropTracker>,
    tx: mpsc::Sender<Result<NotificationEvent, Error>>,
    mut cancel: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() {
                    break;
                }
            }
            datagram = server.receive() => {
                let Some(datagram) = datagram else { break; };
                let outcome = run_isolated(|| {
                    handle_v2c_datagram(&datagram, &communities, &tracker, bundle.as_deref())
                });
                match outcome {
                    Ok(V2cOutcome::Event { reply, event }) => {
                        if let Some(reply) = reply {
                            match dispatch_reply(
                                || server.sendto(&reply, datagram.source_address),
                                &tx,
                            ).await
                            {
                                Dispatch::Continue => {}
                                Dispatch::ErrSent => continue,
                                Dispatch::ChannelClosed => break,
                            }
                        }
                        if tx.send(Ok(*event)).await.is_err() {
                            break;
                        }
                    }
                    Ok(V2cOutcome::Dropped) => {}
                    Err(error) => {
                        if tx.send(Err(error)).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Processes one v1/v2c datagram synchronously (listener.py:198–249).
///
/// Decode/community/notification-kind failures are counted drops; an INFORM
/// ack-encode failure or an event-construction failure surfaces as `Err`
/// (the reference raises both out of `receive()`), and the loop forwards the
/// error to the channel.
fn handle_v2c_datagram(
    datagram: &ReceivedDatagram,
    communities: &Option<Vec<Vec<u8>>>,
    tracker: &DropTracker,
    bundle: Option<&MibBundle>,
) -> Result<V2cOutcome, Error> {
    let message = match tracked_decode_message(&datagram.data) {
        Ok(message) => message,
        Err(_) => {
            tracker.record(
                classify_v2c_drop(&datagram.data),
                datagram.source_address,
                &datagram.data,
            );
            return Ok(V2cOutcome::Dropped);
        }
    };
    if !community_allowed(communities, &message.community) {
        tracker.record(
            DropReason::WrongCommunity,
            datagram.source_address,
            &datagram.data,
        );
        return Ok(V2cOutcome::Dropped);
    }
    if !matches!(
        message.pdu.kind,
        PduKind::Trap | PduKind::SnmpV2Trap | PduKind::InformRequest
    ) {
        tracker.record(
            DropReason::NotNotification,
            datagram.source_address,
            &datagram.data,
        );
        return Ok(V2cOutcome::Dropped);
    }
    let reply = if message.pdu.kind == PduKind::InformRequest {
        Some(encode_v2c_inform_ack(&message).map_err(Error::Protocol)?)
    } else {
        None
    };
    let event = notification_event_from_message(&message, Some(datagram.source_address), bundle)
        .map_err(Error::Protocol)?;
    Ok(V2cOutcome::Event {
        reply,
        event: Box::new(event),
    })
}

/// Encodes an INFORM RESPONSE echoing the request id and varbinds
/// (listener.py:237–249).
fn encode_v2c_inform_ack(message: &SnmpMessage) -> Result<Vec<u8>, ProtocolError> {
    let response = SnmpMessage {
        version: message.version,
        community: message.community.clone(),
        pdu: Pdu {
            kind: PduKind::Response,
            request_id: message.pdu.request_id,
            error_status: 0,
            error_index: 0,
            varbinds: message.pdu.varbinds.clone(),
            v1_trap: None,
        },
    };
    encode_message(&response)
}

/// Immutable v3 listener context shared across datagrams in the receive loop.
struct V3LoopContext {
    user: UsmUser,
    local_engine: UsmLocalEngine,
    codec: UsmModel,
    guard: V3ReplayGuard,
    anchor: Duration,
    clock: Arc<dyn Clock>,
    bundle: Option<Arc<MibBundle>>,
    tracker: Arc<DropTracker>,
}

/// The v3 receive loop (listener.py:303–397): probe REPORT, auth/priv decode,
/// replay guard, inform ack. An ack/report encode or send failure, or a
/// handler panic, surfaces as an `Err` event (the reference raises out of
/// `receive()`); everything else is a counted drop.
async fn v3_receive_loop(
    server: Arc<UdpServer>,
    ctx: V3LoopContext,
    tx: mpsc::Sender<Result<NotificationEvent, Error>>,
    mut cancel: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() {
                    break;
                }
            }
            datagram = server.receive() => {
                let Some(datagram) = datagram else { break; };
                let current_engine_time =
                    current_engine_time(&ctx.local_engine, ctx.anchor, ctx.clock.as_ref());
                let outcome = run_isolated(|| {
                    handle_v3_datagram(&datagram, &ctx, current_engine_time)
                });
                match outcome {
                    Ok(V3Outcome::Event { reply, event }) => {
                        if let Some(reply) = reply {
                            match dispatch_reply(
                                || server.sendto(&reply, datagram.source_address),
                                &tx,
                            ).await
                            {
                                Dispatch::Continue => {}
                                Dispatch::ErrSent => continue,
                                Dispatch::ChannelClosed => break,
                            }
                        }
                        if tx.send(Ok(*event)).await.is_err() {
                            break;
                        }
                    }
                    Ok(V3Outcome::Reply { reply }) => {
                        match dispatch_reply(
                            || server.sendto(&reply, datagram.source_address),
                            &tx,
                        ).await
                        {
                            Dispatch::ChannelClosed => break,
                            Dispatch::Continue | Dispatch::ErrSent => {}
                        }
                    }
                    Ok(V3Outcome::Dropped) => {}
                    Err(error) => {
                        if tx.send(Err(error)).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Processes one v3 datagram synchronously; `Ok(Dropped)` means it was
/// counted as a drop or silently skipped (probe REPORT). `Err` surfaces an
/// ack-encode failure or a handler panic via the loop.
fn handle_v3_datagram(
    datagram: &ReceivedDatagram,
    ctx: &V3LoopContext,
    current_engine_time: u32,
) -> Result<V3Outcome, Error> {
    let decoded = match tracked_decode_v3(&datagram.data) {
        Ok(decoded) => decoded,
        Err(_) => {
            ctx.tracker.record(
                DropReason::UndecodableBer,
                datagram.source_address,
                &datagram.data,
            );
            return Ok(V3Outcome::Dropped);
        }
    };
    if is_discovery_probe(&decoded) {
        // A REPORT for an empty-engineID probe; encode failure is itself a
        // drop (listener.py:316–331). A send failure surfaces as an `Err`
        // event via the loop's `Reply` dispatch.
        return match encode_discovery_report(&decoded, &ctx.local_engine, Some(current_engine_time))
        {
            Ok(report) => Ok(V3Outcome::Reply { reply: report }),
            Err(_) => {
                ctx.tracker.record(
                    DropReason::UndecodableBer,
                    datagram.source_address,
                    &datagram.data,
                );
                Ok(V3Outcome::Dropped)
            }
        };
    }

    let envelope = match decode_v3_notification_message(&decoded, &ctx.user, &ctx.codec) {
        Ok(Some(envelope)) => envelope,
        Ok(None) => {
            ctx.tracker.record(
                classify_v3_unmatched(&decoded, &ctx.user),
                datagram.source_address,
                &datagram.data,
            );
            return Ok(V3Outcome::Dropped);
        }
        Err(Error::Authentication) => {
            ctx.tracker.record(
                DropReason::AuthenticationFailed,
                datagram.source_address,
                &datagram.data,
            );
            return Ok(V3Outcome::Dropped);
        }
        Err(_) => {
            ctx.tracker.record(
                DropReason::UndecodableBer,
                datagram.source_address,
                &datagram.data,
            );
            return Ok(V3Outcome::Dropped);
        }
    };

    let params = &envelope.view.usm_params;
    let verdict = ctx.guard.check(
        &params.engine_id,
        params.engine_boots,
        params.engine_time,
        &ctx.user.username,
        &params.priv_params,
    );
    if verdict != V3ReceiveVerdict::Accept {
        ctx.tracker.record(
            drop_reason_from_verdict(verdict),
            datagram.source_address,
            &datagram.data,
        );
        return Ok(V3Outcome::Dropped);
    }

    let reply = if envelope.pdu.kind == PduKind::InformRequest {
        Some(encode_inform_response(
            &envelope,
            &ctx.user,
            &ctx.local_engine,
            &ctx.codec,
            Some(current_engine_time),
        )?)
    } else {
        None
    };
    let event = notification_event_from_v3_envelope(
        &envelope,
        Some(datagram.source_address),
        ctx.bundle.as_deref(),
    )
    .map_err(Error::Protocol)?;
    Ok(V3Outcome::Event {
        reply,
        event: Box::new(event),
    })
}

/// The listener's monotonic-advanced engine time (listener.py:290–301): the
/// configured `engine_time` advanced by the elapsed monotonic time, clamped to
/// the signed-INTEGER maximum.
fn current_engine_time(local_engine: &UsmLocalEngine, anchor: Duration, clock: &dyn Clock) -> u32 {
    let elapsed = clock.monotonic().saturating_sub(anchor).as_secs() as u32;
    local_engine
        .engine_time
        .saturating_add(elapsed)
        .min(MAX_ENGINE_TIME)
}

/// Picks the drop reason for a datagram that failed the v1/v2c decode path
/// (listener.py:419–427).
fn classify_v2c_drop(data: &[u8]) -> DropReason {
    match peek_message_version(data) {
        Ok(version) if !(version == SNMP_V1_VERSION || version == SNMP_V2C_VERSION) => {
            DropReason::UnsupportedVersion
        }
        _ => DropReason::UndecodableBer,
    }
}

/// Test-only decode counters, scoped to this module so the decode-once
/// pinning tests are immune to decodes performed by other tests.
#[cfg(test)]
static TEST_V2C_DECODE_COUNT: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static TEST_V3_DECODE_COUNT: AtomicU64 = AtomicU64::new(0);

/// Decodes a v1/v2c message, counting the call for the decode-exactly-once
/// pin (item 4a; the reference's `decode_message` monkeypatch).
fn tracked_decode_message(data: &[u8]) -> Result<SnmpMessage, ProtocolError> {
    #[cfg(test)]
    TEST_V2C_DECODE_COUNT.fetch_add(1, Ordering::Relaxed);
    decode_message(data)
}

/// Decodes a v3 message header, counting the call for the decode-exactly-once
/// pin (item 4a; the reference's `decode_v3_message` monkeypatch).
fn tracked_decode_v3(data: &[u8]) -> Result<V3DecodedDatagram, ProtocolError> {
    #[cfg(test)]
    TEST_V3_DECODE_COUNT.fetch_add(1, Ordering::Relaxed);
    V3DecodedDatagram::decode(data)
}

/// Decodes just the version INTEGER of a message, without a full decode
/// (listener.py:430–440). Shared with the responder's version dispatch.
pub(crate) fn peek_message_version(data: &[u8]) -> Result<i64, ProtocolError> {
    let (tag, content, _offset) = crate::codec::decode_tlv(data, 0)?;
    if tag != 0x30 {
        return Err(ProtocolError::new(format!(
            "Expected SNMP message SEQUENCE, found 0x{tag:02x}"
        )));
    }
    let (tag, raw, _offset) = crate::codec::decode_tlv(content, 0)?;
    if tag != 0x02 {
        return Err(ProtocolError::new(format!(
            "Expected version INTEGER, found 0x{tag:02x}"
        )));
    }
    if raw.is_empty() {
        return Err(ProtocolError::new("INTEGER content cannot be empty"));
    }
    decode_signed_content(raw)
}

/// Community allow-listing (listener.py:403–412). Shared with the responder.
pub(crate) fn community_allowed(communities: &Option<Vec<Vec<u8>>>, community: &[u8]) -> bool {
    match communities {
        None => true,
        Some(allowed) => allowed.iter().any(|candidate| candidate == community),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::Clock;
    use crate::types::varbind::VarBind;
    use std::time::Duration;

    /// A controllable clock for the rate-limit tests.
    struct FakeClock {
        now: Mutex<Duration>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                now: Mutex::new(Duration::ZERO),
            }
        }

        fn advance(&self, seconds: u64) {
            *self.now.lock().unwrap() += Duration::from_secs(seconds);
        }
    }

    impl Clock for FakeClock {
        fn monotonic(&self) -> Duration {
            *self.now.lock().unwrap()
        }

        fn unix(&self) -> u64 {
            0
        }
    }

    /// Serializes the tests whose handlers bump the shared decode counters
    /// (the two `handle_v2c_datagram` tests and the two decode-once pins).
    static DECODE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[test]
    fn drop_counts_reconcile_total_with_per_reason() {
        let counts = DropCounts::default();
        counts.record(DropReason::UndecodableBer);
        counts.record(DropReason::UndecodableBer);
        counts.record(DropReason::WrongCommunity);
        assert_eq!(counts.total(), 3);
        assert_eq!(counts.get(DropReason::UndecodableBer), 2);
        assert_eq!(counts.get(DropReason::WrongCommunity), 1);
        assert_eq!(counts.get(DropReason::NotNotification), 0);
        let sum: u64 = counts.iter().map(|(_reason, count)| count).sum();
        assert_eq!(sum, counts.total());
    }

    #[test]
    fn drop_warning_format_matches_reference() {
        let message = format_drop_message(
            DropReason::UndecodableBer,
            "127.0.0.1:40040".parse().unwrap(),
            b"not-snmp",
        );
        assert!(message.contains("undecodable-ber"), "{message}");
        assert!(message.contains("127.0.0.1:40040"), "{message}");
        assert!(message.contains("0x6e6f742d736e6d70"), "{message}");
    }

    #[test]
    fn drop_log_is_rate_limited_per_reason() {
        let fake = Arc::new(FakeClock::new());
        let tracker = DropTracker::new(fake.clone());
        // First record logs.
        tracker.record(
            DropReason::UndecodableBer,
            "127.0.0.1:1".parse().unwrap(),
            b"x",
        );
        let logged = tracker
            .last_log
            .lock()
            .unwrap()
            .get(&DropReason::UndecodableBer)
            .copied();
        assert_eq!(logged, Some(Duration::ZERO));
        // A second drop within the interval keeps the same log timestamp.
        tracker.record(
            DropReason::UndecodableBer,
            "127.0.0.1:1".parse().unwrap(),
            b"x",
        );
        let logged_again = tracker
            .last_log
            .lock()
            .unwrap()
            .get(&DropReason::UndecodableBer)
            .copied();
        assert_eq!(logged, logged_again);
        // After the interval a new drop logs again.
        fake.advance(6);
        tracker.record(
            DropReason::UndecodableBer,
            "127.0.0.1:1".parse().unwrap(),
            b"x",
        );
        let logged_later = tracker
            .last_log
            .lock()
            .unwrap()
            .get(&DropReason::UndecodableBer)
            .copied();
        assert_eq!(logged_later, Some(Duration::from_secs(6)));
        // A different reason is not suppressed by the first.
        tracker.record(
            DropReason::WrongCommunity,
            "127.0.0.1:1".parse().unwrap(),
            b"y",
        );
        assert_eq!(
            tracker
                .last_log
                .lock()
                .unwrap()
                .get(&DropReason::WrongCommunity)
                .copied(),
            Some(Duration::from_secs(6))
        );
    }

    #[test]
    fn classify_v2c_drop_picks_unsupported_version() {
        // 30 07 02 01 02 ... : a SEQUENCE whose version INTEGER is 2.
        let mut bytes = vec![0x30, 0x07, 0x02, 0x01, 0x02];
        bytes.extend_from_slice(&[0x04, 0x02, 0x61, 0x61]);
        assert_eq!(classify_v2c_drop(&bytes), DropReason::UnsupportedVersion);
        assert_eq!(classify_v2c_drop(b"not-snmp"), DropReason::UndecodableBer);
        // A valid version (0) whose message is otherwise malformed: the outer
        // decode failed, so UNDECODABLE_BER.
        let mut bytes = vec![0x30, 0x07, 0x02, 0x01, 0x00];
        bytes.extend_from_slice(&[0x04, 0x02, 0x61, 0x61]);
        assert_eq!(classify_v2c_drop(&bytes), DropReason::UndecodableBer);
    }

    #[test]
    fn community_allowed_matches_reference() {
        assert!(community_allowed(&None, b"public"));
        assert!(community_allowed(
            &Some(vec![b"private".to_vec()]),
            b"private"
        ));
        assert!(!community_allowed(
            &Some(vec![b"private".to_vec()]),
            b"public"
        ));
    }

    #[test]
    fn current_engine_time_advances_and_clamps() {
        let fake = FakeClock::new();
        let anchor = Duration::ZERO;
        let engine = UsmLocalEngine {
            engine_id: vec![1],
            engine_boots: 1,
            engine_time: 100,
        };
        assert_eq!(current_engine_time(&engine, anchor, &fake), 100);
        fake.advance(149);
        assert_eq!(current_engine_time(&engine, anchor, &fake), 249);
        fake.advance(2);
        assert_eq!(current_engine_time(&engine, anchor, &fake), 251);
        let maxed = UsmLocalEngine {
            engine_id: vec![1],
            engine_boots: 1,
            engine_time: MAX_ENGINE_TIME - 5,
        };
        fake.advance(100);
        assert_eq!(current_engine_time(&maxed, anchor, &fake), MAX_ENGINE_TIME);
    }

    #[test]
    fn config_defaults_are_sane() {
        let config = ListenerConfig::default();
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, 162);
        assert!(config.communities.is_none());
    }

    // ── panic isolation + ack-failure surfacing (review items 1, 3) ────────

    #[test]
    fn run_isolated_surfaces_str_panic_as_protocol_error() {
        let err = run_isolated(|| -> Result<u32, Error> { panic!("boom") }).unwrap_err();
        assert!(
            err.to_string().contains("listener internal panic: boom"),
            "{err}"
        );
    }

    #[test]
    fn run_isolated_surfaces_string_panic_as_protocol_error() {
        let err =
            run_isolated(|| -> Result<u32, Error> { std::panic::panic_any(String::from("boom")) })
                .unwrap_err();
        assert!(
            err.to_string().contains("listener internal panic: boom"),
            "{err}"
        );
    }

    #[test]
    fn run_isolated_passes_handler_errors_through() {
        let err = run_isolated(|| -> Result<u32, Error> {
            Err(Error::Protocol(ProtocolError::new("handler failure")))
        })
        .unwrap_err();
        assert!(err.to_string().contains("handler failure"), "{err}");
    }

    #[test]
    fn run_isolated_passes_values_through() {
        assert_eq!(run_isolated(|| Ok(42u32)).unwrap(), 42);
    }

    #[tokio::test]
    async fn dispatch_reply_send_failure_surfaces_err_event() {
        let (tx, mut rx) = mpsc::channel(4);
        let dispatch = dispatch_reply(
            || async { Err(TransportError::Io("boom".to_string())) },
            &tx,
        )
        .await;
        assert_eq!(
            dispatch,
            Dispatch::ErrSent,
            "failure is not silently ignored"
        );
        let item = rx.recv().await.expect("Err event delivered");
        assert!(
            matches!(item, Err(Error::Transport(_))),
            "expected Err(Transport), got {item:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_reply_send_success_is_silent() {
        let (tx, mut rx) = mpsc::channel(4);
        let dispatch = dispatch_reply(|| async { Ok(()) }, &tx).await;
        assert_eq!(dispatch, Dispatch::Continue);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), rx.recv())
                .await
                .is_err(),
            "a successful reply sends no event"
        );
    }

    #[tokio::test]
    async fn handle_v2c_datagram_surfaces_trap_event_without_ack() {
        let _guard = DECODE_TEST_LOCK.lock().await;
        let tracker = DropTracker::new(Arc::new(FakeClock::new()));
        let datagram = ReceivedDatagram {
            data: v2c_message(b"public", 7, PduKind::SnmpV2Trap),
            source_address: "127.0.0.1:40000".parse().unwrap(),
        };
        match handle_v2c_datagram(&datagram, &None, &tracker, None).unwrap() {
            V2cOutcome::Event { reply, event } => {
                assert!(reply.is_none(), "traps get no ack");
                assert_eq!(event.request_id, 7);
            }
            V2cOutcome::Dropped => panic!("valid trap must not be dropped"),
        }
    }

    #[tokio::test]
    async fn handle_v2c_datagram_encodes_inform_ack() {
        let _guard = DECODE_TEST_LOCK.lock().await;
        let tracker = DropTracker::new(Arc::new(FakeClock::new()));
        let datagram = ReceivedDatagram {
            data: v2c_message(b"public", 7, PduKind::InformRequest),
            source_address: "127.0.0.1:40000".parse().unwrap(),
        };
        match handle_v2c_datagram(&datagram, &None, &tracker, None).unwrap() {
            V2cOutcome::Event { reply, event } => {
                let ack = reply.expect("informs get an ack");
                let decoded = decode_message(&ack).unwrap();
                assert_eq!(decoded.pdu.kind, PduKind::Response);
                assert_eq!(decoded.pdu.request_id, event.request_id);
            }
            V2cOutcome::Dropped => panic!("valid inform must not be dropped"),
        }
    }

    // ── decode-exactly-once pins (review item 4a) ──────────────────────────

    #[tokio::test]
    async fn listener_decodes_v2c_message_once_per_datagram() {
        // Port of test_notification_listener_decodes_message_once_per_datagram
        // (and the v2c half of the decode-count tests): every datagram is
        // decoded exactly once, even when it fails (the version peek on the
        // failure path is a TLV walk, not a decode).
        let _guard = DECODE_TEST_LOCK.lock().await;
        TEST_V2C_DECODE_COUNT.store(0, Ordering::Relaxed);
        let listener = NotificationListener::bind(ListenerConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            clock: Arc::new(FakeClock::new()),
            ..Default::default()
        })
        .await
        .unwrap();
        let addr = listener.local_addr();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for datagram in [
            b"not-snmp".to_vec(),
            vec![0x30, 0x05, 0x02, 0x01, 0x01],
            v2c_message(b"public", 9, PduKind::SnmpV2Trap),
        ] {
            socket.send_to(&datagram, addr).await.unwrap();
        }
        let event = listener
            .recv()
            .await
            .expect("channel open")
            .expect("no error");
        assert_eq!(event.request_id, 9);
        assert_eq!(
            TEST_V2C_DECODE_COUNT.load(Ordering::Relaxed),
            3,
            "three datagrams, three decodes — never more"
        );
    }

    #[tokio::test]
    async fn listener_decodes_v3_header_once_per_datagram() {
        // Port of test_v3_notification_listener_decodes_header_once_per_datagram
        // and _decode_count_scales_with_datagrams: the header is decoded once
        // at the listener boundary (probe detection, auth verify, and scoped
        // decode all reuse the view).
        let _guard = DECODE_TEST_LOCK.lock().await;
        TEST_V3_DECODE_COUNT.store(0, Ordering::Relaxed);
        let user = UsmUser::new(
            "listener".to_string(),
            crate::security::usm::kdf::AuthProtocol::None_,
            crate::security::usm::AuthKey::Passphrase(Vec::new()),
            crate::security::usm::kdf::PrivProtocol::None_,
            crate::security::usm::PrivKey::Passphrase(Vec::new()),
        )
        .unwrap();
        let peer_engine = UsmLocalEngine {
            engine_id: [vec![0x80, 0x00, 0x01, 0x02, 0x03], vec![0x41; 12]].concat(),
            engine_boots: 7,
            engine_time: 111,
        };
        let probe_model = UsmModel::new(
            user.clone(),
            Vec::new(),
            None,
            Arc::new(SystemClock),
            Arc::new(SystemRng),
        );
        let probe = probe_model.build_discovery_probe().unwrap();
        let wrong_user = v3_raw_notification(
            &UsmUser::new(
                "other".to_string(),
                crate::security::usm::kdf::AuthProtocol::None_,
                crate::security::usm::AuthKey::Passphrase(Vec::new()),
                crate::security::usm::kdf::PrivProtocol::None_,
                crate::security::usm::PrivKey::Passphrase(Vec::new()),
            )
            .unwrap(),
            1,
            peer_engine.clone(),
        );
        let valid = v3_raw_notification(&user, 2, peer_engine);

        let listener = V3NotificationListener::bind(
            ListenerConfig {
                host: "127.0.0.1".to_string(),
                port: 0,
                clock: Arc::new(FakeClock::new()),
                ..Default::default()
            },
            user,
            UsmLocalEngine {
                engine_id: [vec![0x80, 0x00, 0x01, 0x02, 0x03], vec![0x42; 12]].concat(),
                engine_boots: 7,
                engine_time: 111,
            },
        )
        .await
        .unwrap();
        let addr = listener.local_addr();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for datagram in [probe, wrong_user, b"not-snmp".to_vec(), valid] {
            socket.send_to(&datagram, addr).await.unwrap();
        }
        let event = listener
            .recv()
            .await
            .expect("channel open")
            .expect("no error");
        assert_eq!(event.request_id, 2);
        assert_eq!(
            TEST_V3_DECODE_COUNT.load(Ordering::Relaxed),
            4,
            "four datagrams, four header decodes — never more"
        );
    }

    /// Encodes a v2c trap/inform message (test-module fixture).
    fn v2c_message(community: &[u8], request_id: u32, kind: PduKind) -> Vec<u8> {
        encode_message(&SnmpMessage {
            version: crate::codec::message::SnmpVersion::V2c,
            community: community.to_vec(),
            pdu: Pdu {
                kind,
                request_id,
                error_status: 0,
                error_index: 0,
                varbinds: vec![VarBind::new(
                    crate::types::oid::Oid::from_arcs(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap(),
                    crate::types::value::SnmpValue::Integer(7),
                )],
                v1_trap: None,
            },
        })
        .unwrap()
    }

    /// Wraps a trap for `user` with `engine` authoritative (test-module
    /// fixture).
    fn v3_raw_notification(user: &UsmUser, request_id: u32, engine: UsmLocalEngine) -> Vec<u8> {
        let model = UsmModel::new(
            user.clone(),
            Vec::new(),
            Some(engine),
            Arc::new(SystemClock),
            Arc::new(SystemRng),
        );
        model
            .wrap_pdu(&Pdu {
                kind: PduKind::SnmpV2Trap,
                request_id,
                error_status: 0,
                error_index: 0,
                varbinds: vec![VarBind::new(
                    crate::types::oid::Oid::from_arcs(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap(),
                    crate::types::value::SnmpValue::Integer(7),
                )],
                v1_trap: None,
            })
            .unwrap()
    }
}
