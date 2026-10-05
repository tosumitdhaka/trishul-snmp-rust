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

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::sync::watch;

use crate::codec::message::{SnmpMessage, decode_message, encode_message};
use crate::codec::pdu::{Pdu, PduKind};
use crate::error::{Error, ProtocolError};
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

/// The v1/v2c receive loop (listener.py:198–249). Every datagram that cannot
/// surface as an event is counted as a drop; the loop never terminates on a
/// bad datagram.
async fn v2c_receive_loop(
    server: Arc<UdpServer>,
    communities: Option<Vec<Vec<u8>>>,
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
                if let Some(event) = handle_v2c_datagram(
                    &datagram,
                    &communities,
                    &tracker,
                    &server,
                ).await
                    && tx.send(Ok(event)).await.is_err()
                {
                    break;
                }
            }
        }
    }
}

async fn handle_v2c_datagram(
    datagram: &ReceivedDatagram,
    communities: &Option<Vec<Vec<u8>>>,
    tracker: &DropTracker,
    server: &UdpServer,
) -> Option<NotificationEvent> {
    let message = match decode_message(&datagram.data) {
        Ok(message) => message,
        Err(_) => {
            tracker.record(
                classify_v2c_drop(&datagram.data),
                datagram.source_address,
                &datagram.data,
            );
            return None;
        }
    };
    if !community_allowed(communities, &message.community) {
        tracker.record(
            DropReason::WrongCommunity,
            datagram.source_address,
            &datagram.data,
        );
        return None;
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
        return None;
    }
    if message.pdu.kind == PduKind::InformRequest {
        send_v2c_inform_ack(&message, datagram.source_address, server).await;
    }
    notification_event_from_message(&message, Some(datagram.source_address)).ok()
}

/// Acknowledges an INFORM with a RESPONSE echoing the request id and varbinds
/// (listener.py:237–249).
async fn send_v2c_inform_ack(message: &SnmpMessage, addr: SocketAddr, server: &UdpServer) {
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
    if let Ok(encoded) = encode_message(&response) {
        let _ = server.sendto(&encoded, addr).await;
    }
}

/// Immutable v3 listener context shared across datagrams in the receive loop.
struct V3LoopContext {
    user: UsmUser,
    local_engine: UsmLocalEngine,
    codec: UsmModel,
    guard: V3ReplayGuard,
    anchor: Duration,
    clock: Arc<dyn Clock>,
    tracker: Arc<DropTracker>,
}

/// The v3 receive loop (listener.py:303–397): probe REPORT, auth/priv decode,
/// replay guard, inform ack. An inform-ack encode failure surfaces as an
/// `Err` event (the reference raises it out of `receive()`); everything else
/// is a counted drop.
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
                match handle_v3_datagram(&datagram, &ctx, current_engine_time, &server).await {
                    Ok(Some(event)) => {
                        if tx.send(Ok(event)).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {}
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

/// Processes one v3 datagram; `Ok(None)` means it was dropped (counted) or
/// silently skipped (probe REPORT). `Err` surfaces an inform-ack failure.
async fn handle_v3_datagram(
    datagram: &ReceivedDatagram,
    ctx: &V3LoopContext,
    current_engine_time: u32,
    server: &UdpServer,
) -> Result<Option<NotificationEvent>, Error> {
    let decoded = match V3DecodedDatagram::decode(&datagram.data) {
        Ok(decoded) => decoded,
        Err(_) => {
            ctx.tracker.record(
                DropReason::UndecodableBer,
                datagram.source_address,
                &datagram.data,
            );
            return Ok(None);
        }
    };
    if is_discovery_probe(&decoded) {
        // A REPORT for an empty-engineID probe; encode failure is itself a
        // drop (listener.py:316–331).
        match encode_discovery_report(&decoded, &ctx.local_engine, Some(current_engine_time)) {
            Ok(report) => {
                let _ = server.sendto(&report, datagram.source_address).await;
            }
            Err(_) => {
                ctx.tracker.record(
                    DropReason::UndecodableBer,
                    datagram.source_address,
                    &datagram.data,
                );
            }
        }
        return Ok(None);
    }

    let envelope = match decode_v3_notification_message(&decoded, &ctx.user, &ctx.codec) {
        Ok(Some(envelope)) => envelope,
        Ok(None) => {
            ctx.tracker.record(
                classify_v3_unmatched(&decoded, &ctx.user),
                datagram.source_address,
                &datagram.data,
            );
            return Ok(None);
        }
        Err(Error::Authentication) => {
            ctx.tracker.record(
                DropReason::AuthenticationFailed,
                datagram.source_address,
                &datagram.data,
            );
            return Ok(None);
        }
        Err(_) => {
            ctx.tracker.record(
                DropReason::UndecodableBer,
                datagram.source_address,
                &datagram.data,
            );
            return Ok(None);
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
        return Ok(None);
    }

    if envelope.pdu.kind == PduKind::InformRequest {
        let response = encode_inform_response(
            &envelope,
            &ctx.user,
            &ctx.local_engine,
            &ctx.codec,
            Some(current_engine_time),
        )?;
        let _ = server.sendto(&response, datagram.source_address).await;
    }
    Ok(Some(
        notification_event_from_v3_envelope(&envelope, Some(datagram.source_address))
            .map_err(Error::Protocol)?,
    ))
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

/// Decodes just the version INTEGER of a message, without a full decode
/// (listener.py:430–440).
fn peek_message_version(data: &[u8]) -> Result<i64, ProtocolError> {
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

/// Community allow-listing (listener.py:403–412).
fn community_allowed(communities: &Option<Vec<Vec<u8>>>, community: &[u8]) -> bool {
    match communities {
        None => true,
        Some(allowed) => allowed.iter().any(|candidate| candidate == community),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::Clock;
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
}
