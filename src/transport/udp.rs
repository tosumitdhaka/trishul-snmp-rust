//! UdpClient, UdpServer (bounded queue, drop counters) (← udp.py)

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::error::TransportError;
use crate::time::{Clock, SystemClock};

/// Maximum datagram size accepted by the transports (reference default).
pub const MAX_DATAGRAM_SIZE: usize = 65535;

/// Transport abstraction shared by the session, dispatcher, and tests.
///
/// `open`/`close` are idempotent. `receive` applies its own deadline and
/// reports `TransportError::Timeout` on expiry — dispatcher deadlines are
/// built on top of that (tokio::time, not the Clock trait; §7).
///
/// Methods return boxed futures so the trait stays `dyn`-compatible
/// (`async fn` in traits is not object-safe).
pub trait UdpTransport: Send + Sync {
    /// Create and connect/bind the underlying socket.
    fn open(&self) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>>;
    /// Close the underlying socket (idempotent).
    fn close(&self) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>>;
    /// Send one datagram.
    fn send(
        &self,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>>;
    /// Receive the next datagram within `timeout`.
    fn receive(
        &self,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, TransportError>> + Send + '_>>;
}

/// Connected UDP client for request/response flows (← udp.py:UdpClient).
///
/// The tokio socket is created in `open` and shared behind an `Arc` so
/// `send`/`receive` (which take `&self`) can clone it out of the std mutex and
/// never hold the guard across an await.
pub struct UdpClient {
    host: String,
    port: u16,
    socket: Mutex<Option<Arc<UdpSocket>>>,
}

impl UdpClient {
    /// Creates an unopened client for `host:port`.
    #[must_use]
    pub fn new(host: String, port: u16) -> Self {
        Self {
            host,
            port,
            socket: Mutex::new(None),
        }
    }

    /// The bound local address, once open.
    #[must_use]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.socket
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .and_then(|socket| socket.local_addr().ok())
    }

    fn with_socket<T>(&self, f: impl FnOnce(&Arc<UdpSocket>) -> T) -> Result<T, TransportError> {
        let guard = self
            .socket
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match guard.as_ref() {
            Some(socket) => Ok(f(socket)),
            None => Err(TransportError::Io("UDP client is not open".to_string())),
        }
    }
}

impl UdpTransport for UdpClient {
    fn open(&self) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>> {
        Box::pin(async move {
            {
                let guard = self
                    .socket
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if guard.is_some() {
                    return Ok(());
                }
            }
            let mut addrs =
                std::net::ToSocketAddrs::to_socket_addrs(&(self.host.as_str(), self.port))
                    .map_err(|_| {
                        TransportError::Io(format!(
                            "Unable to resolve UDP target {}:{}",
                            self.host, self.port
                        ))
                    })?;
            let addr = addrs.next().ok_or_else(|| {
                TransportError::Io(format!(
                    "Unable to resolve UDP target {}:{}",
                    self.host, self.port
                ))
            })?;
            let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
                .await
                .map_err(|e| TransportError::Io(format!("Unable to create UDP socket: {e}")))?;
            socket.connect(addr).await.map_err(|e| {
                TransportError::Io(format!(
                    "Unable to connect UDP socket to {}:{}: {e}",
                    self.host, self.port
                ))
            })?;
            let socket = Arc::new(socket);
            *self
                .socket
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(socket);
            Ok(())
        })
    }

    fn close(&self) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>> {
        Box::pin(async move {
            *self
                .socket
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
            Ok(())
        })
    }

    fn send(
        &self,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>> {
        let data = data.to_vec();
        Box::pin(async move {
            let socket = self.with_socket(Arc::clone)?;
            socket
                .send(&data)
                .await
                .map_err(|e| TransportError::Io(format!("Failed to send UDP datagram: {e}")))?;
            Ok(())
        })
    }

    fn receive(
        &self,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, TransportError>> + Send + '_>> {
        Box::pin(async move {
            let socket = self.with_socket(Arc::clone)?;
            let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
            let (n, _peer) = match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
                Err(_elapsed) => return Err(TransportError::Timeout),
                Ok(Err(e)) => {
                    return Err(TransportError::Io(format!(
                        "Failed to receive UDP datagram: {e}"
                    )));
                }
                Ok(Ok(result)) => result,
            };
            buf.truncate(n);
            Ok(buf)
        })
    }
}

/// One inbound datagram (← udp.py:ReceivedDatagram).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedDatagram {
    /// The datagram payload.
    pub data: Vec<u8>,
    /// The sending peer address.
    pub source_address: SocketAddr,
}

/// Bound UDP server for inbound receive and reply flows (← udp.py:UdpServer).
///
/// A background task pumps the socket into a bounded mpsc channel. Datagrams
/// arriving while the queue is full are dropped and counted (`dropped`), with
/// a rate-limited warning (at most one per `DROP_LOG_INTERVAL`, gated by the
/// injected `Clock`). The `shutdown` watch signal stops the task; once it
/// exits, the channel closes and pending `receive()` calls return `None`.
pub struct UdpServer {
    socket: Arc<UdpSocket>,
    rx: tokio::sync::Mutex<mpsc::Receiver<ReceivedDatagram>>,
    dropped: Arc<Mutex<u64>>,
    shutdown: tokio::sync::watch::Sender<bool>,
}

const DROP_LOG_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_QUEUE_CAPACITY: usize = 1024;

impl UdpServer {
    /// Binds the UDP server socket on `host:port` (port 0 = ephemeral).
    pub async fn bind(host: &str, port: u16) -> Result<Self, TransportError> {
        Self::bind_with(host, port, DEFAULT_QUEUE_CAPACITY, Arc::new(SystemClock)).await
    }

    /// Binds with an explicit queue capacity and clock (test seam).
    pub async fn bind_with(
        host: &str,
        port: u16,
        queue_capacity: usize,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, TransportError> {
        if queue_capacity < 1 {
            return Err(TransportError::Io(
                "queue_capacity must be at least 1".to_string(),
            ));
        }
        let socket = UdpSocket::bind((host, port)).await.map_err(|e| {
            TransportError::Io(format!(
                "Unable to bind UDP server socket on {host}:{port}: {e}"
            ))
        })?;
        let socket = Arc::new(socket);
        let (tx, rx) = mpsc::channel(queue_capacity);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let dropped = Arc::new(Mutex::new(0u64));
        let last_drop_warning = Arc::new(Mutex::new(None));
        let server = Self {
            socket: Arc::clone(&socket),
            rx: tokio::sync::Mutex::new(rx),
            dropped: Arc::clone(&dropped),
            shutdown: shutdown_tx,
        };
        let task_socket = Arc::clone(&socket);
        let task_clock = Arc::clone(&clock);
        let task_dropped = Arc::clone(&dropped);
        let task_last_warning = Arc::clone(&last_drop_warning);
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
            loop {
                tokio::select! {
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    recv = task_socket.recv_from(&mut buf) => {
                        let (n, source_address) = match recv {
                            Ok(result) => result,
                            Err(_) => break,
                        };
                        let datagram = ReceivedDatagram {
                            data: buf[..n].to_vec(),
                            source_address,
                        };
                        if tx.try_send(datagram).is_err() {
                            // Overflow: drop + count, rate-limited warning.
                            *task_dropped
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner()) += 1;
                            let now = task_clock.monotonic();
                            let mut last = task_last_warning
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            if last.is_none_or(|l| now.saturating_sub(l) >= DROP_LOG_INTERVAL) {
                                *last = Some(now);
                                eprintln!(
                                    "UDP receive queue is full (capacity {queue_capacity}); dropping inbound datagrams"
                                );
                            }
                        }
                    }
                }
            }
        });
        Ok(server)
    }

    /// Number of inbound datagrams dropped because the queue was full.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        *self
            .dropped
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The bound local address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.socket
            .local_addr()
            .expect("UdpServer socket has a local address")
    }

    /// Sends a datagram to a specific remote peer.
    pub async fn sendto(&self, data: &[u8], addr: SocketAddr) -> Result<(), TransportError> {
        self.socket
            .send_to(data, addr)
            .await
            .map_err(|e| TransportError::Io(format!("Failed to send UDP datagram: {e}")))?;
        Ok(())
    }

    /// Waits for the next inbound datagram; `None` once the channel closes
    /// (server dropped or the pump task exited).
    pub async fn receive(&self) -> Option<ReceivedDatagram> {
        self.rx.lock().await.recv().await
    }
}

impl Drop for UdpServer {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::SystemClock;

    #[tokio::test]
    async fn udp_client_open_send_receive_close_roundtrip() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let client = Arc::new(UdpClient::new("127.0.0.1".to_string(), server_addr.port()));
        assert_eq!(client.local_addr(), None);
        client.open().await.unwrap();
        assert!(client.local_addr().is_some());

        let client_socket = client.socket.lock().unwrap().clone().unwrap();
        let client_addr = client_socket.local_addr().unwrap();
        let mut buf = [0u8; 16];
        let sender = tokio::spawn({
            let client = Arc::clone(&client);
            async move {
                client.send(b"ping").await.unwrap();
            }
        });
        let (n, from) = server_socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(from, client_addr);
        server_socket.send_to(b"pong", from).await.unwrap();
        sender.await.unwrap();
        let reply = client.receive(Duration::from_secs(1)).await.unwrap();
        assert_eq!(reply, b"pong");

        client.close().await.unwrap();
        assert_eq!(client.local_addr(), None);
        assert!(matches!(
            client.send(b"x").await,
            Err(TransportError::Io(_))
        ));
    }

    #[tokio::test]
    async fn udp_client_receive_times_out() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpClient::new(
            "127.0.0.1".to_string(),
            server_socket.local_addr().unwrap().port(),
        );
        client.open().await.unwrap();
        let err = client.receive(Duration::from_millis(30)).await.unwrap_err();
        assert_eq!(err, TransportError::Timeout);
    }

    #[tokio::test]
    async fn udp_server_receive_and_sendto_roundtrip() {
        let server = UdpServer::bind("127.0.0.1", 0).await.unwrap();
        let server_addr = server.local_addr();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        peer.send_to(b"hello", server_addr).await.unwrap();
        let datagram = tokio::time::timeout(Duration::from_secs(1), server.receive())
            .await
            .unwrap()
            .expect("server open");
        assert_eq!(datagram.data, b"hello");
        server
            .sendto(b"reply", datagram.source_address)
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        let (n, _) = peer.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"reply");
    }

    #[tokio::test]
    async fn udp_server_drops_and_counts_when_queue_full() {
        let server = UdpServer::bind_with("127.0.0.1", 0, 1, Arc::new(SystemClock))
            .await
            .unwrap();
        let addr = server.local_addr();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for i in 0..5u8 {
            peer.send_to(&[i], addr).await.unwrap();
        }
        for _ in 0..100 {
            if server.dropped() >= 4 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(server.dropped() >= 4, "dropped = {}", server.dropped());
    }

    #[test]
    fn system_clock_and_rng_are_injectable() {
        let clock = SystemClock;
        let _mono = clock.monotonic();
        let _unix = clock.unix();
        let rng = crate::time::SystemRng;
        let mut buf = [0u8; 8];
        crate::time::Rng::fill_bytes(&rng, &mut buf);
        assert_ne!(buf, [0u8; 8]);
    }
}
