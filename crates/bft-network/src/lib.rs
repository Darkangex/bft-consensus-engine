// ═══════════════════════════════════════════════════════════════════
//  bft-network — Asynchronous networking with fault injection
//  Version: 0.1.0
// ═══════════════════════════════════════════════════════════════════
//
//  Components:
//    1. Transport trait       — abstract send/receive interface
//    2. SimulatedTransport   — in-process channels for testing
//    3. FaultConfig          — latency, drops, duplicates
//    4. TcpTransport         — real TCP with length-delimited framing
//    5. PeerManager          — connection lifecycle management
//
//  All transports are async (Tokio). The simulated transport enables
//  deterministic testing without real sockets.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::{Buf, BufMut, BytesMut};
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, warn};

use bft_types::{NodeId, WireMessage};

// ═══════════════════════════════════════════════════════════════════
//  1. FAULT INJECTION CONFIG
// ═══════════════════════════════════════════════════════════════════

/// Configuration for simulating unreliable network conditions.
#[derive(Debug, Clone)]
pub struct FaultConfig {
    /// Range of artificial latency in milliseconds [min, max).
    pub latency_min_ms: u64,
    pub latency_max_ms: u64,
    /// Probability of dropping a message (0.0 = never, 1.0 = always).
    pub drop_rate: f64,
    /// Probability of duplicating a message.
    pub duplicate_rate: f64,
}

impl Default for FaultConfig {
    fn default() -> Self {
        Self {
            latency_min_ms: 0,
            latency_max_ms: 0,
            drop_rate: 0.0,
            duplicate_rate: 0.0,
        }
    }
}

impl FaultConfig {
    /// A clean network with no faults.
    pub fn clean() -> Self {
        Self::default()
    }

    /// A lossy network for stress testing.
    pub fn lossy() -> Self {
        Self {
            latency_min_ms: 10,
            latency_max_ms: 100,
            drop_rate: 0.1,
            duplicate_rate: 0.05,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
//  2. TRANSPORT ERRORS
// ═══════════════════════════════════════════════════════════════════

/// Errors from the networking layer.
#[derive(Debug)]
pub enum NetworkError {
    /// The target node is not connected.
    PeerNotFound { node_id: NodeId },
    /// Channel closed unexpectedly.
    ChannelClosed,
    /// I/O error on TCP socket.
    Io(std::io::Error),
    /// Serialization/deserialization error.
    Codec(String),
}

impl std::fmt::Display for NetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PeerNotFound { node_id } => write!(f, "peer {node_id} not found"),
            Self::ChannelClosed => write!(f, "channel closed"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Codec(msg) => write!(f, "codec error: {msg}"),
        }
    }
}

impl std::error::Error for NetworkError {}

impl From<std::io::Error> for NetworkError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// ═══════════════════════════════════════════════════════════════════
//  3. SIMULATED TRANSPORT (in-process, for tests)
// ═══════════════════════════════════════════════════════════════════

/// A simulated network that routes messages between nodes via
/// in-process MPSC channels. Supports configurable fault injection.
///
/// Usage:
///   let network = SimulatedNetwork::new(fault_config);
///   let (tx_0, rx_0) = network.register(0).await;
///   let (tx_1, rx_1) = network.register(1).await;
///   // Now node 0 can send to node 1 via tx_0.send(1, msg)
pub struct SimulatedNetwork {
    fault_config: FaultConfig,
    inboxes: Arc<Mutex<HashMap<NodeId, mpsc::Sender<(NodeId, WireMessage)>>>>,
}

impl SimulatedNetwork {
    pub fn new(fault_config: FaultConfig) -> Self {
        Self {
            fault_config,
            inboxes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a node and return its sender handle + receiver.
    pub async fn register(
        &self,
        node_id: NodeId,
    ) -> (
        SimulatedSender,
        mpsc::Receiver<(NodeId, WireMessage)>,
    ) {
        let (tx, rx) = mpsc::channel(256);
        self.inboxes.lock().await.insert(node_id, tx);

        let sender = SimulatedSender {
            self_id: node_id,
            fault_config: self.fault_config.clone(),
            inboxes: Arc::clone(&self.inboxes),
        };

        (sender, rx)
    }
}

/// Handle for a node to send messages to other nodes in the
/// simulated network.
#[derive(Clone)]
pub struct SimulatedSender {
    self_id: NodeId,
    fault_config: FaultConfig,
    inboxes: Arc<Mutex<HashMap<NodeId, mpsc::Sender<(NodeId, WireMessage)>>>>,
}

impl SimulatedSender {
    /// Send a message to a specific peer with fault injection.
    ///
    /// All RNG decisions are computed upfront so that `ThreadRng`
    /// (which is `!Send`) is never held across `.await` boundaries.
    pub async fn send(&self, target: NodeId, msg: WireMessage) -> Result<(), NetworkError> {
        // ── Pre-compute all random decisions (ThreadRng is !Send) ──
        let (should_drop, delay_ms, should_duplicate) = {
            let mut rng = rand::thread_rng();
            let drop = rng.gen::<f64>() < self.fault_config.drop_rate;
            let delay = if self.fault_config.latency_max_ms > 0 {
                Some(rng.gen_range(self.fault_config.latency_min_ms..self.fault_config.latency_max_ms))
            } else {
                None
            };
            let dup = rng.gen::<f64>() < self.fault_config.duplicate_rate;
            (drop, delay, dup)
        };
        // `rng` is dropped here — safe to `.await` below

        // ── Fault: packet drop ──
        if should_drop {
            debug!(from = self.self_id, to = target, "FAULT: dropped message");
            return Ok(());
        }

        // ── Fault: artificial latency ──
        if let Some(delay) = delay_ms {
            tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
        }

        // ── Deliver the message ──
        let inboxes = self.inboxes.lock().await;
        let tx = inboxes
            .get(&target)
            .ok_or(NetworkError::PeerNotFound { node_id: target })?;

        tx.send((self.self_id, msg.clone()))
            .await
            .map_err(|_| NetworkError::ChannelClosed)?;

        // ── Fault: message duplication ──
        if should_duplicate {
            debug!(from = self.self_id, to = target, "FAULT: duplicated message");
            let _ = tx.send((self.self_id, msg)).await;
        }

        Ok(())
    }

    /// Broadcast a message to all registered peers (except self).
    pub async fn broadcast(&self, msg: WireMessage) -> Vec<Result<(), NetworkError>> {
        let peer_ids: Vec<NodeId> = {
            let inboxes = self.inboxes.lock().await;
            inboxes.keys().filter(|id| **id != self.self_id).copied().collect()
        };

        let mut results = Vec::with_capacity(peer_ids.len());
        for peer in peer_ids {
            results.push(self.send(peer, msg.clone()).await);
        }
        results
    }
}

// ═══════════════════════════════════════════════════════════════════
//  4. TCP TRANSPORT (real network)
// ═══════════════════════════════════════════════════════════════════

/// Length-delimited framing: [4-byte big-endian length][payload].
const HEADER_LEN: usize = 4;

/// Encode a `WireMessage` into a length-prefixed byte buffer.
pub fn frame_encode(msg: &WireMessage) -> Vec<u8> {
    let payload = msg.to_bytes();
    let len = payload.len() as u32;
    let mut buf = Vec::with_capacity(HEADER_LEN + payload.len());
    buf.put_u32(len);
    buf.extend_from_slice(&payload);
    buf
}

/// Read one length-delimited `WireMessage` from a TCP stream.
pub async fn frame_read(stream: &mut TcpStream) -> Result<WireMessage, NetworkError> {
    let mut len_buf = [0u8; HEADER_LEN];
    stream.read_exact(&mut len_buf).await?;
    let len = (&len_buf[..]).get_u32() as usize;

    if len > 16 * 1024 * 1024 {
        return Err(NetworkError::Codec(format!(
            "message too large: {len} bytes"
        )));
    }

    let mut payload = BytesMut::with_capacity(len);
    payload.resize(len, 0);
    stream.read_exact(&mut payload).await?;

    WireMessage::from_bytes(&payload).map_err(|e| NetworkError::Codec(e.to_string()))
}

/// Write one length-delimited `WireMessage` to a TCP stream.
pub async fn frame_write(stream: &mut TcpStream, msg: &WireMessage) -> Result<(), NetworkError> {
    let data = frame_encode(msg);
    stream.write_all(&data).await?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
//  5. PEER MANAGER — TCP connection lifecycle
// ═══════════════════════════════════════════════════════════════════

/// Manages TCP connections to peer nodes.
///
/// Listens for inbound connections and creates outbound connections
/// on demand. Routes received messages to a single inbox channel.
pub struct PeerManager {
    self_id: NodeId,
    listen_addr: String,
    peer_addrs: HashMap<NodeId, String>,
    inbox_tx: mpsc::Sender<(NodeId, WireMessage)>,
}

impl PeerManager {
    pub fn new(
        self_id: NodeId,
        listen_addr: String,
        peer_addrs: HashMap<NodeId, String>,
        inbox_tx: mpsc::Sender<(NodeId, WireMessage)>,
    ) -> Self {
        Self {
            self_id,
            listen_addr,
            peer_addrs,
            inbox_tx,
        }
    }

    /// Start listening for inbound peer connections.
    /// Spawns a background task that accepts connections forever.
    pub async fn start_listener(&self) -> Result<(), NetworkError> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        let inbox_tx = self.inbox_tx.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!(?addr, "accepted inbound connection");
                        let tx = inbox_tx.clone();
                        tokio::spawn(Self::handle_inbound(stream, tx));
                    }
                    Err(e) => {
                        warn!("accept error: {e}");
                    }
                }
            }
        });

        Ok(())
    }

    /// Handle an inbound connection: read messages and forward to inbox.
    async fn handle_inbound(
        mut stream: TcpStream,
        inbox_tx: mpsc::Sender<(NodeId, WireMessage)>,
    ) {
        loop {
            match frame_read(&mut stream).await {
                Ok(msg) => {
                    // Extract sender from the wire message payload (best-effort)
                    let sender_id = 0; // Will be identified by SignedMessage inside
                    if inbox_tx.send((sender_id, msg)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    debug!("inbound read error: {e}");
                    break;
                }
            }
        }
    }

    /// Send a message to a specific peer via TCP.
    pub async fn send_to(&self, target: NodeId, msg: &WireMessage) -> Result<(), NetworkError> {
        let addr = self
            .peer_addrs
            .get(&target)
            .ok_or(NetworkError::PeerNotFound { node_id: target })?;

        let mut stream = TcpStream::connect(addr).await?;
        frame_write(&mut stream, msg).await
    }

    /// Broadcast a message to all known peers.
    pub async fn broadcast(&self, msg: &WireMessage) {
        for (&peer_id, _) in &self.peer_addrs {
            if peer_id == self.self_id {
                continue;
            }
            if let Err(e) = self.send_to(peer_id, msg).await {
                debug!(peer = peer_id, "broadcast send failed: {e}");
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
//  6. TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use bft_types::{MessageType, PROTOCOL_VERSION};

    fn test_wire_msg(data: u8) -> WireMessage {
        WireMessage {
            version: PROTOCOL_VERSION,
            msg_type: MessageType::Consensus,
            payload: vec![data],
        }
    }

    #[tokio::test]
    async fn test_simulated_send_receive() {
        let network = SimulatedNetwork::new(FaultConfig::clean());
        let (tx0, _rx0) = network.register(0).await;
        let (_tx1, mut rx1) = network.register(1).await;

        let msg = test_wire_msg(42);
        tx0.send(1, msg.clone()).await.unwrap();

        let (from, received) = rx1.recv().await.unwrap();
        assert_eq!(from, 0);
        assert_eq!(received.payload, vec![42]);
    }

    #[tokio::test]
    async fn test_simulated_broadcast() {
        let network = SimulatedNetwork::new(FaultConfig::clean());
        let (tx0, _rx0) = network.register(0).await;
        let (_tx1, mut rx1) = network.register(1).await;
        let (_tx2, mut rx2) = network.register(2).await;

        let msg = test_wire_msg(99);
        let results = tx0.broadcast(msg).await;

        // Both peers should receive
        assert!(results.iter().all(|r| r.is_ok()));
        assert!(rx1.recv().await.is_some());
        assert!(rx2.recv().await.is_some());
    }

    #[tokio::test]
    async fn test_simulated_drop_rate_100_percent() {
        let config = FaultConfig {
            drop_rate: 1.0,
            ..FaultConfig::clean()
        };
        let network = SimulatedNetwork::new(config);
        let (tx0, _rx0) = network.register(0).await;
        let (_tx1, mut rx1) = network.register(1).await;

        let msg = test_wire_msg(1);
        tx0.send(1, msg).await.unwrap();

        // Should be dropped — channel should be empty
        let result = tokio::time::timeout(
            tokio::time::Duration::from_millis(100),
            rx1.recv(),
        )
        .await;
        assert!(result.is_err(), "message should have been dropped");
    }

    #[tokio::test]
    async fn test_frame_encode_decode() {
        let msg = test_wire_msg(7);
        let encoded = frame_encode(&msg);

        // First 4 bytes are the length
        let len = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        let payload = &encoded[4..];
        assert_eq!(len as usize, payload.len());

        let decoded = WireMessage::from_bytes(payload).unwrap();
        assert_eq!(decoded.payload, vec![7]);
    }

    #[tokio::test]
    async fn test_peer_not_found() {
        let network = SimulatedNetwork::new(FaultConfig::clean());
        let (tx0, _rx0) = network.register(0).await;

        let msg = test_wire_msg(1);
        let result = tx0.send(99, msg).await;
        assert!(matches!(result, Err(NetworkError::PeerNotFound { node_id: 99 })));
    }
}
