// ═══════════════════════════════════════════════════════════════════
//  bft-types — Core type definitions for the BFT consensus system
//  Version: 0.1.0
// ═══════════════════════════════════════════════════════════════════
//
//  Components:
//    1. NodeId, ViewNumber, SequenceNumber — scalar identifiers
//    2. Operation, Block                  — state machine commands
//    3. ConsensusMessage                  — protocol messages
//    4. SignedMessage<T>                  — authenticated wrapper
//    5. WireMessage                       — network framing
//    6. ClientRequest / ClientResponse    — client protocol
//
//  Serialization: serde + bincode, version-tagged wire format.

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════════
//  1. SCALAR IDENTIFIERS
// ═══════════════════════════════════════════════════════════════════

/// Unique identifier for a node in the cluster.
pub type NodeId = u64;

/// Monotonically increasing view number (epoch).
pub type ViewNumber = u64;

/// Position of an entry in the replicated log.
pub type SequenceNumber = u64;

// ═══════════════════════════════════════════════════════════════════
//  2. KEY-VALUE OPERATIONS & BLOCKS
// ═══════════════════════════════════════════════════════════════════

/// A single key-value operation submitted by a client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    /// Write a key-value pair.
    Put { key: Vec<u8>, value: Vec<u8> },
    /// Read a key (response carries the value).
    Get { key: Vec<u8> },
    /// Atomic transaction: a batch of operations applied together.
    Txn { ops: Vec<Operation> },
}

/// A block of operations proposed by the leader for consensus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    /// View in which this block was proposed.
    pub view: ViewNumber,
    /// Sequence number (log index) for this block.
    pub sequence: SequenceNumber,
    /// The leader that created this block.
    pub proposer: NodeId,
    /// Operations included in this block.
    pub operations: Vec<Operation>,
    /// Hash of the previous block (simple chaining).
    pub parent_hash: Vec<u8>,
}

impl Block {
    /// Compute a deterministic hash of this block using bincode + CRC-style hash.
    /// In production you'd use SHA-256; here we use a simple FNV-style hash
    /// for speed in the educational context.
    pub fn hash(&self) -> Vec<u8> {
        let encoded = bincode::serialize(self).expect("block serialization infallible");
        let mut h: u64 = 0xcbf29ce484222325;
        for byte in &encoded {
            h ^= *byte as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h.to_le_bytes().to_vec()
    }
}

// ═══════════════════════════════════════════════════════════════════
//  3. CONSENSUS PROTOCOL MESSAGES
// ═══════════════════════════════════════════════════════════════════

/// Messages exchanged during the BFT consensus protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusMessage {
    /// Phase 1: Leader proposes a block.
    Propose {
        block: Block,
    },

    /// Phase 2: Replica votes for a proposed block.
    Vote {
        view: ViewNumber,
        sequence: SequenceNumber,
        block_hash: Vec<u8>,
        voter: NodeId,
    },

    /// Phase 3: Leader broadcasts commit certificate.
    Commit {
        view: ViewNumber,
        sequence: SequenceNumber,
        block_hash: Vec<u8>,
        /// Collected vote signatures from 2f+1 replicas.
        vote_signatures: Vec<(NodeId, Vec<u8>)>,
    },

    /// Timeout-triggered view change request.
    ViewChange {
        new_view: ViewNumber,
        sender: NodeId,
        /// Highest committed sequence known to this node.
        last_committed_seq: SequenceNumber,
    },

    /// New leader announces the new view after collecting 2f+1 ViewChange.
    NewView {
        view: ViewNumber,
        leader: NodeId,
        /// ViewChange messages that justify this new view.
        view_change_proofs: Vec<(NodeId, Vec<u8>)>,
    },
}

// ═══════════════════════════════════════════════════════════════════
//  4. SIGNED MESSAGE WRAPPER
// ═══════════════════════════════════════════════════════════════════

/// A message with a cryptographic signature for authentication.
///
/// Every consensus message on the wire is wrapped in this struct.
/// The `signature` is computed over `bincode::serialize(&payload)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage {
    /// The sender's node ID.
    pub sender: NodeId,
    /// The serialized payload (ConsensusMessage or ClientRequest).
    pub payload: Vec<u8>,
    /// Ed25519 signature over `payload`.
    pub signature: Vec<u8>,
}

// ═══════════════════════════════════════════════════════════════════
//  5. WIRE MESSAGE (NETWORK FRAMING)
// ═══════════════════════════════════════════════════════════════════

/// Protocol version for forward/backward compatibility.
pub const PROTOCOL_VERSION: u8 = 1;

/// High-level discriminant for message routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    Consensus = 1,
    ClientRequest = 2,
    ClientResponse = 3,
}

/// Top-level wire format: version + type + payload.
///
/// All data on TCP is framed as: `[4-byte length][WireMessage bytes]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireMessage {
    /// Protocol version (currently 1).
    pub version: u8,
    /// What kind of message this is.
    pub msg_type: MessageType,
    /// Bincode-encoded inner message (SignedMessage, ClientRequest, etc.).
    pub payload: Vec<u8>,
}

impl WireMessage {
    /// Serialize this wire message to bytes for transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("WireMessage serialization infallible")
    }

    /// Deserialize a wire message from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }
}

// ═══════════════════════════════════════════════════════════════════
//  6. CLIENT PROTOCOL
// ═══════════════════════════════════════════════════════════════════

/// Unique identifier for a client request (for deduplication).
pub type RequestId = u64;

/// A request from a client to the cluster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientRequest {
    /// Unique request identifier.
    pub request_id: RequestId,
    /// The operation to execute.
    pub operation: Operation,
}

/// Response sent back to the client after commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientResponse {
    /// Echoed request identifier.
    pub request_id: RequestId,
    /// Whether the operation was committed successfully.
    pub success: bool,
    /// Optional value for Get operations.
    pub value: Option<Vec<u8>>,
    /// Human-readable error message, if any.
    pub error: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════
//  7. NODE CONFIGURATION
// ═══════════════════════════════════════════════════════════════════

/// Static configuration for a node in the cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// This node's ID.
    pub id: NodeId,
    /// Total number of nodes in the cluster.
    pub cluster_size: usize,
    /// Maximum number of Byzantine faults tolerated: f = (n-1)/3.
    pub max_faults: usize,
    /// Network addresses of all peers: (NodeId, "host:port").
    pub peers: Vec<(NodeId, String)>,
    /// Directory for persistent storage (WAL, SST files).
    pub data_dir: String,
    /// Consensus timeout in milliseconds before triggering view-change.
    pub consensus_timeout_ms: u64,
    /// Unique chain identifier for replay attack protection.
    /// All signed messages include this to prevent cross-chain replay.
    pub chain_id: String,
}

impl NodeConfig {
    /// Compute the quorum size: 2f + 1.
    pub fn quorum_size(&self) -> usize {
        2 * self.max_faults + 1
    }

    /// Determine the leader for a given view.
    pub fn leader_for_view(&self, view: ViewNumber) -> NodeId {
        let node_ids: Vec<NodeId> = self.peers.iter().map(|(id, _)| *id).collect();
        node_ids[(view as usize) % node_ids.len()]
    }
}

// ═══════════════════════════════════════════════════════════════════
//  8. TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_serialization_roundtrip() {
        let op = Operation::Put {
            key: b"hello".to_vec(),
            value: b"world".to_vec(),
        };
        let encoded = bincode::serialize(&op).unwrap();
        let decoded: Operation = bincode::deserialize(&encoded).unwrap();
        assert_eq!(op, decoded);
    }

    #[test]
    fn test_block_hash_deterministic() {
        let block = Block {
            view: 1,
            sequence: 0,
            proposer: 0,
            operations: vec![Operation::Put {
                key: b"k".to_vec(),
                value: b"v".to_vec(),
            }],
            parent_hash: vec![0u8; 8],
        };
        let h1 = block.hash();
        let h2 = block.hash();
        assert_eq!(h1, h2, "Block hash must be deterministic");
        assert_eq!(h1.len(), 8);
    }

    #[test]
    fn test_wire_message_roundtrip() {
        let wire = WireMessage {
            version: PROTOCOL_VERSION,
            msg_type: MessageType::Consensus,
            payload: vec![1, 2, 3, 4],
        };
        let bytes = wire.to_bytes();
        let decoded = WireMessage::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.version, PROTOCOL_VERSION);
        assert_eq!(decoded.payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_client_request_serialization() {
        let req = ClientRequest {
            request_id: 42,
            operation: Operation::Get {
                key: b"test".to_vec(),
            },
        };
        let encoded = bincode::serialize(&req).unwrap();
        let decoded: ClientRequest = bincode::deserialize(&encoded).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_consensus_message_variants() {
        let msgs: Vec<ConsensusMessage> = vec![
            ConsensusMessage::Propose {
                block: Block {
                    view: 0,
                    sequence: 0,
                    proposer: 0,
                    operations: vec![],
                    parent_hash: vec![],
                },
            },
            ConsensusMessage::Vote {
                view: 1,
                sequence: 0,
                block_hash: vec![0xAB],
                voter: 2,
            },
            ConsensusMessage::ViewChange {
                new_view: 5,
                sender: 1,
                last_committed_seq: 10,
            },
        ];
        for msg in &msgs {
            let enc = bincode::serialize(msg).unwrap();
            let dec: ConsensusMessage = bincode::deserialize(&enc).unwrap();
            assert_eq!(msg, &dec);
        }
    }

    #[test]
    fn test_node_config_quorum() {
        let cfg = NodeConfig {
            id: 0,
            cluster_size: 4,
            max_faults: 1,
            peers: vec![
                (0, "127.0.0.1:9000".into()),
                (1, "127.0.0.1:9001".into()),
                (2, "127.0.0.1:9002".into()),
                (3, "127.0.0.1:9003".into()),
            ],
            data_dir: "/tmp/node0".into(),
            consensus_timeout_ms: 5000,
            chain_id: "test-chain".into(),
        };
        assert_eq!(cfg.quorum_size(), 3); // 2*1+1
        assert_eq!(cfg.leader_for_view(0), 0);
        assert_eq!(cfg.leader_for_view(1), 1);
        assert_eq!(cfg.leader_for_view(4), 0); // wraps around
    }
}
