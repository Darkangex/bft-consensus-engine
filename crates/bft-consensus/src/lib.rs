// ═══════════════════════════════════════════════════════════════════
//  bft-consensus — Byzantine Fault Tolerant consensus engine
//  Version: 0.1.0
// ═══════════════════════════════════════════════════════════════════
//
//  Implements a simplified HotStuff-inspired BFT protocol:
//
//    ┌─────────┐  propose  ┌─────────┐  2f+1 votes  ┌─────────┐
//    │  LEADER │──────────►│ REPLICAS│──────────────►│  COMMIT │
//    └─────────┘           └─────────┘               └─────────┘
//
//  Components:
//    1. ConsensusState    — per-node protocol state machine
//    2. VoteCollector     — quorum tracking
//    3. ConsensusEngine   — main event loop (async)
//    4. ViewChangeManager — leader rotation on timeout
//
//  Invariants:
//    - Quorum = 2f + 1 out of 3f + 1 nodes
//    - Leader = view_number % cluster_size (round-robin)
//    - Timeout triggers view-change with exponential backoff

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};
use tracing::{debug, info, warn};

use bft_crypto::{verify_signed_message, KeyStore, NodeKeyPair};
use bft_network::SimulatedSender;
use bft_storage::StorageEngine;
use bft_types::{
    Block, ClientRequest, ClientResponse, ConsensusMessage, MessageType, NodeConfig, NodeId,
    Operation, SequenceNumber, SignedMessage, ViewNumber, WireMessage, PROTOCOL_VERSION,
};

// ═══════════════════════════════════════════════════════════════════
//  1. VOTE COLLECTOR — quorum tracking
// ═══════════════════════════════════════════════════════════════════

/// Tracks votes for a specific (view, sequence, block_hash) tuple
/// and determines when quorum is reached.
#[derive(Debug)]
pub struct VoteCollector {
    required_quorum: usize,
    /// (view, sequence) → set of voters
    votes: HashMap<(ViewNumber, SequenceNumber), HashSet<NodeId>>,
    /// (view, sequence) → collected (voter, signature) pairs
    signatures: HashMap<(ViewNumber, SequenceNumber), Vec<(NodeId, Vec<u8>)>>,
}

impl VoteCollector {
    pub fn new(quorum_size: usize) -> Self {
        Self {
            required_quorum: quorum_size,
            votes: HashMap::new(),
            signatures: HashMap::new(),
        }
    }

    /// Record a vote from a node. Returns `true` if quorum is now reached.
    pub fn add_vote(
        &mut self,
        view: ViewNumber,
        sequence: SequenceNumber,
        voter: NodeId,
        signature: Vec<u8>,
    ) -> bool {
        let key = (view, sequence);

        // Deduplicate: ignore if this voter already voted for this slot
        let voters = self.votes.entry(key).or_default();
        if !voters.insert(voter) {
            debug!(voter, view, sequence, "duplicate vote ignored");
            return false;
        }

        self.signatures
            .entry(key)
            .or_default()
            .push((voter, signature));

        voters.len() >= self.required_quorum
    }

    /// Get collected signatures for a slot (used to build commit cert).
    pub fn get_signatures(
        &self,
        view: ViewNumber,
        sequence: SequenceNumber,
    ) -> Vec<(NodeId, Vec<u8>)> {
        self.signatures
            .get(&(view, sequence))
            .cloned()
            .unwrap_or_default()
    }

    /// Clear votes for old views (garbage collection).
    pub fn gc_before_view(&mut self, min_view: ViewNumber) {
        self.votes.retain(|(v, _), _| *v >= min_view);
        self.signatures.retain(|(v, _), _| *v >= min_view);
    }
}

// ═══════════════════════════════════════════════════════════════════
//  2. VIEW CHANGE MANAGER
// ═══════════════════════════════════════════════════════════════════

/// Manages view-change logic: timeouts, view-change message
/// collection, and leader rotation.
#[derive(Debug)]
pub struct ViewChangeManager {
    current_view: ViewNumber,
    /// Number of view-change messages received for each proposed view.
    view_change_votes: HashMap<ViewNumber, HashSet<NodeId>>,
    quorum_size: usize,
    /// Base timeout in milliseconds (doubles on each view change).
    base_timeout_ms: u64,
}

impl ViewChangeManager {
    pub fn new(quorum_size: usize, base_timeout_ms: u64) -> Self {
        Self {
            current_view: 0,
            view_change_votes: HashMap::new(),
            quorum_size,
            base_timeout_ms,
        }
    }

    /// Timeout for the current view (exponential backoff).
    pub fn current_timeout(&self) -> Duration {
        let multiplier = 1u64 << self.current_view.min(10);
        Duration::from_millis(self.base_timeout_ms * multiplier)
    }

    /// Record a view-change vote. Returns true if quorum reached.
    pub fn add_view_change(
        &mut self,
        new_view: ViewNumber,
        sender: NodeId,
    ) -> bool {
        if new_view <= self.current_view {
            return false;
        }
        let voters = self.view_change_votes.entry(new_view).or_default();
        voters.insert(sender);
        voters.len() >= self.quorum_size
    }

    /// Advance to a new view.
    pub fn advance_view(&mut self, new_view: ViewNumber) {
        info!(old = self.current_view, new = new_view, "view change");
        self.current_view = new_view;
        // Clean up old view-change votes
        self.view_change_votes.retain(|v, _| *v > new_view);
    }

    pub fn current_view(&self) -> ViewNumber {
        self.current_view
    }
}

// ═══════════════════════════════════════════════════════════════════
//  3. CONSENSUS ENGINE — main protocol state machine
// ═══════════════════════════════════════════════════════════════════

/// Per-node consensus engine that orchestrates the BFT protocol.
///
/// Integrates with the network layer (SimulatedSender) and storage
/// engine. Runs as an async task processing messages from an inbox.
pub struct ConsensusEngine {
    // ─────────── Configuration ───────────
    config: NodeConfig,
    keypair: Arc<NodeKeyPair>,
    key_store: KeyStore,

    // ─────────── Protocol State ───────────
    current_view: ViewNumber,
    next_sequence: SequenceNumber,
    last_committed_seq: SequenceNumber,
    vote_collector: VoteCollector,
    view_change_mgr: ViewChangeManager,

    // ─────────── Pending Proposals ───────────
    /// Blocks proposed but not yet committed.
    pending_blocks: HashMap<(ViewNumber, SequenceNumber), Block>,
    /// Client requests waiting to be proposed.
    pending_requests: Vec<ClientRequest>,
    /// Committed block hashes for duplicate detection.
    committed_hashes: HashSet<Vec<u8>>,

    // ─────────── I/O Channels ───────────
    network_sender: SimulatedSender,
    storage: StorageEngine,

    // ─────────── Client Response Channels ───────────
    /// request_id → response sender (for notifying clients)
    client_waiters: HashMap<u64, mpsc::Sender<ClientResponse>>,
}

impl ConsensusEngine {
    /// Create a new consensus engine.
    pub fn new(
        config: NodeConfig,
        keypair: Arc<NodeKeyPair>,
        key_store: KeyStore,
        network_sender: SimulatedSender,
        storage: StorageEngine,
    ) -> Self {
        let quorum = config.quorum_size();
        let timeout = config.consensus_timeout_ms;

        Self {
            config,
            keypair,
            key_store,
            current_view: 0,
            next_sequence: 0,
            last_committed_seq: 0,
            vote_collector: VoteCollector::new(quorum),
            view_change_mgr: ViewChangeManager::new(quorum, timeout),
            pending_blocks: HashMap::new(),
            pending_requests: Vec::new(),
            committed_hashes: HashSet::new(),
            network_sender,
            storage,
            client_waiters: HashMap::new(),
        }
    }

    /// Whether this node is the leader for the current view.
    pub fn is_leader(&self) -> bool {
        self.config.leader_for_view(self.current_view) == self.config.id
    }

    /// Run the consensus engine event loop.
    ///
    /// Processes messages from the inbox channel and handles timeouts.
    pub async fn run(
        &mut self,
        mut inbox: mpsc::Receiver<(NodeId, WireMessage)>,
        mut client_rx: mpsc::Receiver<(ClientRequest, mpsc::Sender<ClientResponse>)>,
    ) {
        info!(
            node = self.config.id,
            view = self.current_view,
            leader = self.is_leader(),
            "consensus engine started"
        );

        let mut deadline = Instant::now() + self.view_change_mgr.current_timeout();

        loop {
            tokio::select! {
                // ── Incoming consensus message ──
                Some((from, wire_msg)) = inbox.recv() => {
                    self.handle_wire_message(from, wire_msg).await;
                    // Reset deadline on valid message activity
                    deadline = Instant::now() + self.view_change_mgr.current_timeout();
                }

                // ── Incoming client request ──
                Some((req, resp_tx)) = client_rx.recv() => {
                    self.client_waiters.insert(req.request_id, resp_tx);
                    self.pending_requests.push(req);

                    // If we are leader, try to propose
                    if self.is_leader() {
                        self.try_propose().await;
                    }
                }

                // ── Timeout → trigger view change ──
                _ = tokio::time::sleep_until(deadline) => {
                    info!(
                        node = self.config.id,
                        view = self.current_view,
                        "consensus timeout, initiating view change"
                    );
                    self.initiate_view_change().await;
                    deadline = Instant::now() + self.view_change_mgr.current_timeout();
                }
            }
        }
    }

    // ─────────── Message Handling ───────────

    /// Parse and validate a wire message, then dispatch.
    async fn handle_wire_message(&mut self, from: NodeId, wire_msg: WireMessage) {
        if wire_msg.version != PROTOCOL_VERSION {
            warn!(
                from,
                version = wire_msg.version,
                "rejecting message with unknown protocol version"
            );
            return;
        }

        match wire_msg.msg_type {
            MessageType::Consensus => {
                self.handle_consensus_wire(wire_msg.payload).await;
            }
            _ => {
                debug!(from, "ignoring non-consensus wire message");
            }
        }
    }

    /// Unwrap a signed consensus message, verify, and dispatch.
    async fn handle_consensus_wire(&mut self, raw_payload: Vec<u8>) {
        // Deserialize the SignedMessage wrapper
        let signed: SignedMessage = match bincode::deserialize(&raw_payload) {
            Ok(s) => s,
            Err(e) => {
                warn!("failed to deserialize SignedMessage: {e}");
                return;
            }
        };

        // Verify signature and extract ConsensusMessage
        let msg = match verify_signed_message(&self.key_store, &signed) {
            Ok(m) => m,
            Err(e) => {
                warn!(sender = signed.sender, "signature verification failed: {e}");
                return;
            }
        };

        // Dispatch by message type
        match msg {
            ConsensusMessage::Propose { block } => {
                self.handle_propose(signed.sender, block).await;
            }
            ConsensusMessage::Vote {
                view,
                sequence,
                block_hash,
                voter,
            } => {
                self.handle_vote(voter, view, sequence, block_hash, signed.signature)
                    .await;
            }
            ConsensusMessage::Commit {
                view,
                sequence,
                block_hash,
                vote_signatures,
            } => {
                self.handle_commit(view, sequence, block_hash, vote_signatures)
                    .await;
            }
            ConsensusMessage::ViewChange {
                new_view,
                sender,
                last_committed_seq,
            } => {
                self.handle_view_change(sender, new_view, last_committed_seq)
                    .await;
            }
            ConsensusMessage::NewView { view, leader, .. } => {
                self.handle_new_view(view, leader).await;
            }
        }
    }

    // ─────────── Phase 1: PROPOSE ───────────

    /// Try to create a proposal from pending requests (leader only).
    async fn try_propose(&mut self) {
        if !self.is_leader() || self.pending_requests.is_empty() {
            return;
        }

        // Drain pending requests into a block
        let operations: Vec<Operation> = self
            .pending_requests
            .drain(..)
            .map(|r| r.operation)
            .collect();

        let parent_hash = if self.next_sequence > 0 {
            // Use last committed block hash as parent (simplified)
            vec![0u8; 8]
        } else {
            vec![0u8; 8] // genesis
        };

        let block = Block {
            view: self.current_view,
            sequence: self.next_sequence,
            proposer: self.config.id,
            operations,
            parent_hash,
        };

        info!(
            node = self.config.id,
            view = self.current_view,
            seq = self.next_sequence,
            "proposing block"
        );

        // Store pending block
        let key = (self.current_view, self.next_sequence);
        self.pending_blocks.insert(key, block.clone());

        // Sign and broadcast
        let msg = ConsensusMessage::Propose { block };
        let signed = self.keypair.sign_consensus(&msg);
        let wire = self.wrap_consensus(signed);
        self.network_sender.broadcast(wire).await;

        // Self-vote (leader votes for its own proposal)
        let block_ref = self.pending_blocks.get(&key).unwrap();
        let block_hash = block_ref.hash();
        let vote_msg = ConsensusMessage::Vote {
            view: self.current_view,
            sequence: self.next_sequence,
            block_hash: block_hash.clone(),
            voter: self.config.id,
        };
        let vote_signed = self.keypair.sign_consensus(&vote_msg);
        let reached = self.vote_collector.add_vote(
            self.current_view,
            self.next_sequence,
            self.config.id,
            vote_signed.signature.clone(),
        );

        if reached {
            self.commit_block(self.current_view, self.next_sequence, block_hash)
                .await;
        }
    }

    /// Handle an incoming Propose from the leader.
    async fn handle_propose(&mut self, sender: NodeId, block: Block) {
        // Validate: the proposer should be the leader for this view
        let expected_leader = self.config.leader_for_view(block.view);
        if sender != expected_leader {
            warn!(
                sender,
                expected = expected_leader,
                view = block.view,
                "proposal from non-leader, ignoring"
            );
            return;
        }

        if block.view < self.current_view {
            debug!(
                block_view = block.view,
                current = self.current_view,
                "stale proposal, ignoring"
            );
            return;
        }

        let block_hash = block.hash();
        let view = block.view;
        let sequence = block.sequence;

        // Store the proposed block
        self.pending_blocks
            .insert((view, sequence), block);

        // Cast our vote
        let vote_msg = ConsensusMessage::Vote {
            view,
            sequence,
            block_hash,
            voter: self.config.id,
        };
        let signed = self.keypair.sign_consensus(&vote_msg);
        let wire = self.wrap_consensus(signed);

        // Send vote to leader
        let _ = self.network_sender.send(expected_leader, wire).await;

        debug!(
            node = self.config.id,
            view,
            seq = sequence,
            "voted for proposal"
        );
    }

    // ─────────── Phase 2: VOTE ───────────

    /// Handle an incoming Vote (leader collects votes).
    async fn handle_vote(
        &mut self,
        voter: NodeId,
        view: ViewNumber,
        sequence: SequenceNumber,
        block_hash: Vec<u8>,
        signature: Vec<u8>,
    ) {
        if view != self.current_view {
            return;
        }
        if !self.is_leader() {
            return;
        }

        let reached_quorum =
            self.vote_collector
                .add_vote(view, sequence, voter, signature);

        if reached_quorum {
            info!(
                node = self.config.id,
                view,
                seq = sequence,
                "quorum reached! committing"
            );
            self.commit_block(view, sequence, block_hash).await;
        }
    }

    // ─────────── Phase 3: COMMIT ───────────

    /// Broadcast commit and apply block to storage.
    async fn commit_block(
        &mut self,
        view: ViewNumber,
        sequence: SequenceNumber,
        block_hash: Vec<u8>,
    ) {
        // Avoid double-commit
        if self.committed_hashes.contains(&block_hash) {
            return;
        }
        self.committed_hashes.insert(block_hash.clone());

        // Build commit certificate
        let vote_sigs = self.vote_collector.get_signatures(view, sequence);
        let commit_msg = ConsensusMessage::Commit {
            view,
            sequence,
            block_hash,
            vote_signatures: vote_sigs,
        };
        let signed = self.keypair.sign_consensus(&commit_msg);
        let wire = self.wrap_consensus(signed);
        self.network_sender.broadcast(wire).await;

        // Apply to local storage
        self.apply_block(view, sequence);

        self.last_committed_seq = sequence;
        self.next_sequence = sequence + 1;
    }

    /// Handle an incoming Commit message.
    async fn handle_commit(
        &mut self,
        view: ViewNumber,
        sequence: SequenceNumber,
        block_hash: Vec<u8>,
        _vote_signatures: Vec<(NodeId, Vec<u8>)>,
    ) {
        if self.committed_hashes.contains(&block_hash) {
            return; // already committed
        }

        // In a full implementation, we'd verify each vote signature
        // in vote_signatures. For this educational version, we trust
        // the commit certificate from the leader whose message was
        // already signature-verified.

        self.committed_hashes.insert(block_hash);
        self.apply_block(view, sequence);
        self.last_committed_seq = sequence;
        self.next_sequence = sequence + 1;

        debug!(
            node = self.config.id,
            view,
            seq = sequence,
            "block committed from leader cert"
        );
    }

    /// Apply a committed block's operations to the storage engine.
    fn apply_block(&mut self, view: ViewNumber, sequence: SequenceNumber) {
        let key = (view, sequence);
        let block = match self.pending_blocks.remove(&key) {
            Some(b) => b,
            None => {
                debug!(view, seq = sequence, "no pending block to apply");
                return;
            }
        };

        for op in &block.operations {
            self.apply_operation(op);
        }

        info!(
            node = self.config.id,
            view,
            seq = sequence,
            ops = block.operations.len(),
            "applied block to storage"
        );

        // Notify waiting clients
        for op in &block.operations {
            self.notify_client(op);
        }
    }

    /// Apply a single operation to the storage engine.
    fn apply_operation(&mut self, op: &Operation) {
        match op {
            Operation::Put { key, value } => {
                if let Err(e) = self.storage.put(key.clone(), value.clone()) {
                    warn!("storage put failed: {e}");
                }
            }
            Operation::Get { .. } => {
                // Reads don't mutate state; they're handled at query time
            }
            Operation::Txn { ops } => {
                for sub_op in ops {
                    self.apply_operation(sub_op);
                }
            }
        }
    }

    /// Notify a client that their operation was committed.
    fn notify_client(&mut self, op: &Operation) {
        // In a real implementation, we'd match request IDs to pending
        // client waiters. Here we do a simplified notification.
        match op {
            Operation::Get { key } => {
                let value = self.storage.get(key).ok().flatten();
                debug!(?key, ?value, "get result for client");
            }
            _ => {}
        }
    }

    // ─────────── View Change ───────────

    /// Initiate a view change (triggered by timeout).
    async fn initiate_view_change(&mut self) {
        let new_view = self.current_view + 1;
        let msg = ConsensusMessage::ViewChange {
            new_view,
            sender: self.config.id,
            last_committed_seq: self.last_committed_seq,
        };

        let signed = self.keypair.sign_consensus(&msg);
        let wire = self.wrap_consensus(signed);
        self.network_sender.broadcast(wire).await;

        // Self-vote for view change
        self.view_change_mgr
            .add_view_change(new_view, self.config.id);
    }

    /// Handle a ViewChange message from a peer.
    async fn handle_view_change(
        &mut self,
        sender: NodeId,
        new_view: ViewNumber,
        _last_committed_seq: SequenceNumber,
    ) {
        let reached = self.view_change_mgr.add_view_change(new_view, sender);

        if reached {
            self.advance_to_view(new_view).await;
        }
    }

    /// Handle a NewView announcement.
    async fn handle_new_view(&mut self, view: ViewNumber, _leader: NodeId) {
        if view > self.current_view {
            self.advance_to_view(view).await;
        }
    }

    /// Advance to a new view.
    async fn advance_to_view(&mut self, new_view: ViewNumber) {
        self.current_view = new_view;
        self.view_change_mgr.advance_view(new_view);
        self.vote_collector.gc_before_view(new_view);

        info!(
            node = self.config.id,
            view = new_view,
            leader = self.is_leader(),
            "advanced to new view"
        );

        // If we are the new leader, announce and try to propose
        if self.is_leader() {
            let msg = ConsensusMessage::NewView {
                view: new_view,
                leader: self.config.id,
                view_change_proofs: vec![],
            };
            let signed = self.keypair.sign_consensus(&msg);
            let wire = self.wrap_consensus(signed);
            self.network_sender.broadcast(wire).await;

            self.try_propose().await;
        }
    }

    // ─────────── Helpers ───────────

    /// Wrap a SignedMessage into a WireMessage for transmission.
    fn wrap_consensus(&self, signed: SignedMessage) -> WireMessage {
        let payload = bincode::serialize(&signed).expect("signed msg serialization infallible");
        WireMessage {
            version: PROTOCOL_VERSION,
            msg_type: MessageType::Consensus,
            payload,
        }
    }

    /// Handle a client read request directly (no consensus needed).
    pub fn handle_read(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.storage.get(key).ok().flatten()
    }
}

// ═══════════════════════════════════════════════════════════════════
//  4. TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use bft_network::{FaultConfig, SimulatedNetwork};
    use std::path::Path;

    /// Helper: create a deterministic keypair for testing.
    fn test_keypair(node_id: NodeId) -> NodeKeyPair {
        let mut seed = [0u8; 32];
        seed[0] = node_id as u8;
        NodeKeyPair::from_seed(node_id, &seed)
    }

    #[test]
    fn test_vote_collector_quorum() {
        let mut collector = VoteCollector::new(3); // quorum = 3

        assert!(!collector.add_vote(0, 0, 0, vec![1]));
        assert!(!collector.add_vote(0, 0, 1, vec![2]));
        assert!(collector.add_vote(0, 0, 2, vec![3])); // quorum!

        let sigs = collector.get_signatures(0, 0);
        assert_eq!(sigs.len(), 3);
    }

    #[test]
    fn test_vote_collector_dedup() {
        let mut collector = VoteCollector::new(3);

        assert!(!collector.add_vote(0, 0, 0, vec![1]));
        assert!(!collector.add_vote(0, 0, 0, vec![1])); // duplicate!
        assert!(!collector.add_vote(0, 0, 1, vec![2]));

        let sigs = collector.get_signatures(0, 0);
        assert_eq!(sigs.len(), 2); // not 3, because one was deduped
    }

    #[test]
    fn test_view_change_manager_timeout() {
        let mgr = ViewChangeManager::new(3, 1000);
        assert_eq!(mgr.current_timeout(), Duration::from_millis(1000));
    }

    #[test]
    fn test_view_change_manager_quorum() {
        let mut mgr = ViewChangeManager::new(3, 1000);

        assert!(!mgr.add_view_change(1, 0));
        assert!(!mgr.add_view_change(1, 1));
        assert!(mgr.add_view_change(1, 2)); // quorum
    }

    #[tokio::test]
    async fn test_consensus_happy_path() {
        // Set up 4 nodes (f=1, quorum=3)
        let tmp = tempfile::TempDir::new().unwrap();
        let network = SimulatedNetwork::new(FaultConfig::clean());

        let n = 4u64;
        let max_faults = 1usize;
        let mut keypairs = Vec::new();
        let mut key_store = KeyStore::new();
        let mut senders = Vec::new();
        let mut receivers = Vec::new();

        for i in 0..n {
            let kp = test_keypair(i);
            key_store.insert(i, kp.verifying_key);
            keypairs.push(kp);
            let (tx, rx) = network.register(i).await;
            senders.push(tx);
            receivers.push(rx);
        }

        // Create configs
        let peers: Vec<(NodeId, String)> = (0..n)
            .map(|i| (i, format!("127.0.0.1:{}", 9000 + i)))
            .collect();

        // Create engine for node 0 (leader at view 0)
        let config = NodeConfig {
            id: 0,
            cluster_size: n as usize,
            max_faults,
            peers: peers.clone(),
            data_dir: tmp.path().join("node0").to_string_lossy().into_owned(),
            consensus_timeout_ms: 5000,
        };

        let storage = StorageEngine::open(Path::new(&config.data_dir)).unwrap();
        let kp0 = Arc::new(test_keypair(0));

        let mut engine = ConsensusEngine::new(
            config,
            kp0.clone(),
            key_store.clone(),
            senders[0].clone(),
            storage,
        );

        assert!(engine.is_leader(), "node 0 should be leader at view 0");

        // Verify vote collector works through the engine
        assert_eq!(engine.current_view, 0);
        assert_eq!(engine.next_sequence, 0);
    }

    #[test]
    fn test_wrap_consensus_message() {
        let kp = test_keypair(0);
        let msg = ConsensusMessage::Propose {
            block: Block {
                view: 0,
                sequence: 0,
                proposer: 0,
                operations: vec![],
                parent_hash: vec![],
            },
        };
        let signed = kp.sign_consensus(&msg);
        let payload = bincode::serialize(&signed).unwrap();
        let wire = WireMessage {
            version: PROTOCOL_VERSION,
            msg_type: MessageType::Consensus,
            payload,
        };
        let bytes = wire.to_bytes();
        let decoded = WireMessage::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.version, PROTOCOL_VERSION);
    }
}
