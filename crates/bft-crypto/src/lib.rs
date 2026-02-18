// ═══════════════════════════════════════════════════════════════════
//  bft-crypto — Cryptographic primitives for BFT consensus
//  Version: 0.1.0
// ═══════════════════════════════════════════════════════════════════
//
//  Components:
//    1. KeyPair         — Ed25519 key generation and storage
//    2. Signer          — message signing
//    3. Verifier        — signature verification (async-safe)
//    4. KeyStore        — maps NodeId → PublicKey for the cluster
//
//  Crypto library: ed25519-dalek 2.x
//  Async offload: tokio::task::spawn_blocking for verification

use std::collections::HashMap;

use ed25519_dalek::{
    Signature, Signer as DalekSigner, SigningKey, Verifier as DalekVerifier, VerifyingKey,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use bft_types::{ConsensusMessage, NodeId, SignedMessage};

// ═══════════════════════════════════════════════════════════════════
//  1. KEY PAIR
// ═══════════════════════════════════════════════════════════════════

/// An Ed25519 keypair for a single node.
///
/// The signing key is kept private; the verifying key is shared
/// with all peers.
#[derive(Debug)]
pub struct NodeKeyPair {
    pub node_id: NodeId,
    signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl NodeKeyPair {
    /// Generate a fresh random keypair for the given node.
    pub fn generate(node_id: NodeId) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            node_id,
            signing_key,
            verifying_key,
        }
    }

    /// Create a keypair from known bytes (for deterministic tests).
    pub fn from_seed(node_id: NodeId, seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        Self {
            node_id,
            signing_key,
            verifying_key,
        }
    }

    /// Sign arbitrary bytes, returning the 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig: Signature = self.signing_key.sign(message);
        sig.to_bytes().to_vec()
    }

    /// Sign a consensus message, producing a `SignedMessage`.
    pub fn sign_consensus(&self, msg: &ConsensusMessage) -> SignedMessage {
        let payload = bincode::serialize(msg).expect("consensus msg serialization infallible");
        let signature = self.sign(&payload);
        SignedMessage {
            sender: self.node_id,
            payload,
            signature,
        }
    }

    /// Sign a consensus message with replay protection context.
    ///
    /// The signature is computed over `chain_id || view || payload`,
    /// preventing messages from being replayed across chains or views.
    /// This is the production-safe variant of `sign_consensus`.
    pub fn sign_consensus_with_context(
        &self,
        msg: &ConsensusMessage,
        chain_id: &str,
        view: u64,
    ) -> SignedMessage {
        let payload = bincode::serialize(msg).expect("consensus msg serialization infallible");

        // Build domain-separated signing input: chain_id || view || payload
        let mut signing_input = Vec::with_capacity(chain_id.len() + 8 + payload.len());
        signing_input.extend_from_slice(chain_id.as_bytes());
        signing_input.extend_from_slice(&view.to_le_bytes());
        signing_input.extend_from_slice(&payload);

        let signature = self.sign(&signing_input);
        SignedMessage {
            sender: self.node_id,
            payload,
            signature,
        }
    }

    /// Export the verifying (public) key as bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

// ═══════════════════════════════════════════════════════════════════
//  2. KEY STORE — cluster-wide public key registry
// ═══════════════════════════════════════════════════════════════════

/// Serializable representation of a public key for network exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyInfo {
    pub node_id: NodeId,
    pub key_bytes: [u8; 32],
}

/// Registry mapping NodeId → VerifyingKey for all cluster members.
///
/// Used by every node to verify signatures from peers.
#[derive(Debug, Clone)]
pub struct KeyStore {
    keys: HashMap<NodeId, VerifyingKey>,
}

impl KeyStore {
    /// Create an empty key store.
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Build a key store from a list of public key infos.
    pub fn from_public_keys(infos: &[PublicKeyInfo]) -> Result<Self, CryptoError> {
        let mut keys = HashMap::with_capacity(infos.len());
        for info in infos {
            let vk = VerifyingKey::from_bytes(&info.key_bytes)
                .map_err(|e| CryptoError::InvalidPublicKey {
                    node_id: info.node_id,
                    reason: e.to_string(),
                })?;
            keys.insert(info.node_id, vk);
        }
        Ok(Self { keys })
    }

    /// Register a node's public key.
    pub fn insert(&mut self, node_id: NodeId, key: VerifyingKey) {
        self.keys.insert(node_id, key);
    }

    /// Look up a node's verifying key.
    pub fn get(&self, node_id: NodeId) -> Option<&VerifyingKey> {
        self.keys.get(&node_id)
    }

    /// Number of registered keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════
//  3. SIGNATURE VERIFICATION
// ═══════════════════════════════════════════════════════════════════

/// Verify a signature synchronously (for use in blocking contexts).
pub fn verify_signature(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), CryptoError> {
    let sig =
        Signature::from_slice(signature_bytes).map_err(|e| CryptoError::MalformedSignature {
            reason: e.to_string(),
        })?;
    verifying_key
        .verify(message, &sig)
        .map_err(|_| CryptoError::InvalidSignature)
}

/// Verify a `SignedMessage` against the cluster's key store.
///
/// Returns the deserialized `ConsensusMessage` if valid.
pub fn verify_signed_message(
    key_store: &KeyStore,
    signed: &SignedMessage,
) -> Result<ConsensusMessage, CryptoError> {
    // ── Step 1: look up sender's public key ──
    let vk = key_store
        .get(signed.sender)
        .ok_or(CryptoError::UnknownSender {
            node_id: signed.sender,
        })?;

    // ── Step 2: verify signature over payload ──
    verify_signature(vk, &signed.payload, &signed.signature)?;

    // ── Step 3: deserialize the consensus message ──
    let msg: ConsensusMessage =
        bincode::deserialize(&signed.payload).map_err(|e| CryptoError::DeserializationFailed {
            reason: e.to_string(),
        })?;

    Ok(msg)
}

/// Verify a `SignedMessage` with replay protection context.
///
/// Reconstructs the domain-separated signing input `chain_id || view || payload`
/// and verifies the signature against it. This rejects messages signed
/// under a different chain_id or view number.
pub fn verify_signed_message_with_context(
    key_store: &KeyStore,
    signed: &SignedMessage,
    chain_id: &str,
    view: u64,
) -> Result<ConsensusMessage, CryptoError> {
    // ── Step 1: look up sender's public key ──
    let vk = key_store
        .get(signed.sender)
        .ok_or(CryptoError::UnknownSender {
            node_id: signed.sender,
        })?;

    // ── Step 2: reconstruct domain-separated signing input ──
    let mut signing_input = Vec::with_capacity(chain_id.len() + 8 + signed.payload.len());
    signing_input.extend_from_slice(chain_id.as_bytes());
    signing_input.extend_from_slice(&view.to_le_bytes());
    signing_input.extend_from_slice(&signed.payload);

    // ── Step 3: verify signature over reconstructed input ──
    verify_signature(vk, &signing_input, &signed.signature)?;

    // ── Step 4: deserialize the consensus message ──
    let msg: ConsensusMessage =
        bincode::deserialize(&signed.payload).map_err(|e| CryptoError::DeserializationFailed {
            reason: e.to_string(),
        })?;

    Ok(msg)
}

/// Verify a signed message asynchronously by offloading to a blocking
/// thread pool. This prevents signature verification from blocking
/// the Tokio async reactor.
pub async fn verify_signed_message_async(
    key_store: KeyStore,
    signed: SignedMessage,
) -> Result<ConsensusMessage, CryptoError> {
    tokio::task::spawn_blocking(move || verify_signed_message(&key_store, &signed))
        .await
        .map_err(|e| CryptoError::TaskJoinError {
            reason: e.to_string(),
        })?
}

/// Verify a signed message with replay protection context, asynchronously.
///
/// Offloads CPU-intensive Ed25519 verification to `spawn_blocking`,
/// preventing reactor thread starvation. Also validates domain-separated
/// context (chain_id + view) to reject replayed messages.
pub async fn verify_signed_message_with_context_async(
    key_store: KeyStore,
    signed: SignedMessage,
    chain_id: String,
    view: u64,
) -> Result<ConsensusMessage, CryptoError> {
    tokio::task::spawn_blocking(move || {
        verify_signed_message_with_context(&key_store, &signed, &chain_id, view)
    })
    .await
    .map_err(|e| CryptoError::TaskJoinError {
        reason: e.to_string(),
    })?
}

// ═══════════════════════════════════════════════════════════════════
//  4. ERROR TYPES
// ═══════════════════════════════════════════════════════════════════

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// The sender's NodeId is not in the key store.
    UnknownSender { node_id: NodeId },
    /// The public key bytes are malformed.
    InvalidPublicKey { node_id: NodeId, reason: String },
    /// Signature bytes are not a valid Ed25519 signature.
    MalformedSignature { reason: String },
    /// Signature verification failed (wrong key or tampered data).
    InvalidSignature,
    /// Could not deserialize the payload after signature check.
    DeserializationFailed { reason: String },
    /// The blocking task panicked or was cancelled.
    TaskJoinError { reason: String },
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSender { node_id } => {
                write!(f, "unknown sender: node {node_id}")
            }
            Self::InvalidPublicKey { node_id, reason } => {
                write!(f, "invalid public key for node {node_id}: {reason}")
            }
            Self::MalformedSignature { reason } => {
                write!(f, "malformed signature: {reason}")
            }
            Self::InvalidSignature => write!(f, "signature verification failed"),
            Self::DeserializationFailed { reason } => {
                write!(f, "payload deserialization failed: {reason}")
            }
            Self::TaskJoinError { reason } => {
                write!(f, "blocking task failed: {reason}")
            }
        }
    }
}

impl std::error::Error for CryptoError {}

// ═══════════════════════════════════════════════════════════════════
//  5. TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use bft_types::{Block, ConsensusMessage, Operation};

    fn test_keypair(node_id: NodeId) -> NodeKeyPair {
        let mut seed = [0u8; 32];
        seed[0] = node_id as u8;
        NodeKeyPair::from_seed(node_id, &seed)
    }

    fn build_key_store(keypairs: &[&NodeKeyPair]) -> KeyStore {
        let mut ks = KeyStore::new();
        for kp in keypairs {
            ks.insert(kp.node_id, kp.verifying_key);
        }
        ks
    }

    #[test]
    fn test_sign_and_verify_bytes() {
        let kp = test_keypair(0);
        let message = b"hello world";
        let sig = kp.sign(message);

        assert!(verify_signature(&kp.verifying_key, message, &sig).is_ok());
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let kp = test_keypair(0);
        let message = b"hello world";
        let mut sig = kp.sign(message);

        // Tamper with one byte
        sig[0] ^= 0xFF;

        assert!(verify_signature(&kp.verifying_key, message, &sig).is_err());
    }

    #[test]
    fn test_wrong_key_rejected() {
        let kp0 = test_keypair(0);
        let kp1 = test_keypair(1);
        let message = b"hello world";
        let sig = kp0.sign(message);

        // Verify with wrong key
        assert!(verify_signature(&kp1.verifying_key, message, &sig).is_err());
    }

    #[test]
    fn test_sign_consensus_message() {
        let kp = test_keypair(0);
        let msg = ConsensusMessage::Propose {
            block: Block {
                view: 1,
                sequence: 0,
                proposer: 0,
                operations: vec![Operation::Put {
                    key: b"k".to_vec(),
                    value: b"v".to_vec(),
                }],
                parent_hash: vec![0u8; 8],
            },
        };

        let signed = kp.sign_consensus(&msg);
        let ks = build_key_store(&[&kp]);
        let recovered = verify_signed_message(&ks, &signed).unwrap();

        assert_eq!(msg, recovered);
    }

    #[test]
    fn test_unknown_sender_rejected() {
        let kp0 = test_keypair(0);
        let kp1 = test_keypair(1);

        let msg = ConsensusMessage::Vote {
            view: 1,
            sequence: 0,
            block_hash: vec![0xAB],
            voter: 1,
        };
        let signed = kp1.sign_consensus(&msg);

        // Key store only has kp0
        let ks = build_key_store(&[&kp0]);
        let result = verify_signed_message(&ks, &signed);

        assert!(matches!(result, Err(CryptoError::UnknownSender { .. })));
    }

    #[tokio::test]
    async fn test_async_verification() {
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
        let ks = build_key_store(&[&kp]);

        let result = verify_signed_message_async(ks, signed).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), msg);
    }

    #[test]
    fn test_key_store_from_public_keys() {
        let kp0 = test_keypair(0);
        let kp1 = test_keypair(1);

        let infos = vec![
            PublicKeyInfo {
                node_id: 0,
                key_bytes: kp0.public_key_bytes(),
            },
            PublicKeyInfo {
                node_id: 1,
                key_bytes: kp1.public_key_bytes(),
            },
        ];

        let ks = KeyStore::from_public_keys(&infos).unwrap();
        assert_eq!(ks.len(), 2);
        assert!(ks.get(0).is_some());
        assert!(ks.get(1).is_some());
        assert!(ks.get(99).is_none());
    }
}
