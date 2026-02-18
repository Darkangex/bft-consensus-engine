// ═══════════════════════════════════════════════════════════════════
//  bft-node — Full BFT consensus node binary
//  Version: 0.2.0 (Hardened)
// ═══════════════════════════════════════════════════════════════════
//
//  Integrates all components:
//    - Consensus engine (BFT protocol) with PaceMaker
//    - Storage engine (WAL + LSM-tree)
//    - Network transport (simulated or TCP)
//    - Crypto (Ed25519 signing/verification with replay protection)
//    - Graceful shutdown via CancellationToken
//
//  Usage:
//    bft-node --id 0 --cluster-size 4 --data-dir ./data/node0
//
//  For the educational simulation, all nodes run in-process using
//  SimulatedNetwork. For real deployment, switch to TcpTransport.

use std::path::Path;
use std::sync::Arc;

use clap::Parser;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use bft_consensus::ConsensusEngine;
use bft_crypto::{KeyStore, NodeKeyPair};
use bft_network::{FaultConfig, SimulatedNetwork};
use bft_storage::StorageEngine;
use bft_types::{
    ClientRequest, ClientResponse, NodeConfig, NodeId, Operation,
};

// ═══════════════════════════════════════════════════════════════════
//  CLI ARGUMENTS
// ═══════════════════════════════════════════════════════════════════

#[derive(Parser, Debug)]
#[command(name = "bft-node")]
#[command(about = "BFT Consensus Node — Byzantine Fault Tolerant distributed KV store")]
struct Args {
    /// Number of nodes in the cluster (default: 4 for f=1).
    #[arg(long, default_value_t = 4)]
    cluster_size: u64,

    /// Maximum Byzantine faults tolerated (default: 1).
    #[arg(long, default_value_t = 1)]
    max_faults: usize,

    /// Base consensus timeout in milliseconds.
    #[arg(long, default_value_t = 2000)]
    timeout_ms: u64,

    /// Base directory for node data.
    #[arg(long, default_value = "./data")]
    data_dir: String,

    /// Enable network fault injection (lossy mode).
    #[arg(long, default_value_t = false)]
    lossy: bool,

    /// Number of test operations to run in demo mode.
    #[arg(long, default_value_t = 10)]
    demo_ops: usize,

    /// Chain ID for replay protection.
    #[arg(long, default_value = "bft-mainnet-v1")]
    chain_id: String,
}

// ═══════════════════════════════════════════════════════════════════
//  MAIN — multi-node in-process simulation
// ═══════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() {
    // ── Initialize tracing ──
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();

    let args = Args::parse();

    info!(
        cluster_size = args.cluster_size,
        max_faults = args.max_faults,
        lossy = args.lossy,
        chain_id = %args.chain_id,
        "starting BFT cluster simulation (hardened v0.2)"
    );

    // ── Validate parameters ──
    let n = args.cluster_size;
    let f = args.max_faults;
    assert!(
        n >= 3 * f as u64 + 1,
        "cluster_size must be >= 3*max_faults + 1"
    );

    // ── Generate keypairs for all nodes ──
    let mut keypairs: Vec<Arc<NodeKeyPair>> = Vec::new();
    let mut key_store = KeyStore::new();

    for i in 0..n {
        let mut seed = [0u8; 32];
        seed[0] = i as u8;
        seed[1] = (i >> 8) as u8;
        let kp = NodeKeyPair::from_seed(i, &seed);
        key_store.insert(i, kp.verifying_key);
        keypairs.push(Arc::new(kp));
    }

    info!("generated {} keypairs", n);

    // ── Create simulated network ──
    let fault_config = if args.lossy {
        FaultConfig::lossy()
    } else {
        FaultConfig::clean()
    };
    let network = SimulatedNetwork::new(fault_config);

    // ── Register all nodes in the network ──
    let peers: Vec<(NodeId, String)> = (0..n)
        .map(|i| (i, format!("127.0.0.1:{}", 9000 + i)))
        .collect();

    let mut client_txs: Vec<mpsc::Sender<(ClientRequest, mpsc::Sender<ClientResponse>)>> =
        Vec::new();

    // FIX 5: Shared CancellationToken for coordinated shutdown
    let cancel_token = CancellationToken::new();

    for i in 0..n {
        let (sender, receiver) = network.register(i).await;

        let config = NodeConfig {
            id: i,
            cluster_size: n as usize,
            max_faults: f,
            peers: peers.clone(),
            data_dir: format!("{}/node_{}", args.data_dir, i),
            consensus_timeout_ms: args.timeout_ms,
            chain_id: args.chain_id.clone(),
        };

        // Create storage
        let storage = StorageEngine::open(Path::new(&config.data_dir))
            .expect("failed to open storage");

        // Create consensus engine
        let mut engine = ConsensusEngine::new(
            config,
            Arc::clone(&keypairs[i as usize]),
            key_store.clone(),
            sender,
            storage,
        );

        // Client request channel
        let (client_tx, client_rx) = mpsc::channel(64);
        client_txs.push(client_tx);

        // FIX 5: Pass CancellationToken to engine
        let cancel = cancel_token.clone();

        // Spawn consensus engine task
        tokio::spawn(async move {
            engine.run(receiver, client_rx, cancel).await;
        });
    }

    info!("all {} nodes started", n);

    // ── Demo: send some operations ──
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    info!("sending {} demo operations", args.demo_ops);

    for i in 0..args.demo_ops {
        let key = format!("key_{}", i);
        let value = format!("value_{}", i);

        let req = ClientRequest {
            request_id: i as u64,
            operation: Operation::Put {
                key: key.as_bytes().to_vec(),
                value: value.as_bytes().to_vec(),
            },
        };

        let (resp_tx, mut resp_rx) = mpsc::channel(1);

        // Send to leader (node 0 at view 0)
        if let Err(e) = client_txs[0].send((req, resp_tx)).await {
            warn!("failed to send client request: {e}");
            continue;
        }

        // Wait for response with timeout
        match tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            resp_rx.recv(),
        )
        .await
        {
            Ok(Some(resp)) => {
                info!(
                    request_id = resp.request_id,
                    success = resp.success,
                    "operation committed"
                );
            }
            Ok(None) => {
                info!(op = i, "response channel closed (operation likely committed)");
            }
            Err(_) => {
                warn!(op = i, "operation timed out waiting for commit");
            }
        }
    }

    // Let the system settle
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // FIX 5: Graceful shutdown — cancel all engines
    info!("shutting down cluster...");
    cancel_token.cancel();
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // ── Summary ──
    println!("\n═══════════════════════════════════════════════════════════");
    println!("  BFT Cluster Simulation Complete (Hardened v0.2)");
    println!("═══════════════════════════════════════════════════════════");
    println!("  Nodes:        {}", n);
    println!("  Max faults:   {} (quorum = {})", f, 2 * f + 1);
    println!("  Operations:   {}", args.demo_ops);
    println!("  Chain ID:     {}", args.chain_id);
    println!("  Network mode: {}", if args.lossy { "LOSSY" } else { "CLEAN" });
    println!("═══════════════════════════════════════════════════════════");
}
