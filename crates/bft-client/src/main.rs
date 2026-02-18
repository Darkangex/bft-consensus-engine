// ═══════════════════════════════════════════════════════════════════
//  bft-client — CLI client for the BFT distributed KV store
//  Version: 0.1.0
// ═══════════════════════════════════════════════════════════════════
//
//  Commands:
//    bft-client put <key> <value> --node <addr>
//    bft-client get <key> --node <addr>
//    bft-client bench --node <addr> --ops <N>
//
//  Connects to a BFT node via TCP, sends operations, waits for
//  commit confirmation, and measures latency/throughput.

use std::time::Instant;

use bytes::{Buf, BufMut};
use clap::{Parser, Subcommand};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;


use bft_types::{
    ClientRequest, ClientResponse, MessageType, Operation, WireMessage, PROTOCOL_VERSION,
};

// ═══════════════════════════════════════════════════════════════════
//  CLI ARGUMENTS
// ═══════════════════════════════════════════════════════════════════

#[derive(Parser, Debug)]
#[command(name = "bft-client")]
#[command(about = "CLI client for BFT distributed key-value store")]
struct Args {
    /// Node address to connect to.
    #[arg(long, default_value = "127.0.0.1:9000")]
    node: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Write a key-value pair.
    Put {
        key: String,
        value: String,
    },
    /// Read a value by key.
    Get {
        key: String,
    },
    /// Run a throughput/latency benchmark.
    Bench {
        /// Number of operations to send.
        #[arg(long, default_value_t = 1000)]
        ops: usize,
        /// Value size in bytes.
        #[arg(long, default_value_t = 64)]
        value_size: usize,
    },
}

// ═══════════════════════════════════════════════════════════════════
//  WIRE PROTOCOL HELPERS
// ═══════════════════════════════════════════════════════════════════

/// Send a client request over TCP with length-delimited framing.
async fn send_request(
    stream: &mut TcpStream,
    req: &ClientRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let req_bytes = bincode::serialize(req)?;
    let wire = WireMessage {
        version: PROTOCOL_VERSION,
        msg_type: MessageType::ClientRequest,
        payload: req_bytes,
    };
    let payload = wire.to_bytes();
    let len = payload.len() as u32;

    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.put_u32(len);
    buf.extend_from_slice(&payload);

    stream.write_all(&buf).await?;
    Ok(())
}

/// Receive a client response over TCP.
async fn recv_response(
    stream: &mut TcpStream,
) -> Result<ClientResponse, Box<dyn std::error::Error>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = (&len_buf[..]).get_u32() as usize;

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;

    let wire: WireMessage = bincode::deserialize(&payload)?;
    let resp: ClientResponse = bincode::deserialize(&wire.payload)?;
    Ok(resp)
}

// ═══════════════════════════════════════════════════════════════════
//  MAIN
// ═══════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();

    let args = Args::parse();

    match args.command {
        Command::Put { key, value } => {
            run_put(&args.node, &key, &value).await;
        }
        Command::Get { key } => {
            run_get(&args.node, &key).await;
        }
        Command::Bench { ops, value_size } => {
            run_bench(&args.node, ops, value_size).await;
        }
    }
}

// ─────────── PUT ───────────

async fn run_put(node: &str, key: &str, value: &str) {
    println!("PUT {} = {} → {}", key, value, node);

    match TcpStream::connect(node).await {
        Ok(mut stream) => {
            let req = ClientRequest {
                request_id: 1,
                operation: Operation::Put {
                    key: key.as_bytes().to_vec(),
                    value: value.as_bytes().to_vec(),
                },
            };

            let start = Instant::now();
            if let Err(e) = send_request(&mut stream, &req).await {
                eprintln!("  ✗ send failed: {e}");
                return;
            }

            match recv_response(&mut stream).await {
                Ok(resp) => {
                    let elapsed = start.elapsed();
                    if resp.success {
                        println!("  ✓ committed in {:.2?}", elapsed);
                    } else {
                        println!(
                            "  ✗ failed: {}",
                            resp.error.unwrap_or_else(|| "unknown".into())
                        );
                    }
                }
                Err(e) => {
                    eprintln!("  ✗ response failed: {e}");
                }
            }
        }
        Err(e) => {
            eprintln!("  ✗ connection failed: {e}");
            eprintln!("  Note: Run bft-node first to start the cluster.");
        }
    }
}

// ─────────── GET ───────────

async fn run_get(node: &str, key: &str) {
    println!("GET {} ← {}", key, node);

    match TcpStream::connect(node).await {
        Ok(mut stream) => {
            let req = ClientRequest {
                request_id: 1,
                operation: Operation::Get {
                    key: key.as_bytes().to_vec(),
                },
            };

            let start = Instant::now();
            if let Err(e) = send_request(&mut stream, &req).await {
                eprintln!("  ✗ send failed: {e}");
                return;
            }

            match recv_response(&mut stream).await {
                Ok(resp) => {
                    let elapsed = start.elapsed();
                    if resp.success {
                        match resp.value {
                            Some(v) => {
                                let val_str =
                                    String::from_utf8(v).unwrap_or_else(|_| "<binary>".into());
                                println!("  ✓ value = \"{}\" ({:.2?})", val_str, elapsed);
                            }
                            None => println!("  ✓ key not found ({:.2?})", elapsed),
                        }
                    } else {
                        println!(
                            "  ✗ failed: {}",
                            resp.error.unwrap_or_else(|| "unknown".into())
                        );
                    }
                }
                Err(e) => {
                    eprintln!("  ✗ response failed: {e}");
                }
            }
        }
        Err(e) => {
            eprintln!("  ✗ connection failed: {e}");
        }
    }
}

// ─────────── BENCHMARK ───────────

async fn run_bench(node: &str, ops: usize, value_size: usize) {
    println!("═══════════════════════════════════════════════════════════");
    println!("  BFT Client Benchmark");
    println!("═══════════════════════════════════════════════════════════");
    println!("  Target:      {}", node);
    println!("  Operations:  {}", ops);
    println!("  Value size:  {} bytes", value_size);
    println!("═══════════════════════════════════════════════════════════\n");

    let value = vec![0x42u8; value_size];
    let mut latencies: Vec<f64> = Vec::with_capacity(ops);
    let mut success_count = 0usize;
    let mut fail_count = 0usize;

    let total_start = Instant::now();

    for i in 0..ops {
        let key = format!("bench_key_{:06}", i);
        let req = ClientRequest {
            request_id: i as u64,
            operation: Operation::Put {
                key: key.as_bytes().to_vec(),
                value: value.clone(),
            },
        };

        let op_start = Instant::now();

        match TcpStream::connect(node).await {
            Ok(mut stream) => {
                if send_request(&mut stream, &req).await.is_ok() {
                    match recv_response(&mut stream).await {
                        Ok(resp) if resp.success => {
                            let elapsed_ms = op_start.elapsed().as_secs_f64() * 1000.0;
                            latencies.push(elapsed_ms);
                            success_count += 1;
                        }
                        _ => fail_count += 1,
                    }
                } else {
                    fail_count += 1;
                }
            }
            Err(_) => {
                fail_count += 1;
            }
        }
    }

    let total_elapsed = total_start.elapsed();

    // ── Calculate statistics ──
    if !latencies.is_empty() {
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p50 = latencies[latencies.len() / 2];
        let p95 = latencies[(latencies.len() as f64 * 0.95) as usize];
        let p99 = latencies[(latencies.len() as f64 * 0.99) as usize];
        let avg = latencies.iter().sum::<f64>() / latencies.len() as f64;
        let throughput = success_count as f64 / total_elapsed.as_secs_f64();

        println!("  Results:");
        println!("  ─────────────────────────────────────────");
        println!("  {:.<30} {:>10}", "Successful ops", success_count);
        println!("  {:.<30} {:>10}", "Failed ops", fail_count);
        println!(
            "  {:.<30} {:>10.2} ms",
            "Avg latency", avg
        );
        println!("  {:.<30} {:>10.2} ms", "P50 latency", p50);
        println!("  {:.<30} {:>10.2} ms", "P95 latency", p95);
        println!("  {:.<30} {:>10.2} ms", "P99 latency", p99);
        println!(
            "  {:.<30} {:>10.0} ops/s",
            "Throughput", throughput
        );
        println!("  {:.<30} {:>10.2?}", "Total time", total_elapsed);
        println!("  ─────────────────────────────────────────");
    } else {
        println!("  No successful operations. Is the BFT cluster running?");
        println!("  Run: cargo run --bin bft-node");
    }
}
