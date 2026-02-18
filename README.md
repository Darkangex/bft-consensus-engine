<div align="center">

# 🔐 BFT Consensus Engine

### Byzantine Fault Tolerant Distributed Key-Value Store

*A production-grade consensus engine built from scratch in Rust — no frameworks, no shortcuts.*

[![Rust](https://img.shields.io/badge/Rust-1.75+-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-33%20passing-brightgreen?style=flat-square)]()
[![Architecture](https://img.shields.io/badge/Architecture-BFT%20%7C%20LSM--tree-purple?style=flat-square)]()

---

[English](#-overview) · [Español](#-descripción-general)

</div>

---

## 🌐 Overview

This project implements a **Byzantine Fault Tolerant (BFT) consensus engine** with an integrated **distributed key-value storage system**, written entirely in Rust. It is designed to maintain a replicated state machine across `N` nodes, tolerating up to `f` Byzantine (arbitrarily malicious) faults where `N ≥ 3f + 1`.

The system achieves **safety** (all honest nodes agree on the same state) and **liveness** (the system continues to make progress) even in the presence of nodes that crash, send corrupted data, or act adversarially.

### Why This Project?

Distributed consensus is one of the hardest problems in computer science. This project demonstrates deep understanding of:

- **Distributed systems theory** — BFT protocols, quorum-based voting, view-change mechanisms
- **Systems programming in Rust** — ownership, lifetimes, `Send`/`Sync` safety, zero-cost abstractions
- **Crash-safe storage design** — Write-Ahead Logging, LSM-trees, CRC32 integrity verification
- **Async networking** — Tokio-based event loops, length-delimited framing, fault injection
- **Cryptographic authentication** — Ed25519 digital signatures with async verification offload

### What We Innovate

| Area | Innovation |
|------|-----------|
| **Protocol Design** | Simplified HotStuff-inspired 3-phase BFT (Propose → Vote → Commit) with exponential backoff view-change, designed for educational clarity without sacrificing correctness |
| **Network Simulation** | Built-in fault injection layer (latency, packet loss, message duplication) enabling deterministic testing of consensus under adversarial network conditions |
| **Send-Safe Async RNG** | Pre-computed random decisions before `.await` boundaries to maintain `Send` safety across Tokio task spawns — a non-trivial pattern in async Rust |
| **Crash Recovery** | Full WAL-based crash recovery with CRC32 integrity checks, allowing nodes to rejoin the cluster after unexpected termination without data loss |
| **Modular Architecture** | 7-crate workspace with clean dependency boundaries — each crate is independently testable and replaceable |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     BFT Cluster (N=4, f=1)                  │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  Node 0  │  │  Node 1  │  │  Node 2  │  │  Node 3  │   │
│  │ (Leader) │  │(Replica) │  │(Replica) │  │(Replica) │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
│       │              │              │              │         │
│       └──────────────┴──────────────┴──────────────┘         │
│                    Consensus Protocol                        │
│              Propose → Vote → Commit (2f+1)                  │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Storage Engine (per node)               │    │
│  │  WAL → MemTable (BTreeMap) → SSTable (LSM-tree)     │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
         ▲                                    ▲
         │ put/get/txn                        │ TCP + Ed25519
    ┌────┴─────┐                         ┌────┴─────┐
    │  Client  │                         │   Peers  │
    │   CLI    │                         │ (signed) │
    └──────────┘                         └──────────┘
```

### Crate Dependency Graph

```
bft-node (binary)          bft-client (binary)
    │                           │
    ├── bft-consensus           ├── bft-types
    │   ├── bft-network         ├── bft-crypto
    │   ├── bft-storage         └── (tokio, clap)
    │   ├── bft-crypto
    │   └── bft-types
    ├── bft-network
    │   ├── bft-crypto
    │   └── bft-types
    ├── bft-storage
    │   └── bft-types
    └── bft-crypto
        └── bft-types
```

### Crate Overview

| Crate | Lines | Responsibility |
|-------|-------|---------------|
| **`bft-types`** | ~360 | Core data structures: messages, blocks, operations, wire format, node configuration |
| **`bft-crypto`** | ~300 | Ed25519 keypair management, message signing, signature verification with async offload |
| **`bft-network`** | ~460 | Asynchronous networking: simulated transport (MPSC), TCP with length-delimited framing, configurable fault injection |
| **`bft-storage`** | ~480 | Crash-safe storage engine: Write-Ahead Log (CRC32), MemTable (BTreeMap), SSTable segments, compaction |
| **`bft-consensus`** | ~870 | BFT consensus protocol: leader election, Propose→Vote→Commit, view-change, quorum verification |
| **`bft-node`** | ~195 | Node binary: multi-node in-process simulation, CLI configuration |
| **`bft-client`** | ~240 | Client CLI: `put`, `get`, `bench` commands with latency measurement |

---

## 🔬 How It Works

### Consensus Flow

```
  Client                 Leader (Node 0)           Replicas (1, 2, 3)
    │                         │                          │
    │──── PUT(k, v) ─────────►│                          │
    │                         │                          │
    │                    ┌────┴────┐                     │
    │                    │ Create  │                     │
    │                    │  Block  │                     │
    │                    └────┬────┘                     │
    │                         │                          │
    │                         │──── PROPOSE(block) ─────►│
    │                         │                          │
    │                         │◄──── VOTE(block_hash) ───│
    │                         │◄──── VOTE(block_hash) ───│
    │                         │◄──── VOTE(block_hash) ───│
    │                    ┌────┴────┐                     │
    │                    │ Quorum  │                     │
    │                    │ 2f + 1  │                     │
    │                    └────┬────┘                     │
    │                         │                          │
    │                         │──── COMMIT(cert) ───────►│
    │                         │                          │
    │                    ┌────┴────┐              ┌──────┴──────┐
    │                    │  Apply  │              │    Apply    │
    │                    │ to KV   │              │   to KV    │
    │                    └────┬────┘              └──────┬──────┘
    │                         │                          │
    │◄──── OK ────────────────│                          │
    │                         │                          │
```

### View Change (Leader Failure)

When the leader fails to propose within the timeout period:

1. **Detection** — Replicas timeout waiting for proposals (exponential backoff: `base × 2^view`)
2. **Vote** — Each replica broadcasts `ViewChange(new_view, last_committed_seq)`
3. **Quorum** — When `2f+1` view-change messages are collected, the view advances
4. **New Leader** — `leader = new_view % cluster_size` (deterministic round-robin)
5. **Recovery** — New leader broadcasts `NewView` and resumes proposing

### Storage Engine (LSM-tree)

```
  Write Path                          Read Path
  ──────────                          ──────────

  PUT(k, v)                           GET(k)
      │                                  │
      ▼                                  ▼
  ┌────────┐                        ┌─────────┐
  │  WAL   │  (append, CRC32)       │MemTable │──── found? ──► return
  └───┬────┘                        └────┬────┘
      │                                  │ miss
      ▼                                  ▼
  ┌─────────┐                       ┌─────────┐
  │MemTable │                       │SSTable 0│──── found? ──► return
  └────┬────┘                       └────┬────┘
       │ (threshold: 4MB)                │ miss
       ▼                                 ▼
  ┌─────────┐                       ┌─────────┐
  │ SSTable │  (flush, sorted)      │SSTable 1│──── found? ──► return
  └─────────┘                       └────┬────┘
                                         │ miss
                                         ▼
                                      (nil)
```

---

## 🚀 Getting Started

### Prerequisites

- **Rust** 1.75+ (install via [rustup](https://rustup.rs/))
- **OS**: Windows (GNU toolchain), Linux, macOS

### Build

```bash
# Clone the repository
git clone https://github.com/<your-username>/bft-consensus-engine.git
cd bft-consensus-engine

# Build all crates
cargo build --workspace

# Run all tests (33 tests)
cargo test --workspace
```

### Run the Cluster Simulation

```bash
# Default: 4 nodes, f=1, clean network
cargo run --bin bft-node

# With fault injection (10% packet loss, random latency)
cargo run --bin bft-node -- --lossy

# Custom configuration
cargo run --bin bft-node -- --cluster-size 7 --max-faults 2 --timeout-ms 3000
```

### Client CLI

```bash
# Write a key-value pair
cargo run --bin bft-client -- put mykey "hello world"

# Read a value
cargo run --bin bft-client -- get mykey

# Run throughput benchmark (1000 ops, 64-byte values)
cargo run --bin bft-client -- bench --ops 1000 --value-size 64
```

---

## 🧪 Testing

```bash
# Run all 33 tests
cargo test --workspace

# Run tests with output
cargo test --workspace -- --nocapture
```

### Test Coverage

| Crate | Tests | What's Tested |
|-------|-------|--------------|
| `bft-types` | 6 | Serialization roundtrips, config quorum calculation, block hashing determinism |
| `bft-crypto` | 7 | Sign/verify Ed25519, key store management, async verification, invalid signature rejection |
| `bft-network` | 5 | Simulated send/receive, broadcast, 100% drop rate, framing encode/decode, peer-not-found |
| `bft-storage` | 9 | WAL append/replay, MemTable CRUD, SSTable write/read, crash recovery, flush, compaction |
| `bft-consensus` | 6 | Vote collector quorum, deduplication, view-change manager, consensus happy path, wire encoding |

---

## 📁 Project Structure

```
bft-consensus-engine/
├── Cargo.toml                    # Workspace root with shared dependencies
├── .gitignore
├── README.md                     # This file
├── ARCHITECTURE.md               # Detailed architecture documentation
│
└── crates/
    ├── bft-types/                # Core type definitions
    │   ├── Cargo.toml
    │   └── src/lib.rs            # NodeId, Block, ConsensusMessage, WireMessage...
    │
    ├── bft-crypto/               # Cryptographic primitives
    │   ├── Cargo.toml
    │   └── src/lib.rs            # NodeKeyPair, KeyStore, Ed25519 sign/verify
    │
    ├── bft-network/              # Networking layer
    │   ├── Cargo.toml
    │   └── src/lib.rs            # SimulatedNetwork, TcpTransport, FaultConfig
    │
    ├── bft-storage/              # Storage engine
    │   ├── Cargo.toml
    │   └── src/lib.rs            # WAL, MemTable, SSTable, StorageEngine
    │
    ├── bft-consensus/            # Consensus protocol
    │   ├── Cargo.toml
    │   └── src/lib.rs            # ConsensusEngine, VoteCollector, ViewChangeManager
    │
    ├── bft-node/                 # Node binary
    │   ├── Cargo.toml
    │   └── src/main.rs           # Multi-node simulation CLI
    │
    └── bft-client/               # Client binary
        ├── Cargo.toml
        └── src/main.rs           # put/get/bench CLI
```

---

## 🛡️ Safety & Correctness Guarantees

| Property | Mechanism |
|----------|-----------|
| **Safety** | No two honest nodes commit different values for the same sequence number. Ensured by `2f+1` quorum requirement. |
| **Liveness** | The system makes progress as long as `≤ f` nodes are faulty. View-change with exponential backoff prevents livelock. |
| **Crash Safety** | Every write is persisted to WAL before acknowledgment. CRC32 checksums detect partial writes. |
| **Authentication** | All consensus messages are Ed25519 signed. Invalid signatures are rejected before processing. |
| **Async Safety** | `ThreadRng` (which is `!Send`) is never held across `.await` points. All RNG decisions are pre-computed. |

---

## 🔧 Technical Decisions

| Decision | Rationale |
|----------|-----------|
| **Bincode over Protobuf** | Zero-copy deserialization, no code generation step, native Rust integration |
| **BTreeMap for MemTable** | Sorted iteration for efficient SSTable flushes; `O(log n)` lookups |
| **Ed25519 over ECDSA** | Faster verification, deterministic signatures, smaller key sizes |
| **Simulated network** | Enables deterministic testing without real sockets; fault injection for chaos testing |
| **Monorepo workspace** | Shared dependency versions, atomic refactoring, single `cargo test` for full validation |

---

## 📊 Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `tokio` | 1.x | Async runtime (TCP, timers, task spawning) |
| `serde` + `bincode` | 1.x | Efficient binary serialization |
| `ed25519-dalek` | 2.x | Ed25519 digital signatures |
| `clap` | 4.x | CLI argument parsing |
| `tracing` | 0.1.x | Structured async-aware logging |
| `crc32fast` | 1.x | CRC32 checksums for WAL integrity |
| `bytes` | 1.x | Efficient byte buffer management |

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

<div align="center">

**Built from scratch in Rust. No frameworks. No shortcuts.**

*Demonstrating mastery of distributed systems, systems programming, and cryptographic protocols.*

</div>

---
---

<div align="center">

# 🔐 Motor de Consenso BFT

### Almacén Clave-Valor Distribuido con Tolerancia a Fallos Bizantinos

*Un motor de consenso de nivel producción construido desde cero en Rust — sin frameworks, sin atajos.*

</div>

---

## 🌐 Descripción General

Este proyecto implementa un **motor de consenso tolerante a fallos bizantinos (BFT)** con un **sistema de almacenamiento clave-valor distribuido** integrado, escrito completamente en Rust. Está diseñado para mantener una máquina de estados replicada entre `N` nodos, tolerando hasta `f` fallos bizantinos (arbitrariamente maliciosos) donde `N ≥ 3f + 1`.

El sistema logra **seguridad** (todos los nodos honestos acuerdan el mismo estado) y **vivacidad** (el sistema continúa progresando) incluso en presencia de nodos que se caen, envían datos corruptos o actúan de forma adversarial.

### ¿Por Qué Este Proyecto?

El consenso distribuido es uno de los problemas más difíciles en ciencias de la computación. Este proyecto demuestra conocimiento profundo de:

- **Teoría de sistemas distribuidos** — Protocolos BFT, votación basada en quórum, mecanismos de cambio de vista
- **Programación de sistemas en Rust** — ownership, lifetimes, seguridad `Send`/`Sync`, abstracciones de costo cero
- **Diseño de almacenamiento a prueba de fallos** — Write-Ahead Logging, árboles LSM, verificación de integridad CRC32
- **Redes asíncronas** — Bucles de eventos basados en Tokio, framing delimitado por longitud, inyección de fallos
- **Autenticación criptográfica** — Firmas digitales Ed25519 con descarga de verificación asíncrona

### Qué Innovamos

| Área | Innovación |
|------|-----------|
| **Diseño del Protocolo** | BFT de 3 fases inspirado en HotStuff (Proponer → Votar → Confirmar) con cambio de vista con retroceso exponencial, diseñado para claridad educativa sin sacrificar corrección |
| **Simulación de Red** | Capa de inyección de fallos integrada (latencia, pérdida de paquetes, duplicación de mensajes) que permite pruebas determinísticas del consenso bajo condiciones adversariales |
| **RNG Async Send-Safe** | Decisiones aleatorias pre-calculadas antes de las fronteras `.await` para mantener la seguridad `Send` en spawns de tareas Tokio — un patrón no trivial en Rust asíncrono |
| **Recuperación ante Caídas** | Recuperación completa basada en WAL con verificaciones de integridad CRC32, permitiendo que los nodos se reincorporen al clúster después de una terminación inesperada sin pérdida de datos |
| **Arquitectura Modular** | Workspace de 7 crates con límites de dependencia limpios — cada crate es testeable y reemplazable de forma independiente |

---

## 🏗️ Arquitectura

### Visión General de Crates

| Crate | Líneas | Responsabilidad |
|-------|--------|----------------|
| **`bft-types`** | ~360 | Estructuras de datos: mensajes, bloques, operaciones, formato wire, configuración de nodos |
| **`bft-crypto`** | ~300 | Gestión de pares de claves Ed25519, firma de mensajes, verificación con descarga asíncrona |
| **`bft-network`** | ~460 | Red asíncrona: transporte simulado (MPSC), TCP con framing, inyección de fallos configurable |
| **`bft-storage`** | ~480 | Motor de almacenamiento: WAL (CRC32), MemTable (BTreeMap), segmentos SSTable, compactación |
| **`bft-consensus`** | ~870 | Protocolo de consenso BFT: elección de líder, Proponer→Votar→Confirmar, cambio de vista |
| **`bft-node`** | ~195 | Binario del nodo: simulación multi-nodo en proceso, configuración CLI |
| **`bft-client`** | ~240 | CLI del cliente: comandos `put`, `get`, `bench` con medición de latencia |

---

## 🔬 Cómo Funciona

### Flujo de Consenso

1. **El cliente** envía una operación `PUT(clave, valor)` al nodo líder
2. **El líder** agrupa operaciones en un bloque y envía `PROPOSE(bloque)` a todas las réplicas
3. **Las réplicas** verifican la firma Ed25519 y la validez del líder, luego envían `VOTE(hash_bloque)` al líder
4. **El líder** recopila `2f+1` votos (quórum), construye un certificado de confirmación
5. **Confirmación** — El líder difunde `COMMIT(certificado)` a todas las réplicas
6. **Aplicación** — Cada nodo aplica las operaciones del bloque a su motor de almacenamiento local

### Cambio de Vista (Fallo del Líder)

1. **Detección** — Las réplicas agotan el tiempo esperando propuestas
2. **Voto** — Cada réplica difunde `ViewChange(nueva_vista, último_seq_confirmado)`
3. **Quórum** — Cuando se recopilan `2f+1` mensajes, la vista avanza
4. **Nuevo Líder** — `líder = nueva_vista % tamaño_clúster` (round-robin determinístico)

### Motor de Almacenamiento (Árbol LSM)

- **Ruta de escritura**: `PUT → WAL (CRC32) → MemTable → SSTable (al superar 4MB)`
- **Ruta de lectura**: `GET → MemTable → SSTables (más reciente primero)`
- **Recuperación**: Al reiniciar, se reproduce el WAL para reconstruir el MemTable
- **Compactación**: Fusiona múltiples SSTables en uno, eliminando tombstones

---

## 🚀 Inicio Rápido

### Prerrequisitos

- **Rust** 1.75+ (instalar via [rustup](https://rustup.rs/))

### Compilar y Probar

```bash
# Clonar el repositorio
git clone https://github.com/<tu-usuario>/bft-consensus-engine.git
cd bft-consensus-engine

# Compilar todos los crates
cargo build --workspace

# Ejecutar las 33 pruebas
cargo test --workspace
```

### Ejecutar la Simulación

```bash
# Por defecto: 4 nodos, f=1, red limpia
cargo run --bin bft-node

# Con inyección de fallos (10% pérdida, latencia aleatoria)
cargo run --bin bft-node -- --lossy

# Configuración personalizada
cargo run --bin bft-node -- --cluster-size 7 --max-faults 2
```

### Cliente CLI

```bash
# Escribir un par clave-valor
cargo run --bin bft-client -- put miclave "hola mundo"

# Leer un valor
cargo run --bin bft-client -- get miclave

# Benchmark de rendimiento
cargo run --bin bft-client -- bench --ops 1000 --value-size 64
```

---

## 🧪 Pruebas

33 pruebas unitarias cubren todos los componentes críticos:

| Crate | Pruebas | Qué se Prueba |
|-------|---------|--------------|
| `bft-types` | 6 | Serialización, cálculo de quórum, hashing de bloques |
| `bft-crypto` | 7 | Firma/verificación Ed25519, gestión de claves, rechazo de firmas inválidas |
| `bft-network` | 5 | Envío/recepción simulado, broadcast, tasa de pérdida 100%, codificación de frames |
| `bft-storage` | 9 | WAL, MemTable CRUD, SSTable, recuperación ante caídas, compactación |
| `bft-consensus` | 6 | Quórum de votos, deduplicación, cambio de vista, camino feliz del consenso |

---

## 🛡️ Garantías de Seguridad y Corrección

| Propiedad | Mecanismo |
|-----------|-----------|
| **Seguridad** | Quórum `2f+1` — ningún nodo honesto confirma valores diferentes para el mismo número de secuencia |
| **Vivacidad** | El sistema progresa mientras `≤ f` nodos estén defectuosos. Cambio de vista con retroceso exponencial |
| **Persistencia** | Toda escritura se persiste en WAL antes de confirmar. CRC32 detecta escrituras parciales |
| **Autenticación** | Todos los mensajes de consenso firmados con Ed25519. Firmas inválidas rechazadas antes de procesar |
| **Seguridad Async** | `ThreadRng` (`!Send`) nunca se mantiene a través de puntos `.await` |

---

<div align="center">

**Construido desde cero en Rust. Sin frameworks. Sin atajos.**

*Demostrando dominio de sistemas distribuidos, programación de sistemas y protocolos criptográficos.*

</div>
