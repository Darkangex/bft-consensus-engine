# Architecture / Arquitectura

## System Overview / Visión General del Sistema

```
                    ┌──────────────────────────────────────────┐
                    │           BFT Consensus Cluster           │
                    │                                          │
                    │   ┌────────┐ ┌────────┐ ┌────────┐      │
                    │   │ Node 0 │ │ Node 1 │ │ Node 2 │ ...  │
                    │   │(Leader)│ │(Replica)│ │(Replica)│      │
                    │   └───┬────┘ └───┬────┘ └───┬────┘      │
                    │       │          │          │            │
                    │       ▼          ▼          ▼            │
                    │   ┌──────────────────────────────────┐   │
                    │   │    Consensus Protocol (BFT)      │   │
                    │   │  Propose → Vote → Commit (2f+1)  │   │
                    │   └──────────────┬───────────────────┘   │
                    │                  │                        │
                    │                  ▼                        │
                    │   ┌──────────────────────────────────┐   │
                    │   │      Storage Engine (LSM-tree)    │   │
                    │   │   WAL → MemTable → SSTable        │   │
                    │   └──────────────────────────────────┘   │
                    └──────────────────────────────────────────┘
```

---

## Module Architecture / Arquitectura de Módulos

### 1. `bft-types` — Core Data Structures / Estructuras de Datos

**EN:** Defines the shared vocabulary of the system. All other crates depend on these types.

**ES:** Define el vocabulario compartido del sistema. Todos los demás crates dependen de estos tipos.

```
NodeId          = u64           (unique node identifier)
ViewNumber      = u64           (monotonically increasing view counter)
SequenceNumber  = u64           (block sequence in the committed log)
Operation       = Put | Get | Txn
Block           = { view, sequence, proposer, operations, parent_hash }
ConsensusMessage = Propose | Vote | Commit | ViewChange | NewView
WireMessage     = { version: u8, msg_type, payload: Vec<u8> }
```

**Design principle / Principio de diseño:**
All types implement `Serialize + Deserialize` via serde. Bincode is used for wire encoding — it's faster than Protobuf for Rust-to-Rust communication and requires no `.proto` schema files.

---

### 2. `bft-crypto` — Cryptographic Layer / Capa Criptográfica

**EN:** Provides Ed25519 digital signature operations with async safety guarantees.

**ES:** Proporciona operaciones de firma digital Ed25519 con garantías de seguridad asíncrona.

```
NodeKeyPair
  ├── from_seed(node_id, seed)     → deterministic key generation
  ├── sign_bytes(data)             → (signature, public_key)
  ├── sign_consensus(msg)          → SignedMessage
  └── verify_bytes(data, sig, pk)  → Result<()>

KeyStore
  ├── insert(node_id, public_key)
  └── get(node_id) → Option<PublicKey>

verify_signed_message(key_store, signed_msg) → Result<ConsensusMessage>
verify_signed_message_async(key_store, signed_msg) → Future<Result<ConsensusMessage>>
```

**Critical pattern / Patrón crítico:**
`verify_signed_message_async` uses `tokio::task::spawn_blocking` to offload CPU-intensive signature verification from the async reactor thread, preventing latency spikes.

---

### 3. `bft-network` — Networking Layer / Capa de Red

**EN:** Dual-mode networking: simulated (in-process channels) for testing, TCP for production.

**ES:** Red de doble modo: simulada (canales en proceso) para pruebas, TCP para producción.

```
SimulatedNetwork
  └── register(node_id) → (SimulatedSender, Receiver)

SimulatedSender
  ├── send(target, msg)     → Result<()>   (with fault injection)
  └── broadcast(msg)        → Vec<Result>

FaultConfig
  ├── clean()    → no faults
  └── lossy()    → latency: 10-100ms, drop: 10%, duplicate: 5%

PeerManager (TCP)
  ├── start_listener()      → accepts inbound connections
  ├── send_to(target, msg)  → TCP with length-delimited framing
  └── broadcast(msg)
```

**Wire format / Formato de trama:**
```
┌──────────────┬────────────────────────────┐
│ Length (4B)   │ Payload (N bytes)          │
│ big-endian   │ bincode(WireMessage)       │
└──────────────┴────────────────────────────┘
```

**Send safety pattern / Patrón de seguridad Send:**
```rust
// ThreadRng is !Send — cannot live across .await
let (should_drop, delay_ms, should_duplicate) = {
    let mut rng = rand::thread_rng();
    (rng.gen::<f64>() < drop_rate, ..., ...)
};
// rng is dropped here — safe to .await below
if let Some(delay) = delay_ms {
    tokio::time::sleep(Duration::from_millis(delay)).await;
}
```

---

### 4. `bft-storage` — Storage Engine / Motor de Almacenamiento

**EN:** LSM-tree based storage with crash recovery via Write-Ahead Log.

**ES:** Almacenamiento basado en árbol LSM con recuperación ante caídas mediante Write-Ahead Log.

```
StorageEngine
  ├── open(data_dir)        → recover from WAL if exists
  ├── put(key, value)       → WAL → MemTable → (flush if >4MB)
  ├── delete(key)           → WAL → MemTable (tombstone)
  ├── get(key)              → MemTable → SSTables (newest first)
  ├── flush_memtable()      → write sorted SSTable, truncate WAL
  └── compact()             → merge all SSTables, remove tombstones

WriteAheadLog
  ├── append(entry)         → [len:4B][payload:NB][crc32:4B]
  ├── replay(path)          → Vec<WalEntry> (skip corrupted)
  └── truncate()            → clear after flush

MemTable = BTreeMap<Vec<u8>, Option<Vec<u8>>>
  └── None values represent tombstones (deletions)

SSTable (on-disk format):
  ├── Repeated: [key_len:4B][key][has_value:1B][value_len:4B][value]
  └── Footer: [entry_count:8B]
```

**Crash safety invariant / Invariante de seguridad ante caídas:**
1. Every mutation is written to WAL **before** being applied to MemTable
2. WAL entries include CRC32 checksums — partial writes are detected and skipped during recovery
3. SSTables are immutable once written — no corruption risk from concurrent reads

---

### 5. `bft-consensus` — BFT Protocol / Protocolo BFT

**EN:** The core protocol engine implementing a simplified HotStuff-inspired BFT consensus.

**ES:** El motor del protocolo principal que implementa un consenso BFT inspirado en HotStuff.

```
ConsensusEngine
  ├── new(config, keypair, key_store, network, storage)
  ├── run(inbox, client_rx)     → main event loop (tokio::select!)
  ├── try_propose()             → create block, sign, broadcast, self-vote
  ├── handle_propose()          → verify leader, store block, vote
  ├── handle_vote()             → collect votes, check quorum
  ├── commit_block()            → broadcast cert, apply to storage
  ├── initiate_view_change()    → broadcast ViewChange, self-vote
  └── advance_to_view()        → update state, announce NewView

VoteCollector
  ├── add_vote(view, seq, voter, sig) → bool (quorum reached?)
  ├── get_signatures(view, seq)       → Vec<(NodeId, sig)>
  └── gc_before_view(min_view)        → cleanup old entries

ViewChangeManager
  ├── add_view_change(new_view, sender) → bool (quorum reached?)
  ├── advance_view(new_view)
  └── current_timeout() → Duration (base * 2^view, exponential backoff)
```

**Quorum math / Matemática de quórum:**
- Cluster size: `N = 3f + 1`
- Quorum: `Q = 2f + 1`
- Leader: `view_number % N`
- For `N=4, f=1`: quorum is 3 out of 4 nodes

**State machine / Máquina de estados:**
```
    ┌────────────┐              ┌────────────┐
    │  WAITING   │─── client ──►│ PROPOSING  │
    │ (replica)  │   request    │  (leader)  │
    └──────┬─────┘              └──────┬─────┘
           │                           │
           │◄──── PROPOSE ─────────────│
           │                           │
    ┌──────┴─────┐              ┌──────┴─────┐
    │  VOTING    │──── VOTE ───►│ COLLECTING │
    └──────┬─────┘              └──────┬─────┘
           │                           │ (2f+1 votes)
           │◄──── COMMIT ─────────────│
           │                           │
    ┌──────┴─────┐              ┌──────┴─────┐
    │ COMMITTED  │              │ COMMITTED  │
    │  (apply)   │              │  (apply)   │
    └────────────┘              └────────────┘

    ─── timeout ───►  VIEW CHANGE  ───► NEW VIEW
```

---

## Data Flow / Flujo de Datos

### Write Path / Ruta de Escritura

```
Client                                          
  │ PUT(k, v)                                   
  ▼                                             
Leader Node                                     
  │ 1. Create Block with operation              
  │ 2. Sign with Ed25519                        
  │ 3. Broadcast PROPOSE to replicas            
  │ 4. Self-vote                                
  ▼                                             
Replicas                                        
  │ 1. Verify Ed25519 signature                 
  │ 2. Verify sender is current leader          
  │ 3. Store proposed block                     
  │ 4. Send VOTE back to leader                 
  ▼                                             
Leader (vote collection)                        
  │ 1. Collect 2f+1 votes (quorum)              
  │ 2. Build commit certificate                 
  │ 3. Broadcast COMMIT to all                  
  ▼                                             
All Nodes                                       
  │ 1. Write to WAL (CRC32)                     
  │ 2. Insert into MemTable                     
  │ 3. Flush to SSTable if threshold reached    
  ▼                                             
  ✓ Committed & Durable                         
```

### Read Path / Ruta de Lectura

```
Client
  │ GET(k)
  ▼
Any Node (no consensus needed)
  │ 1. Check MemTable     → found? return
  │ 2. Check SSTable[0]   → found? return (newest)
  │ 3. Check SSTable[1]   → found? return
  │ ...
  │ N. Not found           → return None
  ▼
  ✓ Value or None
```

---

## Concurrency Model / Modelo de Concurrencia

**EN:** The system uses Tokio's cooperative multitasking model. Each node runs as an independent async task.

**ES:** El sistema usa el modelo de multitarea cooperativa de Tokio. Cada nodo ejecuta como una tarea asíncrona independiente.

```
tokio::select! {
    // Branch 1: Incoming consensus messages
    Some((from, msg)) = inbox.recv() => { ... }

    // Branch 2: Incoming client requests  
    Some((req, resp_tx)) = client_rx.recv() => { ... }

    // Branch 3: Consensus timeout
    _ = tokio::time::sleep_until(deadline) => { ... }
}
```

**Thread safety guarantees / Garantías de seguridad de hilos:**
- `SimulatedSender`: `Clone + Send` (uses `Arc<Mutex<HashMap>>` for inbox routing)
- `ConsensusEngine`: `Send` (no `Rc`, no `RefCell`, no `ThreadRng` across awaits)
- `StorageEngine`: synchronous I/O — called from async context without blocking risk (file I/O is fast for small WAL entries)

---

## Fault Tolerance Model / Modelo de Tolerancia a Fallos

| Fault Type | How Handled |
|-----------|-------------|
| **Node crash** | WAL recovery on restart; view-change elects new leader |
| **Network partition** | Quorum prevents split-brain; `2f+1` guarantees overlap |
| **Message loss** | Timeout triggers view-change; delivery not required from all |
| **Message duplication** | Vote deduplication in VoteCollector (HashSet per slot) |
| **Byzantine leader** | Replicas verify leader identity; invalid proposals rejected |
| **Forged signatures** | Ed25519 verification on every consensus message |
| **Disk corruption** | CRC32 on WAL entries; corrupted entries skipped during recovery |
