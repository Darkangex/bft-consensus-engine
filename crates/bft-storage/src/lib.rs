// ═══════════════════════════════════════════════════════════════════
//  bft-storage — Crash-safe storage engine with WAL + LSM-tree
//  Version: 0.1.0
// ═══════════════════════════════════════════════════════════════════
//
//  Components:
//    1. WalEntry / WriteAheadLog  — append-only log with CRC32
//    2. MemTable                  — sorted in-memory index (BTreeMap)
//    3. SSTable                   — sorted segment on disk
//    4. StorageEngine             — façade coordinating WAL → Mem → SST
//
//  Crash safety: every write goes to WAL first. On recovery, the WAL
//  is replayed to rebuild the MemTable. SSTables are immutable once
//  flushed.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════════════
//  1. WAL ENTRY FORMAT
// ═══════════════════════════════════════════════════════════════════

/// A single WAL entry: a key-value write or delete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalEntry {
    Put { key: Vec<u8>, value: Vec<u8> },
    Delete { key: Vec<u8> },
}

/// On-disk format for a WAL record:
///   [4 bytes: payload length][N bytes: bincode payload][4 bytes: CRC32]
const WAL_HEADER_SIZE: usize = 4;
const WAL_CRC_SIZE: usize = 4;

// ═══════════════════════════════════════════════════════════════════
//  2. WRITE-AHEAD LOG
// ═══════════════════════════════════════════════════════════════════

/// Append-only write-ahead log with CRC32 integrity checks.
///
/// Every mutation to the storage engine is recorded here before
/// being applied to the in-memory index. On crash recovery, the WAL
/// is replayed to rebuild state.
pub struct WriteAheadLog {
    file: File,
    path: PathBuf,
    entry_count: u64,
}

impl WriteAheadLog {
    /// Open (or create) a WAL file at the given path.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        Ok(Self {
            file,
            path: path.to_path_buf(),
            entry_count: 0,
        })
    }

    /// Append an entry to the WAL with CRC32 integrity.
    pub fn append(&mut self, entry: &WalEntry) -> io::Result<()> {
        let payload = bincode::serialize(entry)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let crc = crc32fast::hash(&payload);

        // Write: [len: u32][payload][crc: u32]
        let len = payload.len() as u32;
        self.file.write_all(&len.to_le_bytes())?;
        self.file.write_all(&payload)?;
        self.file.write_all(&crc.to_le_bytes())?;
        self.file.flush()?;

        self.entry_count += 1;
        Ok(())
    }

    /// Replay all valid entries from the WAL file.
    ///
    /// Entries with CRC mismatches (e.g., from partial writes during
    /// a crash) are skipped with a warning.
    pub fn replay(path: &Path) -> io::Result<Vec<WalEntry>> {
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut entries = Vec::new();
        let mut corrupted_count = 0u64;

        loop {
            // Read length header
            let mut len_buf = [0u8; WAL_HEADER_SIZE];
            match reader.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
            let payload_len = u32::from_le_bytes(len_buf) as usize;

            // Sanity check: reject absurdly large entries
            if payload_len > 64 * 1024 * 1024 {
                warn!(payload_len, "WAL entry too large, stopping replay");
                break;
            }

            // Read payload
            let mut payload = vec![0u8; payload_len];
            match reader.read_exact(&mut payload) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    warn!("truncated WAL entry, skipping");
                    break;
                }
                Err(e) => return Err(e),
            }

            // Read CRC
            let mut crc_buf = [0u8; WAL_CRC_SIZE];
            match reader.read_exact(&mut crc_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    warn!("truncated WAL CRC, skipping last entry");
                    break;
                }
                Err(e) => return Err(e),
            }
            let stored_crc = u32::from_le_bytes(crc_buf);
            let computed_crc = crc32fast::hash(&payload);

            if stored_crc != computed_crc {
                warn!(
                    stored_crc,
                    computed_crc, "CRC mismatch in WAL, skipping entry"
                );
                corrupted_count += 1;
                continue;
            }

            // Deserialize
            match bincode::deserialize::<WalEntry>(&payload) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    warn!("WAL entry deserialization failed: {e}");
                    corrupted_count += 1;
                }
            }
        }

        if corrupted_count > 0 {
            warn!(corrupted_count, "skipped corrupted WAL entries");
        }

        info!(
            valid_entries = entries.len(),
            "WAL replay complete"
        );

        Ok(entries)
    }

    /// Number of entries appended in this session.
    pub fn entry_count(&self) -> u64 {
        self.entry_count
    }

    /// Truncate the WAL (used after flushing MemTable to SSTable).
    pub fn truncate(&mut self) -> io::Result<()> {
        self.file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.path)?;
        self.entry_count = 0;
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════
//  3. MEMTABLE — sorted in-memory index
// ═══════════════════════════════════════════════════════════════════

/// In-memory sorted key-value store backed by a BTreeMap.
///
/// Supports `None` values to represent deletions (tombstones).
pub struct MemTable {
    data: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    size_bytes: usize,
}

impl MemTable {
    pub fn new() -> Self {
        Self {
            data: BTreeMap::new(),
            size_bytes: 0,
        }
    }

    /// Insert a key-value pair.
    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.size_bytes += key.len() + value.len();
        self.data.insert(key, Some(value));
    }

    /// Mark a key as deleted (tombstone).
    pub fn delete(&mut self, key: Vec<u8>) {
        self.size_bytes += key.len();
        self.data.insert(key, None);
    }

    /// Look up a key. Returns `Some(Some(value))` if found,
    /// `Some(None)` if tombstoned, `None` if not in memtable.
    pub fn get(&self, key: &[u8]) -> Option<&Option<Vec<u8>>> {
        self.data.get(key)
    }

    /// Approximate size in bytes (for flush threshold decisions).
    pub fn size_bytes(&self) -> usize {
        self.size_bytes
    }

    /// Number of entries (including tombstones).
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Drain all entries for flushing to an SSTable.
    pub fn drain(&mut self) -> BTreeMap<Vec<u8>, Option<Vec<u8>>> {
        self.size_bytes = 0;
        std::mem::take(&mut self.data)
    }
}

impl Default for MemTable {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════
//  4. SSTABLE — sorted string table on disk
// ═══════════════════════════════════════════════════════════════════

/// A simple sorted string table (SSTable) written to disk.
///
/// Format:
///   Repeated entries of: [key_len: u32][key][has_value: u8][value_len: u32][value]
///   Footer: [entry_count: u64]
///
/// Entries are sorted by key. Tombstones have `has_value = 0`.
pub struct SSTable;

impl SSTable {
    /// Flush a sorted map of entries to an SSTable file.
    pub fn write(
        path: &Path,
        data: &BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    ) -> io::Result<()> {
        let mut file = File::create(path)?;
        let mut count = 0u64;

        for (key, value) in data {
            // Key
            let key_len = key.len() as u32;
            file.write_all(&key_len.to_le_bytes())?;
            file.write_all(key)?;

            // Value (or tombstone marker)
            match value {
                Some(v) => {
                    file.write_all(&[1u8])?; // has_value = true
                    let val_len = v.len() as u32;
                    file.write_all(&val_len.to_le_bytes())?;
                    file.write_all(v)?;
                }
                None => {
                    file.write_all(&[0u8])?; // tombstone
                }
            }
            count += 1;
        }

        // Footer: entry count
        file.write_all(&count.to_le_bytes())?;
        file.flush()?;

        Ok(())
    }

    /// Read all entries from an SSTable file into a sorted map.
    pub fn read(path: &Path) -> io::Result<BTreeMap<Vec<u8>, Option<Vec<u8>>>> {
        let data = fs::read(path)?;
        let mut pos = 0;
        let mut entries = BTreeMap::new();

        // The last 8 bytes are the entry count (footer)
        if data.len() < 8 {
            return Ok(entries);
        }
        let footer_start = data.len() - 8;

        while pos < footer_start {
            // Key length
            if pos + 4 > footer_start {
                break;
            }
            let key_len =
                u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;

            // Key
            if pos + key_len > footer_start {
                break;
            }
            let key = data[pos..pos + key_len].to_vec();
            pos += key_len;

            // Has value flag
            if pos >= footer_start {
                break;
            }
            let has_value = data[pos];
            pos += 1;

            let value = if has_value == 1 {
                // Value length
                if pos + 4 > footer_start {
                    break;
                }
                let val_len =
                    u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
                pos += 4;

                // Value
                if pos + val_len > footer_start {
                    break;
                }
                let v = data[pos..pos + val_len].to_vec();
                pos += val_len;
                Some(v)
            } else {
                None
            };

            entries.insert(key, value);
        }

        Ok(entries)
    }
}

// ═══════════════════════════════════════════════════════════════════
//  5. STORAGE ENGINE — unified façade
// ═══════════════════════════════════════════════════════════════════

/// Threshold in bytes before the MemTable is flushed to an SSTable.
const MEMTABLE_FLUSH_THRESHOLD: usize = 4 * 1024 * 1024; // 4 MB

/// The main storage engine coordinating WAL, MemTable, and SSTables.
///
/// Write path: WAL → MemTable → (flush to SSTable when threshold hit)
/// Read path:  MemTable → SSTable files (newest first)
///
/// Crash recovery: replay WAL → rebuild MemTable.
pub struct StorageEngine {
    data_dir: PathBuf,
    wal: WriteAheadLog,
    memtable: MemTable,
    /// SSTable file paths, ordered newest-first.
    sstable_paths: Vec<PathBuf>,
    /// Counter for generating unique SSTable filenames.
    next_sst_id: u64,
}

impl StorageEngine {
    /// Open or create a storage engine in the given directory.
    ///
    /// If a WAL exists from a previous run, it is replayed to
    /// restore state.
    pub fn open(data_dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(data_dir)?;

        let wal_path = data_dir.join("wal.log");
        let mut memtable = MemTable::new();

        // ── Crash recovery: replay WAL ──
        let entries = WriteAheadLog::replay(&wal_path)?;
        for entry in &entries {
            match entry {
                WalEntry::Put { key, value } => {
                    memtable.put(key.clone(), value.clone());
                }
                WalEntry::Delete { key } => {
                    memtable.delete(key.clone());
                }
            }
        }

        if !entries.is_empty() {
            info!(
                count = entries.len(),
                "recovered entries from WAL"
            );
        }

        // ── Discover existing SSTable files ──
        let mut sstable_paths: Vec<PathBuf> = Vec::new();
        let mut max_sst_id = 0u64;

        if data_dir.exists() {
            for entry in fs::read_dir(data_dir)? {
                let entry = entry?;
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "sst" {
                        if let Some(stem) = path.file_stem() {
                            if let Some(s) = stem.to_str() {
                                if let Some(stripped) = s.strip_prefix("sst_") {
                                    if let Ok(id) = stripped.parse::<u64>() {
                                        max_sst_id = max_sst_id.max(id);
                                    }
                                }
                            }
                        }
                        sstable_paths.push(path);
                    }
                }
            }
        }

        // Sort newest first (higher ID = newer)
        sstable_paths.sort_by(|a, b| b.cmp(a));

        let wal = WriteAheadLog::open(&wal_path)?;

        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            wal,
            memtable,
            sstable_paths,
            next_sst_id: max_sst_id + 1,
        })
    }

    /// Write a key-value pair.
    ///
    /// The write is durable once this returns (written to WAL).
    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> io::Result<()> {
        // ── Step 1: write to WAL ──
        self.wal.append(&WalEntry::Put {
            key: key.clone(),
            value: value.clone(),
        })?;

        // ── Step 2: update MemTable ──
        self.memtable.put(key, value);

        // ── Step 3: flush if above threshold ──
        if self.memtable.size_bytes() >= MEMTABLE_FLUSH_THRESHOLD {
            self.flush_memtable()?;
        }

        Ok(())
    }

    /// Delete a key.
    pub fn delete(&mut self, key: Vec<u8>) -> io::Result<()> {
        self.wal.append(&WalEntry::Delete { key: key.clone() })?;
        self.memtable.delete(key);
        Ok(())
    }

    /// Read a value by key.
    ///
    /// Checks MemTable first, then SSTables from newest to oldest.
    pub fn get(&self, key: &[u8]) -> io::Result<Option<Vec<u8>>> {
        // ── Check MemTable ──
        if let Some(entry) = self.memtable.get(key) {
            return match entry {
                Some(value) => Ok(Some(value.clone())),
                None => Ok(None), // tombstone
            };
        }

        // ── Check SSTables (newest first) ──
        for sst_path in &self.sstable_paths {
            let table = SSTable::read(sst_path)?;
            if let Some(entry) = table.get(key) {
                return match entry {
                    Some(value) => Ok(Some(value.clone())),
                    None => Ok(None), // tombstone
                };
            }
        }

        Ok(None)
    }

    /// Flush the current MemTable to a new SSTable and truncate the WAL.
    pub fn flush_memtable(&mut self) -> io::Result<()> {
        if self.memtable.is_empty() {
            return Ok(());
        }

        let sst_path = self
            .data_dir
            .join(format!("sst_{:06}.sst", self.next_sst_id));
        self.next_sst_id += 1;

        let data = self.memtable.drain();
        SSTable::write(&sst_path, &data)?;

        debug!(?sst_path, entries = data.len(), "flushed memtable to SSTable");

        // Newest SSTable goes to the front
        self.sstable_paths.insert(0, sst_path);

        // Truncate WAL since memtable is now persisted
        self.wal.truncate()?;

        Ok(())
    }

    /// Compact all SSTables into a single merged SSTable.
    ///
    /// This is a simple full compaction: read all SSTables, merge,
    /// write one new SSTable, delete the old ones.
    pub fn compact(&mut self) -> io::Result<()> {
        if self.sstable_paths.len() < 2 {
            return Ok(());
        }

        info!(
            count = self.sstable_paths.len(),
            "starting SSTable compaction"
        );

        // Merge all SSTables (oldest first so newer values win)
        let mut merged = BTreeMap::new();
        for sst_path in self.sstable_paths.iter().rev() {
            let table = SSTable::read(sst_path)?;
            for (k, v) in table {
                merged.insert(k, v);
            }
        }

        // Remove tombstones during compaction
        merged.retain(|_, v| v.is_some());

        // Write merged SSTable
        let new_path = self
            .data_dir
            .join(format!("sst_{:06}.sst", self.next_sst_id));
        self.next_sst_id += 1;
        SSTable::write(&new_path, &merged)?;

        // Delete old SSTables
        for old_path in &self.sstable_paths {
            let _ = fs::remove_file(old_path);
        }

        self.sstable_paths = vec![new_path];

        info!("compaction complete");
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════
//  6. TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_wal_append_and_replay() {
        let tmp = TempDir::new().unwrap();
        let wal_path = tmp.path().join("test.wal");

        // Write entries
        {
            let mut wal = WriteAheadLog::open(&wal_path).unwrap();
            wal.append(&WalEntry::Put {
                key: b"k1".to_vec(),
                value: b"v1".to_vec(),
            })
            .unwrap();
            wal.append(&WalEntry::Put {
                key: b"k2".to_vec(),
                value: b"v2".to_vec(),
            })
            .unwrap();
            wal.append(&WalEntry::Delete {
                key: b"k1".to_vec(),
            })
            .unwrap();
        }

        // Replay
        let entries = WriteAheadLog::replay(&wal_path).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries[0],
            WalEntry::Put {
                key: b"k1".to_vec(),
                value: b"v1".to_vec()
            }
        );
        assert_eq!(
            entries[2],
            WalEntry::Delete {
                key: b"k1".to_vec()
            }
        );
    }

    #[test]
    fn test_memtable_basic() {
        let mut mt = MemTable::new();
        mt.put(b"hello".to_vec(), b"world".to_vec());
        assert_eq!(mt.get(b"hello"), Some(&Some(b"world".to_vec())));
        assert_eq!(mt.get(b"missing"), None);

        mt.delete(b"hello".to_vec());
        assert_eq!(mt.get(b"hello"), Some(&None)); // tombstone
    }

    #[test]
    fn test_sstable_write_read() {
        let tmp = TempDir::new().unwrap();
        let sst_path = tmp.path().join("test.sst");

        let mut data = BTreeMap::new();
        data.insert(b"apple".to_vec(), Some(b"red".to_vec()));
        data.insert(b"banana".to_vec(), Some(b"yellow".to_vec()));
        data.insert(b"cherry".to_vec(), None); // tombstone

        SSTable::write(&sst_path, &data).unwrap();
        let loaded = SSTable::read(&sst_path).unwrap();

        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[&b"apple".to_vec()], Some(b"red".to_vec()));
        assert_eq!(loaded[&b"banana".to_vec()], Some(b"yellow".to_vec()));
        assert_eq!(loaded[&b"cherry".to_vec()], None);
    }

    #[test]
    fn test_storage_engine_put_get() {
        let tmp = TempDir::new().unwrap();
        let mut engine = StorageEngine::open(tmp.path()).unwrap();

        engine.put(b"key1".to_vec(), b"value1".to_vec()).unwrap();
        engine.put(b"key2".to_vec(), b"value2".to_vec()).unwrap();

        assert_eq!(engine.get(b"key1").unwrap(), Some(b"value1".to_vec()));
        assert_eq!(engine.get(b"key2").unwrap(), Some(b"value2".to_vec()));
        assert_eq!(engine.get(b"missing").unwrap(), None);
    }

    #[test]
    fn test_storage_engine_overwrite() {
        let tmp = TempDir::new().unwrap();
        let mut engine = StorageEngine::open(tmp.path()).unwrap();

        engine.put(b"key".to_vec(), b"v1".to_vec()).unwrap();
        engine.put(b"key".to_vec(), b"v2".to_vec()).unwrap();

        assert_eq!(engine.get(b"key").unwrap(), Some(b"v2".to_vec()));
    }

    #[test]
    fn test_storage_engine_delete() {
        let tmp = TempDir::new().unwrap();
        let mut engine = StorageEngine::open(tmp.path()).unwrap();

        engine.put(b"key".to_vec(), b"value".to_vec()).unwrap();
        engine.delete(b"key".to_vec()).unwrap();

        assert_eq!(engine.get(b"key").unwrap(), None);
    }

    #[test]
    fn test_storage_engine_crash_recovery() {
        let tmp = TempDir::new().unwrap();

        // Write some data and "crash" (drop without flush)
        {
            let mut engine = StorageEngine::open(tmp.path()).unwrap();
            engine.put(b"survived".to_vec(), b"yes".to_vec()).unwrap();
        }

        // Reopen — should recover from WAL
        let engine = StorageEngine::open(tmp.path()).unwrap();
        assert_eq!(
            engine.get(b"survived").unwrap(),
            Some(b"yes".to_vec()),
            "data should survive crash via WAL replay"
        );
    }

    #[test]
    fn test_storage_engine_flush_and_read_from_sst() {
        let tmp = TempDir::new().unwrap();
        let mut engine = StorageEngine::open(tmp.path()).unwrap();

        engine.put(b"k1".to_vec(), b"v1".to_vec()).unwrap();
        engine.put(b"k2".to_vec(), b"v2".to_vec()).unwrap();
        engine.flush_memtable().unwrap();

        // MemTable is now empty; reads should come from SSTable
        assert!(engine.memtable.is_empty());
        assert_eq!(engine.get(b"k1").unwrap(), Some(b"v1".to_vec()));
        assert_eq!(engine.get(b"k2").unwrap(), Some(b"v2".to_vec()));
    }

    #[test]
    fn test_storage_engine_compaction() {
        let tmp = TempDir::new().unwrap();
        let mut engine = StorageEngine::open(tmp.path()).unwrap();

        // Create two SSTables
        engine.put(b"a".to_vec(), b"1".to_vec()).unwrap();
        engine.flush_memtable().unwrap();

        engine.put(b"b".to_vec(), b"2".to_vec()).unwrap();
        engine.put(b"a".to_vec(), b"updated".to_vec()).unwrap();
        engine.flush_memtable().unwrap();

        assert_eq!(engine.sstable_paths.len(), 2);

        // Compact
        engine.compact().unwrap();
        assert_eq!(engine.sstable_paths.len(), 1);

        // Values should still be correct
        assert_eq!(engine.get(b"a").unwrap(), Some(b"updated".to_vec()));
        assert_eq!(engine.get(b"b").unwrap(), Some(b"2".to_vec()));
    }
}
