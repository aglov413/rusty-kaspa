use std::{cell::RefCell, collections::HashMap, fmt, sync::Arc};

use kaspa_consensus_core::KType;
use kaspa_database::{
    prelude::{DbKey, StoreError},
    registry::DatabaseStorePrefixes,
};
use kaspa_hashes::Hash;

use crate::model::stores::ghostdag::GhostdagData;
use kaspa_database::prelude::{BatchDbWriter, CachePolicy, CachedDbAccess, DB};
use rocksdb::WriteBatch;

pub struct MemoryDagknightStore {
    dk_map: RefCell<HashMap<DagknightKey, Arc<GhostdagData>>>,
}

pub trait DagknightStoreReader {
    fn get_selected_parent(&self, dk_key: DagknightKey) -> Result<Hash, StoreError>;
    fn get_data(&self, dk_key: DagknightKey) -> Result<Arc<GhostdagData>, StoreError>;
    fn has(&self, dk_key: DagknightKey) -> Result<bool, StoreError>;
}

#[derive(Clone)]
pub struct DagknightKey {
    pub pov_hash: Hash,
    pub root_hash: Hash,
    pub k: KType,
    pub free_search: bool,
    // Precomputed bytes in order: root_hash || k(u16 BE) || pov_hash || free_search
    bytes: [u8; kaspa_hashes::HASH_SIZE * 2 + 3],
}

impl DagknightKey {
    pub fn new(root_hash: Hash, pov_hash: Hash, k: KType, free_search: bool) -> Self {
        // Layout must match DB-level expectations where `k` is encoded as a u16
        // (two bytes). Allocate enough space: root_hash + k(2) + pov_hash + free_search(1).
        let mut bytes = [0u8; kaspa_hashes::HASH_SIZE * 2 + 3];
        let hash_size = kaspa_hashes::HASH_SIZE;
        bytes[..hash_size].copy_from_slice(root_hash.as_ref());

        // Encode k as big-endian u16 to match other code paths that construct
        // DB keys using two bytes for k.
        let k_be = k.to_be_bytes();
        bytes[hash_size] = k_be[0];
        bytes[hash_size + 1] = k_be[1];

        bytes[(hash_size + 2)..(hash_size + 2 + hash_size)].copy_from_slice(pov_hash.as_ref());
        bytes[(2 * hash_size) + 2] = if free_search { 1 } else { 0 };

        Self { pov_hash, root_hash, k, free_search, bytes }
    }

    pub const SERIALIZED_LEN: usize = kaspa_hashes::HASH_SIZE * 2 + 3;

    /// Parses a logical key produced by [`Self::new`]. `bytes` excludes the store prefix.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() != Self::SERIALIZED_LEN {
            return Err(StoreError::DataInconsistency(format!(
                "DagknightKey expects {} bytes, got {}",
                Self::SERIALIZED_LEN,
                bytes.len()
            )));
        }
        let hash_size = kaspa_hashes::HASH_SIZE;
        let root_hash = Hash::from_slice(&bytes[..hash_size]);
        let k = KType::from_be_bytes([bytes[hash_size], bytes[hash_size + 1]]);
        let pov_hash = Hash::from_slice(&bytes[(hash_size + 2)..(2 * hash_size + 2)]);
        let free_search = match bytes[2 * hash_size + 2] {
            0 => false,
            1 => true,
            other => {
                return Err(StoreError::DataInconsistency(format!("DagknightKey free_search flag must be 0 or 1, got {other}")));
            }
        };
        Ok(Self::new(root_hash, pov_hash, k, free_search))
    }
}

impl fmt::Display for DagknightKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.bytes)
    }
}

impl AsRef<[u8]> for DagknightKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Eq for DagknightKey {}

impl std::hash::Hash for DagknightKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Hash based on the logical key fields
        self.root_hash.hash(state);
        self.k.hash(state);
        self.pov_hash.hash(state);
        self.free_search.hash(state);
    }
}

impl PartialEq for DagknightKey {
    fn eq(&self, other: &Self) -> bool {
        self.pov_hash == other.pov_hash
            && self.k == other.k
            && self.root_hash == other.root_hash
            && self.free_search == other.free_search
    }
}

pub trait DagknightStore {
    fn insert(&self, key: DagknightKey, dk_data: Arc<GhostdagData>) -> Result<(), StoreError>;
    fn delete(&self, key: DagknightKey) -> Result<(), StoreError>;
    fn delete_rooted_range(&self, batch: &mut WriteBatch, hash: Hash) -> Result<u32, StoreError>;
}

impl MemoryDagknightStore {
    pub fn new(dk_map: RefCell<HashMap<DagknightKey, Arc<GhostdagData>>>) -> Self {
        Self { dk_map }
    }
}

impl DagknightStoreReader for MemoryDagknightStore {
    fn get_selected_parent(&self, dk_key: DagknightKey) -> Result<Hash, StoreError> {
        Ok(self.get_data(dk_key)?.selected_parent)
    }

    fn get_data(&self, key: DagknightKey) -> Result<Arc<GhostdagData>, StoreError> {
        if let Some(pov_block_dk_data) = self.dk_map.borrow().get(&key) {
            Ok(pov_block_dk_data.clone())
        } else {
            Err(StoreError::KeyNotFound(DbKey::new(DatabaseStorePrefixes::DagKnight.as_ref(), key)))
        }
    }

    fn has(&self, dk_key: DagknightKey) -> Result<bool, StoreError> {
        Ok(self.dk_map.borrow().contains_key(&dk_key))
    }
}

impl DagknightStore for MemoryDagknightStore {
    fn insert(&self, key: DagknightKey, dk_data: Arc<GhostdagData>) -> Result<(), StoreError> {
        self.dk_map.borrow_mut().insert(key, dk_data);

        Ok(())
    }

    fn delete(&self, key: DagknightKey) -> Result<(), StoreError> {
        self.dk_map.borrow_mut().remove(&key);

        Ok(())
    }

    fn delete_rooted_range(&self, _batch: &mut WriteBatch, _hash: Hash) -> Result<u32, StoreError> {
        unimplemented!()
    }
}

/// A DB + cache implementation of `DagknightStore` trait, with concurrency support.
#[derive(Clone)]
pub struct DbDagknightStore {
    db: Arc<DB>,
    access: CachedDbAccess<DagknightKey, Arc<GhostdagData>>,
}

impl DbDagknightStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        let prefix = DatabaseStorePrefixes::DagKnight.as_ref().to_vec();
        Self { db: Arc::clone(&db), access: CachedDbAccess::new(db, cache_policy, prefix) }
    }

    pub fn insert_batch(&self, batch: &mut WriteBatch, key: DagknightKey, data: Arc<GhostdagData>) -> Result<(), StoreError> {
        if self.access.has(key.clone())? {
            return Err(StoreError::KeyAlreadyExists(key.to_string()));
        }
        self.access.write(BatchDbWriter::new(batch), key, data)?;
        Ok(())
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, key: DagknightKey) -> Result<(), StoreError> {
        self.access.delete(BatchDbWriter::new(batch), key)
    }
}

impl DagknightStoreReader for DbDagknightStore {
    fn get_selected_parent(&self, dk_key: DagknightKey) -> Result<Hash, StoreError> {
        Ok(self.get_data(dk_key)?.selected_parent)
    }

    fn get_data(&self, dk_key: DagknightKey) -> Result<Arc<GhostdagData>, StoreError> {
        self.access.read(dk_key)
    }

    fn has(&self, dk_key: DagknightKey) -> Result<bool, StoreError> {
        self.access.has(dk_key)
    }
}

impl DagknightStore for DbDagknightStore {
    fn insert(&self, key: DagknightKey, dk_data: Arc<GhostdagData>) -> Result<(), StoreError> {
        if self.access.has(key.clone())? {
            return Err(StoreError::KeyAlreadyExists(key.to_string()));
        }
        let mut batch = WriteBatch::default();
        self.access.write(BatchDbWriter::new(&mut batch), key, dk_data)?;
        self.db.write(batch)?;
        Ok(())
    }

    fn delete(&self, key: DagknightKey) -> Result<(), StoreError> {
        let mut batch = WriteBatch::default();
        self.access.delete(BatchDbWriter::new(&mut batch), key)?;
        self.db.write(batch)?;
        Ok(())
    }

    fn delete_rooted_range(&self, batch: &mut WriteBatch, hash: Hash) -> Result<u32, StoreError> {
        // delete records that have a prefix rooted at this DK store key + hash
        let root_bytes_prefix = {
            let mut bytes = Vec::with_capacity(kaspa_hashes::HASH_SIZE + 1);
            bytes.extend(DatabaseStorePrefixes::DagKnight.as_ref());
            bytes.extend_from_slice(hash.as_ref());
            bytes
        };
        let start_conflict_genesis_bytes = {
            let mut bytes = Vec::with_capacity(kaspa_hashes::HASH_SIZE + 2);
            bytes.extend_from_slice(&root_bytes_prefix);
            bytes.push(0); // k = 0 u16 first byte
            bytes.push(0); // k = 0 u16 second byte
            bytes
        };
        let end_conflict_genesis_bytes = {
            let mut bytes = Vec::with_capacity(kaspa_hashes::HASH_SIZE + 2);
            bytes.extend_from_slice(&root_bytes_prefix);
            // TODO[DK]: This range check misses entries where k = u16::MAX. However, we don't expect k to reach that value anyway
            // in practice so we don't expect records to exist here as well. In the DK implementation, k may be clamped to max out
            // lower than k = u16::MAX
            bytes.push(0xFF); // k = 0xFFFF u16 first byte
            bytes.push(0xFF); // k = 0xFFFF u16 second byte
            bytes
        };
        let prefix_len = DatabaseStorePrefixes::DagKnight.as_ref().len();
        let mut keys = Vec::new();
        let mut iterator = self.db.raw_iterator();
        iterator.seek(&start_conflict_genesis_bytes);
        while iterator.valid() {
            let key = iterator.key();
            let raw_key = key.unwrap();
            if raw_key >= end_conflict_genesis_bytes.as_slice() {
                break;
            }
            keys.push(DagknightKey::from_bytes(&raw_key[prefix_len..])?);
            iterator.next();
        }
        // A scan cut short by an iterator error would delete only part of the range.
        iterator.status()?;

        let count = keys.len() as u32;
        if count > 0 {
            self.access.delete_many(BatchDbWriter::new(batch), &mut keys.into_iter())?;
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dagknight_key_encodes_free_search_flag() {
        use kaspa_hashes::Hash;

        let root: Hash = 0xAA_u64.into();
        let pov: Hash = 0xBB_u64.into();
        let k: KType = 5;

        let key_committed = DagknightKey::new(root, pov, k, false);
        let key_free = DagknightKey::new(root, pov, k, true);

        // Keys with different free_search values must be distinct
        assert_ne!(key_committed.as_ref(), key_free.as_ref());

        // Verify the free_search flag is encoded as the last byte
        assert_eq!(key_committed.as_ref().last().unwrap(), &0u8);
        assert_eq!(key_free.as_ref().last().unwrap(), &1u8);
    }

    #[test]
    fn test_dagknight_key_encodes_k() {
        use crate::model::stores::dagknight::DagknightKey;
        use kaspa_hashes::Hash;

        let root: Hash = 0xAA_u64.into();
        let pov: Hash = 0xBB_u64.into();
        let k1: KType = 0x0001;
        let k2: KType = 0x0101; // 2nd byte is the same as above

        let key1 = DagknightKey::new(root, pov, k1, false);
        let key2 = DagknightKey::new(root, pov, k2, false);

        // The DB key bytes must differ when k differs. This captures the previous
        // bug where `k` was encoded incorrectly and keys collided across k values.
        println!("key1 bytes: {:?}", key1.as_ref());
        println!("key2 bytes: {:?}", key2.as_ref());
        assert_ne!(key1.as_ref(), key2.as_ref(), "DagknightKey DB bytes must encode k uniquely");

        // Also assert that the differing two-byte `k` slot differs (sanity check on layout)
        let hash_size = kaspa_hashes::HASH_SIZE;
        // k is encoded as two bytes after root_hash
        assert_ne!(
            &key1.as_ref()[hash_size..hash_size + 2],
            &key2.as_ref()[hash_size..hash_size + 2],
            "k slot (two bytes) must differ for different k values"
        );
    }

    #[test]
    fn test_db_dagknight_store_isolates_by_k() {
        use crate::model::stores::dagknight::DbDagknightStore;
        use crate::model::stores::ghostdag::GhostdagData;
        use kaspa_database::prelude::CachePolicy;
        use kaspa_database::prelude::ConnBuilder;
        use kaspa_hashes::Hash;
        use std::sync::Arc;

        // Create a temporary RocksDB
        let (_lifetime, db) = kaspa_database::create_temp_db!(ConnBuilder::default().with_files_limit(10));

        let store = DbDagknightStore::new(db.clone(), CachePolicy::Count(16));

        let root: Hash = 0xAA_u64.into();
        let pov: Hash = 0xBB_u64.into();

        let k1 = 0x0001;
        let k2 = 0x0101; // 2nd byte is the same as above

        // Create two distinct GhostdagData values
        let gd1 = GhostdagData::new(
            10,
            Default::default(),
            Hash::from_u64_word(1),
            Default::default(),
            Default::default(),
            Default::default(),
        );
        let gd2 = GhostdagData::new(
            20,
            Default::default(),
            Hash::from_u64_word(2),
            Default::default(),
            Default::default(),
            Default::default(),
        );

        let key1 = DagknightKey::new(root, pov, k1, false);
        let key2 = DagknightKey::new(root, pov, k2, false);

        // Insert both into the DB-backed store
        store.insert(key1.clone(), Arc::new(gd1)).expect("insert k1");
        store.insert(key2.clone(), Arc::new(gd2)).expect("insert k2");

        // Read them back and verify isolation
        let read1 = store.get_data(key1).expect("read k1");
        let read2 = store.get_data(key2).expect("read k2");

        assert_eq!(read1.blue_score, 10);
        assert_eq!(read2.blue_score, 20);
    }

    #[test]
    fn test_delete_rooted_range_invalidates_cache() {
        use crate::model::stores::ghostdag::GhostdagData;
        use kaspa_database::prelude::{CachePolicy, ConnBuilder};
        use kaspa_hashes::Hash;
        use std::sync::Arc;

        let (_lifetime, db) = kaspa_database::create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbDagknightStore::new(db.clone(), CachePolicy::Count(64));

        let pruned_root: Hash = 0xAA_u64.into();
        let kept_root: Hash = 0xCC_u64.into();
        let pov: Hash = 0xBB_u64.into();

        let gd = || {
            Arc::new(GhostdagData::new(
                10,
                Default::default(),
                Hash::from_u64_word(1),
                Default::default(),
                Default::default(),
                Default::default(),
            ))
        };

        // The range bounds exclude `k = KType::MAX` by design; see the TODO[DK] above.
        let pruned_keys = [
            DagknightKey::new(pruned_root, pov, 1, false),
            DagknightKey::new(pruned_root, pov, 1, true),
            DagknightKey::new(pruned_root, pov, 0x0101, false),
        ];
        let kept_key = DagknightKey::new(kept_root, pov, 1, false);

        for key in pruned_keys.iter() {
            store.insert(key.clone(), gd()).expect("insert");
        }
        store.insert(kept_key.clone(), gd()).expect("insert kept");

        for key in pruned_keys.iter() {
            assert!(store.has(key.clone()).unwrap());
        }

        let mut batch = WriteBatch::default();
        let deleted = store.delete_rooted_range(&mut batch, pruned_root).unwrap();
        db.write(batch).unwrap();

        assert_eq!(deleted, pruned_keys.len() as u32);
        for key in pruned_keys.iter() {
            assert!(!store.has(key.clone()).unwrap(), "pruned key must not be reported as present");
            assert!(store.get_data(key.clone()).is_err(), "pruned key must not return stale data");
        }
        assert!(store.has(kept_key.clone()).unwrap(), "entries rooted at another block must be preserved");
        assert!(store.get_data(kept_key).is_ok());
    }

    /// Neighbouring roots must be untouched.
    #[test]
    fn test_delete_rooted_range_empty_is_noop() {
        use crate::model::stores::ghostdag::GhostdagData;
        use kaspa_database::prelude::{CachePolicy, ConnBuilder};
        use kaspa_hashes::Hash;
        use std::sync::Arc;

        let (_lifetime, db) = kaspa_database::create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbDagknightStore::new(db.clone(), CachePolicy::Count(64));

        let key = DagknightKey::new(0xAA_u64.into(), 0xBB_u64.into(), 1, false);
        store
            .insert(
                key.clone(),
                Arc::new(GhostdagData::new(
                    10,
                    Default::default(),
                    Hash::from_u64_word(1),
                    Default::default(),
                    Default::default(),
                    Default::default(),
                )),
            )
            .unwrap();

        let mut batch = WriteBatch::default();
        let deleted = store.delete_rooted_range(&mut batch, 0xDD_u64.into()).unwrap();
        db.write(batch).unwrap();

        assert_eq!(deleted, 0);
        assert!(store.has(key).unwrap());
    }

    #[test]
    fn test_dagknight_key_from_bytes_roundtrip() {
        let key = DagknightKey::new(0xAA_u64.into(), 0xBB_u64.into(), 0x0101, true);
        let parsed = DagknightKey::from_bytes(key.as_ref()).unwrap();
        assert!(key == parsed);
        assert_eq!(key.as_ref(), parsed.as_ref());
        assert_eq!(parsed.k, 0x0101);
        assert!(parsed.free_search);

        assert!(DagknightKey::from_bytes(&key.as_ref()[..DagknightKey::SERIALIZED_LEN - 1]).is_err());
        let mut bad = key.as_ref().to_vec();
        *bad.last_mut().unwrap() = 2;
        assert!(DagknightKey::from_bytes(&bad).is_err(), "unknown free_search flag must be rejected");
    }
}
