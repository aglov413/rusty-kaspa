//! Persistent store for the LtHash shadow accumulator, one entry per chain block.
//!
//! **Shadow only.** Nothing in the validation path reads this store. See
//! `crypto/lthash/INTEGRATION.md`.
//!
//! # Why this store has to exist
//!
//! It would be tempting to recompute the shadow on demand rather than persist 2048 bytes per
//! chain block. That would be wrong, and the reason is the reorg path.
//!
//! On a reorg the virtual processor does **not** roll the accumulator back. UTXO diffs are
//! reversed block by block, but the multiset is restored by re-reading the new sink's stored
//! value wholesale (`virtual_processor/processor.rs`, the `utxo_multisets_store.get(new_sink)`
//! at the top of `resolve_virtual`). A shadow that is not persisted with exactly the same
//! lifecycle has nothing to be restored *from*, so it would silently carry the pre-reorg
//! state forward — and since wrong removals are undetectable in any group-based multiset
//! hash, nothing would report it.
//!
//! So the shadow is written in the same `WriteBatch` as the MuHash and deleted in the same
//! pruning batch. The two cannot diverge across a crash, and reorg recovery is automatic
//! because it reuses the mechanism that already works for MuHash.
//!
//! Storage cost is +2048 bytes per retained chain block, bounded by pruning depth.

use std::sync::Arc;

use kaspa_database::prelude::CachePolicy;
use kaspa_database::prelude::DB;
use kaspa_database::prelude::StoreError;
use kaspa_database::prelude::{BatchDbWriter, CachedDbAccess, DirectDbWriter};
use kaspa_database::registry::DatabaseStorePrefixes;
use kaspa_hashes::Hash;
use kaspa_lthash::{LtHash, LtHashParams};
use rocksdb::WriteBatch;

use kaspa_consensus_core::BlockHasher;

/// Serialized LtHash state: the canonical little-endian lane encoding, 2048 bytes at the
/// default parameters. Stored as raw bytes rather than a typed value so that a parameter
/// change is a visible deserialization failure rather than a silent misread.
type SerializedLtHash = Vec<u8>;

pub trait ShadowLtHashStoreReader {
    fn get(&self, hash: Hash) -> Result<LtHash, StoreError>;
}

pub trait ShadowLtHashStore: ShadowLtHashStoreReader {
    fn insert(&self, hash: Hash, state: &LtHash) -> Result<(), StoreError>;
    fn delete(&self, hash: Hash) -> Result<(), StoreError>;
}

#[derive(Clone)]
pub struct DbShadowLtHashStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, SerializedLtHash, BlockHasher>,
}

impl DbShadowLtHashStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ShadowLtHash.into()) }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    /// Write in the caller's batch. Must be the *same* batch that writes the MuHash for this
    /// block, so the two states cannot diverge if the process dies mid-commit.
    ///
    /// Overwrites rather than rejecting an existing key. The MuHash store errors on a
    /// duplicate insert because that would signal a real invariant break; the shadow
    /// deliberately has no such failure mode, per the "shadow can never take down a node"
    /// invariant in `crypto/lthash/INTEGRATION.md`.
    pub fn set_batch(&self, batch: &mut WriteBatch, hash: Hash, state: &LtHash) -> Result<(), StoreError> {
        self.access.write(BatchDbWriter::new(batch), hash, state.serialize())
    }

    /// Delete in the caller's batch. Must be the same pruning batch that deletes the MuHash.
    pub fn delete_batch(&self, batch: &mut WriteBatch, hash: Hash) -> Result<(), StoreError> {
        self.access.delete(BatchDbWriter::new(batch), hash)
    }
}

impl ShadowLtHashStoreReader for DbShadowLtHashStore {
    fn get(&self, hash: Hash) -> Result<LtHash, StoreError> {
        let bytes = self.access.read(hash)?;
        LtHash::deserialize(LtHashParams::default(), &bytes).map_err(|e| {
            // A parameter change makes every stored state unreadable. Surface that as a clear
            // store error rather than a panic -- callers disable the shadow on error.
            StoreError::DataInconsistency(format!("stored LtHash state is not readable at the current parameters: {e}"))
        })
    }
}

impl ShadowLtHashStore for DbShadowLtHashStore {
    fn insert(&self, hash: Hash, state: &LtHash) -> Result<(), StoreError> {
        self.access.write(DirectDbWriter::new(&self.db), hash, state.serialize())
    }

    fn delete(&self, hash: Hash) -> Result<(), StoreError> {
        self.access.delete(DirectDbWriter::new(&self.db), hash)
    }
}
