//! [`ShadowedMuHash`] — a MuHash carrying an optional LtHash shadow.
//!
//! **The shadow never participates in validation.** [`ShadowedMuHash::finalize`] returns the
//! MuHash digest and only the MuHash digest; the LtHash value is reachable only through
//! [`ShadowedMuHash::lthash`] and is compared against nothing in the consensus path.
//!
//! # Why a wrapper rather than a second field
//!
//! The UTXO multiset is mutated at seven sites across the virtual processor. Adding a
//! parallel `lthash` field beside `multiset_hash` and updating both at each site would make
//! a missed site a *silent* divergence — and because removals fail silently in any
//! group-based multiset hash, that divergence would surface much later as an inexplicable
//! mismatch with no trace of where it began.
//!
//! Wrapping instead makes it structurally impossible to update one accumulator without the
//! other: there is no way to reach the inner `MuHash` mutably from the pipeline. Changing
//! `UtxoProcessingContext::multiset_hash` to this type makes the compiler enumerate every
//! site, converting a class of silent runtime drift into compile errors.

use crate::{
    lthash::LtHashExtensions,
    muhash::MuHashExtensions,
    tx::{TransactionOutpoint, UtxoEntry, VerifiableTransaction},
};
use kaspa_hashes::Hash;
use kaspa_lthash::{LtHash, LtHashParams};
use kaspa_muhash::MuHash;

#[derive(Clone, Debug)]
pub struct ShadowedMuHash {
    muhash: MuHash,
    /// `None` whenever the shadow is disabled. Also becomes `None` if two accumulators with
    /// mismatched shadow state are combined, so the failure mode is "shadow turns off",
    /// never "shadow reports a wrong value".
    lthash: Option<LtHash>,
}

impl ShadowedMuHash {
    /// Empty accumulator. `shadow` selects whether an LtHash is maintained alongside.
    pub fn new(shadow: bool) -> Self {
        Self { muhash: MuHash::new(), lthash: shadow.then(|| LtHash::new(LtHashParams::default())) }
    }

    /// Rebuild from persisted parts, e.g. when seeding from the selected parent's stored state.
    pub fn from_parts(muhash: MuHash, lthash: Option<LtHash>) -> Self {
        Self { muhash, lthash }
    }

    pub fn shadow_enabled(&self) -> bool {
        self.lthash.is_some()
    }

    pub fn muhash(&self) -> &MuHash {
        &self.muhash
    }

    pub fn lthash(&self) -> Option<&LtHash> {
        self.lthash.as_ref()
    }

    pub fn into_parts(self) -> (MuHash, Option<LtHash>) {
        (self.muhash, self.lthash)
    }

    pub fn add_transaction(&mut self, tx: &impl VerifiableTransaction, block_daa_score: u64) {
        self.muhash.add_transaction(tx, block_daa_score);
        if let Some(lt) = self.lthash.as_mut() {
            lt.add_transaction(tx, block_daa_score);
        }
    }

    pub fn add_utxo(&mut self, outpoint: &TransactionOutpoint, entry: &UtxoEntry) {
        self.muhash.add_utxo(outpoint, entry);
        if let Some(lt) = self.lthash.as_mut() {
            // Fully qualified: `LtHash` has an inherent `add_utxo` over the lthash crate's own
            // mirror types, which would otherwise win resolution. See `crate::lthash`.
            <LtHash as LtHashExtensions>::add_utxo(lt, outpoint, entry);
        }
    }

    /// Union with another accumulator, mirroring `MuHash::combine`.
    ///
    /// If the two disagree about whether a shadow is present, the shadow is **dropped** rather
    /// than guessed at: with one side missing there is no correct value to produce, and
    /// carrying the present side forward would yield a shadow that does not describe the UTXO
    /// set. Reporting *no* shadow is recoverable; reporting a wrong one would make the drift
    /// check meaningless.
    ///
    /// This is a normal, reachable state, not a bug — it is exactly what happens when the
    /// shadow is enabled on a chain that was synced without it: the seed loaded from the store
    /// has no shadow while the freshly built per-transaction accumulators do. An earlier
    /// version asserted the two always agreed, which would have panicked every debug build in
    /// that situation, violating the "a shadow can never take a node down" invariant.
    pub fn combine(&mut self, other: &Self) {
        self.muhash.combine(&other.muhash);
        match (self.lthash.as_mut(), other.lthash.as_ref()) {
            (Some(a), Some(b)) => a.union_in_place(b),
            _ => self.lthash = None,
        }
    }

    /// The consensus commitment. **MuHash only** — the shadow is never a commitment.
    pub fn finalize(&mut self) -> Hash {
        self.muhash.finalize()
    }
}
