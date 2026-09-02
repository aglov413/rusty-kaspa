//! LtHash accumulation over UTXOs, mirroring [`crate::muhash::MuHashExtensions`].
//!
//! **Shadow only.** Nothing here participates in validation. See
//! `crypto/lthash/INTEGRATION.md`.
//!
//! The one design rule that matters: this module never encodes a UTXO itself. It calls
//! [`crate::muhash::encode_utxo`], which calls the same private `write_utxo` MuHash uses, so
//! the two accumulators are fed byte-identical elements by construction rather than by
//! convention. A second encoding implementation here would silently make the two
//! accumulators incomparable, which is the exact failure this whole experiment exists to
//! avoid.

use crate::{
    muhash::encode_utxo,
    tx::{TransactionOutpoint, UtxoEntry, VerifiableTransaction},
};
use kaspa_lthash::LtHash;

pub trait LtHashExtensions {
    fn add_transaction(&mut self, tx: &impl VerifiableTransaction, block_daa_score: u64);
    fn add_utxo(&mut self, outpoint: &TransactionOutpoint, entry: &UtxoEntry);
    fn remove_utxo(&mut self, outpoint: &TransactionOutpoint, entry: &UtxoEntry);
}

impl LtHashExtensions for LtHash {
    /// Mirrors `MuHashExtensions::add_transaction` exactly: every populated input is removed
    /// using its own entry (so the entry's original DAA score and coinbase flag, not the
    /// spending block's), and every output is added at the point-of-view DAA score.
    fn add_transaction(&mut self, tx: &impl VerifiableTransaction, block_daa_score: u64) {
        let tx_id = tx.id();
        for (input, entry) in tx.populated_inputs() {
            // Fully qualified on purpose. `LtHash` also has *inherent* `add_utxo`/`remove_utxo`
            // taking the lthash crate's own standalone mirror types, and inherent methods win
            // resolution over trait methods. Both produce identical bytes, but leaving the call
            // ambiguous invites a future reader to "simplify" it into the wrong one.
            <LtHash as LtHashExtensions>::remove_utxo(self, &input.previous_outpoint, entry);
        }
        for (i, output) in tx.outputs().iter().enumerate() {
            let outpoint = TransactionOutpoint::new(tx_id, i as u32);
            let entry = UtxoEntry::new(output.value, output.script_public_key.clone(), block_daa_score, tx.is_coinbase());
            <LtHash as LtHashExtensions>::add_utxo(self, &outpoint, &entry);
        }
    }

    fn add_utxo(&mut self, outpoint: &TransactionOutpoint, entry: &UtxoEntry) {
        self.add_element(&encode_utxo(outpoint, entry));
    }

    fn remove_utxo(&mut self, outpoint: &TransactionOutpoint, entry: &UtxoEntry) {
        self.remove_element(&encode_utxo(outpoint, entry));
    }
}
