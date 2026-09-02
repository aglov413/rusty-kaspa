//! Byte encoding of a UTXO, **identical to the one MuHash uses**.
//!
//! This module is the load-bearing part of the whole experiment. LtHash and MuHash must be
//! fed byte-identical element encodings, otherwise any later comparison between the two
//! accumulators measures the encoding difference rather than the accumulator difference.
//!
//! The reference is `consensus/core/src/muhash.rs::write_utxo` in this repository, which at
//! the time of writing (branch `dk-with-tcp`, commit `3b834c65`) reads:
//!
//! ```text
//! fn write_utxo(writer: &mut impl HasherBase, entry: &UtxoEntry, outpoint: &TransactionOutpoint) {
//!     writer
//!         // Outpoint
//!         .update(outpoint.transaction_id)
//!         .update(outpoint.index.to_le_bytes())
//!         // Utxo entry
//!         .update(entry.block_daa_score.to_le_bytes())
//!         .update(entry.amount.to_le_bytes())
//!         .write_bool(entry.is_coinbase)
//!         .update(entry.script_public_key.version().to_le_bytes())
//!         .write_var_bytes(entry.script_public_key.script());
//! }
//! ```
//!
//! with the helpers from `consensus/core/src/hashing/mod.rs`:
//!
//! * `write_bool(b)` -> a single byte, `0x01` or `0x00`
//! * `write_var_bytes(s)` -> `write_len(s.len())` followed by `s`
//! * `write_len(n)` -> `(n as u64).to_le_bytes()`, i.e. **eight** length bytes
//!
//! # Layout
//!
//! ```text
//! offset  size  field                             encoding
//! ------  ----  --------------------------------  --------------------------------
//! 0       32    outpoint.transaction_id           raw 32 bytes
//! 32      4     outpoint.index                    u32 little-endian
//! 36      8     entry.block_daa_score             u64 little-endian
//! 44      8     entry.amount                      u64 little-endian
//! 52      1     entry.is_coinbase                 0x01 / 0x00
//! 53      2     script_public_key.version         u16 little-endian
//! 55      8     script_public_key.script().len()  u64 little-endian
//! 63      L     script_public_key.script()        raw bytes
//! ------  ----
//! total = 63 + L
//! ```
//!
//! Three traps that a naive reimplementation falls into, called out because they are the
//! difference between "comparable" and "silently incomparable":
//!
//! 1. **DAA score comes before amount.** The `UtxoEntry` *struct* declares
//!    `amount, script_public_key, block_daa_score, is_coinbase`; the *hashed* order is
//!    different. Follow `write_utxo`, not the struct.
//! 2. **The script length is a fixed 8-byte LE `u64`**, not a varint and not a `u32`.
//! 3. There is **no length prefix and no domain tag on the encoding itself** -- the domain
//!    separation lives in the Blake2b key of the element hasher, not in these bytes.
//!
//! The types below are minimal local mirrors of `kaspa_consensus_core::tx::{UtxoEntry,
//! TransactionOutpoint, ScriptPublicKey}`. They exist so that this crate has **no
//! dependency on any consensus crate**, per the task constraint. They carry only the fields
//! that `write_utxo` actually reads.

/// Number of bytes a UTXO encoding occupies before the variable-length script.
pub const UTXO_PREFIX_LEN: usize = 63;

/// A transaction outpoint: which output of which transaction.
///
/// Mirrors `kaspa_consensus_core::tx::TransactionOutpoint`. `transaction_id` is the raw
/// 32-byte hash exactly as `Hash::as_bytes()` would yield it -- MuHash writes it through
/// `update(outpoint.transaction_id)`, i.e. with no reordering of any kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Outpoint {
    pub transaction_id: [u8; 32],
    pub index: u32,
}

impl Outpoint {
    pub const fn new(transaction_id: [u8; 32], index: u32) -> Self {
        Self { transaction_id, index }
    }
}

/// A script public key: a version plus an opaque script.
///
/// Mirrors `kaspa_consensus_core::tx::ScriptPublicKey`, whose version type is
/// `ScriptPublicKeyVersion = u16`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScriptPublicKey {
    pub version: u16,
    pub script: Vec<u8>,
}

impl ScriptPublicKey {
    pub fn new(version: u16, script: Vec<u8>) -> Self {
        Self { version, script }
    }
}

/// A UTXO entry.
///
/// Mirrors `kaspa_consensus_core::tx::UtxoEntry`. Field order here follows the *struct*
/// declaration for familiarity; the *encoding* order is fixed by [`write_utxo`] and is
/// deliberately different.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtxoEntry {
    pub amount: u64,
    pub script_public_key: ScriptPublicKey,
    pub block_daa_score: u64,
    pub is_coinbase: bool,
}

impl UtxoEntry {
    pub fn new(amount: u64, script_public_key: ScriptPublicKey, block_daa_score: u64, is_coinbase: bool) -> Self {
        Self { amount, script_public_key, block_daa_score, is_coinbase }
    }
}

/// Appends the MuHash element encoding of `(outpoint, entry)` to `out`.
///
/// The argument order mirrors `write_utxo(writer, entry, outpoint)` in the consensus crate
/// only in spirit; here the outpoint comes first because that is the order the bytes come
/// out in, which is less confusing to read against the layout table above.
pub fn write_utxo(out: &mut Vec<u8>, outpoint: &Outpoint, entry: &UtxoEntry) {
    // --- Outpoint ---
    // `.update(outpoint.transaction_id)`
    out.extend_from_slice(&outpoint.transaction_id);
    // `.update(outpoint.index.to_le_bytes())`
    out.extend_from_slice(&outpoint.index.to_le_bytes());

    // --- UTXO entry ---
    // `.update(entry.block_daa_score.to_le_bytes())`   <- note: BEFORE amount
    out.extend_from_slice(&entry.block_daa_score.to_le_bytes());
    // `.update(entry.amount.to_le_bytes())`
    out.extend_from_slice(&entry.amount.to_le_bytes());
    // `.write_bool(entry.is_coinbase)`
    out.push(if entry.is_coinbase { 1u8 } else { 0u8 });
    // `.update(entry.script_public_key.version().to_le_bytes())`
    out.extend_from_slice(&entry.script_public_key.version.to_le_bytes());
    // `.write_var_bytes(entry.script_public_key.script())`
    //   == `.write_len(len)` (u64 LE) then the script bytes
    out.extend_from_slice(&(entry.script_public_key.script.len() as u64).to_le_bytes());
    out.extend_from_slice(&entry.script_public_key.script);
}

/// Convenience wrapper around [`write_utxo`] that allocates.
pub fn encode_utxo(outpoint: &Outpoint, entry: &UtxoEntry) -> Vec<u8> {
    let mut out = Vec::with_capacity(UTXO_PREFIX_LEN + entry.script_public_key.script.len());
    write_utxo(&mut out, outpoint, entry);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_offsets_are_as_documented() {
        let outpoint = Outpoint::new([0xAA; 32], 0x0102_0304);
        let entry =
            UtxoEntry::new(0x1122_3344_5566_7788, ScriptPublicKey::new(0xBEEF, vec![0x51, 0x52, 0x53]), 0x0807_0605_0403_0201, true);
        let bytes = encode_utxo(&outpoint, &entry);

        assert_eq!(bytes.len(), UTXO_PREFIX_LEN + 3);
        assert_eq!(&bytes[0..32], &[0xAA; 32]);
        assert_eq!(&bytes[32..36], &0x0102_0304u32.to_le_bytes());
        assert_eq!(&bytes[36..44], &0x0807_0605_0403_0201u64.to_le_bytes());
        assert_eq!(&bytes[44..52], &0x1122_3344_5566_7788u64.to_le_bytes());
        assert_eq!(bytes[52], 1);
        assert_eq!(&bytes[53..55], &0xBEEFu16.to_le_bytes());
        assert_eq!(&bytes[55..63], &3u64.to_le_bytes());
        assert_eq!(&bytes[63..], &[0x51, 0x52, 0x53]);
    }

    #[test]
    fn empty_script_is_length_zero_then_nothing() {
        let bytes = encode_utxo(&Outpoint::new([0; 32], 0), &UtxoEntry::new(0, ScriptPublicKey::new(0, Vec::new()), 0, false));
        assert_eq!(bytes.len(), UTXO_PREFIX_LEN);
        assert_eq!(&bytes[55..63], &0u64.to_le_bytes());
        assert_eq!(bytes[52], 0);
    }
}
