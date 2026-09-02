use crate::{
    hashing::HasherExtensions,
    tx::{TransactionOutpoint, UtxoEntry, VerifiableTransaction},
};
use kaspa_hashes::HasherBase;
use kaspa_muhash::MuHash;

pub trait MuHashExtensions {
    fn add_transaction(&mut self, tx: &impl VerifiableTransaction, block_daa_score: u64);
    fn add_utxo(&mut self, outpoint: &TransactionOutpoint, entry: &UtxoEntry);
    fn from_transaction(tx: &impl VerifiableTransaction, block_daa_score: u64) -> Self;
    fn from_utxo(outpoint: &TransactionOutpoint, entry: &UtxoEntry) -> Self;
}

impl MuHashExtensions for MuHash {
    fn add_transaction(&mut self, tx: &impl VerifiableTransaction, block_daa_score: u64) {
        let tx_id = tx.id();
        for (input, entry) in tx.populated_inputs() {
            let mut writer = self.remove_element_builder();
            write_utxo(&mut writer, entry, &input.previous_outpoint);
            writer.finalize();
        }
        for (i, output) in tx.outputs().iter().enumerate() {
            let outpoint = TransactionOutpoint::new(tx_id, i as u32);
            let entry = UtxoEntry::new(output.value, output.script_public_key.clone(), block_daa_score, tx.is_coinbase());
            self.add_utxo(&outpoint, &entry);
        }
    }

    fn add_utxo(&mut self, outpoint: &TransactionOutpoint, entry: &UtxoEntry) {
        let mut writer = self.add_element_builder();
        write_utxo(&mut writer, entry, outpoint);
        writer.finalize();
    }

    fn from_transaction(tx: &impl VerifiableTransaction, block_daa_score: u64) -> Self {
        let mut mh = Self::new();
        mh.add_transaction(tx, block_daa_score);
        mh
    }

    fn from_utxo(outpoint: &TransactionOutpoint, entry: &UtxoEntry) -> Self {
        let mut mh = Self::new();
        mh.add_utxo(outpoint, entry);
        mh
    }
}

/// Collects the exact bytes [`write_utxo`] emits.
///
/// [`HasherBase`] has a single method, `update`, and [`HasherExtensions`] is blanket
/// implemented over it, so `HasherBase` already *is* the sink abstraction `write_utxo`
/// writes through. Implementing it for a byte buffer therefore lets a non-hasher consumer —
/// specifically the LtHash shadow accumulator — obtain byte-identical element encodings
/// without `write_utxo` being modified, duplicated, or reimplemented.
///
/// Any second implementation of this encoding would be a silent-divergence hazard: two
/// accumulators fed different bytes are not comparable, and nothing would report it. There
/// is deliberately exactly one implementation, and this is how you reach it.
#[derive(Default, Debug, Clone)]
pub struct ByteSink(Vec<u8>);

impl ByteSink {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    /// Reuse the allocation across many UTXOs.
    pub fn clear(&mut self) {
        self.0.clear()
    }
}

impl HasherBase for ByteSink {
    #[inline]
    fn update<A: AsRef<[u8]>>(&mut self, data: A) -> &mut Self {
        self.0.extend_from_slice(data.as_ref());
        self
    }
}

/// Fixed-size portion of a UTXO element encoding, before the variable-length script.
pub const UTXO_ENCODING_PREFIX_LEN: usize = 63;

/// Returns the exact bytes MuHash hashes for this UTXO.
///
/// This is the canonical entry point for anything that needs the element encoding without
/// being a hasher. It calls the same [`write_utxo`] the accumulator uses, so the two cannot
/// drift apart.
pub fn encode_utxo(outpoint: &TransactionOutpoint, entry: &UtxoEntry) -> Vec<u8> {
    let mut sink = ByteSink::with_capacity(UTXO_ENCODING_PREFIX_LEN + entry.script_public_key.script().len());
    write_utxo(&mut sink, entry, outpoint);
    sink.into_inner()
}

fn write_utxo(writer: &mut impl HasherBase, entry: &UtxoEntry, outpoint: &TransactionOutpoint) {
    writer
        // Outpoint
        .update(outpoint.transaction_id)
        .update(outpoint.index.to_le_bytes())
        // Utxo entry
        .update(entry.block_daa_score.to_le_bytes())
        .update(entry.amount.to_le_bytes())
        .write_bool(entry.is_coinbase)
        .update(entry.script_public_key.version().to_le_bytes())
        .write_var_bytes(entry.script_public_key.script());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::ScriptPublicKey;
    use kaspa_hashes::{Hash, Hasher, MuHashElementHash};

    fn spk(version: u16, script: Vec<u8>) -> ScriptPublicKey {
        ScriptPublicKey::from_vec(version, script)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The whole point of [`ByteSink`]: bytes obtained through it must drive MuHash to the
    /// same place as the hasher path. If this ever fails, any shadow accumulator fed by
    /// `encode_utxo` has silently stopped being comparable to MuHash.
    #[test]
    fn encode_utxo_matches_the_hasher_path() {
        let cases = [
            (Hash::from_bytes([0u8; 32]), 0u32, 0u64, 0u64, false, 0u16, vec![]),
            (Hash::from_bytes([0xAA; 32]), 1, 5_000_000_000, 123_456, true, 0, vec![0x20; 34]),
            (Hash::from_bytes([0xFF; 32]), u32::MAX, u64::MAX, u64::MAX, true, u16::MAX, vec![0xFF; 3]),
            (Hash::from_bytes([0x5A; 32]), 7, 1, 2, false, 1, (0u16..600).map(|i| i as u8).collect()),
        ];

        for (txid, index, amount, daa, coinbase, version, script) in cases {
            let outpoint = TransactionOutpoint::new(txid, index);
            let entry = UtxoEntry::new(amount, spk(version, script), daa, coinbase);

            let mut via_hasher = MuHash::new();
            via_hasher.add_utxo(&outpoint, &entry);

            let mut via_bytes = MuHash::new();
            via_bytes.add_element(&encode_utxo(&outpoint, &entry));

            assert_eq!(via_hasher.finalize(), via_bytes.finalize(), "ByteSink diverged from the hasher path");
        }
    }

    /// Frozen element digests, pinning the exact byte layout `write_utxo` emits.
    ///
    /// These are `MuHashElementHash` (Blake2b-256 keyed `b"MuHashElement"`) over the encoding,
    /// and they are the same values frozen in `crypto/lthash/tests/muhash_encoding_vectors.rs`.
    /// Holding them in both places is deliberate: it keeps the shadow crate's standalone copy
    /// of the encoding provably identical to this one without either depending on the other.
    ///
    /// A failure here means the consensus UTXO element encoding changed. That is a hard fork,
    /// and it should never happen by accident.
    #[test]
    fn utxo_element_encoding_frozen_vectors() {
        let mut ascending = [0u8; 32];
        for (i, b) in ascending.iter_mut().enumerate() {
            *b = i as u8;
        }

        let cases: [(&str, TransactionOutpoint, UtxoEntry, usize, &str); 5] = [
            (
                "all-zero, empty script",
                TransactionOutpoint::new(Hash::from_bytes([0u8; 32]), 0),
                UtxoEntry::new(0, spk(0, vec![]), 0, false),
                63,
                "f3d6308c663c0e7aaf8ae5f9dd073b83223c689b0d939e9f3747d87b1303c6e6",
            ),
            (
                "coinbase, p2pk-ish",
                TransactionOutpoint::new(Hash::from_bytes([0xAA; 32]), 1),
                UtxoEntry::new(5_000_000_000, spk(0, vec![0x20; 34]), 123_456, true),
                97,
                "8b4e153672fe8f7cec2bb60420cd8dab79c498fa3e0997573ada00d5e0baed6b",
            ),
            (
                "max fields",
                TransactionOutpoint::new(Hash::from_bytes([0xFF; 32]), u32::MAX),
                UtxoEntry::new(u64::MAX, spk(u16::MAX, vec![0xFF; 3]), u64::MAX, true),
                66,
                "dab163672bf0f59bea924f99defd23fa3c0aec14b6541744afad4c89911c5943",
            ),
            (
                "asymmetric bytes",
                TransactionOutpoint::new(Hash::from_bytes(ascending), 0x0102_0304),
                UtxoEntry::new(0x1122_3344_5566_7788, spk(0xBEEF, vec![0x51, 0x52, 0x53]), 0x0807_0605_0403_0201, false),
                66,
                "541cc773a8ae035b6d41eaa40533b387ccc1748ba33773d3e21606c41ede0728",
            ),
            (
                "long script (600 bytes)",
                TransactionOutpoint::new(Hash::from_bytes([0x5A; 32]), 7),
                UtxoEntry::new(1, spk(1, (0u16..600).map(|i| i as u8).collect()), 2, false),
                663,
                "dd07fe57bc2ff4d7c6914915e7b8ea35ea9b69d8b94c2b8be2ca77f31e827269",
            ),
        ];

        for (name, outpoint, entry, expected_len, expected_digest) in cases {
            let bytes = encode_utxo(&outpoint, &entry);
            assert_eq!(bytes.len(), expected_len, "[{name}] encoding length changed");
            assert_eq!(
                hex(&MuHashElementHash::hash(&bytes).as_bytes()),
                expected_digest,
                "[{name}] UTXO element encoding changed — this is a consensus break"
            );
        }
    }

    /// Documented byte layout, asserted field by field. `block_daa_score` precedes `amount`,
    /// which is the opposite of the `UtxoEntry` struct declaration order and the easiest
    /// thing to get wrong in a reimplementation.
    #[test]
    fn utxo_encoding_layout() {
        let outpoint = TransactionOutpoint::new(Hash::from_bytes([0xAA; 32]), 0x0102_0304);
        let entry = UtxoEntry::new(0x1122_3344_5566_7788, spk(0xBEEF, vec![0x51, 0x52, 0x53]), 0x0807_0605_0403_0201, true);
        let b = encode_utxo(&outpoint, &entry);

        assert_eq!(b.len(), UTXO_ENCODING_PREFIX_LEN + 3);
        assert_eq!(&b[0..32], &[0xAA; 32]);
        assert_eq!(&b[32..36], &0x0102_0304u32.to_le_bytes());
        assert_eq!(&b[36..44], &0x0807_0605_0403_0201u64.to_le_bytes(), "block_daa_score must precede amount");
        assert_eq!(&b[44..52], &0x1122_3344_5566_7788u64.to_le_bytes());
        assert_eq!(b[52], 1);
        assert_eq!(&b[53..55], &0xBEEFu16.to_le_bytes());
        assert_eq!(&b[55..63], &3u64.to_le_bytes(), "script length is a fixed u64, not a varint");
        assert_eq!(&b[63..], &[0x51, 0x52, 0x53]);
    }
}
