//! Frozen witnesses that [`kaspa_lthash::encoding`] reproduces MuHash's UTXO serialization
//! byte-for-byte.
//!
//! # How these vectors were obtained, and what they prove
//!
//! `consensus/core/src/muhash.rs::write_utxo` is a private function, so it cannot be called
//! from a test. Its *output* is observable through the accumulator, though: if
//!
//! ```text
//! MuHash::new().add_utxo(op, entry).finalize()
//!   ==
//! MuHash::new().add_element(kaspa_lthash::encoding::encode_utxo(op, entry)).finalize()
//! ```
//!
//! then the two byte strings were identical, up to a Blake2b collision.
//!
//! That equality was established for every case below by a throwaway harness with path
//! dependencies on `kaspa-consensus-core` and `kaspa-muhash`; it reported `ALL_MATCH=true`.
//! The harness is reproduced verbatim in `MUHASH-SURVEY.md` (appendix) so the check can be re-run.
//! It is deliberately *not* part of this crate: the crate must not depend on any consensus
//! crate.
//!
//! What is frozen here instead is a value this crate can recompute with only
//! `blake2b_simd`: `Blake2b-256(key = b"MuHashElement", msg = encode_utxo(...))` -- that is,
//! MuHash's own element digest over our bytes. Since the harness established that our bytes
//! equal consensus's bytes, pinning this digest pins the encoding. If anyone changes the
//! layout in `encoding.rs`, these tests fail immediately, and the failure means "you have
//! desynchronised from MuHash".
//!
//! Vectors generated against branch `dk-with-tcp`, commit `3b834c65`.

use kaspa_lthash::encoding::{Outpoint, ScriptPublicKey, UtxoEntry, encode_utxo};

/// MuHash's element-hash domain separator, from `crypto/hashes/src/hashers.rs`:
/// `struct MuHashElementHash => b"MuHashElement"`, used as the Blake2b **key**.
const MUHASH_ELEMENT_DOMAIN: &[u8] = b"MuHashElement";

fn muhash_element_digest(bytes: &[u8]) -> String {
    let h = blake2b_simd::Params::new().hash_length(32).key(MUHASH_ELEMENT_DOMAIN).to_state().update(bytes).finalize();
    h.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct Vector {
    name: &'static str,
    outpoint: Outpoint,
    entry: UtxoEntry,
    encoding_len: usize,
    /// Blake2b-256 keyed b"MuHashElement" over the encoding.
    element_digest: &'static str,
    /// Hex of the first 63 bytes (the fixed-size prefix).
    prefix_hex: &'static str,
}

fn vectors() -> Vec<Vector> {
    let mut ascending = [0u8; 32];
    for (i, b) in ascending.iter_mut().enumerate() {
        *b = i as u8;
    }

    vec![
        Vector {
            name: "all-zero, empty script",
            outpoint: Outpoint::new([0u8; 32], 0),
            entry: UtxoEntry::new(0, ScriptPublicKey::new(0, vec![]), 0, false),
            encoding_len: 63,
            element_digest: "f3d6308c663c0e7aaf8ae5f9dd073b83223c689b0d939e9f3747d87b1303c6e6",
            prefix_hex: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        },
        Vector {
            name: "coinbase, p2pk-ish",
            outpoint: Outpoint::new([0xAAu8; 32], 1),
            entry: UtxoEntry::new(5_000_000_000, ScriptPublicKey::new(0, vec![0x20; 34]), 123_456, true),
            encoding_len: 97,
            element_digest: "8b4e153672fe8f7cec2bb60420cd8dab79c498fa3e0997573ada00d5e0baed6b",
            prefix_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0100000040e201000000000000f2052a010000000100002200000000000000",
        },
        Vector {
            name: "max fields",
            outpoint: Outpoint::new([0xFFu8; 32], u32::MAX),
            entry: UtxoEntry::new(u64::MAX, ScriptPublicKey::new(u16::MAX, vec![0xFF; 3]), u64::MAX, true),
            encoding_len: 66,
            element_digest: "dab163672bf0f59bea924f99defd23fa3c0aec14b6541744afad4c89911c5943",
            prefix_hex: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01ffff0300000000000000",
        },
        Vector {
            name: "asymmetric bytes",
            outpoint: Outpoint::new(ascending, 0x0102_0304),
            entry: UtxoEntry::new(
                0x1122_3344_5566_7788,
                ScriptPublicKey::new(0xBEEF, vec![0x51, 0x52, 0x53]),
                0x0807_0605_0403_0201,
                false,
            ),
            encoding_len: 66,
            element_digest: "541cc773a8ae035b6d41eaa40533b387ccc1748ba33773d3e21606c41ede0728",
            prefix_hex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f040302010102030405060708887766554433221100efbe0300000000000000",
        },
        Vector {
            name: "long script (600 bytes)",
            outpoint: Outpoint::new([0x5Au8; 32], 7),
            entry: UtxoEntry::new(1, ScriptPublicKey::new(1, (0u16..600).map(|i| i as u8).collect()), 2, false),
            encoding_len: 663,
            element_digest: "dd07fe57bc2ff4d7c6914915e7b8ea35ea9b69d8b94c2b8be2ca77f31e827269",
            prefix_hex: "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a07000000020000000000000001000000000000000001005802000000000000",
        },
    ]
}

#[test]
fn encoding_matches_muhash_frozen_vectors() {
    for v in vectors() {
        let bytes = encode_utxo(&v.outpoint, &v.entry);
        assert_eq!(bytes.len(), v.encoding_len, "[{}] encoding length changed", v.name);
        assert_eq!(hex(&bytes[..63]), v.prefix_hex, "[{}] fixed-size prefix changed", v.name);
        assert_eq!(
            muhash_element_digest(&bytes),
            v.element_digest,
            "[{}] encoding no longer matches the MuHash element bytes -- \
             LtHash and MuHash are now hashing different things and are NOT comparable",
            v.name
        );
    }
}

#[test]
fn encoding_length_is_63_plus_script_len() {
    for script_len in [0usize, 1, 25, 34, 600, 4096] {
        let bytes =
            encode_utxo(&Outpoint::new([0u8; 32], 0), &UtxoEntry::new(0, ScriptPublicKey::new(0, vec![0xABu8; script_len]), 0, false));
        assert_eq!(bytes.len(), 63 + script_len);
        // The script length is a fixed 8-byte little-endian u64 at offset 55, not a varint.
        assert_eq!(&bytes[55..63], &(script_len as u64).to_le_bytes());
    }
}

#[test]
fn distinct_utxos_encode_distinctly() {
    // Cheap sanity check that no field is being dropped on the floor.
    let base_op = Outpoint::new([0u8; 32], 0);
    let base_entry = UtxoEntry::new(0, ScriptPublicKey::new(0, vec![]), 0, false);
    let base = encode_utxo(&base_op, &base_entry);

    let variants = [
        encode_utxo(&Outpoint::new([1u8; 32], 0), &base_entry),
        encode_utxo(&Outpoint::new([0u8; 32], 1), &base_entry),
        encode_utxo(&base_op, &UtxoEntry::new(1, ScriptPublicKey::new(0, vec![]), 0, false)),
        encode_utxo(&base_op, &UtxoEntry::new(0, ScriptPublicKey::new(0, vec![]), 1, false)),
        encode_utxo(&base_op, &UtxoEntry::new(0, ScriptPublicKey::new(0, vec![]), 0, true)),
        encode_utxo(&base_op, &UtxoEntry::new(0, ScriptPublicKey::new(1, vec![]), 0, false)),
        encode_utxo(&base_op, &UtxoEntry::new(0, ScriptPublicKey::new(0, vec![0]), 0, false)),
    ];

    for (i, v) in variants.iter().enumerate() {
        assert_ne!(&base, v, "variant {i} encoded identically to the base UTXO");
        for (j, w) in variants.iter().enumerate().skip(i + 1) {
            assert_ne!(v, w, "variants {i} and {j} collided");
        }
    }

    // Amount and DAA score must not be swappable -- they are adjacent u64s, so a
    // transposed implementation would still pass a length check.
    let amount_set = encode_utxo(&base_op, &UtxoEntry::new(7, ScriptPublicKey::new(0, vec![]), 0, false));
    let daa_set = encode_utxo(&base_op, &UtxoEntry::new(0, ScriptPublicKey::new(0, vec![]), 7, false));
    assert_ne!(amount_set, daa_set, "amount and block_daa_score appear to be transposed");
    assert_eq!(&daa_set[36..44], &7u64.to_le_bytes(), "block_daa_score must sit at offset 36");
    assert_eq!(&amount_set[44..52], &7u64.to_le_bytes(), "amount must sit at offset 44");
}
