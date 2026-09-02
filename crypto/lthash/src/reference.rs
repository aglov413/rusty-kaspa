//! A deliberately naive reference implementation, written independently of [`LtHash`].
//!
//! This exists solely to be differentially tested against the real thing. It is written to
//! be *obviously* correct rather than efficient, and to share as little code with
//! [`LtHash`] as possible while still being comparable:
//!
//! * It keeps a `BTreeMap<Vec<u8>, i64>` of element -> signed multiplicity. Removals of
//!   never-added elements are recorded as negative counts, which is exactly the semantics
//!   the group gives you.
//! * [`ReferenceLtHash::state`] **recomputes the whole state from scratch** on every call.
//!   Nothing is accumulated incrementally, so an incremental bug in `LtHash` cannot hide.
//! * Where `LtHash` accumulates by repeated `wrapping_add`, the reference multiplies the
//!   expanded element by the count with a single `wrapping_mul`. Different code path, same
//!   answer -- `k` additions of `x` mod `2^W` is `k*x` mod `2^W`, including for negative
//!   `k` via two's-complement, since `-1 mod 2^64` reduces to `-1 mod 2^W`.
//!
//! What it necessarily *does* share is [`crate::expand::expand_element`]. Two independent
//! implementations of the same hash-to-element step would not agree by construction, so
//! there would be nothing to compare. The differential therefore tests the accumulator
//! logic -- ordering, cancellation, multiplicity, union -- and not the expansion.

use std::collections::BTreeMap;

use crate::LtHash;
use crate::expand::expand_element;
use crate::params::LtHashParams;

/// Naive multiset accumulator: keeps the multiset, recomputes the hash on demand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceLtHash {
    params: LtHashParams,
    /// Element bytes -> signed multiplicity. Entries at zero are pruned so that equality
    /// of two `ReferenceLtHash` values means equality of multisets.
    counts: BTreeMap<Vec<u8>, i64>,
}

impl ReferenceLtHash {
    /// An empty multiset.
    pub fn new(params: LtHashParams) -> Self {
        Self { params, counts: BTreeMap::new() }
    }

    pub fn params(&self) -> LtHashParams {
        self.params
    }

    /// The underlying signed multiset. Useful for test diagnostics.
    pub fn counts(&self) -> &BTreeMap<Vec<u8>, i64> {
        &self.counts
    }

    /// Adds one occurrence of `data`.
    pub fn add_element(&mut self, data: &[u8]) {
        self.bump(data, 1);
    }

    /// Removes one occurrence of `data`, going negative if it was never added.
    pub fn remove_element(&mut self, data: &[u8]) {
        self.bump(data, -1);
    }

    /// Merges another reference multiset into this one (the union operation).
    pub fn union_in_place(&mut self, other: &Self) {
        assert_eq!(self.params, other.params, "cannot combine references with different parameters");
        for (element, &count) in other.counts.iter() {
            self.bump(element, count);
        }
    }

    /// True iff the multiset is empty. Note this is a *multiset* emptiness test, which is
    /// strictly stronger than `LtHash::is_identity` -- the latter can also be true on a
    /// hash collision.
    pub fn is_empty_multiset(&self) -> bool {
        self.counts.is_empty()
    }

    /// Recomputes the LtHash state from scratch.
    pub fn state(&self) -> LtHash {
        let mask = self.params.lane_mask();
        let mut lanes = vec![0u64; self.params.lanes()];
        for (element, &count) in self.counts.iter() {
            if count == 0 {
                continue; // pruned already, but be explicit
            }
            let expanded = expand_element(&self.params, element);
            // Two's-complement reinterpretation: for count < 0 this is `2^64 + count`,
            // and multiplying by it mod 2^64 then reducing mod 2^W gives `count * x mod 2^W`
            // because 2^W divides 2^64 for every W <= 64.
            let k = count as u64;
            for (lane, &e) in lanes.iter_mut().zip(expanded.iter()) {
                *lane = lane.wrapping_add(e.wrapping_mul(k)) & mask;
            }
        }
        LtHash::from_lanes(self.params, lanes)
    }

    /// Convenience: the digest of the recomputed state.
    pub fn digest(&self) -> [u8; crate::DIGEST_SIZE] {
        self.state().digest()
    }

    fn bump(&mut self, data: &[u8], delta: i64) {
        let entry = self.counts.entry(data.to_vec()).or_insert(0);
        *entry = entry.checked_add(delta).expect("multiplicity overflowed i64");
        if *entry == 0 {
            self.counts.remove(data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_matches_lthash_on_a_tiny_case() {
        let params = LtHashParams::default();
        let mut r = ReferenceLtHash::new(params);
        let mut h = LtHash::new(params);

        for e in [b"a".as_slice(), b"b", b"a", b"c"] {
            r.add_element(e);
            h.add_element(e);
        }
        r.remove_element(b"b");
        h.remove_element(b"b");

        assert_eq!(r.state(), h);
    }

    #[test]
    fn reference_handles_negative_counts() {
        let params = LtHashParams::default();
        let mut r = ReferenceLtHash::new(params);
        let mut h = LtHash::new(params);

        r.remove_element(b"never added");
        h.remove_element(b"never added");
        assert_eq!(r.state(), h);
        assert_eq!(r.counts().get(b"never added".as_slice()), Some(&-1));

        r.add_element(b"never added");
        h.add_element(b"never added");
        assert_eq!(r.state(), h);
        assert!(r.is_empty_multiset());
        assert!(h.is_identity());
    }
}
