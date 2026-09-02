//! Property tests for [`LtHash`]. This is the real deliverable of the exercise.
//!
//! The claims being pinned down, in order of appearance:
//!
//! 1. **Order independence** -- the same multiset in any insertion order gives the same state.
//! 2. **Add/remove inverse** -- add-then-remove restores the prior state; a full teardown
//!    returns to the identity.
//! 3. **Silent wrong removals** -- removing something that was never added produces a
//!    perfectly well-formed state with no error, and re-adding it restores the original.
//!    This documents the drift risk rather than guarding against it: the construction
//!    cannot detect a wrong removal, so anything built on it needs an external invariant.
//! 4. **Multiset, not set** -- adding an element twice differs from adding it once.
//! 5. **Union is an abelian group operation** -- associative, commutative, identity, inverse.
//! 6. **Differential** -- agreement with a from-scratch reference implementation
//!    ([`kaspa_lthash::reference::ReferenceLtHash`]) on sets up to ~1e5 elements.
//!
//! Plus serialization round-trips and an equivalence check between the two packing paths.

use std::collections::BTreeMap;

use proptest::prelude::*;
use rand::SeedableRng;
use rand::seq::SliceRandom;
use rand_chacha::ChaCha8Rng;

use kaspa_lthash::encoding::{Outpoint, ScriptPublicKey, UtxoEntry, encode_utxo};
use kaspa_lthash::packing;
use kaspa_lthash::reference::ReferenceLtHash;
use kaspa_lthash::{LtHash, LtHashParams};

// -------------------------------------------------------------------------------------
// Strategies
// -------------------------------------------------------------------------------------

/// Arbitrary element bytes. Includes the empty string, which is a legal element.
fn element() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..40)
}

/// A small multiset of elements, with deliberate repeats so multiplicity actually gets
/// exercised: elements are drawn from a small alphabet.
fn elements(max: usize) -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop::collection::vec(prop::collection::vec(0u8..6, 1..4), 0..max)
}

/// Parameter sets small enough that the general bit-packing path stays cheap, but spanning
/// aligned and unaligned lane widths and the `W = 64` edge.
fn small_params() -> impl Strategy<Value = LtHashParams> {
    (1usize..48, 1u32..=64).prop_map(|(n, w)| LtHashParams::new(n, w).expect("valid by construction"))
}

/// A UTXO, encoded exactly as MuHash would encode it.
fn utxo_element() -> impl Strategy<Value = Vec<u8>> {
    (
        prop::array::uniform32(any::<u8>()),
        any::<u32>(),
        any::<u64>(),
        any::<u64>(),
        any::<bool>(),
        any::<u16>(),
        prop::collection::vec(any::<u8>(), 0..40),
    )
        .prop_map(|(txid, index, amount, daa, coinbase, version, script)| {
            encode_utxo(&Outpoint::new(txid, index), &UtxoEntry::new(amount, ScriptPublicKey::new(version, script), daa, coinbase))
        })
}

fn accumulate(params: LtHashParams, items: &[Vec<u8>]) -> LtHash {
    let mut h = LtHash::new(params);
    for item in items {
        h.add_element(item);
    }
    h
}

// -------------------------------------------------------------------------------------
// 1. Order independence
// -------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// The same multiset inserted in a shuffled order yields the identical state.
    #[test]
    fn order_independence(params in small_params(), items in elements(24), seed in any::<u64>()) {
        let straight = accumulate(params, &items);

        let mut shuffled = items.clone();
        shuffled.shuffle(&mut ChaCha8Rng::seed_from_u64(seed));
        let permuted = accumulate(params, &shuffled);

        prop_assert_eq!(straight, permuted);
    }

    /// Order independence holds for *mixed* add/remove sequences too, not just adds: the
    /// group is abelian, so any interleaving of the same operations agrees.
    #[test]
    fn order_independence_with_removals(
        params in small_params(),
        ops in prop::collection::vec((prop::collection::vec(0u8..6, 1..4), any::<bool>()), 0..24),
        seed in any::<u64>(),
    ) {
        let apply = |ops: &[(Vec<u8>, bool)]| {
            let mut h = LtHash::new(params);
            for (item, is_add) in ops {
                if *is_add { h.add_element(item) } else { h.remove_element(item) }
            }
            h
        };

        let mut shuffled = ops.clone();
        shuffled.shuffle(&mut ChaCha8Rng::seed_from_u64(seed));

        prop_assert_eq!(apply(&ops), apply(&shuffled));
    }

    /// Real UTXO encodings, not just arbitrary bytes.
    #[test]
    fn order_independence_over_utxos(utxos in prop::collection::vec(utxo_element(), 0..12), seed in any::<u64>()) {
        let params = LtHashParams::default();
        let straight = accumulate(params, &utxos);
        let mut shuffled = utxos.clone();
        shuffled.shuffle(&mut ChaCha8Rng::seed_from_u64(seed));
        prop_assert_eq!(straight, accumulate(params, &shuffled));
    }
}

// -------------------------------------------------------------------------------------
// 2. Add / remove are exact inverses
// -------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// Adding an element and then removing it returns to exactly the prior state --
    /// including the prior *state*, not merely the prior digest.
    #[test]
    fn add_then_remove_returns_to_prior_state(
        params in small_params(),
        items in elements(16),
        extra in element(),
    ) {
        let before = accumulate(params, &items);

        let mut after = before.clone();
        after.add_element(&extra);
        after.remove_element(&extra);

        prop_assert_eq!(&before, &after);
        prop_assert_eq!(before.digest(), after.digest());
    }

    /// Removing every element that was added, in an arbitrary order, returns to identity.
    #[test]
    fn full_teardown_returns_to_identity(params in small_params(), items in elements(24), seed in any::<u64>()) {
        let mut h = accumulate(params, &items);

        let mut teardown = items.clone();
        teardown.shuffle(&mut ChaCha8Rng::seed_from_u64(seed));
        for item in &teardown {
            h.remove_element(item);
        }

        prop_assert!(h.is_identity(), "state after full teardown: {:?}", h);
        prop_assert_eq!(h, LtHash::identity(params));
    }

    /// Remove-then-add is just as much an inverse pair as add-then-remove.
    #[test]
    fn remove_then_add_returns_to_prior_state(params in small_params(), items in elements(16), extra in element()) {
        let before = accumulate(params, &items);
        let mut after = before.clone();
        after.remove_element(&extra);
        after.add_element(&extra);
        prop_assert_eq!(before, after);
    }
}

// -------------------------------------------------------------------------------------
// 3. Wrong removals fail silently -- the drift risk this crate exists to characterise
// -------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// Removing an element that was never added:
    ///
    /// * does not error, does not panic, and does not produce anything distinguishable
    ///   from a legitimate state -- the result serializes, deserializes and digests exactly
    ///   like any other state;
    /// * moves the state somewhere else (so the corruption is real);
    /// * is undone exactly by re-adding the same element.
    ///
    /// The middle point is the whole warning. A node that removes a UTXO it never added
    /// gets no signal at all; it just carries a wrong accumulator forward until some later
    /// commitment comparison fails, with nothing to indicate where the drift started.
    #[test]
    fn removing_never_added_element_is_silent_and_reversible(
        params in small_params(),
        items in elements(16),
        ghost in element(),
    ) {
        prop_assume!(!items.contains(&ghost));

        let original = accumulate(params, &items);

        let mut corrupted = original.clone();
        corrupted.remove_element(&ghost);

        // (a) The corrupted state is indistinguishable from a well-formed one.
        let serialized = corrupted.serialize();
        prop_assert_eq!(serialized.len(), params.state_bytes());
        prop_assert_eq!(LtHash::deserialize(params, &serialized).unwrap(), corrupted.clone());
        prop_assert_eq!(corrupted.digest().len(), 32);

        // (b) It really did move (unless the expansion of `ghost` is the zero vector, which
        //     is astronomically unlikely for realistic parameters but is possible for the
        //     tiny ones this test also generates, so allow it explicitly).
        let ghost_expansion_is_zero = kaspa_lthash::expand_element(&params, &ghost).iter().all(|&l| l == 0);
        if !ghost_expansion_is_zero {
            prop_assert_ne!(&original, &corrupted, "wrong removal left the state unchanged");
        }

        // (c) Re-adding restores it exactly. No repair procedure is needed *if* you know
        //     what was wrongly removed -- which in practice you do not.
        corrupted.add_element(&ghost);
        prop_assert_eq!(original, corrupted);
    }

    /// A wrong removal of one element is exactly cancelled by a wrong *addition* of the
    /// same element elsewhere. Two independent bugs can mask each other -- which is why a
    /// digest match is evidence about the multiset, not about the code that built it.
    #[test]
    fn wrong_removal_and_wrong_addition_cancel(params in small_params(), items in elements(12), ghost in element()) {
        let mut a = accumulate(params, &items);
        a.remove_element(&ghost);

        let mut b = accumulate(params, &items);
        b.remove_element(&ghost);
        b.add_element(&ghost);
        b.remove_element(&ghost);

        prop_assert_eq!(a, b);
    }
}

// -------------------------------------------------------------------------------------
// 4. Multiset semantics
// -------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 96, ..ProptestConfig::default() })]

    /// Adding the same element twice is distinct from adding it once. Uses the default
    /// parameters: with `N*W = 16384` bits of state, a coincidence here would be a
    /// 2^-16384 event, so this is a real assertion rather than a probabilistic one.
    #[test]
    fn adding_twice_differs_from_adding_once(item in element()) {
        let params = LtHashParams::default();

        let mut once = LtHash::new(params);
        once.add_element(&item);

        let mut twice = LtHash::new(params);
        twice.add_element(&item);
        twice.add_element(&item);

        prop_assert_ne!(&once, &twice);
        prop_assert_ne!(once.digest(), twice.digest());
        prop_assert_ne!(&twice, &LtHash::identity(params));
    }

    /// Multiplicity is tracked exactly: `k` copies of `x` differ from `j` copies for `j != k`,
    /// and `k` copies removed once leaves `k-1` copies.
    #[test]
    fn multiplicity_is_exact(item in element(), k in 1usize..6) {
        let params = LtHashParams::default();

        let states: Vec<LtHash> = (0..=k)
            .map(|copies| {
                let mut h = LtHash::new(params);
                for _ in 0..copies {
                    h.add_element(&item);
                }
                h
            })
            .collect();

        for i in 0..states.len() {
            for j in (i + 1)..states.len() {
                prop_assert_ne!(&states[i], &states[j], "{} copies collided with {} copies", i, j);
            }
        }

        let mut down = states[k].clone();
        down.remove_element(&item);
        prop_assert_eq!(&down, &states[k - 1]);
    }

    /// `{a, a}` is not `{a, b}` -- multiset equality, not set equality.
    #[test]
    fn duplicate_is_not_the_same_as_a_second_distinct_element(a in element(), b in element()) {
        prop_assume!(a != b);
        let params = LtHashParams::default();

        let mut aa = LtHash::new(params);
        aa.add_element(&a);
        aa.add_element(&a);

        let mut ab = LtHash::new(params);
        ab.add_element(&a);
        ab.add_element(&b);

        prop_assert_ne!(aa, ab);
    }
}

// -------------------------------------------------------------------------------------
// 5. Union is an abelian group operation
// -------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn union_is_commutative(params in small_params(), xs in elements(12), ys in elements(12)) {
        let a = accumulate(params, &xs);
        let b = accumulate(params, &ys);
        prop_assert_eq!(a.union(&b), b.union(&a));
    }

    #[test]
    fn union_is_associative(
        params in small_params(),
        xs in elements(10),
        ys in elements(10),
        zs in elements(10),
    ) {
        let a = accumulate(params, &xs);
        let b = accumulate(params, &ys);
        let c = accumulate(params, &zs);
        prop_assert_eq!(a.union(&b).union(&c), a.union(&b.union(&c)));
    }

    #[test]
    fn identity_is_neutral_for_union(params in small_params(), xs in elements(12)) {
        let a = accumulate(params, &xs);
        let e = LtHash::identity(params);
        prop_assert_eq!(a.union(&e), a.clone());
        prop_assert_eq!(e.union(&a), a.clone());
    }

    /// Every state has an inverse: `a.union(a.inverse()) == identity`, expressed here as
    /// `a - a == 0` via `difference`.
    #[test]
    fn every_state_has_an_inverse(params in small_params(), xs in elements(12)) {
        let a = accumulate(params, &xs);
        prop_assert!(a.difference(&a).is_identity());
    }

    /// The homomorphism itself: the union of two accumulators equals the accumulator over
    /// the concatenated multisets. This is what makes parallel/incremental accumulation
    /// legal -- and it is exactly the property `MuHash::combine` relies on inside
    /// `validate_transactions_with_muhash_in_parallel`.
    #[test]
    fn union_equals_accumulating_the_concatenation(params in small_params(), xs in elements(12), ys in elements(12)) {
        let combined = accumulate(params, &xs).union(&accumulate(params, &ys));
        let concatenated = accumulate(params, &xs.iter().chain(ys.iter()).cloned().collect::<Vec<_>>());
        prop_assert_eq!(combined, concatenated);
    }

    /// Union distributes over an arbitrary partition of the multiset, in any grouping --
    /// the general form of the previous property, and the thing a rayon `reduce` needs.
    #[test]
    fn union_over_an_arbitrary_partition(params in small_params(), chunks in prop::collection::vec(elements(6), 0..6)) {
        let by_chunk = chunks
            .iter()
            .map(|c| accumulate(params, c))
            .fold(LtHash::identity(params), |acc, h| acc.union(&h));
        let flat = accumulate(params, &chunks.concat());
        prop_assert_eq!(by_chunk, flat);
    }
}

// -------------------------------------------------------------------------------------
// 6. Differential against the naive reference
// -------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// Arbitrary add/remove sequences, checked against a reference that keeps the actual
    /// multiset in a `BTreeMap` and recomputes the state from scratch every time.
    #[test]
    fn differential_against_reference(
        params in small_params(),
        ops in prop::collection::vec((prop::collection::vec(0u8..6, 1..4), any::<bool>()), 0..48),
    ) {
        let mut h = LtHash::new(params);
        let mut r = ReferenceLtHash::new(params);

        for (item, is_add) in &ops {
            if *is_add {
                h.add_element(item);
                r.add_element(item);
            } else {
                h.remove_element(item);
                r.remove_element(item);
            }
            // Check at every step, not just at the end, so a divergence is reported at the
            // operation that caused it.
            prop_assert_eq!(&h, &r.state());
        }

        prop_assert_eq!(h.digest(), r.digest());
    }

    /// The reference agrees on unions too.
    #[test]
    fn differential_union_against_reference(params in small_params(), xs in elements(12), ys in elements(12)) {
        let mut rx = ReferenceLtHash::new(params);
        for x in &xs { rx.add_element(x); }
        let mut ry = ReferenceLtHash::new(params);
        for y in &ys { ry.add_element(y); }

        let mut merged = rx.clone();
        merged.union_in_place(&ry);

        prop_assert_eq!(rx.state().union(&ry.state()), merged.state());
    }

    /// UTXO-shaped elements under the real default parameters.
    #[test]
    fn differential_over_utxos(utxos in prop::collection::vec(utxo_element(), 0..24)) {
        let params = LtHashParams::default();
        let mut h = LtHash::new(params);
        let mut r = ReferenceLtHash::new(params);
        for u in &utxos {
            h.add_element(u);
            r.add_element(u);
        }
        prop_assert_eq!(h, r.state());
    }
}

// -------------------------------------------------------------------------------------
// Serialization and packing
// -------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn serialize_roundtrip(params in small_params(), items in elements(16)) {
        let h = accumulate(params, &items);
        let bytes = h.serialize();
        prop_assert_eq!(bytes.len(), params.state_bytes());
        prop_assert_eq!(LtHash::deserialize(params, &bytes).unwrap(), h);
    }

    /// The byte-aligned packing path and the general bit-level path must agree wherever
    /// both apply. This is what licenses the fast path in `packing`.
    #[test]
    fn packing_paths_agree_on_byte_aligned_widths(
        n in 1usize..40,
        width_bytes in 1u32..=8,
        items in elements(12),
    ) {
        let params = LtHashParams::new(n, width_bytes * 8).unwrap();
        prop_assert!(params.is_byte_aligned());

        let h = accumulate(params, &items);

        // `packing::pack` dispatches to the aligned path here; `bitwise_pack` below is an
        // independent transcription of the general bit-level definition.
        let aligned = packing::pack(&params, h.lanes());
        let mut bitwise = vec![0u8; params.state_bytes()];
        bitwise_pack(&params, h.lanes(), &mut bitwise);
        prop_assert_eq!(&aligned, &bitwise);

        let unpacked_aligned = packing::unpack(&params, &aligned).unwrap();
        let unpacked_bitwise = bitwise_unpack(&params, &bitwise);
        prop_assert_eq!(&unpacked_aligned, &unpacked_bitwise);
        prop_assert_eq!(unpacked_aligned.as_slice(), h.lanes());
    }

    /// Every lane is reduced modulo `2^W` at all times -- no lane ever carries stray high
    /// bits that the packer would silently drop.
    #[test]
    fn lanes_stay_reduced(params in small_params(), ops in prop::collection::vec((element(), any::<bool>()), 0..24)) {
        let mut h = LtHash::new(params);
        let mask = params.lane_mask();
        for (item, is_add) in &ops {
            if *is_add { h.add_element(item) } else { h.remove_element(item) }
            prop_assert!(h.lanes().iter().all(|&l| l & !mask == 0));
        }
    }

    /// Distinct states give distinct digests (Blake2b collision resistance, checked as a
    /// smoke test) and equal states give equal digests (determinism).
    #[test]
    fn digest_is_deterministic_and_state_sensitive(params in small_params(), xs in elements(12), ys in elements(12)) {
        let a = accumulate(params, &xs);
        let b = accumulate(params, &ys);
        prop_assert_eq!(a.digest(), a.clone().digest());
        if a == b {
            prop_assert_eq!(a.digest(), b.digest());
        } else {
            prop_assert_ne!(a.digest(), b.digest());
        }
    }
}

/// Local copies of the general bit-level packing routines, written independently of the
/// crate's internals so that `packing_paths_agree_on_byte_aligned_widths` is a genuine
/// cross-check rather than a call into the same code.
fn bitwise_pack(params: &LtHashParams, lanes: &[u64], out: &mut [u8]) {
    let w = params.lane_bits() as usize;
    for (i, &lane) in lanes.iter().enumerate() {
        for k in 0..w {
            if (lane >> k) & 1 == 1 {
                let bit = i * w + k;
                out[bit / 8] |= 1u8 << (bit % 8);
            }
        }
    }
}

fn bitwise_unpack(params: &LtHashParams, bytes: &[u8]) -> Vec<u64> {
    let w = params.lane_bits() as usize;
    (0..params.lanes())
        .map(|i| {
            let mut lane = 0u64;
            for k in 0..w {
                let bit = i * w + k;
                if (bytes[bit / 8] >> (bit % 8)) & 1 == 1 {
                    lane |= 1u64 << k;
                }
            }
            lane
        })
        .collect()
}

// -------------------------------------------------------------------------------------
// Large-scale differential: ~1e5 elements
// -------------------------------------------------------------------------------------

/// Deterministic pseudo-UTXO generator, so failures are reproducible without a corpus.
fn synthetic_utxo(i: u64) -> Vec<u8> {
    let mut txid = [0u8; 32];
    txid[..8].copy_from_slice(&i.to_le_bytes());
    txid[8..16].copy_from_slice(&(i.wrapping_mul(0x9E37_79B9_7F4A_7C15)).to_le_bytes());
    let script_len = (i % 37) as usize;
    let script: Vec<u8> = (0..script_len).map(|k| (i as u8).wrapping_add(k as u8)).collect();
    encode_utxo(
        &Outpoint::new(txid, (i % 5) as u32),
        &UtxoEntry::new(i.wrapping_mul(1_000_003), ScriptPublicKey::new((i % 3) as u16, script), i / 7, i.is_multiple_of(11)),
    )
}

/// 100_000 distinct elements: order independence, differential agreement with the naive
/// reference, and a full teardown back to identity.
///
/// This is the scale the task asked for. It runs at `opt-level = 2` (see the crate's
/// `[profile.test]`), which keeps it to a few seconds.
#[test]
fn large_scale_differential_100k() {
    const N: u64 = 100_000;
    let params = LtHashParams::default();

    let elements: Vec<Vec<u8>> = (0..N).map(synthetic_utxo).collect();

    // Forward accumulation.
    let mut h = LtHash::new(params);
    let mut r = ReferenceLtHash::new(params);
    for e in &elements {
        h.add_element(e);
        r.add_element(e);
    }

    // The reference recomputes from scratch; agreement here is the real differential.
    assert_eq!(h, r.state(), "100k-element accumulation diverged from the reference");
    assert_eq!(h.digest(), r.digest());
    assert!(!h.is_identity());

    // Same multiset, shuffled.
    let mut shuffled = elements.clone();
    shuffled.shuffle(&mut ChaCha8Rng::seed_from_u64(0xD1CE_D1CE));
    let mut shuffled_hash = LtHash::new(params);
    for e in &shuffled {
        shuffled_hash.add_element(e);
    }
    assert_eq!(h, shuffled_hash, "100k-element accumulation was order dependent");

    // Full teardown in yet another order.
    let mut teardown = elements;
    teardown.shuffle(&mut ChaCha8Rng::seed_from_u64(0xFEED_FACE));
    for e in &teardown {
        h.remove_element(e);
    }
    assert!(h.is_identity(), "100k-element teardown did not return to identity: {h:?}");
}

/// 100_000 elements with heavy multiplicity, split across many partial accumulators that
/// are then unioned in a random order -- the shape a parallel `reduce` produces.
#[test]
fn large_scale_union_of_partitions_100k() {
    const N: u64 = 100_000;
    const CHUNKS: usize = 64;
    let params = LtHashParams::default();

    // 20_000 distinct elements, each appearing up to 5 times.
    let elements: Vec<Vec<u8>> = (0..N).map(|i| synthetic_utxo(i % 20_000)).collect();

    let flat = {
        let mut h = LtHash::new(params);
        for e in &elements {
            h.add_element(e);
        }
        h
    };

    let mut partials: Vec<LtHash> = elements
        .chunks(elements.len().div_ceil(CHUNKS))
        .map(|chunk| {
            let mut h = LtHash::new(params);
            for e in chunk {
                h.add_element(e);
            }
            h
        })
        .collect();
    partials.shuffle(&mut ChaCha8Rng::seed_from_u64(7));

    let merged = partials.iter().fold(LtHash::identity(params), |acc, p| acc.union(p));
    assert_eq!(flat, merged, "union of partitions disagreed with flat accumulation");

    // And against the reference, which recomputes from the multiplicity map.
    let mut counts: BTreeMap<Vec<u8>, i64> = BTreeMap::new();
    for e in &elements {
        *counts.entry(e.clone()).or_insert(0) += 1;
    }
    let mut r = ReferenceLtHash::new(params);
    for (e, c) in &counts {
        for _ in 0..*c {
            r.add_element(e);
        }
    }
    assert_eq!(flat, r.state());
}
