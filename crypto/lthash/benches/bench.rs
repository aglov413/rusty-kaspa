//! Benchmarks for [`LtHash`], written to be directly comparable with
//! `crypto/muhash/benches/bench.rs`.
//!
//! # Comparability
//!
//! The MuHash bench is mirrored as closely as the two APIs allow:
//!
//! | MuHash bench | LtHash bench | note |
//! |---|---|---|
//! | `MuHash::add_element` | `LtHash::add_element` | same 100-byte input, same RNG seed |
//! | `MuHash::remove_element` | `LtHash::remove_element` | |
//! | `MuHash::combine` | `LtHash::union_in_place` | merge two accumulators |
//! | `MuHash::clone` | `LtHash::clone` | 384 vs 2048 bytes copied |
//! | `MuHash::serialize {best,worst,rand}` | `LtHash::serialize` | MuHash's cost is data-dependent (it normalizes, i.e. a 3072-bit modular division); LtHash's is not, so there is only one case |
//! | `MuHash::finalize` | `LtHash::digest` | serialize + Blake2b-256 |
//!
//! Both crates build with the same `[profile.release]` (`lto = "thin"`,
//! `overflow-checks = true`) and the same criterion version, so the numbers are measured
//! under identical codegen and harness settings. Run them back to back on an otherwise idle
//! machine:
//!
//! ```bash
//! cargo bench -p kaspa-muhash          # from the repo root
//! cd crypto/lthash && cargo bench      # from this crate
//! ```
//!
//! # Attribution benches
//!
//! `expand_element` and `lane_add_only` split the per-element cost into its two halves:
//! the Blake2b + ChaCha20 expansion (which scales with `N*W`) and the lane arithmetic
//! (which scales with `N`). That split is what tells you whether a parameter change is
//! expensive, and it has no MuHash counterpart.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use rand_chacha::{
    ChaCha8Rng,
    rand_core::{RngCore, SeedableRng},
};

use kaspa_lthash::encoding::{Outpoint, ScriptPublicKey, UtxoEntry, encode_utxo};
use kaspa_lthash::{LtHash, LtHashParams, expand_element};

fn bench_lthash(c: &mut Criterion) {
    let params = LtHashParams::default();

    // Same seed and same 100-byte element size as the MuHash bench, so `add_element` and
    // `remove_element` are measured on like-for-like input.
    let mut rng = ChaCha8Rng::from_seed([42u8; 32]);
    let mut rand_set = LtHash::new(params);

    let mut data = [0u8; 100];
    rng.fill_bytes(&mut data);
    rand_set.add_element(&data);
    rng.fill_bytes(&mut data);
    rand_set.remove_element(&data);

    rng.fill_bytes(&mut data);

    c.bench_function("LtHash::add_element", |b| {
        let mut lthash = LtHash::new(params);
        b.iter(|| {
            black_box(&mut data);
            lthash.add_element(&data);
        });
        black_box(lthash);
    });

    c.bench_function("LtHash::remove_element", |b| {
        let mut lthash = LtHash::new(params);
        b.iter(|| {
            black_box(&mut data);
            lthash.remove_element(&data);
        });
        black_box(lthash);
    });

    c.bench_function("LtHash::union_in_place", |b| {
        let mut lthash = LtHash::new(params);
        b.iter(|| {
            black_box((&mut rand_set, &mut lthash));
            lthash.union_in_place(&rand_set);
        });
        black_box(lthash);
    });

    c.bench_function("LtHash::clone", |b| {
        b.iter(|| {
            black_box(&mut rand_set);
            rand_set.clone()
        });
    });

    // LtHash serialization is a fixed-cost bit/byte shuffle with no data-dependent branch,
    // so unlike MuHash there is no best/worst/random split to make.
    c.bench_function("LtHash::serialize", |b| b.iter(|| black_box(rand_set.clone()).serialize()));

    c.bench_function("LtHash::digest", |b| {
        b.iter(|| black_box(rand_set.clone()).digest());
    });

    // --- Cost attribution: expansion vs. lane arithmetic ---

    c.bench_function("LtHash::expand_element (Blake2b + ChaCha20 + unpack)", |b| {
        b.iter(|| expand_element(black_box(&params), black_box(&data)));
    });

    c.bench_function("keystream: Blake2b-256 -> ChaCha20, 2048 B", |b| {
        b.iter(|| kaspa_lthash::expand::element_keystream(black_box(&params), black_box(&data)));
    });

    // Regression guard on the unpack path. An early revision spent 79% of `add_element` here,
    // doing a runtime-length `copy_from_slice` per lane; specialising `packing.rs` on the lane
    // width fixed it. These two should stay within a few percent of each other -- if the
    // crate's path drifts away from the straightforward reference again, it shows up here
    // rather than as a vague slowdown.
    let keystream = vec![0xA5u8; params.state_bytes()];

    c.bench_function("unpack: crate's byte-aligned path", |b| {
        b.iter(|| kaspa_lthash::packing::unpack_lossy(black_box(&params), black_box(&keystream)));
    });

    c.bench_function("unpack: chunks_exact u16 reference", |b| {
        b.iter(|| fast_unpack_u16(black_box(&keystream)));
    });

    // --- Realistic input: an actual UTXO encoding rather than 100 random bytes ---

    let utxo = encode_utxo(
        &Outpoint::new([0xAB; 32], 1),
        &UtxoEntry::new(5_000_000_000, ScriptPublicKey::new(0, vec![0x20; 34]), 123_456, false),
    );
    c.bench_function("LtHash::add_utxo (97-byte encoding)", |b| {
        let mut lthash = LtHash::new(params);
        b.iter(|| {
            lthash.add_element(black_box(&utxo));
        });
        black_box(lthash);
    });

    // --- Parameter sweep: how does per-element cost scale with the state size? ---
    //
    // Directly relevant to the unresolved parameter question. The expansion dominates and
    // scales with N*W, so this is close to linear in state bytes.
    for (n, w) in [(512usize, 16u32), (1024, 16), (2048, 16), (4096, 16), (1024, 32), (1024, 8)] {
        let p = LtHashParams::new(n, w).unwrap();
        let name = format!("LtHash::add_element n={n} w={w} ({} B state)", p.state_bytes());
        c.bench_function(&name, |b| {
            let mut lthash = LtHash::new(p);
            b.iter(|| {
                lthash.add_element(black_box(&data));
            });
            black_box(lthash);
        });
    }
}

/// A straightforward `W = 16` unpack, kept as an independent reference for the crate's
/// specialised byte-aligned path to be measured against. Not used by the library.
fn fast_unpack_u16(bytes: &[u8]) -> Vec<u64> {
    bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]]) as u64).collect()
}

criterion_group!(benches, bench_lthash);
criterion_main!(benches);
