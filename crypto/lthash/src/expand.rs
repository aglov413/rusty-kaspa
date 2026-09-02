//! Element expansion: arbitrary bytes -> a point in `(Z_{2^W})^N`.
//!
//! # Construction
//!
//! ```text
//! seed(x)  = Blake2b-256(key = "LtHashElement:n=<N>,w=<W>", message = x)   -> 256 bits
//! lanes(x) = canonical_unpack( ChaCha20(key = seed(x), nonce = 0, counter = 0)
//!                              read for ceil(N*W/8) bytes )
//! ```
//!
//! # Why this construction
//!
//! It is **the same shape the incumbent MuHash uses**
//! (`crypto/muhash/src/lib.rs::data_to_element`: Blake2b-256 keyed `b"MuHashElement"`, then
//! `ChaCha20Rng::from_seed` filling 384 bytes), which is in turn the shape Bitcoin Core's
//! MuHash3072 uses (`SHA256 -> ChaCha20`). Three consequences, all wanted:
//!
//! 1. **A minimal-diff migration story.** If LtHash ever replaces MuHash, element hashing is
//!    unchanged and *only the group the accumulator lives in* changes. That is a far easier
//!    proposition to review than one that changes two things at once.
//! 2. **No new primitives.** `blake2b_simd` and `rand_chacha` are already in this
//!    repository's dependency graph at these versions, so this crate introduces no new
//!    cryptographic code to assess.
//! 3. **Comparability.** Holding the hash-to-element step constant across both accumulators
//!    means an observed divergence is attributable to the algebra, not the expansion.
//!
//! # The 256-bit intermediate, stated plainly
//!
//! `H` factors through a 256-bit value, so **any Blake2b-256 collision is immediately an
//! LtHash collision**: if `x != x'` share a seed then `H(x) = H(x')`, and the singleton
//! multisets `{x}` and `{x'}` collide at a generic cost of about `2^128`, regardless of how
//! large `N*W` is. This is not merely an untargeted-collision concern -- it admits a targeted
//! attack on a published commitment: find a colliding pair offline for `~2^128`, publish one
//! ordinary transaction creating one of them as a UTXO, and thereafter substitute the other
//! with the accumulator state, and so the header commitment, bit-for-bit unchanged.
//!
//! **This is a deliberate, documented acceptance of a ~128-bit classical binding level**, on
//! four grounds:
//!
//! * 128 bits is the level the rest of the stack already sits at -- secp256k1 is ~128-bit,
//!   and Blake2b-256 collision resistance is `~2^128`. A 256-bit-binding commitment guarded
//!   by 128-bit signatures buys nothing that can be spent.
//! * **Solana ships exactly this security level for the same construction at the same
//!   parameters.** Their Accounts Lattice Hash (SIMD-0215) is LtHash with `N = 1024`,
//!   `W = 16`, expanded with the BLAKE3 XOF -- whose 256-bit chaining value imposes the same
//!   `~2^128` cap -- and the proposal states 128-bit security as the design target, citing
//!   Lewi et al. It secures a production chain.
//! * **The cap does not undermine the post-quantum rationale.** That rationale is that Shor
//!   solves MuHash's group problem in *polynomial* time. The best known quantum attack here
//!   is generic collision search: roughly `2^85` under BHT assuming quantum RAM nobody knows
//!   how to build, and plausibly no better than classical in practice. The cap lowers the
//!   ceiling; it does not restore a catastrophic failure mode.
//! * It is roughly **4x cheaper** than a 256-bit-capacity XOF. Measured on one machine, a
//!   2048-byte expansion costs 1.22 us here against 6.62 us for cSHAKE256, which is the
//!   difference between LtHash being ~1.5x *faster* than MuHash per element (1.77 us vs
//!   2.68 us) and ~2.7x slower. See `README.md`.
//!
//! An earlier revision of this crate used cSHAKE256 applied directly to the element, which
//! removes the intermediate entirely and attains ~2^256 binding. It is preserved in git
//! history (commit `fde7f656`) and remains the conservative option if review concludes the
//! cap matters here. **Whether that trade is warranted is `PARAMETER-REVIEW.md` Q3, and it is
//! not settled.**

use blake2b_simd::Params as Blake2bParams;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};

use crate::packing;
use crate::params::LtHashParams;

/// Blake2b key prefix for element expansion.
const ELEMENT_DOMAIN_PREFIX: &str = "LtHashElement:";

/// Blake2b key prefix for the final digest.
const FINALIZE_DOMAIN_PREFIX: &str = "LtHashFinalize:";

/// Blake2b accepts keys of at most 64 bytes. `"LtHashElement:n=<u64>,w=<u32>"` is at most
/// ~41 bytes, so this never trips -- but assert rather than trust the arithmetic.
const MAX_BLAKE2B_KEY: usize = 64;

/// Domain separator (Blake2b key) for element expansion under `params`.
pub(crate) fn element_domain(params: &LtHashParams) -> Vec<u8> {
    let d = format!("{ELEMENT_DOMAIN_PREFIX}{params}").into_bytes();
    debug_assert!(d.len() <= MAX_BLAKE2B_KEY);
    d
}

/// Domain separator (Blake2b key) for the final digest under `params`.
pub(crate) fn finalize_domain(params: &LtHashParams) -> Vec<u8> {
    let d = format!("{FINALIZE_DOMAIN_PREFIX}{params}").into_bytes();
    debug_assert!(d.len() <= MAX_BLAKE2B_KEY);
    d
}

/// Blake2b-256 keyed with `key`, over `data`.
pub(crate) fn blake2b_256(key: &[u8], data: &[u8]) -> [u8; 32] {
    assert!(key.len() <= MAX_BLAKE2B_KEY, "blake2b key too long");
    let hash = Blake2bParams::new().hash_length(32).key(key).to_state().update(data).finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// The 32-byte seed for `data` under `params`.
///
/// Exposed because it is the load-bearing intermediate: a collision here is a collision of
/// the whole accumulator. See the module docs.
pub fn element_seed(params: &LtHashParams, data: &[u8]) -> [u8; 32] {
    blake2b_256(&element_domain(params), data)
}

/// Raw expansion output for `data` under `params`: exactly `params.state_bytes()` bytes.
pub fn element_keystream(params: &LtHashParams, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; params.state_bytes()];
    ChaCha20Rng::from_seed(element_seed(params, data)).fill_bytes(&mut out);
    out
}

/// Expands `data` into `N` lanes of `W` bits.
///
/// Every returned lane is already reduced modulo `2^W`.
pub fn expand_element(params: &LtHashParams, data: &[u8]) -> Vec<u64> {
    // `unpack_lossy` rather than `unpack`: when `N*W` is not a multiple of 8 the trailing
    // bits of the final byte are pseudorandom rather than zero, and are simply discarded.
    packing::unpack_lossy(params, &element_keystream(params, data))
}
