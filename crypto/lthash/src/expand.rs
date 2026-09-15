//! Element expansion: arbitrary bytes -> a point in `(Z_{2^W})^N`.
//!
//! # Construction
//!
//! ```text
//! s        = Blake2b-512(key = "LtHashElement:b2c2:n=<N>,w=<W>", message = x)  -> 64 bytes
//! lanes(x) = canonical_unpack(
//!     ChaCha20(key = s[0..32],  nonce = "LtHashLane\x00\x00", counter = 0) -> bytes 0..1024
//!  || ChaCha20(key = s[32..64], nonce = "LtHashLane\x00\x01", counter = 0) -> bytes 1024..2048 )
//! ```
//!
//! Byte offsets throughout: `s` is 64 bytes, and the keystream offsets are the shipping
//! parameters (`N = 1024`, `W = 16`, so `L = 2048` and each instance fills exactly 1024).
//! In general the split is `floor(L/2)` where `L = ceil(N*W/8)`; for odd `L` the right
//! instance takes the extra byte.
//!
//! ChaCha20 here is the IETF construction (RFC 8439: 96-bit nonce, 32-bit counter) from the
//! `chacha20` crate, not `rand_chacha`'s Bernstein-RNG layout (64-bit stream, 64-bit
//! counter). Both halves of `s` are load-bearing: truncating to `s[0..32]` and keying a
//! single instance would restore the 128-bit collision this construction exists to remove.
//!
//! # Why two ChaCha instances
//!
//! ChaCha20's key is exactly 256 bits, so a single instance can carry at most 256 bits of
//! digest into the keystream -- which is what caps binding at `~2^128` regardless of `N*W`.
//! Splitting the 512-bit digest across two instances and **concatenating** their output
//! (never XOR: XOR would let collisions cancel) makes the whole digest load-bearing. An
//! output collision requires both halves to collide. Treating the ChaCha20 keystream as a
//! PRF, two distinct keys agree over 1024 bytes only with negligible advantage, so a
//! keystream collision implies a key collision, and both halves colliding implies a full
//! 512-bit Blake2b collision -- a generic cost of `~2^256`. (The claim is about the map
//! `k -> keystream(k, nonce, 0)[..1024]`, not about ChaCha20 being injective as a cipher,
//! which it is not.)
//!
//! # Why this construction
//!
//! It **began as the shape the incumbent MuHash uses**
//! (`crypto/muhash/src/lib.rs::data_to_element`: Blake2b-256 keyed `b"MuHashElement"`, then
//! `ChaCha20Rng::from_seed` filling 384 bytes), itself the shape Bitcoin Core's MuHash3072
//! uses (`SHA256 -> ChaCha20`). It no longer matches it. Stated precisely, since an earlier
//! revision of these docs claimed more than is now true:
//!
//! **Still shared with MuHash:**
//!
//! 1. **The element encoding.** The bytes fed to `H` are byte-identical to MuHash's (see
//!    [`crate::encoding`], verified by `tests/muhash_encoding_vectors.rs`). A divergence
//!    between the two accumulators is therefore never attributable to *what* was hashed.
//! 2. **The primitive families.** `blake2b_simd` is what `kaspa-hashes` builds every hasher
//!    on, and `chacha20` arrives via `chacha20poly1305`, so both are already compiled into
//!    this repository at these versions. No new cryptographic code enters the tree.
//!
//! **No longer shared:**
//!
//! 3. **The expansion itself.** MuHash keys one `rand_chacha` instance from a 256-bit
//!    Blake2b seed; this crate keys two RustCrypto `chacha20` (RFC 8439) instances from the
//!    halves of a 512-bit one, under a different domain separator. So a divergence between
//!    the accumulators is attributable to the algebra *or* the expansion, and isolating the
//!    algebra alone -- which the original shape-matching was meant to buy -- no longer
//!    follows from the construction. The encoding vectors are what remain load-bearing.
//!
//! # The funnel, stated plainly
//!
//! An earlier revision of this crate factored `H` through a 256-bit seed, so **any seed
//! collision was immediately an LtHash collision**: if `x != x'` shared a seed then
//! `H(x) = H(x')`, and the singleton multisets `{x}` and `{x'}` collided. Generic collision
//! search on a 256-bit seed costs `~2^128`, regardless of how large `N*W` is.
//!
//! **This is a collision attack, not a second preimage**, and the distinction matters because
//! the cost differs by a square. The attacker chooses *both* members offline for `~2^128`,
//! publishes an ordinary transaction creating one of them as a UTXO, and thereafter
//! substitutes the other, leaving the accumulator state -- and so the header commitment --
//! bit-for-bit unchanged. Finding a second preimage for a UTXO someone *else* published is a
//! different and far harder problem: `~2^256` even against the old seed.
//!
//! What makes the collision worth `~2^128` of an attacker's time is the homomorphism: only
//! *one* element has to be under their control, and the rest of the UTXO set is irrelevant to
//! the substitution.
//!
//! Splitting a 512-bit digest across two ChaCha20 keys closes it: the funnel is the full
//! digest, so generic collision search costs `~2^256`. It cost ~0% to do -- ~1.11 us against
//! 1.15 us for the capped construction -- which is why the previous revision's argument for
//! *tolerating* `~2^128` was retired rather than defended.
//!
//! **What has not been established is that this composition is sound.** Its parts are
//! standard -- splitting a hash into two keys is the ordinary KDF pattern, concatenating
//! independently-keyed PRG output is routine domain extension -- but this arrangement, in
//! this role, has no published analysis and no prior deployment. The reasoning is one paragraph and
//! we believe it, which is the same position that produced the 256-bit funnel. cSHAKE256
//! (FIPS 202, 6.76 us) and TurboSHAKE256 (CFRG draft, 3.38 us) are the standards-backed
//! fallbacks, costed in `PARAMETER-REVIEW.md` §5.1. **Whether to prefer one of them is that
//! document's Q3, and it is not settled.**

use core::fmt::{self, Write};

use blake2b_simd::Params as Blake2bParams;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};

use crate::packing;
use crate::params::LtHashParams;

/// Identifier for the element-expansion construction, as it appears in the domain separator.
///
/// `b2c2` = Blake2b-512 seeding two ChaCha20 instances. Exposed because anything that records
/// or compares LtHash values must be able to say which construction produced them: values from
/// different constructions are not comparable, and nothing about a digest reveals which one it
/// came from. Bump this whenever the expansion changes.
pub const CONSTRUCTION: &str = "b2c2";

/// Blake2b key prefix for element expansion. Built from [`CONSTRUCTION`] so the tag recorded
/// alongside a value and the tag mixed into it cannot drift apart.
const ELEMENT_DOMAIN_HEAD: &str = "LtHashElement:";

/// Blake2b key prefix for the final digest.
const FINALIZE_DOMAIN_PREFIX: &str = "LtHashFinalize:";

/// Blake2b accepts keys of at most 64 bytes. The longest separator is
/// `"LtHashElement:b2c2:n=<u64>,w=<u32>"` at 46 bytes (`n` at `u64::MAX`, `w` at 64), so this
/// never trips -- but assert rather than trust the arithmetic.
const MAX_BLAKE2B_KEY: usize = 64;

/// A domain separator built on the stack.
///
/// Domain separators are short, bounded by [`MAX_BLAKE2B_KEY`], and recomputed for every
/// element -- this is the per-UTXO hot path, so they are not worth a heap allocation.
pub(crate) struct DomainBuf {
    buf: [u8; MAX_BLAKE2B_KEY],
    len: usize,
}

impl DomainBuf {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl fmt::Write for DomainBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len + s.len();
        if end > self.buf.len() {
            return Err(fmt::Error);
        }
        self.buf[self.len..end].copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

fn domain(prefix: &str, params: &LtHashParams) -> DomainBuf {
    let mut d = DomainBuf { buf: [0u8; MAX_BLAKE2B_KEY], len: 0 };
    write!(d, "{prefix}{params}").expect("domain separator fits in MAX_BLAKE2B_KEY");
    d
}

/// Domain separator (Blake2b key) for element expansion under `params`.
pub(crate) fn element_domain(params: &LtHashParams) -> DomainBuf {
    let mut d = DomainBuf { buf: [0u8; MAX_BLAKE2B_KEY], len: 0 };
    write!(d, "{ELEMENT_DOMAIN_HEAD}{CONSTRUCTION}:{params}").expect("domain separator fits in MAX_BLAKE2B_KEY");
    d
}

/// Domain separator (Blake2b key) for the final digest under `params`.
pub(crate) fn finalize_domain(params: &LtHashParams) -> DomainBuf {
    domain(FINALIZE_DOMAIN_PREFIX, params)
}

/// Blake2b-256 keyed with `key`, over `data`.
pub(crate) fn blake2b_256(key: &[u8], data: &[u8]) -> [u8; 32] {
    assert!(key.len() <= MAX_BLAKE2B_KEY, "blake2b key too long");
    let hash = Blake2bParams::new().hash_length(32).key(key).to_state().update(data).finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// The 64-byte digest for `data` under `params`.
///
/// Exposed because it is the load-bearing intermediate: a collision here is a collision of
/// the whole accumulator. Both halves are used, so the funnel is the full 512 bits.
pub fn element_digest(params: &LtHashParams, data: &[u8]) -> [u8; 64] {
    let d = element_domain(params);
    assert!(d.as_bytes().len() <= MAX_BLAKE2B_KEY, "blake2b key too long");
    let hash = Blake2bParams::new().hash_length(64).key(d.as_bytes()).to_state().update(data).finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// Nonce for the left ChaCha20 instance. The two instances already take distinct keys, so
/// distinct nonces are not load-bearing for security -- they are here so that a reviewer does
/// not have to reason about related-key ChaCha at all. They cost nothing: the nonce is a
/// block-state constant.
const NONCE_L: [u8; 12] = *b"LtHashLane\x00\x00";

/// Nonce for the right ChaCha20 instance. Differs from [`NONCE_L`] in its final byte.
const NONCE_R: [u8; 12] = *b"LtHashLane\x00\x01";

/// Raw expansion output for `data` under `params`: exactly `params.state_bytes()` bytes.
///
/// The left instance fills the first `floor(L/2)` bytes and the right instance the remainder,
/// concatenated -- never XOR, which would let collisions cancel. At the shipping parameters
/// `L = 2048` and the halves are 1024 each; for odd `L` the right instance takes the extra
/// byte.
///
/// The `~2^256` funnel argument assumes both halves are long enough that two distinct
/// ChaCha20 keys cannot coincide by chance. At `L = 2048` that is ~2^-8192 per half. It
/// degrades for very small `L` -- a one-byte half collides at 2^-8 -- but a state that small
/// has a far weaker lattice bound anyway, so the funnel is not what fails first there.
pub fn element_keystream(params: &LtHashParams, data: &[u8]) -> Vec<u8> {
    let digest = element_digest(params, data);
    let mut out = vec![0u8; params.state_bytes()];
    let split = out.len() / 2;
    let (first, second) = out.split_at_mut(split);
    ChaCha20::new(digest[..32].into(), &NONCE_L.into()).apply_keystream(first);
    ChaCha20::new(digest[32..64].into(), &NONCE_R.into()).apply_keystream(second);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The tag recorded alongside a value must be the one actually mixed into it. Checked
    /// here rather than in `tests/expansion_spec.rs` because `element_domain` is `pub(crate)`
    /// -- an integration test cannot reach it, and a test that reconstructs the string from
    /// `CONSTRUCTION` would pass through any change to this function's format.
    #[test]
    fn element_domain_is_the_frozen_string() {
        let d = element_domain(&LtHashParams::default());
        assert_eq!(d.as_bytes(), b"LtHashElement:b2c2:n=1024,w=16");
        assert!(d.as_bytes().windows(CONSTRUCTION.len()).any(|w| w == CONSTRUCTION.as_bytes()), "domain must carry CONSTRUCTION");
    }

    #[test]
    fn finalize_domain_is_the_frozen_string() {
        assert_eq!(finalize_domain(&LtHashParams::default()).as_bytes(), b"LtHashFinalize:n=1024,w=16");
    }

    /// Both nonces pinned as bytes. They are otherwise only implied by the keystream vectors.
    #[test]
    fn nonces_are_frozen() {
        assert_eq!(&NONCE_L, b"LtHashLane\x00\x00");
        assert_eq!(&NONCE_R, b"LtHashLane\x00\x01");
        assert_ne!(NONCE_L, NONCE_R, "the two instances must take distinct nonces");
    }
}
