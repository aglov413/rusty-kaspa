//! # LtHash -- a lattice-based homomorphic multiset hash
//!
//! **This is an unaudited experiment.** It is a *shadow* implementation, running alongside the
//! incumbent MuHash UTXO commitment for comparison. It is wired into consensus only as an
//! opt-in, devnet-only shadow: computed and persisted alongside MuHash, and never consulted by
//! any validation decision. The parameter choice is explicitly unresolved. Read `README.md`
//! before forming any opinion about whether this is safe for anything.
//!
//! ## The construction
//!
//! LtHash (Lewi, Kim, Maykov, Weis, *"Securing Update Propagation with Homomorphic
//! Hashing"*, 2019) represents a multiset by a point in the abelian group
//! `(Z_{2^W})^N` -- `N` lanes of `W` bits, added lane-wise with wrapping arithmetic.
//!
//! * An element is expanded by a random oracle `H : {0,1}* -> (Z_{2^W})^N`, instantiated as
//!   `Blake2b-256 -> ChaCha20` — the same shape MuHash uses (see [`expand`] for the
//!   construction, and for why the resulting ~2^128 binding cap is accepted knowingly).
//! * `add(x)` adds `H(x)` lane-wise; `remove(x)` subtracts it lane-wise.
//! * The identity (empty multiset) is the all-zero state.
//! * The union of two multisets is the lane-wise sum of their states.
//!
//! Because the group is abelian, insertion order does not matter, `add` and `remove` are
//! exact inverses, and union is associative and commutative. Those are the properties the
//! test suite pins down.
//!
//! ## Why "post-quantum candidate"
//!
//! MuHash's security rests on the hardness of a problem in a multiplicative group modulo a
//! 3072-bit modulus, which Shor's algorithm dissolves. LtHash's security reduces to a short
//! integer solution (SIS)-flavoured lattice problem, for which no quantum speedup better
//! than generic search is known. That is the entire motivation.
//!
//! The *practical* attack to worry about is Wagner's generalized birthday attack, which is
//! classical. See `README.md`.
//!
//! ## What is deliberately shared with MuHash, and what is not
//!
//! **Shared, and this is critical:** the element encoding. [`encoding::write_utxo`] emits
//! the exact bytes that `consensus/core/src/muhash.rs::write_utxo` emits. Both accumulators
//! hash byte-identical elements, so their outputs are directly comparable.
//!
//! **Not shared:** the domain separators, and obviously the algebra. The *expansion* is
//! deliberately the same shape MuHash uses, which keeps a future migration minimal — only the
//! group the accumulator lives in would change. See [`expand`].
//!
//! ## Example
//!
//! ```
//! use kaspa_lthash::{LtHash, LtHashParams};
//!
//! let mut a = LtHash::new(LtHashParams::default());
//! a.add_element(b"one");
//! a.add_element(b"two");
//!
//! let mut b = LtHash::new(LtHashParams::default());
//! b.add_element(b"two");
//! b.add_element(b"one");
//!
//! assert_eq!(a, b);                      // order independent
//! assert_eq!(a.serialize().len(), 2048); // N=1024 lanes x W=16 bits
//!
//! a.remove_element(b"one");
//! a.remove_element(b"two");
//! assert!(a.is_identity());              // full teardown returns to identity
//! ```

#![forbid(unsafe_code)]

pub mod encoding;
pub mod expand;
pub mod packing;
pub mod params;
pub mod reference;

use core::fmt;

pub use encoding::{Outpoint, ScriptPublicKey, UtxoEntry};
pub use expand::expand_element;
pub use params::{DEFAULT_LANE_BITS, DEFAULT_LANES, LtHashParams, ParamsError};

/// Size of a [`LtHash::digest`] in bytes.
pub const DIGEST_SIZE: usize = 32;

/// Why a deserialization failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeserializeError {
    /// The byte string was not `params.state_bytes()` long.
    WrongLength { expected: usize, got: usize },
    /// The trailing padding bits of the last byte were not zero. Only reachable when
    /// `N * W` is not a multiple of 8.
    NonCanonicalPadding,
}

impl fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeserializeError::WrongLength { expected, got } => {
                write!(f, "expected {expected} state bytes, got {got}")
            }
            DeserializeError::NonCanonicalPadding => write!(f, "non-zero padding bits in the final byte"),
        }
    }
}

impl std::error::Error for DeserializeError {}

/// An LtHash accumulator: `N` lanes of `W` bits, added lane-wise modulo `2^W`.
///
/// Two `LtHash` values are equal iff they have the same parameters and the same lanes.
/// A state is *not* a digest -- see [`LtHash::digest`].
#[derive(Clone, PartialEq, Eq)]
pub struct LtHash {
    params: LtHashParams,
    /// Invariant: `lanes.len() == params.lanes()` and every entry is `< 2^W`.
    ///
    /// # Known optimization, deliberately not taken
    ///
    /// Every lane occupies a full `u64` regardless of `W`. At the default `W = 16` that is a
    /// **4x memory overhead**: 1024 lanes cost 8192 bytes in RAM where the canonical
    /// serialization is 2048. A width-specialised representation (`Vec<u16>` for `W <= 16`,
    /// `Vec<u32>` for `W <= 32`, ...) would cut the resident footprint to the serialized size
    /// and make [`LtHash::clone`] roughly MuHash-competitive — it is currently 94 ns against
    /// MuHash's 18 ns, purely because it copies 10.7x more bytes.
    ///
    /// It is not taken because `N` and `W` are runtime values precisely so a reviewer can
    /// sweep them while `PARAMETER-REVIEW.md` is unanswered. Specialising the lane type means
    /// an enum over widths or const generics, which trades that flexibility for memory that
    /// currently does not matter: `clone` is off the hot path (once per block template, twice
    /// per pruning-point import — never per element or per transaction), and parallel
    /// transaction validation holds only a few tens of KB transiently.
    ///
    /// **Revisit when:** the parameters are fixed by review, *or* profiling shows accumulator
    /// memory mattering — most plausibly if many accumulators are held simultaneously, or if
    /// a much larger `N` is chosen. Until then the flexibility is worth more than the bytes.
    lanes: Vec<u64>,
}

impl LtHash {
    /// The identity element (the empty multiset): all lanes zero.
    pub fn new(params: LtHashParams) -> Self {
        Self { lanes: vec![0u64; params.lanes()], params }
    }

    /// Alias for [`LtHash::new`], for when "identity" reads better than "new".
    pub fn identity(params: LtHashParams) -> Self {
        Self::new(params)
    }

    /// Builds a state directly from lanes. Every lane is reduced modulo `2^W`.
    ///
    /// # Panics
    /// If `lanes.len() != params.lanes()`.
    pub fn from_lanes(params: LtHashParams, mut lanes: Vec<u64>) -> Self {
        assert_eq!(lanes.len(), params.lanes(), "lane count does not match params");
        let mask = params.lane_mask();
        for lane in lanes.iter_mut() {
            *lane &= mask;
        }
        Self { params, lanes }
    }

    /// The parameters this state was built with.
    #[inline]
    pub fn params(&self) -> LtHashParams {
        self.params
    }

    /// The raw lanes, each already reduced modulo `2^W`.
    #[inline]
    pub fn lanes(&self) -> &[u64] {
        &self.lanes
    }

    /// True iff this is the empty multiset.
    ///
    /// Note the standard caveat: a *non-empty* multiset can also hash to the identity if
    /// someone finds a collision. That is precisely what Wagner's attack looks for.
    pub fn is_identity(&self) -> bool {
        self.lanes.iter().all(|&l| l == 0)
    }

    /// Adds one occurrence of `data` to the multiset.
    ///
    /// `data` must be the element encoding -- for UTXOs, use [`LtHash::add_utxo`] or feed
    /// the output of [`encoding::encode_utxo`], so that the bytes match MuHash's.
    pub fn add_element(&mut self, data: &[u8]) {
        let e = expand::expand_element(&self.params, data);
        self.add_lanes(&e);
    }

    /// Removes one occurrence of `data` from the multiset.
    ///
    /// **This never fails.** Removing an element that was never added produces a perfectly
    /// well-formed state that simply does not correspond to any multiset you meant. There
    /// is no membership test and no error path -- that is inherent to the construction, and
    /// it is the drift risk this crate exists to characterise. See the
    /// `removing_never_added_element_is_silent_and_reversible` property test.
    pub fn remove_element(&mut self, data: &[u8]) {
        let e = expand::expand_element(&self.params, data);
        self.sub_lanes(&e);
    }

    /// Adds a UTXO, using the MuHash-identical encoding.
    pub fn add_utxo(&mut self, outpoint: &Outpoint, entry: &UtxoEntry) {
        self.add_element(&encoding::encode_utxo(outpoint, entry));
    }

    /// Removes a UTXO, using the MuHash-identical encoding.
    pub fn remove_utxo(&mut self, outpoint: &Outpoint, entry: &UtxoEntry) {
        self.remove_element(&encoding::encode_utxo(outpoint, entry));
    }

    /// Union of two multisets: lane-wise addition.
    ///
    /// This is the analogue of `MuHash::combine`.
    ///
    /// # Panics
    /// If `other` has different parameters. Mixing parameter sets is a programming error,
    /// not a runtime condition.
    pub fn union_in_place(&mut self, other: &Self) {
        assert_eq!(self.params, other.params, "cannot combine LtHash states with different parameters");
        self.add_lanes(&other.lanes);
    }

    /// Non-mutating [`LtHash::union_in_place`].
    pub fn union(&self, other: &Self) -> Self {
        let mut out = self.clone();
        out.union_in_place(other);
        out
    }

    /// Removes everything in `other` from `self`: lane-wise subtraction.
    ///
    /// The inverse of [`LtHash::union_in_place`], and subject to the same silence about
    /// whether `other` was ever actually part of `self`.
    ///
    /// # Panics
    /// If `other` has different parameters.
    pub fn difference_in_place(&mut self, other: &Self) {
        assert_eq!(self.params, other.params, "cannot subtract LtHash states with different parameters");
        self.sub_lanes(&other.lanes);
    }

    /// Non-mutating [`LtHash::difference_in_place`].
    pub fn difference(&self, other: &Self) -> Self {
        let mut out = self.clone();
        out.difference_in_place(other);
        out
    }

    /// Canonical little-endian serialization of the state.
    ///
    /// For the default parameters this is exactly 2048 bytes. See [`packing`] for the exact
    /// bit order, including the non-byte-aligned case.
    pub fn serialize(&self) -> Vec<u8> {
        packing::pack(&self.params, &self.lanes)
    }

    /// Inverse of [`LtHash::serialize`].
    pub fn deserialize(params: LtHashParams, bytes: &[u8]) -> Result<Self, DeserializeError> {
        if bytes.len() != params.state_bytes() {
            return Err(DeserializeError::WrongLength { expected: params.state_bytes(), got: bytes.len() });
        }
        match packing::unpack(&params, bytes) {
            Some(lanes) => Ok(Self { params, lanes }),
            None => Err(DeserializeError::NonCanonicalPadding),
        }
    }

    /// Blake2b-256 over the canonical little-endian serialization of the state.
    ///
    /// # This is lossy, on purpose and irreversibly
    ///
    /// The state is 2048 bytes under the default parameters; the digest is 32. **The state
    /// cannot be recovered from the digest.** Consequences that matter in practice:
    ///
    /// * A digest is *not* a resumable accumulator. You cannot take a stored digest, add an
    ///   element to it, and get the right answer. Anything that needs to keep accumulating
    ///   must persist [`LtHash::serialize`] -- all 2048 bytes -- not the digest. This is
    ///   the same distinction MuHash draws between `serialize()` (384 bytes, resumable) and
    ///   `finalize()` (32 bytes, terminal), except that LtHash's state is 5.3x larger.
    /// * Two states that differ produce different digests only up to collision resistance
    ///   of Blake2b. The homomorphic properties hold on *states*, not on digests: the
    ///   digest of a union is not any function of the digests of the parts.
    ///
    /// The parameters are bound into the Blake2b **key**, not the message, so the message
    /// really is exactly `serialize()`. Digests taken under different `(N, W)` are
    /// therefore incomparable by construction rather than by convention.
    ///
    /// # On the 32-byte width
    ///
    /// Blake2b-256 is retained here, rather than a XOF, because the output is a fixed 32-byte
    /// value destined for a header field and every other Kaspa header hash is Blake2b-256 —
    /// including MuHash's own `MuHashFinalizeHash`. A XOF buys nothing at fixed width.
    ///
    /// The width does bound *untargeted* collision search at `~2^128`. It does not bound the
    /// attack the commitment actually defends against: poisoning an already-published pruning
    /// point is a second-preimage problem, and Blake2b-256 second-preimage resistance is
    /// `~2^256`. That is why the element expansion, not the digest, was the binding
    /// constraint worth fixing — see [`crate::expand`].
    pub fn digest(&self) -> [u8; DIGEST_SIZE] {
        expand::blake2b_256(&expand::finalize_domain(&self.params), &self.serialize())
    }

    /// The digest as lowercase hex, for logs and test failure messages.
    pub fn digest_hex(&self) -> String {
        self.digest().iter().map(|b| format!("{b:02x}")).collect()
    }

    // --- internals ---

    fn add_lanes(&mut self, other: &[u64]) {
        debug_assert_eq!(other.len(), self.lanes.len());
        let mask = self.params.lane_mask();
        for (lane, &e) in self.lanes.iter_mut().zip(other.iter()) {
            *lane = lane.wrapping_add(e) & mask;
        }
    }

    fn sub_lanes(&mut self, other: &[u64]) {
        debug_assert_eq!(other.len(), self.lanes.len());
        let mask = self.params.lane_mask();
        for (lane, &e) in self.lanes.iter_mut().zip(other.iter()) {
            *lane = lane.wrapping_sub(e) & mask;
        }
    }
}

impl Default for LtHash {
    /// Identity under the default parameters (`N = 1024`, `W = 16`).
    fn default() -> Self {
        Self::new(LtHashParams::default())
    }
}

/// Prints the parameters and the digest rather than 1024 lane values.
impl fmt::Debug for LtHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LtHash")
            .field("params", &format_args!("{}", self.params))
            .field("digest", &format_args!("{}", self.digest_hex()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_is_2048_bytes() {
        let h = LtHash::default();
        assert_eq!(h.params().lanes(), 1024);
        assert_eq!(h.params().lane_bits(), 16);
        assert_eq!(h.serialize().len(), 2048);
        assert!(h.is_identity());
    }

    #[test]
    fn identity_serializes_to_all_zeros() {
        let h = LtHash::default();
        assert!(h.serialize().iter().all(|&b| b == 0));
    }

    #[test]
    fn add_remove_roundtrip() {
        let mut h = LtHash::default();
        h.add_element(b"hello");
        assert!(!h.is_identity());
        h.remove_element(b"hello");
        assert!(h.is_identity());
    }

    #[test]
    fn lane_mask_is_correct_at_the_edges() {
        assert_eq!(LtHashParams::new(1, 1).unwrap().lane_mask(), 1);
        assert_eq!(LtHashParams::new(1, 16).unwrap().lane_mask(), 0xFFFF);
        assert_eq!(LtHashParams::new(1, 63).unwrap().lane_mask(), (1u64 << 63) - 1);
        assert_eq!(LtHashParams::new(1, 64).unwrap().lane_mask(), u64::MAX);
    }

    #[test]
    fn params_are_validated() {
        assert_eq!(LtHashParams::new(0, 16), Err(ParamsError::ZeroLanes));
        assert_eq!(LtHashParams::new(16, 0), Err(ParamsError::LaneBitsOutOfRange(0)));
        assert_eq!(LtHashParams::new(16, 65), Err(ParamsError::LaneBitsOutOfRange(65)));
    }

    #[test]
    fn digest_binds_parameters() {
        // Same (all-zero) serialization length is impossible across these two, but the
        // point stands for the general case: the key differs, so the digest differs.
        let a = LtHash::new(LtHashParams::new(64, 8).unwrap());
        let b = LtHash::new(LtHashParams::new(32, 16).unwrap());
        assert_eq!(a.serialize(), b.serialize()); // both 64 zero bytes
        assert_ne!(a.digest(), b.digest()); // but different domains
    }

    #[test]
    fn deserialize_rejects_wrong_length_and_bad_padding() {
        let params = LtHashParams::new(3, 5).unwrap(); // 15 bits -> 2 bytes, 1 padding bit
        assert_eq!(params.state_bytes(), 2);
        assert_eq!(LtHash::deserialize(params, &[0u8; 3]), Err(DeserializeError::WrongLength { expected: 2, got: 3 }));
        assert_eq!(LtHash::deserialize(params, &[0x00, 0x80]), Err(DeserializeError::NonCanonicalPadding));
        assert!(LtHash::deserialize(params, &[0xFF, 0x7F]).is_ok());
    }
}
