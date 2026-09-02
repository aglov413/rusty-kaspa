//! Parameters of an [`LtHash`](crate::LtHash) instance.
//!
//! `N` (lane count) and `W` (lane width in bits) are deliberately *runtime* values rather
//! than constants or const-generic parameters. The whole point of this crate is to let a
//! cryptographic reviewer sweep the parameter space, and the parameter choice is
//! **unresolved** -- see the README.

use core::fmt;

/// Default lane count. 1024 lanes x 16 bits = 2048 bytes of state.
///
/// This matches the parameterisation most commonly quoted for LtHash (Lewi, Kim,
/// Maykov, Weis, *"Securing Update Propagation with Homomorphic Hashing"*). It is a
/// starting point for experiments, **not** a vetted choice for this codebase.
pub const DEFAULT_LANES: usize = 1024;

/// Default lane width in bits.
pub const DEFAULT_LANE_BITS: u32 = 16;

/// Maximum supported lane width. Lanes are held in a `u64`, so 64 bits is the ceiling.
pub const MAX_LANE_BITS: u32 = 64;

/// Why a set of parameters was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParamsError {
    /// `lanes` must be at least 1.
    ZeroLanes,
    /// `lane_bits` must be in `1..=64`.
    LaneBitsOutOfRange(u32),
    /// `lanes * lane_bits` overflowed `usize`.
    StateTooLarge { lanes: usize, lane_bits: u32 },
}

impl fmt::Display for ParamsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParamsError::ZeroLanes => write!(f, "lane count must be >= 1"),
            ParamsError::LaneBitsOutOfRange(w) => write!(f, "lane width must be in 1..={MAX_LANE_BITS}, got {w}"),
            ParamsError::StateTooLarge { lanes, lane_bits } => {
                write!(f, "state size {lanes} lanes x {lane_bits} bits overflows usize")
            }
        }
    }
}

impl std::error::Error for ParamsError {}

/// The `(N, W)` pair describing an LtHash state: `N` lanes of `W` bits each.
///
/// Lane arithmetic is wrapping modulo `2^W`, so the state is the abelian group
/// `(Z_{2^W})^N` written additively. Everything else in this crate is a consequence of
/// that one fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LtHashParams {
    lanes: usize,
    lane_bits: u32,
}

impl LtHashParams {
    /// Constructs a parameter set, validating it.
    pub const fn new(lanes: usize, lane_bits: u32) -> Result<Self, ParamsError> {
        if lanes == 0 {
            return Err(ParamsError::ZeroLanes);
        }
        if lane_bits == 0 || lane_bits > MAX_LANE_BITS {
            return Err(ParamsError::LaneBitsOutOfRange(lane_bits));
        }
        // `lanes * lane_bits` is used as a bit count; make sure it is representable.
        if lanes > usize::MAX / (lane_bits as usize) {
            return Err(ParamsError::StateTooLarge { lanes, lane_bits });
        }
        Ok(Self { lanes, lane_bits })
    }

    /// Number of lanes, `N`.
    #[inline]
    pub const fn lanes(&self) -> usize {
        self.lanes
    }

    /// Lane width in bits, `W`.
    #[inline]
    pub const fn lane_bits(&self) -> u32 {
        self.lane_bits
    }

    /// Mask selecting the low `W` bits of a `u64`.
    ///
    /// Written as a shift on `u128` to stay correct at `W == 64`, where `1u64 << 64` would
    /// be UB-adjacent (a debug-mode panic / release-mode nonsense).
    #[inline]
    pub const fn lane_mask(&self) -> u64 {
        (((1u128) << self.lane_bits) - 1) as u64
    }

    /// Total number of state bits, `N * W`.
    #[inline]
    pub const fn state_bits(&self) -> usize {
        self.lanes * (self.lane_bits as usize)
    }

    /// Size of the canonical serialization in bytes, `ceil(N * W / 8)`.
    ///
    /// For the default parameters this is exactly 2048.
    #[inline]
    pub const fn state_bytes(&self) -> usize {
        self.state_bits().div_ceil(8)
    }

    /// True when `W` is a whole number of bytes, in which case the canonical
    /// serialization degenerates to "each lane as `W/8` little-endian bytes".
    #[inline]
    pub const fn is_byte_aligned(&self) -> bool {
        self.lane_bits.is_multiple_of(8)
    }
}

impl Default for LtHashParams {
    /// `N = 1024`, `W = 16` -- a 2048-byte state.
    fn default() -> Self {
        // Unwrap-free: these constants are known-valid.
        match Self::new(DEFAULT_LANES, DEFAULT_LANE_BITS) {
            Ok(p) => p,
            Err(_) => unreachable!(),
        }
    }
}

impl fmt::Display for LtHashParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "n={},w={}", self.lanes, self.lane_bits)
    }
}
