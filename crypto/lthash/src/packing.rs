//! Canonical little-endian packing of an LtHash state into bytes, and its inverse.
//!
//! # Canonical form
//!
//! The state is `N` lanes of `W` bits. The serialization is the concatenation of the lanes
//! in index order, each lane written **least-significant bit first**, packed into a byte
//! stream that is itself filled least-significant bit first. Equivalently: bit `j` of the
//! stream lives in byte `j / 8` at bit position `j % 8`, and lane `i` occupies stream bits
//! `[i*W, (i+1)*W)`.
//!
//! When `W` is a multiple of 8 this is exactly "lane `i` as `W/8` little-endian bytes",
//! which is the familiar case (`W = 16` -> two LE bytes per lane, 2048 bytes total for the
//! default parameters).
//!
//! When `W` is not a multiple of 8 the final byte is zero-padded in its high bits. The
//! padding is always zero, so the encoding stays canonical: one state, one byte string.
//!
//! # Why two code paths
//!
//! [`pack`]/[`unpack`] dispatch to a byte-aligned path when `W % 8 == 0`; otherwise they use
//! the general bit-at-a-time path, which is the literal transcription of the definition
//! above.
//!
//! The byte-aligned path is further specialised on the lane width. This is the one place in
//! the crate where speed was deliberately pursued, and it earned its keep: benchmarking
//! showed the previous generic implementation -- which did a `copy_from_slice` of runtime
//! length per lane, i.e. a `memcpy` call and a bounds check for every two bytes -- was 79%
//! of the total cost of `add_element`, at ~5.8 ns to load two bytes. Specialising the width
//! so each arm copies a compile-time-constant number of bytes made unpacking 11x faster and
//! turned LtHash from ~2.8x slower than MuHash per element into ~1.3x faster. See the
//! benchmark section of `README.md`.
//!
//! It is still plain scalar code: no `unsafe` (the crate forbids it), no SIMD intrinsics, no
//! hand-rolled unrolling. The whole change is letting the compiler see a constant width.
//!
//! Correctness is protected by `packing_paths_agree_on_byte_aligned_widths` in
//! `tests/properties.rs`, which checks the aligned path against an *independent*
//! transcription of the general bit-level definition, for every byte-aligned width. That
//! test is the reason this specialisation is safe to make.

use crate::params::LtHashParams;

/// Serializes `lanes` into the canonical byte string described in the module docs.
///
/// # Panics
/// If `lanes.len() != params.lanes()`.
pub fn pack(params: &LtHashParams, lanes: &[u64]) -> Vec<u8> {
    assert_eq!(lanes.len(), params.lanes(), "lane count does not match params");
    let mut out = vec![0u8; params.state_bytes()];
    if params.is_byte_aligned() {
        pack_byte_aligned(params, lanes, &mut out);
    } else {
        pack_bitwise(params, lanes, &mut out);
    }
    out
}

/// Inverse of [`pack`]. Returns `None` if `bytes` is not exactly `params.state_bytes()`
/// long, or if a padding bit in the final byte is set (non-canonical input).
pub fn unpack(params: &LtHashParams, bytes: &[u8]) -> Option<Vec<u64>> {
    if bytes.len() != params.state_bytes() {
        return None;
    }
    // Reject non-canonical encodings: any bit beyond `N*W` must be zero.
    let pad_bits = params.state_bytes() * 8 - params.state_bits();
    if pad_bits > 0 {
        let last = *bytes.last().expect("state_bytes >= 1 since lanes >= 1 and lane_bits >= 1");
        if (last >> (8 - pad_bits)) != 0 {
            return None;
        }
    }
    Some(unpack_lossy(params, bytes))
}

/// Like [`unpack`] but tolerant: takes whatever bits are present and ignores the rest.
///
/// This is what the element expansion uses -- it is fed raw keystream, whose padding bits
/// are of course not zero, and it simply drops them.
///
/// # Panics
/// If `bytes.len() < params.state_bytes()`.
pub fn unpack_lossy(params: &LtHashParams, bytes: &[u8]) -> Vec<u64> {
    assert!(bytes.len() >= params.state_bytes(), "not enough bytes to fill the state");
    if params.is_byte_aligned() { unpack_byte_aligned(params, bytes) } else { unpack_bitwise(params, bytes) }
}

// -------------------------------------------------------------------------------------
// General bit-level path (any W in 1..=64)
// -------------------------------------------------------------------------------------

pub(crate) fn pack_bitwise(params: &LtHashParams, lanes: &[u64], out: &mut [u8]) {
    let w = params.lane_bits() as usize;
    let mut bit = 0usize;
    for &lane in lanes {
        for k in 0..w {
            if (lane >> k) & 1 == 1 {
                out[(bit + k) / 8] |= 1u8 << ((bit + k) % 8);
            }
        }
        bit += w;
    }
}

pub(crate) fn unpack_bitwise(params: &LtHashParams, bytes: &[u8]) -> Vec<u64> {
    let w = params.lane_bits() as usize;
    let mut lanes = Vec::with_capacity(params.lanes());
    let mut bit = 0usize;
    for _ in 0..params.lanes() {
        let mut lane = 0u64;
        for k in 0..w {
            let idx = bit + k;
            if (bytes[idx / 8] >> (idx % 8)) & 1 == 1 {
                lane |= 1u64 << k;
            }
        }
        lanes.push(lane);
        bit += w;
    }
    lanes
}

// -------------------------------------------------------------------------------------
// Byte-aligned path (W in {8, 16, 24, 32, 40, 48, 56, 64})
// -------------------------------------------------------------------------------------

/// Writes `lanes` into `out` as `W/8` little-endian bytes each.
///
/// `out` is exactly `lanes.len() * width` bytes, so `chunks_exact_mut(width)` yields exactly
/// one chunk per lane. The `match` exists so that each arm copies a constant number of
/// bytes; a single generic arm compiles to a `memcpy` call per lane and is an order of
/// magnitude slower.
pub(crate) fn pack_byte_aligned(params: &LtHashParams, lanes: &[u64], out: &mut [u8]) {
    let width = (params.lane_bits() / 8) as usize;
    match width {
        1 => {
            for (dst, &lane) in out.iter_mut().zip(lanes) {
                *dst = lane as u8;
            }
        }
        2 => {
            for (dst, &lane) in out.chunks_exact_mut(2).zip(lanes) {
                dst.copy_from_slice(&(lane as u16).to_le_bytes());
            }
        }
        4 => {
            for (dst, &lane) in out.chunks_exact_mut(4).zip(lanes) {
                dst.copy_from_slice(&(lane as u32).to_le_bytes());
            }
        }
        8 => {
            for (dst, &lane) in out.chunks_exact_mut(8).zip(lanes) {
                dst.copy_from_slice(&lane.to_le_bytes());
            }
        }
        // W in {24, 40, 48, 56}. Byte-at-a-time rather than a runtime-length copy.
        w => {
            for (dst, &lane) in out.chunks_exact_mut(w).zip(lanes) {
                for (k, byte) in dst.iter_mut().enumerate() {
                    *byte = (lane >> (8 * k)) as u8;
                }
            }
        }
    }
}

/// Reads `params.lanes()` lanes of `W/8` little-endian bytes each from the front of `bytes`.
///
/// `bytes` may be longer than the state (see [`unpack_lossy`]), so it is truncated to
/// `state_bytes` first; for a byte-aligned width that is exactly `lanes * width`.
pub(crate) fn unpack_byte_aligned(params: &LtHashParams, bytes: &[u8]) -> Vec<u64> {
    let width = (params.lane_bits() / 8) as usize;
    let bytes = &bytes[..params.state_bytes()];
    match width {
        1 => bytes.iter().map(|&b| b as u64).collect(),
        2 => bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]]) as u64).collect(),
        4 => bytes.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]) as u64).collect(),
        8 => bytes.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().expect("chunks_exact(8) yields 8 bytes"))).collect(),
        // W in {24, 40, 48, 56}.
        w => bytes.chunks_exact(w).map(|c| c.iter().enumerate().fold(0u64, |acc, (k, &b)| acc | ((b as u64) << (8 * k)))).collect(),
    }
}
