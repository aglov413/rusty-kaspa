//! Frozen witnesses pinning the element-expansion construction.
//!
//! The expansion is deliberately specified, not merely implemented:
//!
//! ```text
//! s        = Blake2b-512(key = "LtHashElement:b2c2:n=<N>,w=<W>", message = x)   64 bytes
//! lanes(x) = unpack( ChaCha20(key = s[0..32],  nonce = "LtHashLane\x00\x00") -> first half
//!                 || ChaCha20(key = s[32..64], nonce = "LtHashLane\x00\x01") -> second half )
//! ```
//!
//! Every property and differential test in this crate would still pass if the domain string,
//! the digest length, the split point, the nonces, or the L/R key assignment changed -- they
//! check internal consistency, and a wrong construction is internally consistent. These
//! vectors are what make the construction a specification rather than whatever the code
//! currently happens to do.
//!
//! A failure here is not necessarily a bug. It means the construction changed, which is a
//! consensus-visible event: every stored shadow value and every cross-node comparison made
//! under the old construction is invalidated. Update these vectors only alongside a
//! deliberate decision to do that, and bump the `b2c2` tag in the domain string so old and
//! new values stay structurally distinguishable.

use kaspa_lthash::{LtHashParams, expand};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The standard witness input: 100 bytes 0x00..0x63, matching the bench element size.
fn witness() -> Vec<u8> {
    (0..100u8).collect()
}

#[test]
fn element_digest_is_frozen() {
    let d = expand::element_digest(&LtHashParams::default(), &witness());
    assert_eq!(d.len(), 64, "the digest must be the full Blake2b-512 output, never truncated");
    assert_eq!(
        hex(&d),
        "2ce75cc3878df88e63a847b98ac1d93057b63e0df0bcf21be61b8830e1b2e8d7\
         a506f00a797e6c1f3a6b6ce4d1bf8ff1d0ccd103789f27b58dcab06089d25519",
        "element digest changed: domain string, digest length, or keying mode differs"
    );
}

#[test]
fn element_keystream_is_frozen() {
    let params = LtHashParams::default();
    let ks = expand::element_keystream(&params, &witness());
    assert_eq!(ks.len(), params.state_bytes());
    assert_eq!(ks.len(), 2048);

    // Start of the left stream: pins s[0..32] as the left key and NONCE_L.
    assert_eq!(
        hex(&ks[..32]),
        "558ab7dddf9424ebb68a0bbf30d8b16b16be2fa4c32403c0c43a4069427bc001",
        "left ChaCha20 stream changed: left key half, nonce, or counter start differs"
    );

    // Start of the right stream, at the midpoint: pins the split point at state_bytes()/2,
    // s[32..64] as the right key, and NONCE_R. A single-key construction, a swapped L/R
    // assignment, or a shared nonce all fail here.
    assert_eq!(
        hex(&ks[1024..1056]),
        "34a3a3dabaddb52cabe31a996a5694ec719ef9bb41ef3d2ad49deb9e67ba6c5a",
        "right ChaCha20 stream changed: split point, right key half, or nonce differs"
    );

    assert_eq!(
        hex(&ks[2016..]),
        "f7f5ad9f34c9328e40ce809fcd2789451c7f1e313c4d8af52900ed4788707cf1",
        "end of the right stream changed"
    );
}

/// The two halves must come from different keys. If both instances were keyed on the same
/// 32 bytes, the halves would be identical wherever their counters align -- which is exactly
/// the "one key, two counters" mistake that leaves binding at 2^128.
#[test]
fn the_two_halves_are_independently_keyed() {
    let params = LtHashParams::default();
    let ks = expand::element_keystream(&params, &witness());
    let (left, right) = ks.split_at(params.state_bytes() / 2);
    assert_ne!(left, right, "halves are identical: both instances appear to share a key and nonce");
    assert_ne!(&left[..32], &right[..32], "halves start identically: the key split is not in effect");
}

/// The digest must be exactly `Blake2b-512(key = "LtHashElement:b2c2:n=1024,w=16", msg = x)`,
/// recomputed here from a hardcoded domain rather than from the crate's own constants.
///
/// This pins the domain string, the keying mode (key, not prefix) and the 64-byte output
/// together, through the public API. The earlier version of this test compared
/// `format!("...{CONSTRUCTION}...")` against a literal, which asserted only that
/// `CONSTRUCTION == "b2c2"` and would have passed through any change to `element_domain`'s
/// format. `element_domain` itself is `pub(crate)`; the unit test beside it in `expand.rs`
/// checks the bytes directly.
#[test]
fn digest_matches_an_independently_keyed_blake2b_512() {
    use blake2b_simd::Params;
    let data = witness();
    let independent = Params::new().hash_length(64).key(b"LtHashElement:b2c2:n=1024,w=16").to_state().update(&data).finalize();
    assert_eq!(
        hex(expand::element_digest(&LtHashParams::default(), &data).as_slice()),
        hex(independent.as_bytes()),
        "element_digest no longer matches a Blake2b-512 keyed with the frozen domain string"
    );
    assert_eq!(expand::CONSTRUCTION, "b2c2", "construction tag changed");
}
