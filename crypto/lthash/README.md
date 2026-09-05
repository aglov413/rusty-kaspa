# kaspa-lthash

A shadow implementation of **LtHash** — a lattice-based homomorphic multiset hash — built to
sit alongside the incumbent MuHash UTXO commitment for comparison.

> ## ⚠️ This is an unaudited experiment
>
> **Nothing here has been reviewed by a cryptographer.** The parameter choice, the security
> level it delivers, and the analysis in `PARAMETER-REVIEW.md` are all unverified.
>
> This crate *is* now wired into consensus as an opt-in **shadow accumulator**: with
> `--shadow-lthash` (devnet only, refuses to start elsewhere) it is computed and persisted
> alongside MuHash. **It is never consulted for any validation decision** —
> `verify_expected_utxo_state` compares MuHash, and only MuHash, against the header's
> `utxo_commitment`. With the flag off, no code path behaves differently. See
> `INTEGRATION.md` for the safety invariants.
>
> Do not use this to validate anything. Do not treat any number in this README as a
> security claim that someone has checked.

---

## Why this exists

The UTXO commitment in a header is produced by MuHash, a multiplicative multiset hash whose
security rests on a problem in a multiplicative group modulo a 3072-bit modulus. Shor's
algorithm solves that problem. If a cryptographically relevant quantum computer ever
arrives, MuHash's binding property goes with it.

LtHash (Lewi, Kim, Maykov, Weis, *"Securing Update Propagation with Homomorphic Hashing"*,
IACR ePrint 2019/227) is the obvious candidate replacement: its security reduces to a short
integer solution (SIS)-flavoured lattice problem, for which no quantum algorithm is known
that does better than generic speedups. It is homomorphic in the same way MuHash is —
elements can be added and removed in any order, and partial accumulators can be merged —
so it is a drop-in *shape*, if not a drop-in implementation.

This crate began as step one: get the construction right, get the element encoding
byte-identical to MuHash's, and pin the algebraic properties down with property tests. It has
since grown a measured performance comparison, real-data validation against 44.7M UTXOs, and
an opt-in shadow integration that has run on a live devnet node. Consensus-rule questions —
whether this should ever *replace* MuHash — remain firmly out of scope and are gated on
`PARAMETER-REVIEW.md`.

---

## Where things are documented

This README is the crate's own reference: the construction in brief, **the benchmarks**, the
real-data and live-devnet results, and how to run the tests. The deeper material lives in three
companion documents, and is deliberately *not* repeated here.

| Document | Owns |
|---|---|
| `PARAMETER-REVIEW.md` | The request for cryptographic review. The construction in full (§2), why `(1024, 16)` (§1, §3), the ~2^128 binding cap and why it was accepted (§5.1), Wagner (§5.2), the UTXO element layout and adversarial freedom per field (§6.1), and the open questions (§7). |
| `INTEGRATION.md` | How the shadow is wired into consensus: safety invariants (§2), the one-source encoding rule (§3), change sites (§4), what the shadow validates (§5), rollout (§7), known risks (§8), and the cross-node gap (§8b). |
| `MUHASH-SURVEY.md` | How MuHash behaves in this codebase today — notably §4c, the reorg/backout path the shadow had to match. |

When a claim here is a summary of one of those, it links to it rather than restating it.


---

## Usage

```rust
use kaspa_lthash::{LtHash, LtHashParams};

let mut acc = LtHash::new(LtHashParams::default());   // (1024, 16); identity = all-zero
acc.add_element(b"utxo-encoding-bytes");
acc.remove_element(b"utxo-encoding-bytes");           // exact inverse, any order

let resumable: Vec<u8> = acc.serialize();             // 2048 bytes — persist THIS
let commitment = acc.digest();                        // 32 bytes — terminal, not resumable
```

Inside consensus the accumulator is never driven directly: `LtHashExtensions` in
`consensus/core/src/lthash.rs` calls `muhash::encode_utxo`, so both accumulators are fed
byte-identical elements by construction. See `INTEGRATION.md` §3.


---
## The construction

A state is a point in the abelian group `(Z_{2^W})^N` — `N` lanes of `W` bits, added
lane-wise with wrapping arithmetic.

| | |
|---|---|
| Default `N` (lanes) | 1024 |
| Default `W` (lane bits) | 16 |
| Default state size | 2048 bytes |
| Digest size | 32 bytes (Blake2b-256) |
| Identity (empty multiset) | all lanes zero |
| `add(x)` | lane-wise wrapping **add** of `H(x)` |
| `remove(x)` | lane-wise wrapping **sub** of `H(x)` |
| union of two states | lane-wise wrapping **add** |

`N` and `W` are runtime parameters (`LtHashParams`), not constants and not const generics —
the whole point is to be able to sweep them. Any `N >= 1` and any `W` in `1..=64` works,
including widths that are not a multiple of 8.


### Element expansion, in brief

```text
seed(x)  = Blake2b-256(key = "LtHashElement:n=<N>,w=<W>", message = x)   -> 256 bits
lanes(x) = canonical_unpack( ChaCha20(key = seed(x), nonce = 0, counter = 0) )
```

This deliberately **mirrors MuHash's own expansion** (`crypto/muhash/src/lib.rs`), which is in
turn the shape Bitcoin Core's MuHash3072 uses — so a migration changes only the group the
accumulator lives in, adds no new primitives, and keeps any divergence attributable to the
algebra rather than the expansion.

`H` factors through a 256-bit intermediate, which **caps binding at ~2^128 regardless of
`N*W`**. That is a deliberate, documented acceptance, not an oversight, and an earlier
cSHAKE256 revision (~2^256, ~4x the cost) was reverted to get here. The full argument, the
Solana precedent, and the counter-arguments are `PARAMETER-REVIEW.md` §5.1 — and whether the
trade is right is its **Q3**, which is not settled.

### Digest

`digest()` is `Blake2b-256` over the canonical little-endian serialization of the state,
keyed with `"LtHashFinalize:n=<N>,w=<W>"`. Because the parameters live in the key, the
*message* really is exactly `serialize()`, and digests taken under different parameters are
incomparable by construction.

**The 2048-byte state cannot be recovered from the 32-byte digest.** This matters more than
it sounds:

- A digest is **not a resumable accumulator**. You cannot load a stored digest, add an
  element, and get the right answer. Anything that keeps accumulating must persist all 2048
  bytes of `serialize()`.
- The homomorphism holds on *states*, not digests. The digest of a union is not any function
  of the digests of the parts.

MuHash draws the same line between `serialize()` (384 bytes, resumable) and `finalize()`
(32 bytes, terminal). LtHash's resumable state is 5.3x larger, which is a real storage
consideration for any future integration: the node currently persists one multiset per chain
block in `utxo_multisets_store`.

---


## Parameters and security — see `PARAMETER-REVIEW.md`

`(1024, 16)` is *selected*, not *justified*. The security level it delivers has not been
checked by a cryptographer, and this README makes no claim about it.

Two things worth knowing before reading any number below:

* **The parameters are set by a classical attack, not a quantum one.** Wagner's generalized
  birthday attack is what constrains `(N, W)`; choosing LtHash buys no margin against it
  whatsoever. The post-quantum motivation concerns Shor against MuHash's group, and is a
  separate axis. `PARAMETER-REVIEW.md` §5.2.
* **Binding is capped at ~2^128** by the 256-bit expansion intermediate, knowingly. §5.1.

The parameter sweep that informed the choice is under "Parameter sweep" below; the reasoning
and the open questions are §1, §3, §5 and §7 of the review packet.


---

## Byte-identical element encoding with MuHash

The load-bearing requirement: both accumulators must hash byte-identical element encodings, or
any later comparison measures the encoding difference instead of the accumulator difference.

`src/encoding.rs` reproduces `consensus/core/src/muhash.rs::write_utxo` exactly. **The field
layout, and how much freedom an adversary has over each field, is `PARAMETER-REVIEW.md` §6.1**;
the architectural rule that keeps there being exactly one implementation inside consensus is
`INTEGRATION.md` §3.

Three traps, each of which produces a plausible-looking but incompatible encoding:

1. **DAA score is written before amount** — the opposite of the `UtxoEntry` struct field order.
2. **Script length is a fixed 8-byte little-endian `u64`**, not a varint.
3. **The domain separator is a Blake2b *key*, not a message prefix.**

Parity was verified empirically rather than by reading — `write_utxo` is private, but its output
is observable through the accumulator — and the resulting digests are frozen as golden vectors
in `tests/muhash_encoding_vectors.rs`, so any future layout change fails loudly. The harness and
re-run instructions are in the appendix of `MUHASH-SURVEY.md`.


---
## Measured performance vs. MuHash

Both crates benched with criterion 0.5.1 under an identical `[profile.release]`
(`lto = "thin"`, `overflow-checks = true`), run back to back on the same idle machine.
Reproduce with `cargo bench -p kaspa-muhash` from the repo root and `cargo bench` here.

| Operation | MuHash | LtHash | |
|---|---:|---:|---|
| `add_element` (100 B input) | 2.68 µs | **1.770 µs** | **1.51x faster** |
| `remove_element` | 2.70 µs | **1.875 µs** | **1.44x faster** |
| `combine` / `union_in_place` | 4.41 µs | **0.172 µs** | **26x faster** |
| `serialize` (populated accumulator) | 25.69 µs | **0.384 µs** | **67x faster** |
| `finalize` / `digest` | 26.24 µs | **2.089 µs** | **13x faster** |
| `add_utxo` (97 B encoding) | — | 1.811 µs | encoding adds ~0.04 µs |
| `clone` | **17.8 ns** | 94.0 ns | 5.3x slower — see note |
| resumable state size | **384 B** | 2048 B | 5.3x larger |

**LtHash is faster than MuHash on every operation except `clone`**, which costs 94 ns.

`clone` is a plain memory copy of the accumulator state. In RAM, LtHash holds
`Vec<u64>` × 1024 = **8192 bytes** — each 16-bit lane occupies a full `u64`, so that `W` can
be any width up to 64 without changing the representation — against MuHash's two `U3072` =
768 bytes. So `clone` copies 10.7x more memory and is only 5.3x slower, memcpy overhead
amortising over the larger block. (The *serialized* sizes are 2048 and 384 bytes; those are
what the store holds.)

It is not on a hot path: the accumulator is cloned once per block template and twice per
pruning-point import, never per element or per transaction. The number worth tracking is not
clone latency but the **8 KB resident footprint per live accumulator** — parallel transaction
validation holds one per rayon task, so a few tens of KB transiently.

MuHash's `serialize`/`finalize` cost is data-dependent — 189 ns on a fresh accumulator,
25.7 µs on one with a populated denominator, because `normalize()` performs a 3072-bit modular
division. The populated case is the one that occurs in the node; that is where the 67x comes
from.

*Measured on an otherwise idle machine. Two internal consistency checks pass: `add_element`
(1.770 µs) agrees within 3% with the `n=1024, w=16` sweep entry (1.825 µs), and the unpack
regression guard agrees within 2% with its reference.*

### Where the per-element cost goes

| Component | Cost |
|---|---:|
| Blake2b-256 seed + ChaCha20 setup | ~0.40 µs |
| ChaCha20 keystream, 2048 B (~1.7 GB/s) | 1.219 µs |
| Unpack keystream into 1024 lanes | 0.420 µs |
| Lane-wise wrapping add | ~0.13 µs |
| **total** | **~1.77 µs** |

Roughly two thirds is keystream. An early revision spent 79% of `add_element` in the *unpack*
instead, doing a runtime-length `copy_from_slice` per lane; specialising `packing.rs` on the
lane width cut that 12.7x. The bench keeps a `chunks_exact` reference beside the crate's path
as a regression guard — they now measure 420 ns and 413 ns respectively.

### Alternatives considered

Every expansion that removes the ~2^128 cap costs materially more, and every *faster* one has
the same cap — structural, since 256-bit collision resistance needs a >= 512-bit internal state
to survive the birthday bound. The measured comparison of all five candidates (`Blake2b-256 ->
ChaCha20`, BLAKE3 XOF, Blake2b-512 counter mode, cSHAKE256, SHAKE128/AES-CTR) is the table in
`PARAMETER-REVIEW.md` §5.1.

Worth noting BLAKE3 measured *slower* than ChaCha20 here — its SIMD advantage needs inputs
larger than 2 KB. Choosing ChaCha20 over BLAKE3 costs nothing in security (identical cap) and
avoids a dependency; the Solana precedent is about the security *level*, not the primitive.

### Illustrative block-level cost

200 transactions, 2 inputs + 2 outputs each (800 element operations), 200 `combine`/`union`
calls from the per-transaction rayon reduce, one finalize:

| | element ops | combines | finalize | total |
|---|---:|---:|---:|---:|
| MuHash | 2144 µs | 882 µs | 26 µs | **3052 µs** |
| LtHash | 1416 µs | 34 µs | 2 µs | **1452 µs** (2.1x faster) |

The `combine` column matters independently: MuHash's combine is two 3072-bit modular
multiplications and costs *more* than an add, so the per-transaction reduce is a real expense
that LtHash almost eliminates.

### Cost in context: what fraction of block validation is this?

Measured on the same machine via `cargo bench -p kaspa-consensus --bench check_scripts`:
**script and signature verification costs 35.9 µs per transaction input** (3.5869 ms for 100
inputs, single-threaded). For a typical 2-input / 2-output transaction:

| Work | Cost |
|---|---:|
| Script + signature verification (2 inputs) | 71.8 µs |
| MuHash multiset (4 element ops @ 2.68 µs) | 10.7 µs |
| **LtHash multiset (4 element ops @ 1.770 µs)** | **7.1 µs** |

| Configuration | Relative validation cost |
|---|---:|
| Signature verification + MuHash (today's baseline) | 100% |
| + LtHash shadow (**both** accumulators — what a shadow run pays) | 109% |
| **LtHash replacing MuHash** | **~96%** |

**Replacing MuHash with LtHash makes validation slightly cheaper**, not more expensive — about
4% on the signature-dominated path, plus 25x on union and 13x on finalize. Running the shadow
costs ~9%, because you pay for both accumulators.

These ratios are invariant to block rate: cost per full block is fixed and blocks/second scale
linearly, so every component scales identically. Adoption is a flat question, not a
throughput-ceiling one, and the answer is the same at 10, 25 or 32 BPS. (The GHOSTDAG-K table
in `consensus/core/src/config/bps.rs` panics above 32 BPS.)

Absolute figures at saturated blocks (500,000 mass at the ~646 mass/tx observed on devnet
≈ 774 tx/block); `max_block_mass` does not scale with BPS:

| BPS | sig verify | + MuHash (baseline) | LtHash replacing MuHash |
|---:|---:|---:|---:|
| 10 | 0.56 cores | 0.64 | **0.61** |
| 25 | 1.39 cores | 1.60 | **1.53** |
| 32 (current ceiling) | 1.78 cores | 2.05 | **1.96** |

Caveats: these are saturated blocks — devnet runs at ~0.2% of block capacity, and cost scales
with actual transactions, not block rate. The 646 mass/tx and 2-in/2-out mix come from
observed devnet traffic. 35.9 µs/input is this machine's secp256k1 speed.

**Storage remains the one real regression** — 2048 vs 384 bytes per retained chain block — and
it does not improve with a faster expansion.

### Parameter sweep

`add_element` by parameter set, measured on an idle machine:

| N | W | state | time |
|---:|---:|---:|---:|
| 512 | 16 | 1024 B | 1.152 µs |
| 1024 | 16 | 2048 B | **1.825 µs** |
| 2048 | 16 | 4096 B | 3.199 µs |
| 4096 | 16 | 8192 B | 6.153 µs |
| 1024 | 32 | 4096 B | 2.812 µs |
| 1024 | 8 | 1024 B | 1.268 µs |

**Cost tracks keystream bytes (`N*W/8`), not lane count.** The two 4096-byte configurations —
`(2048, 16)` and `(1024, 32)` — differ by only 1.14x. Under the earlier cSHAKE256 expansion
they differed by 1.7x, and before the unpack fix by more still, because per-lane work
dominated. The table can now be read as a guide to the cost of a parameter change.

Fitting: roughly **0.35 µs fixed** (Blake2b seed, ChaCha20 setup, allocation) plus
**0.60 ns per keystream byte** (~1.7 GB/s) plus a small per-lane term.

### Storage

+1664 bytes per retained chain block in `utxo_multisets_store` (2048 vs 384). Unlike the CPU
numbers, this one does not go away with better code — but it is bounded, and it is smaller
than the 5.3x multiplier suggests.

`Bps::pruning_depth()` resolves to `BPS * PRUNING_DURATION` (30 h) in both configurations,
that term dominating the merge-depth lower bound:

| | pruning depth | MuHash | LtHash | delta |
|---|---:|---:|---:|---:|
| 1 bps | 108,000 | 41.5 MB | 221 MB | **+180 MB** |
| 10 bps | 1,080,000 | 415 MB | 2.21 GB | **+1.8 GB** |

Bounded by the retention window, so it does not grow with chain length. Three things that
might have made this worse and do not:

* **Nothing goes on the wire.** The header's `utxo_commitment` is a 32-byte digest either
  way, so block size and gossip are unaffected. No MuHash or multiset appears anywhere in
  `protocol/` or `rpc/`; during IBD the receiver *computes* the multiset locally from
  streamed UTXO chunks (`ibd/flow.rs:680`) rather than receiving it. This is purely local
  node state.
* **The cache barely moves.** `DbUtxoMultisetsStore` is built with
  `PolicyBuilder::new().max_items(perf.block_data_cache_size).untracked()` — count-based and
  untracked, so a larger entry silently costs proportionally more RAM. But
  `block_data_cache_size` is 200 x bps-clamped-to-10 = 2000 entries, making the delta ~3 MB.
* **Write volume stays modest.** 5.3x more bytes per chain block through the same
  `WriteBatch`, which at 10 bps is roughly +16 KB/s before RocksDB write amplification.

Because storage is cheap, the *safe* design for a future integration is affordable: persist
the full 2048-byte state per chain block, mirroring MuHash's lifecycle exactly, rather than
any recompute-on-demand or digest-only scheme. See the reorg note in `MUHASH-SURVEY.md` §4c —
the accumulator is never rolled back across a reorg, it is re-read wholesale from the store,
and a shadow implementation that tries to be clever there will drift silently.

---

## Real-data validation

Replayed against a real devnet chain (a copy of `consensus-002` from a stopped node, never
the live datadir), accumulating three hashes in one pass over the pruning-point UTXO set:

| | result |
|---|---|
| UTXOs replayed | **44,663,940** |
| MuHash via consensus `add_utxo` | `8450fbaa…40021e5b` |
| MuHash fed **our** `encode_utxo` bytes | `8450fbaa…40021e5b` |
| Header `utxo_commitment` | `8450fbaa…40021e5b` |
| Harness reproduces consensus | **YES** |
| Our encoding == `write_utxo` | **YES** |
| LtHash digest | `e5c5f370b0fc03a8c4d20cfbf139811fa612f7f737872f55f805373092bc5980` |

The first match proves the harness faithfully reproduces consensus; without it the second
would be meaningless. The second proves the encoding in `src/encoding.rs` is byte-identical
to the private `write_utxo` over 44.7 million real UTXOs rather than five hand-picked vectors.


### ⚠️ What this does NOT establish

The field distribution of this chain is extremely narrow — every script exactly 34 bytes, only
script-public-key version 0, 93.4% coinbase. So the replay adds enormous confidence in **scale**
and none in **field variety**: it never exercises a variable-length script, an empty script, or
a non-zero version.

The frozen vectors cover strictly *more* variety than the real data does (empty script, 600-byte
script, version `0xBEEF`, all-max fields). **The two are complementary and neither supersedes the
other.** The same caveat bears on `PARAMETER-REVIEW.md` §6.1: devnet has no script variety to
observe, so this data neither confirms nor refutes the assumption that an adversary has free
choice of the script field. Mainnet would be the place to check.

### Throughput on real data

The 44.7M-UTXO replay ran three accumulators in one pass (MuHash twice, LtHash once) in
635.8 s = 14.24 µs/UTXO. That run predates the expansion change and used cSHAKE256, so it
corroborates the *encoding* and the *method*, not the current per-element cost. The
superseding measurement is under "Live devnet results" below: **2.45 µs/UTXO** for the current
expansion, measured in-node over 45.6M UTXOs.

For the IBD path — where a syncing node accumulates the whole pruning-point UTXO set before
comparing against the header commitment — the current cost is **~112 s** on top of MuHash's
~120 s, down from ~406 s under cSHAKE256. A one-off during initial sync, not a per-block cost
(`PARAMETER-REVIEW.md` §6.2a).

---

## Live devnet results

A devnet node was synced from scratch with `--shadow-lthash`.

### Pruning-point accumulation — a controlled before/after

The shadow is built by one full pass over the imported pruning-point UTXO set. Two runs
happened to land on the **same pruning point** (`f1500710…bfa64605`) with an **identical UTXO
count**, differing only in the expansion:

| Expansion | Elapsed | Per UTXO |
|---|---:|---:|
| cSHAKE256 | 406.3 s | 8.94 µs |
| **`Blake2b-256 -> ChaCha20`** | **111.9 s** | **2.45 µs** |

Same 45,609,558 UTXOs, same machine, **3.6x faster**. Real-node cost exceeds the 1.77 µs
benchmark by ~0.68 µs, which is RocksDB iteration, entry deserialization and allocation.

For the IBD path specifically — where a syncing node accumulates the whole pruning-point UTXO
set before comparing against the header — this is **+112 s** on top of MuHash's ~120 s, rather
than +406 s.

### Lifecycle: the drift check

The drift check rebuilds LtHash from scratch over the pruning-point UTXO set and compares it
against the value maintained incrementally. It has passed at **every pruning point transition
observed**. The runs below are the ones timed by hand; from 2026-09-03 every transition is
recorded automatically in `shadow-lthash-history.jsonl` beside the database, which is the
complete record:

| Run | Expansion | Pruning point | UTXOs | Rebuild | Result |
|---|---|---|---:|---:|---|
| 1\* | cSHAKE256 | `f1500710…` | 45,609,558 | 395.4 s | **match** |
| 2 | `Blake2b-256 -> ChaCha20` | `5da60587…` | 45,471,168 | 111.6 s | **match** |
| 3 | `Blake2b-256 -> ChaCha20` | `19f30664…` | 45,985,164 | 115.1 s | **match** |
| 4 | `Blake2b-256 -> ChaCha20` | `be39bfa0…` | 46,111,403 | 115.4 s | **match** |
| 5 | `Blake2b-256 -> ChaCha20` | `1785436d…` | 46,271,026 | 118.1 s | **match** |

```
[SHADOW-LTHASH] OK -- the incremental shadow matches a from-scratch rebuild over 45471168
                UTXOs at pruning point 5da60587...b8ce2cbb (digest db08db5e...e001d0bc1)
```

In every case the pruning point had *moved* since the shadow was imported, so the value
checked was accumulated block-by-block through `commit_utxo_state` — not the one written at
import. Zero errors and zero warnings across all runs.

\* Run 1 is the only cSHAKE256 rebuild, and it sits at a different pruning point and UTXO
count from every current-expansion run, so comparing it to them is per-element (8.67 µs/UTXO
against 2.4–2.6 µs/UTXO) rather than controlled. The controlled expansion comparison is the
accumulation pass above, where both expansions ran over the identical set.

Throughput is consistent across every pass under the current expansion: 2.4–2.6 µs/UTXO,
on 45.5–46.9M-element sets.


### What the drift check does and does not prove

It compares two genuinely different **code paths** — incremental accumulation against a single
batch pass — so a missed accumulation site, a wrong reorg restore or a mistimed pruning deletion
would fail it. It cannot pass vacuously: with no stored shadow it logs "nothing to compare yet"
rather than `OK`.

But **both sides are LtHash**. A uniformly wrong implementation — wrong encoding, wrong domain
separator — would be wrong identically on both sides and still pass. MuHash's
`assert_utxo_commitment` is anchored to an *external* reference; this is anchored only to itself.
The external anchor is the encoding work above, not this check.

The two do compose, though: `assert_utxo_commitment` runs immediately before the drift check over
the same UTXO-set iteration (`enable_sanity_checks` is hardcoded true in `kaspad/src/args.rs`), so
MuHash establishes that the set on disk is what the network committed to, and the drift check
establishes that LtHash describes that same set. At run 2's pruning point MuHash's rebuild took
2m34s against LtHash's 1m52s.

### ⚠️ What this does NOT establish

**A reorg count.** Nothing in the node logs a reorg, so no run can report one; an earlier claim of
"zero reorgs" was the absence of an indicator that does not exist, and is withdrawn. The reorg
path is not LtHash-specific — both accumulators travel in one value and are restored by the same
lookup — and the one LtHash-specific failure mode would surface at the next pruning point as a
missing comparison. It has not. Full reasoning in `INTEGRATION.md` §8.

**Cross-node agreement — one data point.** On 2026-09-04 two independently operated nodes produced
byte-identical rows at a shared pruning point (`f1caa6c3dacd…`, 47,496,442 UTXOs, `(1024, 16)`,
`OK` on both). What agreed was two independent *from-scratch rebuilds* over UTXO sets MuHash had
each separately verified. But it is n=1, between instances of a single implementation, both seeded
by the same mechanism, compared by hand. `INTEGRATION.md` §8b has the detail and the limits.

**Parameter security.** Unaddressed here; see `PARAMETER-REVIEW.md`.

**Encoding correctness.** Covered by the 44.7M-UTXO replay and the frozen vectors, not by the
drift check — see the note above on what the drift check can and cannot catch.


---
## Testing

```bash
cargo test -p kaspa-lthash              # 41 tests, ~5s
cargo test -p kaspa-consensus-core --lib muhash   # 3 encoding-parity tests
cargo clippy --all-targets
```

The property tests (`tests/properties.rs`, proptest) are the actual deliverable:

| Property | Test |
|---|---|
| Order independence (adds) | `order_independence`, `order_independence_over_utxos` |
| Order independence (mixed add/remove) | `order_independence_with_removals` |
| Add-then-remove restores prior state | `add_then_remove_returns_to_prior_state` |
| Full teardown returns to identity | `full_teardown_returns_to_identity` |
| Remove-then-add restores prior state | `remove_then_add_returns_to_prior_state` |
| Wrong removals are silent and reversible | `removing_never_added_element_is_silent_and_reversible` |
| Two independent bugs can mask each other | `wrong_removal_and_wrong_addition_cancel` |
| Multiset, not set | `adding_twice_differs_from_adding_once`, `multiplicity_is_exact`, `duplicate_is_not_the_same_as_a_second_distinct_element` |
| Union commutative / associative / neutral / invertible | `union_is_commutative`, `union_is_associative`, `identity_is_neutral_for_union`, `every_state_has_an_inverse` |
| Union == accumulating the concatenation (any partition) | `union_equals_accumulating_the_concatenation`, `union_over_an_arbitrary_partition` |
| Differential vs. naive reference | `differential_against_reference`, `differential_union_against_reference`, `differential_over_utxos` |
| ~1e5 elements | `large_scale_differential_100k`, `large_scale_union_of_partitions_100k` |
| Serialization round-trip, packing-path equivalence, lane reduction, digest determinism | `serialize_roundtrip`, `packing_paths_agree_on_byte_aligned_widths`, `lanes_stay_reduced`, `digest_is_deterministic_and_state_sensitive` |

The reference implementation (`src/reference.rs`) keeps a `BTreeMap<Vec<u8>, i64>` of
element → signed multiplicity and **recomputes the state from scratch** on every query,
accumulating with a single `wrapping_mul` per element where `LtHash` uses repeated
`wrapping_add`. Different code path, same answer. It necessarily shares
`expand_element` — two independent expansions would not agree by construction, so there
would be nothing to compare; the differential tests the accumulator logic, not the
expansion.

The 1e5-element tests would be unusably slow in a pure debug build, so the root manifest
carries scoped `[profile.dev.package]` entries for `kaspa-lthash`, `sha3` and `keccak` —
mirroring what it already does for `kaspa-muhash` and `blake2b_simd`. `debug_assert!` and
overflow checks stay on, which is deliberate: lane arithmetic is explicitly `wrapping_*`, so a
stray non-wrapping operation should still panic.

---

## Non-goals, current

- **No consensus role.** The shadow integration computes and persists LtHash but no
  validation decision reads it; `verify_expected_utxo_state` still compares MuHash alone. It
  is devnet-only and off by default. Replacing MuHash is not on the table and is gated on
  `PARAMETER-REVIEW.md`.
- **No `unsafe`** (`#![forbid(unsafe_code)]`) and **no SIMD.** Correctness first. The one
  place speed was pursued is the width specialisation in `packing.rs`, documented above and
  guarded by a property test; everything else is plain scalar iteration, and the general
  non-byte-aligned bit-packing path is still bit-at-a-time. There is little headroom left in
  this crate's own code — about two thirds of `add_element` is ChaCha20 keystream.
- **No width-specialised lane storage.** Lanes are `Vec<u64>` regardless of `W`, a 4x memory
  overhead at the default `W = 16` (8192 bytes resident against a 2048-byte serialization).
  A `Vec<u16>`/`Vec<u32>` representation would remove it and make `clone` MuHash-competitive,
  at the cost of an enum over widths or const generics — trading the runtime `(N, W)`
  flexibility that exists so a reviewer can sweep parameters. Not worth it while the
  parameters are unsettled and `clone` is off the hot path. See the note on `LtHash::lanes`.
- **No serde/borsh derive.** `serialize`/`deserialize` are canonical and the shadow store
  persists their raw bytes deliberately, so a parameter change surfaces as a visible
  deserialization failure rather than a silent misread. No wire format is proposed.
- **No security proof and no parameter analysis.** Benchmarks and real-data validation now
  exist (see above); cryptographic analysis does not.

## Workspace layout

The crate is a member of the rusty-kaspa workspace (`crypto/lthash` in the root `members`
list). It depends only on `blake2b_simd`, `sha3` and `rand_chacha` — **no dependency on any
consensus crate**, so the dependency edge runs one way: `kaspa-consensus-core` and
`kaspa-consensus` depend on it, never the reverse. That keeps the accumulator independently
testable and reviewable.

Scoped `[profile.dev.package]` entries for `kaspa-lthash`, `sha3` and `keccak` in the root
manifest keep the test suite usable in debug builds, mirroring what the workspace already does
for `kaspa-muhash` and `blake2b_simd`.

## References

- Lewi, Kim, Maykov, Weis. *Securing Update Propagation with Homomorphic Hashing.*
  IACR ePrint 2019/227.
- Wagner. *A Generalized Birthday Problem.* CRYPTO 2002.
- Bertoni et al. and the MuHash lineage: Maitin-Shepard, Tibouchi, Aranha,
  *Elliptic Curve Multiset Hash* (2016), and Bitcoin Core's MuHash3072, which
  `crypto/muhash` follows.