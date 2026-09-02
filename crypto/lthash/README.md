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

### Element expansion

```text
seed(x)  = Blake2b-256(key = "LtHashElement:n=<N>,w=<W>", message = x)   -> 256 bits
lanes(x) = canonical_unpack( ChaCha20(key = seed(x), nonce = 0, counter = 0)
                             read for ceil(N*W/8) bytes )
```

**The same shape the incumbent MuHash uses** (`crypto/muhash/src/lib.rs::data_to_element`:
Blake2b-256 keyed `b"MuHashElement"`, then `ChaCha20Rng::from_seed`), which is in turn the
shape Bitcoin Core's MuHash3072 uses. Three reasons:

1. **A minimal-diff migration.** If LtHash replaces MuHash, element hashing is unchanged and
   *only the group the accumulator lives in* changes — far easier to review than a change to
   two things at once.
2. **No new primitives.** `blake2b_simd` and `rand_chacha` are already in this repository.
3. **Comparability.** Holding the hash-to-element step constant means an observed divergence
   between the accumulators is attributable to the algebra, not the expansion.

#### The 256-bit intermediate, stated plainly

`H` factors through a 256-bit value, so **any Blake2b-256 collision is immediately an LtHash
collision** — binding is capped at ~2^128 regardless of how large `N*W` is. That admits a
*targeted* attack on a published commitment: find a colliding pair offline for ~2^128, publish
one ordinary transaction creating one of them as a UTXO, then substitute the other with the
accumulator state, and so the header commitment, bit-for-bit unchanged.

**This is a deliberate, documented acceptance of ~128-bit classical binding**, on four grounds:

* 128 bits is where the rest of the stack already sits — secp256k1 is ~128-bit, Blake2b-256
  collision resistance is ~2^128. A 256-bit-binding commitment guarded by 128-bit signatures
  buys nothing that can be spent.
* **Solana ships this security level for this construction at these parameters.** Their
  Accounts Lattice Hash (SIMD-0215) is LtHash at `N = 1024`, `W = 16` — identical to ours —
  expanded with the BLAKE3 XOF, whose 256-bit chaining value imposes the same cap. The
  proposal states 128-bit as the design target. *Caveat: the SIMD cites Wagner in its
  bibliography but presents no analysis of it. Precedent, not proof.*
* **The cap does not undermine the post-quantum rationale.** That rationale is that Shor
  solves MuHash's group problem in *polynomial* time. The best known quantum attack here is
  generic collision search — ~2^85 under BHT assuming quantum RAM nobody knows how to build,
  plausibly no better than classical in practice. The cap lowers the ceiling; it does not
  restore a catastrophic failure mode.
* **The alternative costs ~4x.** A 2048-byte expansion is 1.26 µs this way against 6.62 µs
  with cSHAKE256 — the difference between LtHash being 1.4x *faster* than MuHash per element
  and 2.7x slower.

An earlier revision used cSHAKE256 applied directly to the element (~2^256 binding, no
intermediate). It is preserved in git history and remains the conservative option.
**Whether this trade is right is `PARAMETER-REVIEW.md` Q3, and it is not settled.**

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

## Parameter choice: (1024, 16) selected — security level still pending review

`N = 1024`, `W = 16` is **the selected parameterisation**, and the choice is deliberate
rather than inherited-by-default.

**Rationale.** It is the only LtHash parameter set that has actually been studied — it is
what Lewi et al. analyse. Any smaller set would be novel parameters requiring their own
cryptographic analysis, which is precisely the expensive thing a shrink was supposed to
avoid. The storage saving available from shrinking (see `PARAMETER-REVIEW.md` §5.1, roughly
1.7 GB at 10 bps) is not worth moving off analysed ground. Over-provisioning is accepted
knowingly, including in the presence of the seed-collision cap described below.

**What is settled:** the choice of `(N, W)`. It is not an open question and should not be
relitigated on storage grounds.

**What is NOT settled, and still needs a cryptographer:** the security level those
parameters actually deliver under this deployment's threat model. Specifically:

- Is 16384 bits of state adequate against Wagner's generalized birthday attack for a
  commitment that must remain binding for the lifetime of the chain? Published estimates
  (~200 bits) and this repo's own naive k-tree model (~255 bits) disagree by ~55 bits and
  the discrepancy is unexplained.
- Was replacing the expansion the right call? The original `Blake2b-256 -> ChaCha20` shape
  caps binding at ~2^128 independently of `(N, W)`. We accept that knowingly — see the
  expansion section above and `PARAMETER-REVIEW.md` §5.1 — for reasons including that Solana
  ships the same level for the same construction. cSHAKE256 removes the cap at ~4x the cost.
  Whether the acceptance is right is Q3.
- Does lattice reduction on the corresponding SIS instance beat the k-tree attack here?

`PARAMETER-REVIEW.md` is the review request covering exactly these. Do not resolve them by
reading this README.

---

## ⚠️ Security rests on resistance to Wagner's generalized birthday attack — a *classical* attack

The motivation for LtHash is post-quantum safety, but **the attack that actually determines
the parameters is classical**. This is the single most important thing to understand about
the scheme, and it is easy to get backwards.

Finding a collision means finding a set of elements whose expansions sum to zero lane-wise
modulo `2^W` — a `k`-sum problem over `(Z_{2^W})^N`. The best known generic attack is
**Wagner's generalized birthday attack** (*"A Generalized Birthday Problem"*, CRYPTO 2002)
and its refinements. Wagner's algorithm trades more list entries for less work: allowing the
adversary to combine `k = 2^t` elements instead of 2 reduces the cost from the naive
birthday bound to roughly `2^(b / (1 + t))` for a `b`-bit target, at the cost of holding
lists of that size.

Three consequences worth being explicit about:

1. **Wagner runs on a classical computer.** Choosing LtHash over MuHash buys resistance to
   Shor. It does not buy any margin against Wagner. The parameters must be large enough to
   defeat Wagner *before* quantum computers enter the discussion at all.
2. **`N*W` bits of state does not mean `N*W` bits of security, or even `N*W/2`.** Wagner's
   attack is precisely the reason the state has to be kilobytes rather than tens of bytes.
   Lewi et al. quote roughly 200 bits of classical security for `(1024, 16)`; that figure is
   *quoted here, not independently verified*, and it is exactly the kind of number that
   should be re-derived under review rather than inherited.
3. **Quantum variants of Wagner exist** and give a modest further speedup over the classical
   version. "Post-quantum" here means "no known catastrophic quantum break", not "quantum
   attacks are irrelevant".

There is a second, more mundane property to keep in view: **removals fail silently**. There
is no membership test. Removing an element that was never added is not an error — it
produces a well-formed state that simply corresponds to a different multiset than intended,
and it will keep producing well-formed states forever afterwards. The first symptom is a
commitment mismatch at some unrelated later point, with nothing pointing at where the drift
started. That is inherent to any group-based multiset hash, MuHash included, and it is
documented by the `removing_never_added_element_is_silent_and_reversible` property test
rather than defended against.

---

## Byte-identical element encoding with MuHash

This is the load-bearing requirement. Both accumulators must hash byte-identical element
encodings, or a later comparison measures the encoding difference instead of the accumulator
difference.

`src/encoding.rs` reproduces `consensus/core/src/muhash.rs::write_utxo` exactly:

```text
offset  size  field                             encoding
------  ----  --------------------------------  --------------------------------
0       32    outpoint.transaction_id           raw 32 bytes
32      4     outpoint.index                    u32 little-endian
36      8     entry.block_daa_score             u64 little-endian
44      8     entry.amount                      u64 little-endian
52      1     entry.is_coinbase                 0x01 / 0x00
53      2     script_public_key.version         u16 little-endian
55      8     script_public_key.script().len()  u64 little-endian
63      L     script_public_key.script()        raw bytes
------  ----
total = 63 + L
```

Three traps, all of which produce a plausible-looking but incompatible encoding:

1. **DAA score is written before amount** — the opposite of the `UtxoEntry` struct's field
   order.
2. **The script length is a fixed 8-byte little-endian `u64`**, not a varint.
3. **The domain separator is a Blake2b *key*, not a message prefix.**

Equality with the consensus implementation was verified empirically, not just by reading:
`write_utxo` is private, but its output is observable through the accumulator, so a
throwaway harness checked that

```text
MuHash::new().add_utxo(op, entry).finalize()
  == MuHash::new().add_element(encode_utxo(op, entry)).finalize()
```

for a range of cases including all-zero, all-max, and long-script UTXOs. It reported
`ALL_MATCH=true`. The harness source and instructions for re-running it are in the appendix
of `MUHASH-SURVEY.md`. The resulting digests are frozen as golden vectors in
`tests/muhash_encoding_vectors.rs`, so any future change to the layout fails loudly.

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
the same cap. That is structural: 256-bit collision resistance requires a >= 512-bit internal
state to survive the birthday bound, and carrying that state is the cost.

| Candidate | 2048-byte expansion | Binding | Verdict |
|---|---:|---|---|
| **`Blake2b-256 -> ChaCha20`** | **1.26 µs** | ~2^128 | **chosen** — mirrors MuHash, no new dependency |
| BLAKE3 XOF (Solana's choice) | 1.69 µs | ~2^128 | same cap, slower here, adds a dependency |
| Blake2b-512 counter mode (Blake2X-style) | 3.78 µs | ~2^256 | rejected: needs a length prefix to disambiguate `data \|\| counter`, the kind of encoding hazard a standardised XOF removes |
| cSHAKE256 | 6.62 µs | ~2^256 | the conservative option, ~4x the cost; used in an earlier revision, preserved in git history |
| SHAKE128 / AES-CTR | — | ~2^128 | 256-bit capacity / key gives the same cap as the chosen option, with no advantage |

Note BLAKE3 measured *slower* than ChaCha20 here — its SIMD advantage needs inputs larger than
2 KB to show. Choosing ChaCha20 over BLAKE3 costs nothing in security (identical cap) and
avoids adding a dependency; the Solana precedent is about the security *level*, not the
specific primitive.

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

The field distribution of this chain is extremely narrow:

| field | observed |
|---|---|
| script length | min 34 / mean 34.0 / **max 34** — every script identical in length |
| SPK version | `{0: 44663940}` — only version 0 |
| coinbase | 93.37% |

So the replay adds enormous confidence in **scale and volume** and none at all in **field
variety**. It never exercises a variable-length script, so the 8-byte `write_var_bytes`
length prefix is only ever observed encoding the value 34; it never exercises an empty
script, a large script, or a non-zero script-public-key version.

The frozen vectors in `tests/muhash_encoding_vectors.rs` cover strictly *more* field variety
than this real data does — empty script, 600-byte script, version `0xBEEF`, all-max fields.
**The two are complementary and neither supersedes the other.** A claim that the encoding is
validated across "the real distribution" would be wrong; it is validated across a real
distribution that happens to be nearly uniform.

The same caveat applies to `PARAMETER-REVIEW.md` §6.1: this data neither confirms nor refutes
the assumption that an adversary has effectively free choice of the script field. Devnet
simply has no script variety to observe. Mainnet would be the place to check that.

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
against the value maintained incrementally. It has now passed five times, at five different
pruning points:

| Run | Expansion | Pruning point | UTXOs | Rebuild | Result |
|---|---|---|---:|---:|---|
| 1 | cSHAKE256 | `f1500710…` | 45,609,558 | 395.4 s | **match** |
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

Throughput is consistent across every pass under the current expansion: 2.45–2.55 µs/UTXO,
on 45.5–46.3M-element sets.

### What the drift check does and does not prove

Worth being precise, because it is weaker evidence than MuHash's equivalent.

It compares two genuinely different **code paths** — incremental accumulation versus a single
batch pass — so a missed accumulation site, a wrong reorg restore, or a mistimed pruning
deletion would fail it. It cannot pass vacuously either: with no stored shadow it logs
"nothing to compare yet" rather than `OK`.

But both sides are LtHash. **If the implementation were uniformly wrong — wrong encoding,
wrong domain separator — both sides would be wrong identically and the check would still
pass.** MuHash's `assert_utxo_commitment` is anchored to an *external* reference (a header
other nodes produced); ours is anchored only to itself.

What supplies the external anchor is the encoding work, not the drift check: the frozen
vectors and the 44.7M-UTXO replay, where MuHash driven by *our* bytes reproduced a real
header's `utxo_commitment`.

Note also that `assert_utxo_commitment` runs immediately before the drift check over the same
UTXO-set iteration (`enable_sanity_checks` is hardcoded true in `kaspad/src/args.rs`). The two
compose: MuHash establishes that the set on disk is what the network committed to, and the
drift check establishes that LtHash describes that same set. Observed at run 2's pruning
point, MuHash's rebuild took 2m34s against LtHash's 1m52s.

### ⚠️ What this does NOT establish

**Reorg survival.** Zero reorgs occurred in any of three multi-hour runs — no chain
disqualifications, no finality violations, across roughly 2.7 million cumulative chain-block
commits. The rollback path is the single most likely source of drift (`MUHASH-SURVEY.md` §4c:
the accumulator is never rolled back, it is re-read wholesale from its store) and it remains
unexercised. Devnet at 10 bps with few peers does not appear to produce competing chains on
its own; deliberately forcing a reorg would be more reliable than waiting.

**Cross-node agreement.** Nothing verifies that a *different* node computes the same LtHash,
because no header carries one — each node only checks itself. Closing this needs visibility,
not consensus: exposing the shadow digest over RPC and comparing across operators would
establish it with no header change and no fork. See `INTEGRATION.md` §4b.

**Parameter security.** Unaddressed here; see `PARAMETER-REVIEW.md`.

**Encoding correctness.** Covered by the 44.7M-UTXO replay and the frozen vectors, not by the
drift check — see the note above on what the drift check can and cannot catch.

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
