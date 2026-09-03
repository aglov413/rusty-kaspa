# LtHash parameter review — request for cryptographic review

**Status:** unreviewed. Nothing in this document has been checked by a cryptographer, and
that is what we are asking for. The implementation it describes is a shadow experiment; it
is wired into consensus only as an opt-in, devnet-only **shadow**: it is computed and
persisted alongside MuHash, and no validation path reads it.

**Prepared by:** the engineering work in `crypto/lthash/` (rusty-kaspa, DagKnight branch).
**Audience:** a cryptographer able to adjudicate generalized-birthday and lattice arguments.

---

## 1. The question, in one paragraph

We are evaluating LtHash as a post-quantum-safe replacement for MuHash as the UTXO set
commitment. The engineering case is settled — the implementation is correct, its element
encoding is byte-identical to MuHash's (verified against 44.7M real UTXOs), and its cost is
measured: **1.5x faster** than MuHash per element, 26x faster on union and 13x on finalize,
at ~96% of today's validation CPU if it replaces MuHash.
What is not settled is the parameter choice. We currently use `N = 1024` lanes of `W = 16`
bits (a 2048-byte state) because that is what Lewi et al. analyse, **not** because anyone
has derived it for this deployment. **We have selected `(1024, 16)` and that choice is not open.** The
reasoning is that it is the only LtHash parameter set anyone has analysed; any smaller set
would be novel parameters needing their own review, which is exactly the cost a shrink was
meant to avoid. We accept the resulting over-provisioning knowingly, including in light of
§5.1. Please do not spend review effort arguing us down to a smaller state.

What we need is (a) the actual classical security level of `(1024, 16)` against Wagner's
generalized birthday attack under our threat model, and (b) given that `(N, W)` is fixed,
whether the ~128-bit seed cap in §5.1 is real and what the right response to it is.

---

## 2. The construction, exactly as implemented

State is a point in the abelian group `(Z_{2^W})^N`, written additively.

```text
domain_e = "LtHashElement:n=<N>,w=<W>"        (Blake2b KEY)
domain_f = "LtHashFinalize:n=<N>,w=<W>"        (Blake2b KEY)

seed(x)  = Blake2b-256(key = domain_e, msg = x)          -> 256 bits
H(x)     = unpack( ChaCha20(key = seed(x), nonce = 0, counter = 0)
                   read for ceil(N*W/8) bytes )
           -> a vector in (Z_{2^W})^N, lanes little-endian, LSB-first
           NOTE: H factors through a 256-bit intermediate. That caps binding
                 at ~2^128 independently of (N, W). Knowingly accepted -- §5.1.

state(M) = SUM over x in M of  mult_M(x) * H(x)          lane-wise, mod 2^W
identity = all-zero vector
add(x)   = state += H(x)        remove(x) = state -= H(x)
union    = lane-wise addition
digest   = Blake2b-256(key = domain_f, msg = canonical_LE_serialization(state))
```

Defaults: `N = 1024`, `W = 16`, so the state is 16384 bits = 2048 bytes, and the digest is
32 bytes. `N` and `W` are runtime parameters; any `N >= 1` and `W` in `1..=64` is supported,
so a re-parameterisation is a config change, not a rewrite.

The expansion **deliberately mirrors MuHash's own** (`crypto/muhash/src/lib.rs`: Blake2b-256
keyed `b"MuHashElement"`, then `ChaCha20Rng::from_seed` filling 384 bytes -- itself the shape
Bitcoin Core's MuHash3072 uses). Three reasons:

1. **A minimal-diff migration.** If LtHash replaces MuHash, element hashing is unchanged and
   *only the group the accumulator lives in* changes -- a far easier proposition to review.
2. **No new primitives.** `blake2b_simd` and `rand_chacha` are already in this repository.
3. **Comparability.** Holding the hash-to-element step constant means any divergence between
   the two accumulators is attributable to the algebra, not the expansion.

The element encoding -- the exact bytes fed to `H` -- is byte-identical to MuHash's; see §6.1.

**An earlier revision used cSHAKE256 applied directly to the element**, removing the 256-bit
intermediate and attaining ~2^256 binding. We reverted it. That decision, and the reasoning,
is §5.1 and **Q3**. The cSHAKE256 implementation is preserved in git history.

---

## 3. The security property required

**Binding.** It must be infeasible to find two distinct multisets `M != M'` over the element
space with `state(M) = state(M')`.

By the group structure this is equivalent to finding distinct elements `x_1..x_k` and
integers `c_1..c_k`, not all zero, with

```text
SUM_i  c_i * H(x_i)  ==  0   (mod 2^W, in every one of the N lanes)
```

subject to the multiset-difference being realizable (see §6.1 on what an element may be).
This is a **k-sum / generalized birthday problem over `(Z_{2^W})^N`**.

Note `c_i` may be negative: `remove` is a first-class operation and the accumulator is a
group, not a monoid. We assume the adversary has access to both signs.

---

## 4. What we have already established (please do not spend time re-deriving)

* **Algebraic correctness.** Order independence, add/remove inverse, full teardown to
  identity, multiset (not set) semantics, associativity and commutativity of union, and
  agreement with a from-scratch reference implementation on multisets up to 1e5 elements.
  26 property tests, `crypto/lthash/tests/properties.rs`.
* **Encoding parity with MuHash.** Verified empirically, not by inspection — see §6.1. In
  addition to the five frozen vectors, the encoding was replayed against a real devnet chain:
  **44,663,940 UTXOs**, with MuHash accumulated both through the consensus `add_utxo` path and
  through our encoded bytes. Both reproduced the pruning point header's `utxo_commitment`
  exactly (`8450fbaa...40021e5b`). Caveat, stated because it bears directly on §6.1: that
  chain's field distribution is nearly uniform — every script exactly 34 bytes, every
  script-public-key version 0, 93% coinbase — so the replay establishes scale, not field
  variety. The hand-written vectors still carry the variety coverage.
* **Live devnet runs.** The drift check — a from-scratch rebuild over the pruning-point UTXO
  set compared against the incrementally maintained value — has passed at **every pruning point
  transition observed**, under both expansions, with the complete per-transition record kept in
  `shadow-lthash-history.jsonl` beside the database. Rebuilds run 2.4–2.6 µs/UTXO over
  45–47M-element sets under the current expansion, against 8.67 µs/UTXO for the one cSHAKE256
  rebuild — roughly 3.4–3.6x, but measured at *different* pruning points and UTXO counts, so it
  is a per-element comparison rather than a controlled one. The controlled measurement is the
  pruning-point accumulation pass in `README.md`: both expansions over the same pruning point
  and the same 45,609,558 UTXOs, 406.3 s against 111.9 s, **3.6x**.
  Zero errors across roughly 2.7 million cumulative commits.
  **Two caveats we want stated: no reorgs have occurred in any run**, so the rollback path is
  unexercised; and the drift check compares LtHash against LtHash, so it validates the
  incremental *lifecycle*, not the implementation — a uniformly wrong encoding would pass it.
  The external anchor for the encoding is §6.1's 44.7M-UTXO replay, not this check.
* **Performance.** Per element: MuHash 2.68 us, LtHash **1.77 us** — LtHash is **1.5x
  faster**, and also 26x faster on union and 13x on finalize (MuHash's `normalize()` performs
  a 3072-bit modular division). Only `clone` is slower (78 ns vs 18 ns, 2048 vs 384 bytes).
  Against script/signature verification at 35.9 us per transaction input, replacing MuHash
  with LtHash costs **~96% of today's validation CPU**. Storage is the one real regression:
  2048 vs 384 bytes of resumable state, bounded by pruning depth (+180 MB at 1 bps,
  +1.8 GB at 10 bps). Benchmarks in `README.md`.

---

## 5. Attack surface, and where we think the real question is

### 5.1 The 256-bit seed caps binding at ~128 bits — knowingly accepted

We believe this is real, we have **accepted it deliberately**, and the acceptance is the
single thing we most want a second opinion on. The reasoning is below the mechanism.

`H` factors through a 256-bit intermediate: `H = expand ∘ Blake2b-256`. Therefore **any
Blake2b-256 collision is immediately an LtHash collision**: if `x != x'` with
`seed(x) = seed(x')`, then `H(x) = H(x')` and the two singleton multisets `{x}` and `{x'}`
collide. Generic collision search on a 256-bit digest costs `~2^128`.

So classical binding security is
`min(128, Wagner_bound(N, W))` — and no choice of `N` and `W` can raise it above ~128
without changing the expansion.

**Why we accept it.** We briefly replaced the expansion with cSHAKE256 applied directly to the
element, which removes the intermediate and attains ~2^256 binding. We measured it, then
reverted, on four grounds:

1. **128 bits is where the rest of the stack already sits.** secp256k1 is ~128-bit;
   Blake2b-256 collision resistance is ~2^128. A 256-bit-binding commitment guarded by
   128-bit signatures buys nothing that can be spent.
2. **Solana ships this security level for this construction at these parameters.** Their
   Accounts Lattice Hash (SIMD-0215) is LtHash at `N = 1024`, `W = 16` — identical to ours —
   expanded with the BLAKE3 XOF, whose 256-bit chaining value imposes the same `~2^128` cap.
   The proposal states 128-bit security as the design target, citing Lewi et al. It secures a
   production chain. **Caveat we want to be honest about: the SIMD lists Wagner in its
   bibliography but presents no analysis of it. This is precedent, not proof.**
3. **The cap does not undermine the post-quantum rationale.** That rationale is that Shor
   solves MuHash's group problem in *polynomial* time. The best known quantum attack against a
   256-bit intermediate is generic collision search — roughly 2^85 under BHT, assuming quantum
   RAM nobody knows how to build, and plausibly no better than classical in practice. The cap
   lowers the ceiling; it does not restore a catastrophic failure mode.
4. **The alternative costs ~4x.** Measured on one machine, a 2048-byte expansion is 1.26 us
   with `Blake2b-256 -> ChaCha20` against 6.62 us with cSHAKE256. That is the difference
   between LtHash being **1.5x faster** than MuHash per element and 2.7x slower — i.e. between
   adopting LtHash being free and costing ~30% of validation CPU.

**If any of those four is wrong, we would rather revert again than defend the choice.** The
cSHAKE256 implementation is preserved in git history and the change is one file. This is Q3.

Taking the textbook k-tree cost model for `n` target bits with `k = 2^t` lists — time and
memory `~2^t * 2^(n/(t+1))`, minimised at `t + 1 = sqrt(n)` giving exponent `2*sqrt(n) - 1`:

| N | W | n = N·W | state | `2*sqrt(n) - 1` |
|---:|---:|---:|---:|---:|
| 1024 | 16 | 16384 | 2048 B | ~255 bits |
| 512 | 16 | 8192 | 1024 B | ~180 bits |
| **256** | **16** | **4096** | **512 B** | **~127 bits** |
| 128 | 16 | 2048 | 256 B | ~90 bits |

If both the ~128-bit seed cap and this cost model hold, then `(N=256, W=16)` — a **512-byte**
state — already saturates the security the seed permits, and the current 2048-byte state is
roughly **4x larger than useful**. That would take the storage regression from +1.8 GB to
about +138 MB at 10 bps, i.e. it would essentially remove the only remaining cost objection
to adopting LtHash.

We are not confident in this and are explicitly asking rather than asserting. Two reasons
for doubt:

1. **Our number disagrees with the literature.** Lewi et al. quote roughly 200 bits of
   security for `(1024, 16)`; the model above gives ~255. We do not know whether the
   difference is a different cost accounting, a refinement of the attack
   (Minder–Sinclair extended k-tree, Bernstein's clamping, memory-restricted variants), or
   an error on our part. **Resolving this discrepancy is question Q2.**
2. **The model ignores memory.** At the optimum, `t + 1 = sqrt(16384) = 128`, meaning
   `2^127` lists of `2^128` entries — absurd. Real adversaries are memory-bounded, and
   memory-restricted Wagner is substantially more expensive. The time-only bound may
   therefore understate practical security by a wide margin, which cuts the *other* way and
   might justify a smaller state still.

Note MuHash has the identical 256-bit funnel (`data_to_element` in
`crypto/muhash/src/lib.rs`), so this is not a regression introduced by LtHash — but it does
mean **"LtHash gives us more bits than MuHash because the state is bigger" is a false
argument**, and we will not make it. What LtHash buys is resistance to *Shor*, not more bits.

**The funnel is an artifact of our implementation, not of LtHash.** We chose
`Blake2b-256 -> ChaCha20` specifically to mirror MuHash's expansion, so that a comparison
between the two accumulators would isolate the algebra rather than the hash-to-element step
(see §2). A canonical LtHash would apply an extendable-output function directly to the
element — SHAKE256, or Blake2X — with no 256-bit waypoint, and would presumably then attain
whatever bound the analysis of `(1024, 16)` actually gives.

There is a tension here we want to name rather than paper over. Our *parameter* decision
rests on staying with the set the literature analysed. Applied consistently, the same
reasoning says stay with the analysed *construction* too — and the analysed construction has
no 256-bit waypoint. We deviate anyway, because §5.1's four grounds seem to us to outweigh it,
and because Solana's production deployment deviates identically. **A reviewer who thinks that
reasoning is motivated rather than sound should say so — that is Q3.**

Alternatives we measured before settling, for completeness. Every faster XOF reintroduces the
same cap, which is structural: 256-bit collision resistance needs a >= 512-bit internal state
to survive the birthday bound, and carrying that state is the cost.

| Candidate | 2048-byte expansion | Binding | Verdict |
|---|---:|---|---|
| `Blake2b-256 -> ChaCha20` | **1.26 us** | ~2^128 | **chosen** — mirrors MuHash, no new dependency |
| BLAKE3 XOF (Solana's) | 1.69 us | ~2^128 | same cap, slower here, adds a dependency |
| Blake2b-512 counter mode (Blake2X-style) | 3.78 us | ~2^256 | rejected: needs a length prefix to disambiguate `data \|\| counter`, an encoding hazard a standardised XOF removes |
| cSHAKE256 | 6.62 us | ~2^256 | the conservative option; ~4x the cost |
| SHAKE128 / AES-CTR | — | ~2^128 | same cap as the chosen option, no advantage |

### 5.2 Wagner's generalized birthday attack

The dominant *classical* attack, and the one that sets `(N, W)`. We want to be explicit
internally that **the parameters are set by a classical attack, not a quantum one** — the
post-quantum motivation concerns Shor against MuHash's group, but choosing LtHash buys no
margin whatsoever against Wagner. Parameters must defeat Wagner before quantum computers
enter the discussion.

### 5.3 Lattice / SIS reduction

LtHash's advertised hardness is a short-integer-solution-flavoured lattice problem. We have
not attempted any lattice analysis. Question Q4 asks whether lattice reduction (BKZ or
similar) on the corresponding SIS instance beats the k-tree attack at these parameters, and
whether the `Z_{2^W}` modulus structure (a power of two, with carries propagating between
lanes) admits attacks that a prime modulus would not.

### 5.4 Quantum

The scheme is being adopted *for* post-quantum reasons, so the quantum picture should be
stated rather than assumed. Question Q5.

---

## 6. Deployment-specific threat model

This is the part a generic LtHash analysis will not cover, and where the answer may differ
from the literature.

### 6.1 What an element actually is, and how much freedom the adversary has

An element is not an arbitrary bitstring. It is the serialization of one UTXO, in a fixed
layout shared byte-for-byte with MuHash:

```text
offset  size  field                             encoding
0       32    outpoint.transaction_id           raw 32 bytes
32      4     outpoint.index                    u32 little-endian
36      8     entry.block_daa_score             u64 little-endian
44      8     entry.amount                      u64 little-endian
52      1     entry.is_coinbase                 0x01 / 0x00
53      2     script_public_key.version         u16 little-endian
55      8     script_public_key.script().len()  u64 little-endian
63      L     script_public_key.script()        raw bytes
        total = 63 + L
```

Parity with the consensus implementation was verified empirically rather than by reading:
`write_utxo` in `consensus/core/src/muhash.rs` is private, but its output is observable
through the accumulator, so a harness checked
`MuHash.add_utxo(op,e).finalize() == MuHash.add_element(our_encoding(op,e)).finalize()`
across all-zero, all-max, asymmetric and long-script cases. It reported `ALL_MATCH=true`,
and the digests are frozen as regression vectors.

Adversarial freedom per field:

| field | freedom |
|---|---|
| `script` | **essentially unbounded** — arbitrary bytes, arbitrary length |
| `transaction_id` | grindable, but each distinct value costs a transaction construction |
| `amount`, `block_daa_score` | constrained by supply and chain position |
| `index`, `version`, `is_coinbase` | narrow |

Our working assumption is that the script field alone gives the adversary effectively free
choice of element, so the constrained encoding provides **no meaningful defensive value**.
Question Q3 asks whether that is right, and in particular whether a syncing node's
acceptance path (§6.2) imposes any well-formedness constraint that would actually bite.

**This assumption is unverified against real data.** A 44.7M-UTXO devnet replay found every
script to be exactly 34 bytes at version 0, so it neither confirms nor refutes the claim —
devnet simply has no script variety to observe. A mainnet UTXO set would be the place to
measure how much freedom the field actually carries in practice.

### 6.2 What breaking binding buys an attacker

Two distinct attacks, of quite different severity:

**(a) IBD poisoning — the serious one.** During initial sync a node downloads the
pruning-point UTXO set, accumulates it locally, and compares against the pruning point
header's `utxo_commitment`
(`consensus/src/pipeline/virtual_processor/processor.rs:1291`). An adversary who can
produce a second UTXO set matching a legitimate header's commitment can feed a syncing node
a false UTXO set — false balances, or coins that exist only from that node's perspective.
This attack is **offline, requires no proof of work, and is reusable**: one forged
(UTXO set, commitment) pair poisons every node that syncs from that adversary.

**(b) Block-level commitment forgery.** `verify_expected_utxo_state`
(`consensus/src/pipeline/virtual_processor/utxo_validation.rs:190`) compares a locally
computed multiset against the block header's commitment. Forging here additionally requires
winning proof of work, so it is strictly harder and less attractive than (a).

### 6.3 Time horizon

The binding requirement is **long-lived**. A historical pruning point's commitment must
remain binding for as long as any node might sync against that header — indefinitely, in
practice. This is unlike a signature, which only needs to hold until the coin moves. We
believe this argues for conservative parameters, and would like that intuition confirmed or
corrected.

There is no online rate limit: the adversary computes entirely offline.

---

## 7. Questions we would like answered

* **Q1.** Is the ~128-bit cap from the 256-bit Blake2b seed (§5.1) real? Note we are keeping
  `(1024, 16)` regardless, so this is not a question about shrinking the state — it is a
  question about whether our expansion is throwing away security the chosen parameters would
  otherwise provide.
* **Q2.** What *is* the classical security level of `(1024, 16)` against the best known
  generalized-birthday attack, and how is it derived? Specifically, please resolve the
  ~200 bits (Lewi et al.) vs ~255 bits (our model, §5.1) discrepancy.
* **Q3 — the one we most want answered.** We use `Blake2b-256 -> ChaCha20`, accepting a
  ~2^128 binding cap (§5.1). Is that acceptable for a UTXO commitment that must stay binding
  for the lifetime of the chain?

  **The question has a measured price tag.** Against script/signature verification at 35.9 us
  per transaction input:

  | Expansion | Binding | Validation cost vs today's baseline |
  |---|---|---:|
  | `Blake2b-256 -> ChaCha20` (**current**) | ~2^128 | **~96%** — LtHash is *cheaper* than MuHash |
  | cSHAKE256 | ~2^256 | ~130% |

  So this is not a throughput-ceiling question — the ratio is invariant to block rate — it is
  a flat question of whether ~30% of validation CPU buys anything real. Sub-questions:

  - Is the reasoning in §5.1 sound, particularly points 2 (Solana precedent) and 3 (the cap
    does not restore a quantum-catastrophic break)?
  - Does a *long-lived* commitment justify more margin than Solana's accounts hash needs? Ours
    must remain binding for as long as any node might sync against a historical pruning point;
    theirs is checked continuously by live validators. We are not sure this distinction
    matters, but it is the strongest argument we can construct against our own choice.
  - If 128 bits is not enough, is cSHAKE256 the right fix, or would a Blake2X-style
    Blake2b-512 counter-mode expansion (measured 3.78 us, ~2^256, no new dependency) be
    preferable? We rejected it because implementing it required a length prefix to
    disambiguate `data || counter`, which is the kind of encoding hazard a standardised XOF
    removes — but that is caution, not analysis.

  Full figures in `README.md`, "Measured performance" and "Cost in context".

* **Q4.** Does lattice reduction on the corresponding SIS instance beat the k-tree attack at
  these parameters? Does the power-of-two modulus and inter-lane carry structure of
  `Z_{2^W}` admit attacks a prime modulus would not?
* **Q5.** Do quantum variants of the k-tree attack meaningfully reduce the bound? We want to
  state the post-quantum claim accurately rather than optimistically.
* **Q6.** Is `Blake2b-256 -> ChaCha20 keystream` a sound random-oracle instantiation for
  `H` here? Is there any structure in deriving 16384 pseudorandom bits from a 256-bit key
  that a k-sum adversary could exploit beyond the seed-collision bound?
* **Q7.** Should the domain separators bind more than `(N, W)` — for example a network or
  version identifier — to prevent cross-context reuse of a collision?

---

## 8. What we are *not* asking

* We are not asking for a code audit. Correctness is covered by the property tests, and
  encoding parity is verified against the incumbent implementation.
* We are not asking about signature schemes. secp256k1 Schnorr/ECDSA remains the chain's
  dominant quantum exposure, and an adversary running Shor steals keys directly rather than
  attacking the UTXO commitment. This work closes a narrower and distinct hole (§6.2), and
  is attractive mainly because it is the *cheap* piece of a post-quantum migration — no
  address format change, no wallet impact, nothing consensus-visible on the wire, since the
  header field remains a 32-byte digest either way. It should not be presented as making
  the chain post-quantum.
* We are not asking whether to adopt LtHash. That is our decision; we need the parameter
  question answered to make it.

---

## 9. Reproducing anything here

```bash
cargo test -p kaspa-lthash                        # 41 tests: properties, vectors, unit
cargo test -p kaspa-consensus-core --lib muhash   # 3 encoding-parity tests
cargo bench -p kaspa-lthash                       # LtHash figures
cargo bench -p kaspa-muhash                       # MuHash figures
```

The crate is a workspace member and depends only on `blake2b_simd`, `sha3` and `rand_chacha`
— no dependency on any consensus crate, so the dependency edge runs one way. `MUHASH-SURVEY.md` documents the MuHash survey this was built against,
including the encoding-parity harness in its appendix.

## 10. References

* Lewi, Kim, Maykov, Weis. *Securing Update Propagation with Homomorphic Hashing.*
  IACR ePrint 2019/227.
* Wagner. *A Generalized Birthday Problem.* CRYPTO 2002.
* Minder, Sinclair. *The Extended k-tree Algorithm.* SODA 2009.
* Bernstein. *Better price-performance ratios for generalized birthday attacks.* 2007.
