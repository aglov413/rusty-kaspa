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
measured: **1.51x faster** than MuHash per element, 25x faster on union and 12x on finalize,
at ~96% of today's validation CPU if it replaces MuHash.
What is not settled is the parameter choice. We currently use `N = 1024` lanes of `W = 16`
bits (a 2048-byte state) because that is what Lewi et al. analyse, **not** because anyone
has derived it for this deployment. **We have selected `(1024, 16)` and that choice is not open.** The
reasoning is that it is the only LtHash parameter set anyone has analysed; any smaller set
would be novel parameters needing their own review, which is exactly the cost a shrink was
meant to avoid. We accept the resulting over-provisioning knowingly, including in light of
§5.1. Please do not spend review effort arguing us down to a smaller state.

What we need is (a) the actual classical security level of `(1024, 16)` against Wagner's
generalized birthday attack under our threat model, and (b) whether the expansion in §2 --
a novel construction, described below and not drawn from any standard -- genuinely delivers
the ~2^256 funnel we claim for it.

An earlier revision funnelled every element through a 256-bit seed, capping binding at
~2^128 regardless of `(N, W)`. That cap is closed (§5.1), which is what makes `(1024, 16)`
a matched choice rather than an over-provisioned one -- but it is closed by a construction
we wrote ourselves, which is the substance of question (b).

---

## 2. The construction, exactly as implemented

State is a point in the abelian group `(Z_{2^W})^N`, written additively.

```text
domain_e = "LtHashElement:b2c2:n=<N>,w=<W>"    (Blake2b KEY)
           the "b2c2" tag names the construction: Blake2b-512 -> 2x ChaCha20.
           It is bumped whenever the expansion changes, so values produced by
           different constructions are never silently compared.
domain_f = "LtHashFinalize:n=<N>,w=<W>"        (Blake2b KEY)

L        = ceil(N*W/8)                                    state size in bytes; 2048 at defaults
s(x)     = Blake2b-512(key = domain_e, msg = x)          -> 64 bytes, one shot
H(x)     = unpack( ChaCha20(key = s(x)[0..32],  nonce = nonce_L) filling bytes 0 .. floor(L/2)
                || ChaCha20(key = s(x)[32..64], nonce = nonce_R) filling bytes floor(L/2) .. L )
           NOTE: offsets are BYTES. At the shipping parameters each instance
                 fills exactly 1024. For odd L the right instance takes the
                 extra byte.
           -> a vector in (Z_{2^W})^N, lanes little-endian, LSB-first
           NOTE: ChaCha20 is the IETF construction (RFC 8439, 96-bit nonce,
                 32-bit counter) from the `chacha20` crate -- NOT rand_chacha's
                 Bernstein-RNG layout. nonce_L = "LtHashLane\x00\x00",
                 nonce_R = "LtHashLane\x00\x01".
           NOTE: BOTH halves of s are load-bearing. Keying a single instance on
                 s[0..32] would restore a ~2^128 cap -- see §5.1.

state(M) = SUM over x in M of  mult_M(x) * H(x)          lane-wise, mod 2^W
identity = all-zero vector
add(x)   = state += H(x)        remove(x) = state -= H(x)
union    = lane-wise addition
digest   = Blake2b-256(key = domain_f, msg = canonical_LE_serialization(state))
```

Defaults: `N = 1024`, `W = 16`, so the state is 16384 bits = 2048 bytes, and the digest is
32 bytes. `N` and `W` are runtime parameters; any `N >= 1` and `W` in `1..=64` is supported,
so a re-parameterisation is a config change, not a rewrite.

The expansion **follows the shape of MuHash's own** (`crypto/muhash/src/lib.rs`: Blake2b
keyed `b"MuHashElement"`, then ChaCha20 filling 384 bytes -- itself the shape Bitcoin Core's
MuHash3072 uses), and departs from it in exactly two places, both deliberate:

* **Blake2b-512 rather than -256, split across two ChaCha20 instances rather than one.**
  ChaCha20's key is exactly 256 bits, so a single instance can carry at most 256 bits of
  digest into the keystream -- which is what capped binding at ~2^128. Splitting the digest
  and **concatenating** the two keystreams (never XOR: XOR would let collisions cancel)
  makes the whole 512 bits load-bearing. An output collision requires both halves to
  collide; treating the ChaCha20 keystream as a PRF, two distinct keys agree over 1024 bytes
  only with negligible advantage, so that implies a full Blake2b-512 collision -- generic
  cost ~2^256. The assumption is on the map `k -> keystream(k, nonce, 0)[..1024]`, not on
  ChaCha20 being injective as a cipher, which it is not.
* **RustCrypto `chacha20` rather than `rand_chacha`.** The same cipher; a different
  implementation, chosen because it carries an aarch64 NEON backend where `ppv-lite86` has
  none, and measured ~10% faster on x86. This is the one primitive the two accumulators no
  longer share.

What is retained: the element encoding is byte-identical to MuHash's (§6.1), so a divergence
between the two accumulators remains attributable to the algebra rather than to what bytes
were hashed.

**This construction is not drawn from any standard and has no published analysis.** It is
simple enough to audit in a page, and generic PRG domain-extension by concatenating
independently-keyed instances is well understood, but nobody outside this repository has
looked at this instance of it. That is question (b) in §1.

The element encoding -- the exact bytes fed to `H` -- is byte-identical to MuHash's; see §6.1.

**An earlier revision used cSHAKE256 applied directly to the element**, removing the 256-bit
intermediate and attaining ~2^256 binding. We reverted it on cost grounds, then reached the
same binding level by a different route (§2). cSHAKE256 remains the standards-backed fallback
if that route does not survive review — it is costed in §5.1's table, the implementation is
preserved in git history, and the change is one file. See **Q3**.

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
  transition observed**, under all three expansions this crate has used, with the complete
  per-transition record kept in `shadow-lthash-history.jsonl` beside the database. Rebuilds run
  2.26–2.35 µs/UTXO over 51M-element sets under the current expansion (n=3) and 2.41–2.62 over
  45–51M under the superseded one (n=11), against 8.67 µs/UTXO for the one cSHAKE256 rebuild — roughly 3.4–3.6x, but measured at *different* pruning points and UTXO counts, so it
  is a per-element comparison rather than a controlled one. The controlled measurement is the
  pruning-point accumulation pass in `README.md`: both expansions over the same pruning point
  and the same 45,609,558 UTXOs, 406.3 s against 111.9 s, **3.6x**.
  Zero errors across roughly 2.7 million cumulative commits.
  **Two caveats we want stated. First, we cannot report a reorg count**, because nothing in the
  node logs a reorg — so these runs claim neither reorg coverage nor its absence. The reorg path
  is not LtHash-specific (both accumulators travel in one value and are restored by the same
  lookup), and a reorg that had broken the shadow would surface at the next pruning point as a
  missing comparison; none has. **Second**, the drift check compares LtHash against LtHash, so it
  validates the incremental *lifecycle*, not the implementation — a uniformly wrong encoding
  would pass it. The external anchor for the encoding is §6.1's 44.7M-UTXO replay, not this
  check.
* **Performance.** Per element: MuHash 2.61 us, LtHash **1.73 us** — LtHash is **1.51x
  faster**, and also 25x faster on union and 12x on finalize (MuHash's `normalize()` performs
  a 3072-bit modular division). Only `clone` is slower (78 ns vs 18 ns, 2048 vs 384 bytes).
  Against script/signature verification at 35.9 us per transaction input, replacing MuHash
  with LtHash costs **~96% of today's validation CPU**. Storage is the one real regression:
  2048 vs 384 bytes of resumable state, bounded by pruning depth (+180 MB at 1 bps,
  +1.8 GB at 10 bps). Benchmarks in `README.md`.

---

## 5. Attack surface, and where we think the real question is

### 5.1 The seed cap — what it was, and how it is now closed

**This section previously argued for accepting a ~2^128 cap. It no longer does.** The cap is
closed, at a cost small enough that the argument for tolerating it stopped being worth making.
What replaces it is a narrower question: whether the construction that closes it is sound.

**The mechanism, as it was.** The expansion factored through a 256-bit intermediate:
`H = expand ∘ Blake2b-256`. Any seed collision was immediately an LtHash collision — if
`x != x'` shared a seed then `H(x) = H(x')` and the singleton multisets `{x}` and `{x'}`
collided, at a generic **collision** cost of `~2^128`. (Not a second preimage: the attacker
chooses both members offline, which is what makes it `2^{n/2}` rather than `2^n`. A second
preimage against a UTXO someone else published costs `~2^256` even against the old seed.) Classical binding was `min(128, Wagner_bound(N, W))`,
and no choice of `(N, W)` could raise it, because the bottleneck was the 256-bit key ChaCha20
accepts, not the lattice.

**How it is closed.** Blake2b-512, split across two ChaCha20 instances keyed on
`s[0..32]` and `s[32..64]`, output concatenated (§2). The narrow key stops being the
bottleneck because two keys carry the whole digest. An output collision needs both halves to
collide, so it implies a full Blake2b-512 collision: `~2^256`.

**What it cost.** 1.07 µs against 1.11 µs for the capped construction it replaced — measured
in one process on one machine. Effectively free, and *faster* than the version that shipped
before it, because the same change removed a per-element `format!` allocation in the domain
separator. LtHash remains ~1.51x faster than MuHash per element.

**What we now want reviewed.** Not whether 2^128 was tolerable — that question is moot — but
whether the concatenation argument holds, and whether splitting one digest into two PRG keys
introduces any correlation concern the naive argument misses. See §7 Q3.

---

**Retained for context: why the cap was previously judged acceptable.** These four grounds
were the case for tolerating ~2^128. They are preserved because they bear on how much the fix
actually buys, and because if the construction in §2 does not survive review, this is the
position to fall back to.

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
4. **The alternative costs ~4x.** Measured on one machine, a 2048-byte expansion was 1.26 us
   with `Blake2b-256 -> ChaCha20` against 6.62 us with cSHAKE256 — the difference between
   LtHash being 1.5x faster than MuHash per element and 2.7x slower.

**Ground 4 is the one that collapsed, and it is what changed the decision.** It assumed the
only route to ~2^256 was a standardised XOF at ~4x the cost. It is not: keeping Blake2b and
ChaCha20 and merely widening the funnel costs ~0%. Once the price fell to nothing, the other
three grounds stopped mattering — they were reasons to tolerate a cap, not reasons to prefer
one. Grounds 1-3 remain the fallback position if §2's construction does not survive review. The
cSHAKE256 implementation is preserved in git history and the change is one file. This is Q3.

Taking the textbook k-tree cost model for `n` target bits with `k = 2^t` lists — time and
memory `~2^t * 2^(n/(t+1))`, minimised at `t + 1 = sqrt(n)` giving exponent `2*sqrt(n) - 1`:

| N | W | n = N·W | state | `2*sqrt(n) - 1` |
|---:|---:|---:|---:|---:|
| 1024 | 16 | 16384 | 2048 B | ~255 bits |
| 512 | 16 | 8192 | 1024 B | ~180 bits |
| **256** | **16** | **4096** | **512 B** | **~127 bits** |
| 128 | 16 | 2048 | 256 B | ~90 bits |

**This argument has inverted since the cap was closed.** While binding was capped at ~2^128,
`(N=256, W=16)` — a 512-byte state — already saturated what the expansion permitted, and
`(1024, 16)` was roughly **4x larger than useful**. With a ~2^256 funnel the table reads the
other way: `(1024, 16)` at ~255 bits is the *matched* choice, and the 2048-byte state is
justified rather than over-provisioned.

It also bounds the ceiling in the other direction. `(1024, 32)` would give
`2*sqrt(32768) - 1` ≈ ~361 bits against a 256-bit funnel — paying 1.76x the expansion cost
(1.75 us against 1.07 us, measured) for security the funnel cannot deliver. So the funnel fix
does not argue for larger parameters; it argues that the existing ones are now correct.

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

**The funnel was an artifact of our implementation, not of LtHash.** The original expansion
mirrored MuHash's specifically so that a comparison between the two accumulators would
isolate the algebra rather than the hash-to-element step (see §2) — and inherited MuHash's
256-bit waypoint along with its shape. A canonical LtHash applies an extendable-output
function directly to the element, with no waypoint at all.

The construction in §2 reaches the same place by a different route: rather than adopting an
XOF, it widens the waypoint to 512 bits by splitting it across two ChaCha20 keys. That keeps
the primitives MuHash uses and the cost it had, which is why it was chosen — but it is also
why it has no standard behind it, whereas SHAKE256 or BLAKE2X would have. `(1024, 16)` should
now attain whatever bound the analysis actually gives, rather than being clipped at ~2^128.

There is a tension here we want to name rather than paper over, and closing the cap sharpened
it rather than resolving it. Our *parameter* decision rests on staying with the set the
literature analysed. Applied consistently, the same reasoning says stay with an analysed
*construction* too — and the construction in §2 is not analysed by anyone. We chose it over
cSHAKE256 and TurboSHAKE256, both of which have standards behind them, on performance grounds:
it is the only ~2^256 option that leaves LtHash faster than MuHash, which is the premise the
whole proposal rests on.

That is a real argument, but it is the shape of argument that should be viewed with suspicion:
*our situation is unusual, so the normal preference for analysed constructions does not apply
to us.* **A reviewer who thinks that reasoning is motivated rather than sound should say so —
that is Q3**, and the standards-backed fallbacks are costed in §5.1's table so that switching
is a decision rather than a rewrite.

Alternatives we measured before settling, for completeness. Every faster XOF reintroduces the
same cap, which is structural: 256-bit collision resistance needs a >= 512-bit internal state
to survive the birthday bound, and carrying that state is the cost.

| Candidate | 2048-byte expansion | Binding | Verdict |
|---|---:|---|---|
| **`Blake2b-512 -> 2x ChaCha20`** | **1.07 us** | **~2^256** | **chosen** — see §2; no standard analysis |
| `Blake2b-256 -> ChaCha20` | 1.11 us | ~2^128 | superseded; the capped construction this replaced |
| `Blake2b-512 -> ChaCha20` (key + 64-bit stream) | 1.10 us | ~2^160 | 320 bits is all one ChaCha instance can absorb |
| BLAKE3 XOF (Solana's) | 1.69 us | ~2^128 | 256-bit chaining value imposes the same cap structurally |
| TurboSHAKE256 | 3.38 us | ~2^256 | Keccak-p[1600,12]; CFRG draft, library API, no new crate |
| BLAKE2Xb | 2.74 us SIMD / 3.82 us serial | ~2^256 | prototyped and verified against the 512 official KAT vectors and the reference C implementation at our output length, then dropped: the parameter block is hand-assembled (`blake2b_simd` implements Blake2b, not BLAKE2X) and the SIMD gain is x86-only, so ARM pays the serial cost. Not retained in the tree; see git history |
| cSHAKE256 | 6.76 us | ~2^256 | **the standards-backed fallback**: FIPS 202, library API, `sha3` already in the tree |

All measured in one process on one idle machine (i5-9600K, AVX2). Earlier revisions of this
document quoted 1.26 us for the capped construction; that figure included a per-element
`format!` allocation since removed, and 1.11 us is the like-for-like number.

Note the ordering by *assurance* runs opposite to the ordering by speed: cSHAKE256 (FIPS) →
TurboSHAKE256 (CFRG draft) → BLAKE2Xb (published spec, hand-rolled parameters) → the chosen
construction (no published analysis). That is not a coincidence, and it is why §7 Q3 exists.

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
(`consensus/src/consensus/mod.rs:1113`, `import_pruning_point_utxo_set`; the equivalent
per-block check is `consensus/src/pipeline/virtual_processor/utxo_validation.rs:190`). An adversary who can
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

* **Q1.** *(largely resolved, retained for the record.)* The ~128-bit cap from the 256-bit
  Blake2b seed was real; the expansion was throwing away security `(1024, 16)` would otherwise
  provide. It is closed (§5.1). What remains of this question is folded into Q3.
* **Q2.** What *is* the classical security level of `(1024, 16)` against the best known
  generalized-birthday attack, and how is it derived? Specifically, please resolve the
  ~200 bits (Lewi et al.) vs ~255 bits (our model, §5.1) discrepancy.
* **Q3 — the one we most want answered.** Is the expansion in §2 sound?

  We close the ~2^128 cap with `Blake2b-512 -> 2x ChaCha20`: the digest split across two
  instances, keystreams concatenated. **No component here is new — splitting a hash output
  into two keys is the standard KDF pattern, and concatenating independently-keyed PRG
  outputs to extend a domain is equally routine. What is unreviewed is this composition**, in
  this role, at these parameters: no published analysis, no test vectors of record, no prior
  deployment. The argument is one paragraph long and we believe it, which is exactly the
  position that produced the 256-bit funnel in the first place. Specifically:

  - Does an output collision genuinely imply a full 512-bit Blake2b collision? The claim is
    that colliding the concatenation requires colliding both halves, and that two distinct
    ChaCha20 keys agree over 1024 bytes of keystream only with negligible PRF advantage. Is
    that the right assumption to be leaning on, and is it enough?
  - Does deriving two PRG keys from halves of a single hash output introduce any correlation
    concern the naive argument misses? The two keys are not independent random values; they
    are two halves of one digest. We believe this is sound if Blake2b-512 behaves as a random
    oracle or a good KDF, which is the usual assumption for this pattern — but the usual
    assumption is doing real work here and we would rather it were named than implied.
  - **How much does the constrained preimage space matter?** The generic `2^{n/2}` birthday
    assumes free choice of set members. Ours are not free: an element is
    `encode_utxo(outpoint, entry)` and the outpoint begins with a `txid`, itself the hash of a
    valid transaction (§6.1). An attacker can still grind cheaply — vary any field, rehash —
    so we do not believe this moves the bound, only the constant factor. We would rather have
    that confirmed than assume it, since it cuts against our own argument for widening the
    seed.
  - The two instances take distinct nonces (`nonce_L`/`nonce_R`) as well as distinct keys.
    We believe the nonces are not load-bearing — nonce reuse matters within a key, not
    across keys — and included them so that related-key ChaCha need not be reasoned about
    at all. Is that reasoning right?
  - **If the answer is "use something standardised instead"**, the measured alternatives are
    in §5.1's table. cSHAKE256 is the conservative choice: FIPS 202, library API, `sha3`
    already in the dependency tree, at 6.76 us against 1.07 us. TurboSHAKE256 sits between
    them at 3.38 us with a CFRG draft behind it. We would rather be told to take one of
    these than have our own construction pass on our own say-so.

  **The price tag, against script/signature verification at 35.9 us per transaction input:**

  | Expansion | Binding | Validation cost vs today's baseline |
  |---|---|---:|
  | `Blake2b-512 -> 2x ChaCha20` (**current**) | ~2^256 | **~96%** — LtHash is *cheaper* than MuHash |
  | TurboSHAKE256 | ~2^256 | ~110% |
  | cSHAKE256 | ~2^256 | ~130% |

  Note what this table no longer says: there is no longer a security/performance tradeoff to
  adjudicate. The question is purely which ~2^256 construction to trust.

  Full figures in `README.md`, "Measured performance" and "Cost in context".

* **Q4.** Does lattice reduction on the corresponding SIS instance beat the k-tree attack at
  these parameters? Does the power-of-two modulus and inter-lane carry structure of
  `Z_{2^W}` admit attacks a prime modulus would not?
* **Q5.** Do quantum variants of the k-tree attack meaningfully reduce the bound? We want to
  state the post-quantum claim accurately rather than optimistically. **This question gains
  weight if the chain moves to post-quantum signatures**: with secp256k1 the commitment is
  nowhere near the weakest link, so the Wagner bound has enormous margin. With ML-DSA or
  SLH-DSA signatures it becomes the number in this document with the least margin *and* the
  least certainty — see Q2 for the ~200 vs ~255 discrepancy we cannot resolve ourselves.
* **Q6.** Is `Blake2b-512 -> 2x ChaCha20 keystream` a sound random-oracle instantiation for
  `H` here? Is there any structure in deriving 16384 pseudorandom bits from two 256-bit keys
  that a k-sum adversary could exploit beyond the seed-collision bound?
* **Q7 — is a 32-byte digest the right width for this commitment?** `digest()` is
  Blake2b-256 over the serialized state, and the result goes into `header.utxo_commitment`,
  which is Kaspa's universal 32-byte `Hash`. Widening it is a type change threading through
  headers, serialization, P2P, RPC and the pruning proof, so we would rather ask now than
  discover later.

  Our reasoning, which we want checked rather than accepted:

  - **Second preimage is the property that matters**, not collision. An attacker must match a
    pruning point that is already published and already agreed on. Blake2b-256 second-preimage
    resistance is `~2^256` classically and `~2^128` under Grover, the latter being NIST
    Category 5 — the highest tier they define.
  - **On collision, 256 bits is only Category 2**: `~2^128` classically, `~2^85` under BHT
    assuming quantum RAM nobody knows how to build. So if the relevant attack is instead an
    adversary grinding two candidate UTXO sets during creation, committing to one and
    substituting the other later, 32 bytes is materially weaker and 64 would be the fix.
  - **Why we think the digest's collision bound is not the expansion's.** Both are `~2^128`
    collision bounds — an earlier revision of this document mislabelled the expansion's as a
    second preimage, which it is not. What separates them is **how much of the UTXO set the
    attacker must control**, not which property is bounded:

    * *Seed collision:* the attacker needs **one element** of their own. The accumulator is
      homomorphic, so substituting `x'` for `x` leaves the state unchanged whatever else the
      set contains. One published transaction and the work is banked.
    * *Digest collision:* the attacker needs two whole accumulator **states** that hash alike,
      which means steering the entire UTXO set — everyone else's transactions included.

    Same number, very different exploitability. That asymmetry is what made the expansion worth
    fixing and, we believe, leaves the digest alone. **If it is wrong, the conclusion inverts**
    and 64 bytes becomes the right answer.

  **This question is sharper under post-quantum signatures.** Today secp256k1 falls to Shor in
  polynomial time, so the commitment is far from the weakest link and the margin is academic.
  If the chain adopts ML-DSA or SLH-DSA, that backstop disappears and the digest stands on its
  own: Category 5 against Category 1-5 signatures, i.e. matched at worst. We believe it still
  holds. We would like that confirmed rather than assumed, because it is the assumption the
  header layout is built on.

* **Q8.** Should the domain separators bind more than `(N, W)` — for example a network or
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
cargo test -p kaspa-lthash                        # 48 tests: properties, vectors, spec, unit
cargo test -p kaspa-consensus-core --lib muhash   # 3 encoding-parity tests
cargo bench -p kaspa-lthash                       # LtHash figures
cargo bench -p kaspa-muhash                       # MuHash figures
```

The crate is a workspace member and depends only on `blake2b_simd` and `chacha20`
— no dependency on any consensus crate, so the dependency edge runs one way. `MUHASH-SURVEY.md` documents the MuHash survey this was built against,
including the encoding-parity harness in its appendix.

## 10. References

* Lewi, Kim, Maykov, Weis. *Securing Update Propagation with Homomorphic Hashing.*
  IACR ePrint 2019/227.
* Wagner. *A Generalized Birthday Problem.* CRYPTO 2002.
* Minder, Sinclair. *The Extended k-tree Algorithm.* SODA 2009.
* Bernstein. *Better price-performance ratios for generalized birthday attacks.* 2007.
