# Shadow integration design — LtHash alongside MuHash

**Status:** implemented and running on devnet. Scoped to **devnet only**, **shadow only**,
**off by default**. LtHash is computed alongside MuHash and is never consulted for any validation
decision. Promotion to testnet or mainnet is gated on the cryptographic review
(`PARAMETER-REVIEW.md`) plus explicit support for a merge — not on this working.

This reverses the constraint the crate was built under ("no edits outside the new crate, do
not touch consensus code"). Everything below therefore lands in consensus and shared crates,
and the design is organised around making that reversible and safe.

---

## 1. Why a live shadow is worth building before the review lands

The 41 property tests and the 44.7M-UTXO replay both validate the accumulator against *static*
inputs. Neither can exercise the thing most likely to break a homomorphic accumulator in
production: **incremental state maintained across reorgs and pruning**.

From the survey (`MUHASH-SURVEY.md` §4c): MuHash is *never rolled back* on a reorg. UTXO diffs
are reversed, but the accumulator is restored by re-reading the new sink's value wholesale
from `utxo_multisets_store` (`virtual_processor/processor.rs:333`). A shadow accumulator that
is not persisted with exactly the same lifecycle will drift — and because wrong removals are
silent by construction, it will drift without any error, surfacing much later as an
inexplicable mismatch.

A live devnet shadow with a drift check is the only way to demonstrate that the lifecycle is
right. That is the thing worth putting in front of a reviewer.

---

## 2. Safety invariants — non-negotiable

1. **No validation decision reads LtHash.** `verify_expected_utxo_state` continues to compare
   MuHash and only MuHash against `header.utxo_commitment`. No new rule error exists.
2. **Off by default.** Enabled only by `--shadow-lthash`, which additionally **refuses to
   start on any network other than devnet**.
3. **No panic path.** Shadow code must not be able to take down a node. Every shadow operation
   is infallible by construction (lane arithmetic cannot fail) or is behind an `Option` that
   is set to `None` on any error, with a single warning logged.
4. **Atomic with MuHash.** The LtHash state is written in the *same* `WriteBatch` as the
   MuHash state and deleted in the same pruning batch, so the two cannot diverge across a
   crash.
5. **Revertible in one commit.** No refactor of unrelated code, no behavioural change when the
   flag is off. `git revert` restores the current tree exactly.

A reviewer should be able to check invariant 1 by grepping for `lthash` in
`utxo_validation.rs` and confirming it never appears in a conditional.

---

## 3. Core design: one wrapper, not two parallel fields

The obvious implementation — add an `lthash: LtHash` field next to `multiset_hash: MuHash`
and update both at each site — is exactly the shape that produces drift. There are seven
accumulation sites; missing one is silent.

Instead, wrap:

```rust
/// A MuHash with an optional LtHash shadow. Every mutation applies to both.
/// `finalize()` returns the MuHash digest ONLY -- the shadow is never a commitment.
pub struct ShadowedMuHash {
    muhash: MuHash,
    lthash: Option<LtHash>,   // None when the shadow is disabled
}
```

Every operation the pipeline performs — `add_transaction`, `add_utxo`, `combine`, `clone` —
forwards to both members. It becomes structurally impossible to update one and forget the
other, which turns a whole class of drift bug into a compile error.

`UtxoProcessingContext.multiset_hash` changes type from `MuHash` to `ShadowedMuHash`. That
single type change propagates to every accumulation site, and the compiler enumerates them.

### The element encoding must have exactly one source

`consensus/core/src/muhash.rs::write_utxo` writes into an `impl HasherBase`. The naive shadow
approach is to reimplement the encoding on the LtHash side — **which would reintroduce exactly
the divergence risk this project exists to eliminate.**

An earlier draft of this document proposed generalising `write_utxo` over a new sink trait.
**That is unnecessary, and the simpler route is strictly safer.** `HasherBase` is a single
method:

```rust
pub trait HasherBase { fn update<A: AsRef<[u8]>>(&mut self, data: A) -> &mut Self; }
```

and `HasherExtensions` (`write_bool`, `write_var_bytes`, `write_len`) is blanket-implemented
for every `T: HasherBase`. `HasherBase` is therefore *already* the sink abstraction. All that
is needed is a byte-collecting type that implements it:

```rust
pub struct ByteSink(Vec<u8>);
impl HasherBase for ByteSink {
    fn update<A: AsRef<[u8]>>(&mut self, data: A) -> &mut Self { self.0.extend_from_slice(data.as_ref()); self }
}
```

**`write_utxo`'s body is not modified.** Its signature, its call order, and every byte it
emits stay exactly as they are; only its visibility changes so the shadow path can call it.
This removes what was previously the single dangerous change in the plan — there is no longer
a refactor that could move a byte, because there is no refactor.

`crypto/lthash/src/encoding.rs` remains the standalone copy used by the crate's own tests,
and the frozen vectors keep the two provably identical.

## 4. Change sites

| # | File | Change |
|---|---|---|
| 1 | root `Cargo.toml` | add `"crypto/lthash"` to `members`; add workspace dep. Delete the `[workspace]` table from `crypto/lthash/Cargo.toml`. |
| 2 | `database/src/registry.rs` | `ShadowLtHash = 200` — deliberately above every used prefix (max 194) to minimise conflict with upstream additions. |
| 3 | `consensus/src/model/stores/shadow_lthash.rs` *(new)* | `DbShadowLtHashStore`, 2048-byte value keyed by chain block hash. Mirrors `utxo_multisets.rs`. |
| 4 | `consensus/core/src/muhash.rs` | add `ByteSink` and widen `write_utxo` visibility (§3). **Body untouched.** |
| 5 | `consensus/core/src/lthash.rs` *(new)* | `LtHashExtensions`: `add_transaction`, `add_utxo`, built on the shared encoding. |
| 6 | `consensus/core/src/shadowed_muhash.rs` *(new)* | `ShadowedMuHash` (§3). |
| 7 | `consensus/src/consensus/storage.rs` | wire the store as `Option<Arc<DbShadowLtHashStore>>`, `Some` only when enabled. |
| 8 | `.../virtual_processor/utxo_validation.rs` | `multiset_hash: ShadowedMuHash`; `validate_transactions_with_muhash_in_parallel` returns and reduces `ShadowedMuHash`. **No change to the commitment comparison.** |
| 9 | `.../virtual_processor/processor.rs` | `commit_utxo_state` writes both in one batch; sink seeding (line ~333) reads both; `process_genesis`; `import_pruning_point_utxo_set`; `append_imported_pruning_point_utxos`. |
| 10 | `.../pruning_processor/processor.rs` | delete the shadow entry in the same pruning batch (~line 502). |
| 11 | `consensus/core/src/config/mod.rs` | `shadow_lthash: bool`, defaulting false, plus a builder method — same shape as `enable_sanity_checks`. |
| 12 | `kaspad/src/args.rs` | `--shadow-lthash` flag; plumbed via `apply_to_config`. Rejects non-devnet. |

As landed: 15 modified files (+538/-22, the single deletion a formatting artifact) plus 4 new
files. All additive in behaviour — with the flag off, no existing code path differs. The one
change previously flagged as delicate (#4) turned out not to require modifying any existing
code at all — see §3.

---

## 5. What the shadow actually validates

There is no LtHash field in block headers, so there is nothing to compare a shadow digest
against. The value is **drift detection**, mirroring the existing MuHash sanity check:

`pruning_processor/processor.rs::assert_utxo_commitment` already rebuilds a MuHash from
scratch over the whole pruning-point UTXO set and asserts it against the header, gated on
`enable_sanity_checks`. The shadow adds the analogue: rebuild LtHash from scratch over the
same set and compare against the incrementally maintained value.

```text
incremental LtHash (maintained across N blocks, M reorgs, K prunings)
    ==?
from-scratch LtHash (recomputed over the current pruning-point UTXO set)
```

A mismatch is the signal the whole project is guarding against, and it is exactly what unit
tests cannot produce. On success, the claim earned is: *"the accumulator lifecycle survives
real block processing, real reorgs and real pruning on a live chain"* — which is a materially
stronger statement than anything in the current README.

This is implemented as `pruning_processor::check_shadow_lthash_drift`, which runs whenever the
pruning point advances and the shadow is enabled. It logs at error level on mismatch and
deliberately does **not** panic (invariant 3): a drift is a research finding, not a consensus
fault.

---

## 6. Costs on devnet

| | effect |
|---|---|
| CPU, per UTXO operation | **1.77 µs benched / 2.45 µs measured on a live node**, against MuHash's 2.68 µs — LtHash is *cheaper* per element |
| Storage | +2048 bytes per retained chain block; **+1.8 GB at devnet's 10 bps** (pruning depth 1,080,000), ~+180 MB at 1 bps |
| Pruning-point import | **111.9 s measured** over 45.6M UTXOs, one-off |
| Drift check | ~112 s over 45.6M UTXOs, once per pruning-point move |
| Node behaviour with flag off | **none** — the `Option` is `None` and no store is opened |

Running the shadow pays for *both* accumulators, which is ~109% of today's validation CPU;
LtHash *replacing* MuHash would be ~96%. See `README.md`, "Cost in context".

Measured on devnet: the node sustained ~11k blocks / ~6.7k UTXO-validated per 10 s during
catch-up and kept pace with the chain tip thereafter. Acceptable for a devnet experiment. Not
a statement about mainnet viability.

---

## 7. Rollout

1. **Phase 1 — plumbing.** *(done)* Every change landed, additive, shadow disabled by default.
2. **Phase 2 — enable on devnet.** *(done, partially)* Synced from scratch with
   `--shadow-lthash`. The drift check has passed at **every pruning point transition observed**,
   under both expansions, with zero errors; the complete per-transition record is kept in
   `shadow-lthash-history.jsonl` beside the database. **How many reorgs this covers is unknown,
   because nothing logs a reorg** — no run can report a count in either direction. See §8.
3. **Phase 3 — report.** *(done for what Phase 2 covered)* Results are in
   `PARAMETER-REVIEW.md` §4 and `README.md`.

Phase 1 was where the risk was. Phase 2 is where the value is; what it still lacks is
accumulated runtime and more than a single cross-node data point (§8b), not a reorg.

## 8. Known risks

- **~~The `write_utxo` refactor touches a consensus-critical encoding.~~** *Resolved during
  implementation:* no refactor was required (§3), so no byte can move. The frozen vectors and
  the 44.7M-UTXO replay still gate any future change to it.
- **A missed accumulation site causes silent drift.** Mitigated structurally by the wrapper
  (§3) — the compiler enumerates the sites, and it caught one a manual search had missed.
- **A shadow panic takes down the node.** Mitigated by invariant 3: lane arithmetic is
  `wrapping_*` and total, store errors disable the shadow rather than propagating, and the
  drift check logs instead of asserting. One violation of this invariant was found and fixed
  during implementation (see §9, `combine`).
- **Reorgs are not counted, and the shadow has no reorg-specific code.** Earlier drafts called
  the reorg path unexercised and reported "zero reorgs". Both were wrong. Nothing in the node
  logs a reorg — `calculate_utxo_state_relatively` logs its split point at `debug!`, and that
  line fires on every virtual resolution whether or not one occurred — so no run has ever been
  in a position to report a count. "Zero" was the absence of an indicator that does not exist,
  not an observation, and it is withdrawn.

  What holds structurally is stronger than the count would have been. `ShadowedMuHash`
  (`consensus/core/src/shadowed_muhash.rs`) carries the MuHash and the `Option<LtHash>` in one
  value and applies every mutating operation to both in lockstep; the reorg site
  (`virtual_processor/processor.rs:492`) restores state through the same
  `load_shadowed_multiset(selected_parent)` call the linear path uses at `:359`. There is no
  LtHash-specific reorg branch that could be unexercised — LtHash is restored by lookup exactly
  as MuHash is (`MUHASH-SURVEY.md` §4c), on code that predates this work.

  The one LtHash-specific behaviour is the `Option` degrading to `None` when no shadow is
  stored at the new selected parent. That is fail-safe by design and, importantly, *detectable*:
  the entry for the next pruning point would then be missing and the drift check logs "no stored
  shadow … nothing to compare yet" in place of `OK`. Every observed transition logged `OK`. So
  the defensible claim is **no reorg has broken the shadow in a way the drift check would catch
  within one pruning interval** — not that no reorg occurred. Converting this into a count needs
  one INFO line on the reorg path: cheap, and not yet done.
- **The drift check has no external anchor.** It compares LtHash against LtHash, so a
  uniformly wrong implementation would pass. The external anchor is the encoding work — the
  frozen vectors and the 44.7M-UTXO replay — not the drift check. See §8b for the related
  cross-node gap.
- **This is still unreviewed cryptography.** Nothing here changes that. A working shadow
  demonstrates the *engineering*; it says nothing about whether `(1024, 16)` is secure. See
  `PARAMETER-REVIEW.md`.

---

## 8b. The cross-node gap, and how to close it cheaply

A header carries one `utxo_commitment`, so during a shadow phase LtHash never enters a header
and each node verifies only its own value. Nothing establishes that two nodes compute the
*same* LtHash.

The tempting fix — a transitional, non-binding second header field — is a bad trade.
`utxo_commitment` feeds the block hash (`consensus/core/src/hashing/header.rs`), so a second
field changes the pre-PoW input and forces every miner and pool to update, not just node
operators; it adds 32 bytes to every archival header (~27 MB/day at 10 bps); and it needs its
own hard fork to introduce, before the fork that switches over.

**Cross-node agreement needs visibility, not consensus.** Several operators run
`--shadow-lthash` and compare values at a shared pruning point. That establishes the same
property with no header change, no mining impact and no fork, during the shadow phase rather
than requiring a preliminary one.

**First cross-node match, 2026-09-04.** Two independently operated nodes — different machines,
different operators — produced byte-identical rows at pruning point
`f1caa6c3dacd1a79b38bfddeb9df773ce22da44bead7db34e249b731d2804b73`: 47,496,442 UTXOs, digest
`323d9496d062fc42582f8a7208879ae05bdc65ba1c4d4dfb51115da7613d4985`, parameters `(1024, 16)` and
outcome `OK` on both sides.

Two properties make this worth more than a digest match alone. The recorded digest is the
*from-scratch rebuild*, so what agreed was two independent rebuilds over two UTXO sets that
MuHash had each separately verified against the header commitment — the UTXO count matching is
itself evidence the inputs were identical. And the two nodes arrived by different histories: one
backfilled two days earlier then maintained incrementally through four pruning transitions and a
restart, the other backfilled about six hours before the match.

**What it is not.** One shared pruning point. Agreement between instances of a *single
implementation*, so a systematic error would agree with itself — the frozen vectors and the
44.7M-UTXO replay remain the only external anchor for the encoding. Both nodes seeded by the
same mechanism (the startup backfill), so a node seeded by genesis accumulation or by IBD
pruning-point import would add a genuinely different route. And the comparison was made by hand
from the JSONL records: a cooperative-operator channel, not a trust-minimized one. A served row
says what a node's history *file* claims, not what the node computed.

**Anchoring rows to pruning points is what makes this work at all.** The pruning point is
committed in block headers and consensus-validated, so two nodes cannot disagree about *which*
block it is without a consensus split — the join key is trustworthy. But nodes do not all record
the same *set* of them: `advance_pruning_point_if_possible` takes `next_pruning_points(...).last()`
and checks only that one, so a node whose sink jumps forward past several pruning samples skips
the intermediate points entirely, and those rows can never be recovered once the shadow entries
are pruned. Histories are therefore sparse in a structured way — every row comparable, coverage
depending on how continuously each node's sink advanced.

---

## 9. Design decisions made during implementation

These are the durable ones — the reasoning a future reader needs, as distinct from the code,
which can be read directly.

* **A wrapper, not a parallel field.** `ShadowedMuHash` forwards every mutation to both
  accumulators. Adding an `lthash` field beside `multiset_hash` and updating both at each of
  the seven accumulation sites would have made a missed site a *silent* divergence — and
  because wrong removals are undetectable in any group-based multiset hash, that divergence
  would surface much later with no trace of where it began. Changing
  `UtxoProcessingContext::multiset_hash` to the wrapper made the compiler enumerate the sites
  instead; it found one (`test_block_builder.rs`) that a manual search had missed.

* **`write_utxo` was not refactored.** `HasherBase` has a single method and
  `HasherExtensions` is blanket-implemented over it, so it already *was* the sink abstraction.
  A `ByteSink` implementing it gives a non-hasher consumer byte-identical encodings with zero
  changes to the consensus-critical function — no byte can move because no line was touched.

* **The store's presence is the enable flag.** `Option<Arc<DbShadowLtHashStore>>`; no
  processor carries a separate boolean, so the store and the behaviour cannot disagree.
  `PruningProcessor` reaches it through its existing `Deref` to `ConsensusStorage`.

* **`VirtualState.multiset` stays `MuHash`.** It is `Serialize`/`Deserialize` and persisted;
  changing its type would alter the on-disk format and break existing databases. Virtual's
  shadow is not persisted and is not needed — on restart virtual is recomputed from the sink,
  whose shadow *is* stored.

* **A missing shadow degrades to `None`, never to identity.** Seeding from identity would
  produce a shadow that does not describe the UTXO set, and the drift check would then report
  a mismatch that means nothing. Reporting the *absence* of a shadow is recoverable; reporting
  a wrong one is not.

* **Enabling the flag on an existing database backfills at startup.**
  `VirtualStateProcessor::backfill_shadow_if_needed`, called from `Consensus::new` before any
  processor runs, seeds an accumulator over the pruning UTXO set already on disk and replays
  the stored chain-block UTXO diffs forward to the sink — the same walk
  `PruningProcessor::advance_pruning_utxoset` performs, without the UTXO-set writes. It writes
  an entry per chain block on the way, not just the sink, for two reasons: the next pruning
  point lands *inside* the replayed range, so the existing drift check verifies the backfill on
  the very next pruning point movement rather than a pruning depth later; and a reorg into the
  range re-reads the shadow wholesale from the store, so the intermediate entries are what keep
  it alive. The result is keyed and pruned identically to what a fresh sync would have written.
  Startup blocks for the duration — one full UTXO-set pass plus the replay. Every failure path
  abandons the backfill and leaves the node reporting no shadow, per invariant 3.

* **Every drift check is recorded to `shadow-lthash-history.jsonl`, beside the database.** The
  drift check only proves a node agrees with *itself*. Establishing LtHash as a viable
  replacement needs agreement between independently operated nodes, and that is impossible to
  compare without a durable record: shadow entries are deleted at pruning, so once a pruning
  point moves, no node can ever again say what it computed there. One JSON line per check makes
  the comparison asynchronous — two operators intersect their histories on pruning point hash and
  compare wherever both have a row, without needing to be at the same pruning point when they
  look. Rows are anchored to **pruning points only**, because a pruning point is the one thing
  two independently operated nodes are guaranteed to agree on; anything node-local (a sink, a
  tip) would not be comparable across operators at all. Both outcomes are recorded, `ok` and
  `drift` — a drift row is the most valuable row the file could hold and must not be the one
  that is missing. Each row carries the full 2048-byte state as well as the digest: LtHash is
  homomorphic, so subtracting two disagreeing states yields the accumulator of exactly the
  symmetric difference of the two UTXO sets, which candidate UTXOs can then be tested against.
  The parameters are recorded too, so rows can never be silently compared across a parameter
  change. Written beside the database rather than inside it (a foreign file in a RocksDB
  directory invites trouble), and every failure warns and returns — this is research output and
  must never interfere with a node.

* **The backfill cross-checks itself against any shadow that survived.** Turning the flag *off*
  for a while and back on leaves the earlier entries in place, because pruning only deletes them
  while the store exists. The replay then overlaps a stretch of states the pipeline accumulated
  incrementally, across real pruning transitions — the strongest available evidence that a
  backfill is correct, and overwriting it blind would destroy it. So every block whose entry
  already exists is compared before being rewritten. Agreement is counted and reported in the
  completion log; a disagreement is logged at error level with both digests and **abandons the
  backfill without writing further**, since nothing here can say which of the two values is wrong
  and continuing risks replacing a good shadow with a bad one. The earlier states are left intact
  for diagnosis and the node runs with no shadow, which is the correct degradation.

* **`ShadowedMuHash::combine` does not assert agreement.** An earlier version asserted that
  both sides always had the same shadow state. That is false: the mismatch is exactly what
  happens when the shadow is enabled on a chain synced without it, and the assertion would
  have panicked every debug build in that situation — violating invariant 3.
