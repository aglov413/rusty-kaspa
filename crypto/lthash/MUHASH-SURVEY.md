# MuHash survey

A read-only survey of how MuHash is implemented, how a UTXO becomes bytes, where the
commitment is compared, and how UTXO diffs are applied and reverted. It is the reference this
crate was built against: every design decision in `INTEGRATION.md` traces back to something
recorded here, particularly §4c on reorg handling.

Nothing in this document changes behaviour, and no consensus code was modified while producing
it.

Commit surveyed: `3b834c65` on branch `dk-with-tcp`.
Comparison baseline: `6834c8e1` (`git merge-base origin/master HEAD`, "ci: static link CRT
on Windows builds (#417) (#865)"). See §5 for the caveat about what "upstream" means here.

---

## 1. The MuHash implementation and its crate location

| Piece | Location |
|---|---|
| Accumulator itself | `crypto/muhash/src/lib.rs` — crate `kaspa-muhash` |
| 3072-bit field arithmetic | `crypto/muhash/src/u3072.rs` (private module; `pub` only under `cfg(fuzzing)`) |
| Wide-int backend | `math/` — crate `kaspa-math` (`Uint3072`) |
| Element/finalize hashers | `crypto/hashes/src/hashers.rs` — crate `kaspa-hashes` |
| UTXO → bytes adapter | `consensus/core/src/muhash.rs` — crate `kaspa-consensus-core`, trait `MuHashExtensions` |
| Byte-writing primitives | `consensus/core/src/hashing/mod.rs` — trait `HasherExtensions` |

Shape of the accumulator (`crypto/muhash/src/lib.rs:33`):

```rust
pub struct MuHash {
    numerator: U3072,
    denominator: U3072,
}
```

- `add_element(data)` multiplies `numerator` by the expanded element.
- `remove_element(data)` multiplies `denominator` by it.
- `combine(other)` multiplies numerators and denominators pairwise (union of multisets).
- `normalize()` does `numerator /= denominator; denominator = 1`.
- `serialize()` normalizes then emits `numerator.to_le_bytes()` — 384 bytes (`SERIALIZED_MUHASH_SIZE = 3072/8`).
- `finalize()` = `MuHashFinalizeHash::hash(serialize())` → 32-byte `Hash`.
- Identity: `numerator = 1, denominator = 1`; `EMPTY_MUHASH` (`crypto/muhash/src/lib.rs:19`) is
  the finalize of that identity and is used verbatim as the genesis `utxo_commitment` for
  testnet/simnet/devnet (`consensus/core/src/config/genesis.rs:133,182,213`).

Element expansion (`crypto/muhash/src/lib.rs:158`, `data_to_element`, and the identical
`MuHashElementBuilder::finalize` at line 147):

```rust
let hash = MuHashElementHash::hash(data);              // Blake2b-256, keyed b"MuHashElement"
let mut stream = ChaCha20Rng::from_seed(hash.as_bytes());
let mut bytes = [0u8; 384];
stream.fill_bytes(&mut bytes);
U3072::from_le_bytes(bytes)                            // 3072-bit odd-ish field element
```

Both hashers are Blake2b with a 32-byte output and the domain separator supplied as the
**Blake2b key**, not as a prefix (`crypto/hashes/src/hashers.rs:77` `blake2b_hasher!`):

```rust
blake2b_simd::Params::new().hash_length(32).key(b"MuHashElement").to_state()
blake2b_simd::Params::new().hash_length(32).key(b"MuHashFinalize").to_state()
```

Two builder-style entry points exist so callers can stream bytes without allocating:
`add_element_builder()` / `remove_element_builder()` return a `MuHashElementBuilder` that
implements `HasherBase`; `finalize()` on the builder performs the same Blake2b → ChaCha20
expansion and multiplies into the chosen field.

---

## 2. The exact UTXO-entry serialization

`consensus/core/src/muhash.rs:50` — this is the *only* function that turns a UTXO into
MuHash element bytes. Everything else routes through it.

```rust
fn write_utxo(writer: &mut impl HasherBase, entry: &UtxoEntry, outpoint: &TransactionOutpoint) {
    writer
        // Outpoint
        .update(outpoint.transaction_id)
        .update(outpoint.index.to_le_bytes())
        // Utxo entry
        .update(entry.block_daa_score.to_le_bytes())
        .update(entry.amount.to_le_bytes())
        .write_bool(entry.is_coinbase)
        .update(entry.script_public_key.version().to_le_bytes())
        .write_var_bytes(entry.script_public_key.script());
}
```

Resolving the helpers (`consensus/core/src/hashing/mod.rs:52,83,48`):

- `write_bool(b)` → one byte, `0x01` if true else `0x00`.
- `write_var_bytes(s)` → `write_len(s.len())` then the raw bytes.
- `write_len(n)` → `(n as u64).to_le_bytes()`, i.e. **8** length bytes, little-endian.

Field widths come from `consensus/core/src/tx.rs:49` (`UtxoEntry`), `tx.rs:72`
(`TransactionOutpoint`, `TransactionIndexType = u32` at `tx.rs:67`) and
`consensus/core/src/tx/script_public_key.rs:28` (`ScriptPublicKeyVersion = u16`).

### Byte layout (exact, in order)

```
offset  size  field                                 encoding
------  ----  ------------------------------------  --------------------------------
0       32    outpoint.transaction_id               raw 32 bytes of the Hash, as stored
32      4     outpoint.index                        u32 little-endian
36      8     entry.block_daa_score                 u64 little-endian
44      8     entry.amount                          u64 little-endian
52      1     entry.is_coinbase                     0x01 / 0x00
53      2     script_public_key.version             u16 little-endian
55      8     script_public_key.script().len()      u64 little-endian
63      L     script_public_key.script()            raw bytes
------  ----
total = 63 + L bytes
```

Three things worth calling out because they are easy to get wrong in a reimplementation:

1. **DAA score precedes amount.** The field order in the `UtxoEntry` struct declaration is
   `amount, script_public_key, block_daa_score, is_coinbase` — the *hashed* order is
   different. Follow `write_utxo`, not the struct.
2. **The script length is 8 bytes, not a varint.** `write_len` is a fixed `u64` LE.
3. **The domain separator is a Blake2b key**, so a reimplementation that prefixes
   `b"MuHashElement"` to the message produces a different digest.

Transaction-level driver (`consensus/core/src/muhash.rs:16`, `add_transaction`): for each
populated input, `write_utxo` into the **remove** field using the input's
`previous_outpoint` and the input's own resolved entry (so the entry's original DAA score
and coinbase flag, not the spending block's); for each output `i`, add a UTXO with
`outpoint = (tx_id, i)`, `block_daa_score = block_daa_score` (the POV block's DAA score,
passed in), `is_coinbase = tx.is_coinbase()`.

---

## 3. Every site comparing a locally computed MuHash against a header `utxo_commitment`

**Consensus-critical comparisons (a mismatch rejects data):**

| # | Site | What it does |
|---|---|---|
| 1 | `consensus/src/pipeline/virtual_processor/utxo_validation.rs:189-192` | `verify_expected_utxo_state`: `ctx.multiset_hash.finalize()` vs `header.utxo_commitment`; mismatch → `RuleError::BadUTXOCommitment`, which disqualifies the block from the virtual chain. This is *the* consensus check. |
| 2 | `consensus/src/pipeline/virtual_processor/processor.rs:1291-1297` | `import_pruning_point_utxo_set`: the multiset accumulated over the UTXO set received during IBD vs `new_pruning_point_header.utxo_commitment`; mismatch → `PruningImportError::ImportedMultisetHashMismatch`. |

**Assertion / sanity-check comparison (debug-style, gated):**

| # | Site | What it does |
|---|---|---|
| 3 | `consensus/src/pipeline/pruning_processor/processor.rs:286-295` | `assert_utxo_commitment`: rebuilds a `MuHash` by iterating the whole pruning-point UTXO set and `assert_eq!`s against the header. Called from line 281 only when `self.config.enable_sanity_checks`. |

**Production side (computed commitment written into a header, not compared):**

| # | Site | What it does |
|---|---|---|
| 4 | `consensus/src/pipeline/virtual_processor/processor.rs:1208` | `build_block_template`: `virtual_state.multiset.clone().finalize()` becomes the new header's `utxo_commitment`. |
| 5 | `consensus/src/consensus/utxo_set_override.rs:14-22` | `set_genesis_utxo_commitment_from_config` (feature `devnet-prealloc` only): derives `config.params.genesis.utxo_commitment` from the preallocated UTXO set. |

**Test-only derivations** (same pattern as #5, listed for completeness, all in
`testing/integration/src/consensus_integration_tests.rs`): lines 1445, 1568, 1671, 1780
set `cfg.params.genesis.utxo_commitment` from a locally built multiset; lines 820-825,
1455-1457, 1575-1577 drive `import_pruning_point_utxo_set` (i.e. exercise comparison #2).

**Where the multiset that feeds #1 is built** — worth knowing because a shadow accumulator
has to be teed in at the same points:

- `consensus/src/pipeline/virtual_processor/utxo_validation.rs:94` — context seeded from the
  selected parent's stored multiset (`utxo_multisets_store`).
- `.../utxo_validation.rs:120` — selected-parent coinbase folded in via `add_transaction`.
- `.../utxo_validation.rs:141-144` — per-block transactions validated and hashed in parallel
  by `validate_transactions_with_muhash_in_parallel` (line 282), which builds one `MuHash`
  per tx via `MuHash::from_transaction` and `reduce`s them with `combine`; the block result
  is folded into the context with `ctx.multiset_hash.combine(&inner_multiset)`. Note this
  path relies on commutativity/associativity of `combine` for determinism under rayon.
- Persisted per chain block by `commit_utxo_state`
  (`consensus/src/pipeline/virtual_processor/processor.rs:519`) into
  `consensus/src/model/stores/utxo_multisets.rs` (stored as a normalized `Uint3072`; the
  store `expect`s the multiset to be normalizable — `utxo_multisets.rs:46,66`).

---

## 4. Where UTXO diffs are applied and reverted

### 4a. The diff type and its add/remove primitives

`consensus/core/src/utxo/utxo_diff.rs`:

- `UtxoDiff { add: UtxoCollection, remove: UtxoCollection }`.
- `add_transaction` (line 224) — mirrors `MuHashExtensions::add_transaction`: `remove_entry`
  for every populated input, `add_entry` for every output.
- `remove_entry` (line 240) — if the outpoint is in `add` with the same DAA score, cancel it
  out of `add`; else insert into `remove`; else `DoubleRemoveCall` error.
- `add_entry` (line 251) — symmetric: cancel from `remove` if present with matching DAA
  score, else insert into `add`, else `DoubleAddCall`.
- `with_diff_in_place(other)` (line 87) — composes two diffs (apply-first-then-second),
  with duplicate-add / duplicate-remove rejection.
- `as_reversed()` (line 71) / `to_reversed()` (line 75) — swap `add` and `remove`. This is
  the revert primitive; `ReversedUtxoDiff` (line 57-62) is the zero-copy view.
- `diff_from(other)` (line 150) — difference of two diffs sharing a base.

### 4b. Application to the persisted UTXO set

- `consensus/src/model/stores/utxo_set.rs:107` `write_diff_batch` — deletes
  `utxo_diff.removed()` keys, writes `utxo_diff.added()`. Batched form, used by virtual.
- `consensus/src/model/stores/utxo_set.rs:165` `write_diff` — the direct (non-batch) form.
- `consensus/src/model/stores/utxo_set.rs:172` `write_many` — bulk insert, used on
  pruning-point UTXO import.

Call sites:

- `consensus/src/pipeline/virtual_processor/processor.rs:605` — `commit_virtual_state`
  applies the accumulated diff to virtual's UTXO set inside the same `WriteBatch` that
  updates virtual state and the selected chain.
- `consensus/src/pipeline/pruning_processor/processor.rs:272-275` — advances the
  pruning-point UTXO set forward along the chain by applying each chain block's stored diff.

### 4c. The reorg / backout path

`consensus/src/pipeline/virtual_processor/processor.rs:410` `calculate_utxo_state_relatively`
is the reorg core. Given `from` (current diff point) and `to` (candidate):

1. If `to` is already `StatusDisqualifiedFromChain`, bail out returning `from` (no work).
2. **Backout leg** (lines 419-428): walk `default_backward_chain_iterator(from)` until a
   block that is a chain ancestor of `to` is found (the split point). For every block passed
   on the way down, fetch its stored mergeset diff and apply it *in reverse*:
   ```rust
   let mergeset_diff = self.utxo_diffs_store.get(current).unwrap();
   diff.with_diff_in_place(&mergeset_diff.as_reversed()).unwrap();
   ```
3. **Forward leg** (lines 440-503): walk `forward_chain_iterator(split_point, to, true)`. If
   the block already has a stored diff, compose it forward
   (`diff.with_diff_in_place(mergeset_diff.deref())`). If not, compute UTXO state from
   scratch (`calculate_utxo_state`), verify it (`verify_expected_utxo_state` — comparison #1
   above), and on success compose the diff forward and `commit_utxo_state`. On failure the
   block is marked `StatusDisqualifiedFromChain` and the diff point stops advancing.

Entry points into that path:

- `resolve_virtual` (`processor.rs:305`) seeds `accumulated_diff` with
  `prev_state.utxo_diff.clone().to_reversed()` — i.e. it starts by undoing virtual's own
  diff — then calls `sink_search_algorithm` (line 657) or, when the DagKnight executor is
  present, `sink_search_algorithm_v2` (line 724). Both drive
  `calculate_utxo_state_relatively` per candidate.
- The multiset is **not** rolled back symmetrically: on a reorg the new sink's multiset is
  re-read wholesale from `utxo_multisets_store` (`processor.rs:333`) and used as the seed for
  virtual's recomputation. So MuHash is never "un-added" across a reorg — only diffs are
  reversed, and the accumulator is restored by lookup. A shadow accumulator must either be
  persisted per chain block the same way or be recomputable, or it will drift on reorgs.

---

## 5. Has the DagKnight branch modified any of the above?

Method: `git diff <merge-base> HEAD` restricted to the files above, where
`merge-base = 6834c8e1 = git merge-base origin/master HEAD`.

**Caveat on "upstream", stated rather than guessed:** `origin` here is
`https://github.com/coderofstuff/rusty-kaspa.git`, a fork, not `kaspanet/rusty-kaspa`. This
report compares against `origin/master` of that fork. **I could not verify whether that
fork's `master` is identical to `kaspanet/rusty-kaspa` `master`** — there is no
`kaspanet` remote configured in this clone and I did not fetch one. If the fork's master
carries its own patches, they would be invisible to this comparison. Everything below
should be read as "relative to `origin/master` of the coderofstuff fork".

### Unmodified (byte-for-byte identical to the merge base)

- `crypto/muhash/` — the entire crate, including `u3072.rs`.
- `crypto/hashes/src/hashers.rs` — the Blake2b domain separators are unchanged.
- `consensus/core/src/muhash.rs` — **`write_utxo` is unchanged.** The element encoding the
  shadow implementation must match is upstream's.
- `consensus/core/src/hashing/mod.rs` — `write_len` / `write_bool` / `write_var_bytes` unchanged.
- `consensus/core/src/utxo/` — the whole UTXO diff/collection/view module is unchanged.
- `consensus/src/model/stores/utxo_multisets.rs`, `consensus/src/model/stores/utxo_set.rs` — unchanged.
- `consensus/src/consensus/utxo_set_override.rs` — unchanged.

### Modified, but not in a way that touches MuHash semantics

`git diff --stat` over the surveyed set:

```
consensus/src/model/stores/virtual_state.rs                  |  17 +-
consensus/src/pipeline/pruning_processor/processor.rs        |  55 ++++-
consensus/src/pipeline/virtual_processor/processor.rs        | 260 +++++++++++++++----
consensus/src/pipeline/virtual_processor/test_block_builder.rs |   7 +-
consensus/src/pipeline/virtual_processor/utxo_inquirer.rs     |   2 +-
consensus/src/pipeline/virtual_processor/utxo_validation.rs   |   2 +-
```

What those diffs actually are:

- **`utxo_validation.rs` — 1 line.** `self.ghostdag_store` → `self.coloring_ghostdag_store`
  in `consensus_ordered_mergeset_without_selected_parent`. The multiset accumulation
  (`add_transaction`, `combine`, `verify_expected_utxo_state`) is untouched. Note the
  *semantic* consequence though: the mergeset order fed into the multiset now comes from the
  coloring GHOSTDAG store rather than the single legacy store. MuHash is order-independent,
  so this cannot change the commitment value — but it does change which blocks are merged,
  which changes the multiset's *contents*. That is a DagKnight consensus change, not a hash
  change.
- **`virtual_state.rs`.** `ghostdag_data` split into `topology_ghostdag_data` and
  `coloring_ghostdag_data`. The `multiset: MuHash` field and its handling are unchanged.
- **`virtual_processor/processor.rs`.** The bulk of the diff is the DagKnight sink search
  (`sink_search_algorithm_v2`, new, line 724) plus the topology/coloring GHOSTDAG store
  split threaded through. `commit_utxo_state`, `commit_virtual_state`,
  `calculate_utxo_state_relatively`, the `utxo_commitment` computation at line 1208, and the
  `import_pruning_point_utxo_set` comparison at line 1292 are unchanged in substance.
  `resolve_virtual` gained a branch selecting v2 when a DagKnight executor is configured, and
  filters tips by the previous sink's merge-depth root (carrying a `TODO[DK]: Revisit this
  filtering logic`).
- **`pruning_processor/processor.rs`.** GHOSTDAG store split, plus new pruning of DagKnight
  and UMC-cascade records. `assert_utxo_commitment` (comparison #3) is unchanged.
- **`utxo_inquirer.rs`, `test_block_builder.rs`.** Store-split renames only.

### Bottom line for the shadow implementation

The element encoding, the expansion, the digest, and the diff algebra are all upstream.
DagKnight changes *which* blocks get merged and *when* the virtual state is recomputed, not
*how* a UTXO becomes bytes. An LtHash that matches `write_utxo` byte-for-byte will be
directly comparable against MuHash on this branch.

---

# Appendix — the MuHash encoding parity harness

`consensus/core/src/muhash.rs::write_utxo` is private, so the shadow crate's encoding cannot
be compared against it directly. It can be compared *through the accumulator*: if

```text
MuHash::new().add_utxo(op, entry).finalize()
  == MuHash::new().add_element(kaspa_lthash::encoding::encode_utxo(op, entry)).finalize()
```

then the two byte strings were equal, up to a Blake2b collision.

This harness was run once against commit `3b834c65` and reported `ALL_MATCH=true` for all
five cases (all-zero/empty script, coinbase with a 34-byte script, all-max fields,
asymmetric byte patterns, and a 600-byte script). Its output digests are frozen as golden
vectors in `crypto/lthash/tests/muhash_encoding_vectors.rs`.

It is deliberately **not** part of the `kaspa-lthash` crate — that crate must stay free of
consensus dependencies. Reproduce it in a scratch directory as follows.

`Cargo.toml`:

```toml
[package]
name = "muhash-parity"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[dependencies]
kaspa-lthash         = { path = "<repo>/crypto/lthash" }
kaspa-muhash         = { path = "<repo>/crypto/muhash" }
kaspa-consensus-core = { path = "<repo>/consensus/core" }
kaspa-hashes         = { path = "<repo>/crypto/hashes" }
blake2b_simd = "1.0"
```

**Important:** copy the repository's root `Cargo.lock` into the scratch directory before
building. Resolving these path dependencies freshly picks up a `wasm-bindgen`/`js-sys`
combination that fails to compile `workflow-core`; reusing the root lock pins the versions
the workspace actually uses.

`src/main.rs`:

```rust
use kaspa_consensus_core::muhash::MuHashExtensions;
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionOutpoint, UtxoEntry};
use kaspa_hashes::Hash;
use kaspa_lthash::encoding as lt;
use kaspa_muhash::MuHash;

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn main() {
    // (txid, index, amount, daa, coinbase, version, script) tuples -- see the crate's
    // tests/muhash_encoding_vectors.rs for the exact five cases used.
    let txid = [0xAAu8; 32];
    let (index, amount, daa, coinbase, version, script) =
        (1u32, 5_000_000_000u64, 123_456u64, true, 0u16, vec![0x20u8; 34]);

    // consensus path
    let outpoint = TransactionOutpoint::new(Hash::from_bytes(txid), index);
    let entry = UtxoEntry::new(amount, ScriptPublicKey::from_vec(version, script.clone()), daa, coinbase);
    let mut a = MuHash::new();
    a.add_utxo(&outpoint, &entry);

    // shadow path
    let bytes = lt::encode_utxo(
        &lt::Outpoint::new(txid, index),
        &lt::UtxoEntry::new(amount, lt::ScriptPublicKey::new(version, script), daa, coinbase),
    );
    let mut b = MuHash::new();
    b.add_element(&bytes);

    assert_eq!(a.finalize(), b.finalize(), "ENCODING MISMATCH");

    // The frozen witness baked into the crate's tests: MuHash's own element domain
    // separator applied to our bytes.
    let elem = blake2b_simd::Params::new()
        .hash_length(32)
        .key(b"MuHashElement")
        .to_state()
        .update(&bytes)
        .finalize();
    println!("{} {}", bytes.len(), hex(elem.as_bytes()));
}
```

Re-run this whenever `write_utxo`, `HasherExtensions`, or the `MuHashElementHash` domain
separator changes upstream. A silent divergence there makes the two accumulators
incomparable without any test failing in the consensus crates.

---

# What this survey informed

The LtHash crate lives in `crypto/lthash/`, a workspace member depending only on
`blake2b_simd`, `sha3` and `rand_chacha` (plus `proptest`/`rand` for tests) — **no dependency
on any consensus crate**, so the dependency edge runs one way.

```
crypto/lthash/
├── README.md                           # parameters, Wagner, benchmarks, live devnet results
├── INTEGRATION.md                      # shadow integration design + safety invariants
├── PARAMETER-REVIEW.md                 # the cryptographic review request
├── MUHASH-SURVEY.md                    # this document
├── src/
│   ├── lib.rs                          # LtHash: add/remove/union/serialize/digest
│   ├── params.rs                       # LtHashParams -- N and W as runtime values
│   ├── packing.rs                      # canonical little-endian state <-> bytes
│   ├── expand.rs                       # Blake2b-256 -> ChaCha20 element expansion
│   ├── encoding.rs                     # MuHash-identical UTXO serialization
│   └── reference.rs                    # naive BTreeMap reference, recomputes from scratch
├── benches/bench.rs                    # criterion, mirrors crypto/muhash/benches/bench.rs
└── tests/
    ├── properties.rs                   # 26 proptest properties incl. two 1e5-element tests
    └── muhash_encoding_vectors.rs      # frozen encoding vectors (see appendix above)
```

The findings that turned out to be load-bearing:

* **§2, the exact byte layout** — reproduced in `src/encoding.rs` and pinned by frozen vectors
  in both this crate and `consensus/core/src/muhash.rs`. This is what makes the two
  accumulators comparable at all.
* **§4c, the reorg path** — the accumulator is *never rolled back*; it is re-read wholesale
  from `utxo_multisets_store`. This is why the shadow is persisted per chain block with the
  same lifecycle rather than recomputed on demand, and why the drift check exists.
* **§5, the DagKnight delta** — the encoding and diff algebra are untouched relative to the
  fork's master, so an LtHash matching `write_utxo` is directly comparable on this branch.

`cargo test -p kaspa-lthash` — 41 passing (11 unit, 3 vector, 26 property, 1 doc).
`cargo test -p kaspa-consensus-core --lib muhash` — 3 encoding-parity tests.
