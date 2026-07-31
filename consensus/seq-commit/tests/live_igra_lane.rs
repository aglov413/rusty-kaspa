// Copyright 2026 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Reconstruct a live IGRA lane's `seq_commit` from a node-served proof.
//!
//! # This file does not build inside zeth — run it from a `rusty-kaspa` checkout
//!
//! It depends on `kaspa-seq-commit`, `kaspa-smt` and `kaspa-hashes`, none of which are published
//! to crates.io. Adding them to zeth as git dependencies fails outright: `kaspa-hashes` pins
//! `js-sys "=0.3.77"`, which cannot coexist with zeth's tree (and would be hopeless inside a
//! risc0 guest). It is kept here as a record of the verification, not as part of the build.
//!
//! It lives on the **`zkprooftest`** branch of the `rusty-kaspa` fork (branched from `master`,
//! which carries both `consensus/seq-commit` and `crypto/txscript/src/zk_precompiles`). That
//! branch is the home for Kaspa-side testing supporting this work. Run it there:
//!
//! ```bash
//! cd ~/rusty-kaspa && git checkout zkprooftest
//! cargo test -p kaspa-seq-commit --test live_igra_lane      # 3 tests, all pass
//! ```
//!
//! This copy is the zeth-side record; keep the two in sync if either is edited.
//!
//! The `consensus/seq-commit` crate is upstream, not IGRA-private: it landed in
//! `kaspanet/rusty-kaspa` via PR #943 ("Kip21 impl", merged 2026-04-20).
//!
//! # What it proves
//!
//! Data captured from a live mainnet node via `GetSeqCommitLaneProof` (RPC 153, over wRPC JSON at
//! `ws://127.0.0.1:18110`) plus the block header. It verifies the chain end to end:
//!
//! `smt_leaf -> compute_root -> lanes_root -> activity_root -> seq_state_root -> seq_commit`
//!
//! and checks the result equals the header's `accepted_id_merkle_root`, which post-KIP-21 carries
//! `seq_commit`. That is the completeness guarantee the trustless exit route depends on: lane
//! activity is committed in the Kaspa header and therefore secured by proof of work.
//!
//! Two supporting tests keep the main one honest: `lane_key` is derived from the subnetwork id
//! alone (not taken from the node), and a forged `lane_tip` fails to reconstruct.
//!
//! To re-capture against a fresher block, see the "Viaduct and ATAN" section of `IGRA.md`.

use kaspa_hashes::{Hash, SeqCommitActiveNode};
use kaspa_seq_commit::hashing::*;
use kaspa_seq_commit::types::*;
use kaspa_smt::proof::OwnedSmtProof;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn h(s: &str) -> Hash {
    let mut b = [0u8; 32];
    b.copy_from_slice(&unhex(s));
    Hash::from_bytes(b)
}

// ── Captured from mainnet, block e6dc9e0c…e0b7d3ed (daa_score 500390375) ──────────────
const BLOCK_HASH: &str = "e6dc9e0c8ccd07772e605140cde7c0f20650daea1341545dfe1f5e52e0b7d3ed";
const EXPECTED_SEQ_COMMIT: &str = "d9a8ff7c8c30c7722a902bf168cb9354059c8bb7d897a9d250060b4ce57daa50";
const LANE_TIP: &str = "be67a6da3333469f7c08598b959bbb768fa3acc62cc39c5903df26163383b4d5";
const BLUE_SCORE: u64 = 498473436;
const INACTIVITY_SHORTCUT: &str = "37f51ff56a084f83c16e656dd1feaf4e203efd85ee9c43801f929a1c3999720a";
const PARENT_SEQ_COMMIT: &str = "f1dfec38dba93594622e7da41fc2ac2d8381080208f63c0c5f987f11989dc202";
const PAYLOAD_AND_CTX_DIGEST: &str = "c87d2229f9ea33cbc95279a4a1058d533f337a0251f5b982f3ee81638163e226";
/// Wire format `bitmap[32] || terminal || siblings`: `fd ff×31`, terminal `01` (Collapsed)
/// at depth `02`, then one 32-byte sibling.
const SMT_PROOF_HEX: &str = "fdffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
0102019e83d43b2c6431bb4c18a67851da5da81b5ac5c661e860473aff38961e64ed";

/// The IGRA lane: user-lane subnetwork id `[namespace(4), 0x16]` per KIP-21.
fn igra_lane_id() -> LaneId {
    let mut id = [0u8; 20];
    id[..4].copy_from_slice(&[0x97, 0xb1, 0x00, 0x00]);
    id
}

fn compute_seq_commit(lane_key: &Hash, proof: &OwnedSmtProof) -> Hash {
    let leaf = smt_leaf_hash(&SmtLeafInput { lane_tip: &h(LANE_TIP), blue_score: BLUE_SCORE });
    let lanes_root =
        proof.as_proof().compute_root::<SeqCommitActiveNode>(lane_key, Some(leaf)).expect("compute_root");
    let activity_root = activity_root_hash(&h(INACTIVITY_SHORTCUT), &lanes_root);
    let state_root = seq_state_root(&SeqState {
        activity_root: &activity_root,
        payload_and_ctx_digest: &h(PAYLOAD_AND_CTX_DIGEST),
    });
    seq_commit(&SeqCommitInput { parent_seq_commit: &h(PARENT_SEQ_COMMIT), state_root: &state_root })
}

/// The lane key is derived from the subnetwork id, not supplied by the node.
#[test]
fn lane_key_derives_from_subnetwork_id() {
    assert_eq!(
        lane_key(&igra_lane_id()),
        h("dd509ebf8d92e586adb13487fbdff211d6da4e498df807245baea080a0df092c"),
    );
}

/// The whole point: a node-served proof reconstructs the header's `seq_commit`.
#[test]
fn live_lane_proof_reconstructs_header_seq_commit() {
    let proof = OwnedSmtProof::from_bytes(&unhex(SMT_PROOF_HEX)).expect("parse smt proof");

    let got = compute_seq_commit(&lane_key(&igra_lane_id()), &proof);

    assert_eq!(
        got,
        h(EXPECTED_SEQ_COMMIT),
        "reconstructed seq_commit != accepted_id_merkle_root of block {BLOCK_HASH}",
    );
}

/// A forged lane tip must not reconstruct the committed value, or the check above is vacuous.
#[test]
fn forged_lane_tip_fails_to_reconstruct() {
    let proof = OwnedSmtProof::from_bytes(&unhex(SMT_PROOF_HEX)).expect("parse smt proof");

    // Same proof, but claim a different lane tip.
    let leaf = smt_leaf_hash(&SmtLeafInput { lane_tip: &h(PARENT_SEQ_COMMIT), blue_score: BLUE_SCORE });
    let lanes_root = proof
        .as_proof()
        .compute_root::<SeqCommitActiveNode>(&lane_key(&igra_lane_id()), Some(leaf))
        .expect("compute_root");
    let activity_root = activity_root_hash(&h(INACTIVITY_SHORTCUT), &lanes_root);
    let state_root = seq_state_root(&SeqState {
        activity_root: &activity_root,
        payload_and_ctx_digest: &h(PAYLOAD_AND_CTX_DIGEST),
    });
    let forged =
        seq_commit(&SeqCommitInput { parent_seq_commit: &h(PARENT_SEQ_COMMIT), state_root: &state_root });

    assert_ne!(forged, h(EXPECTED_SEQ_COMMIT), "a forged lane tip still matched the committed value");
}
