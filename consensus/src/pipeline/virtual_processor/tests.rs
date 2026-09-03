use crate::model::stores::{
    shadow_lthash::{ShadowLtHashStore, ShadowLtHashStoreReader},
    virtual_state::VirtualStateStoreReader,
};
use crate::pipeline::virtual_processor::processor::ShadowBackfillOutcome;
use crate::{consensus::test_consensus::TestConsensus, model::services::reachability::ReachabilityService};
use kaspa_consensus_core::{
    BlockHashSet,
    api::ConsensusApi,
    block::{Block, BlockTemplate, MutableBlock, TemplateBuildMode, TemplateTransactionSelector},
    blockhash,
    blockstatus::BlockStatus,
    coinbase::MinerData,
    config::{ConfigBuilder, params::MAINNET_PARAMS},
    tx::{ScriptPublicKey, ScriptVec, Transaction},
};
use kaspa_hashes::Hash;
use kaspa_lthash::{LtHash, LtHashParams};
use std::{collections::VecDeque, thread::JoinHandle};

struct OnetimeTxSelector {
    txs: Option<Vec<Transaction>>,
}

impl OnetimeTxSelector {
    fn new(txs: Vec<Transaction>) -> Self {
        Self { txs: Some(txs) }
    }
}

impl TemplateTransactionSelector for OnetimeTxSelector {
    fn select_transactions(&mut self) -> Vec<Transaction> {
        self.txs.take().unwrap()
    }

    fn reject_selection(&mut self, _tx_id: kaspa_consensus_core::tx::TransactionId) {
        unimplemented!()
    }

    fn is_successful(&self) -> bool {
        true
    }
}

struct TestContext {
    consensus: TestConsensus,
    join_handles: Vec<JoinHandle<()>>,
    miner_data: MinerData,
    simulated_time: u64,
    current_templates: VecDeque<BlockTemplate>,
    current_tips: BlockHashSet,
}

impl Drop for TestContext {
    fn drop(&mut self) {
        self.consensus.shutdown(std::mem::take(&mut self.join_handles));
    }
}

impl TestContext {
    fn new(consensus: TestConsensus) -> Self {
        let join_handles = consensus.init();
        let genesis_hash = consensus.params().genesis.hash;
        let simulated_time = consensus.params().genesis.timestamp;
        Self {
            consensus,
            join_handles,
            miner_data: new_miner_data(),
            simulated_time,
            current_templates: Default::default(),
            current_tips: BlockHashSet::from_iter([genesis_hash]),
        }
    }

    pub fn build_block_template_row(&mut self, nonces: impl Iterator<Item = usize>) -> &mut Self {
        for nonce in nonces {
            self.simulated_time += self.consensus.params().target_time_per_block();
            self.current_templates.push_back(self.build_block_template(nonce as u64, self.simulated_time));
        }
        self
    }

    pub fn assert_row_parents(&mut self) -> &mut Self {
        for t in self.current_templates.iter() {
            assert_eq!(self.current_tips, BlockHashSet::from_iter(t.block.header.direct_parents().iter().copied()));
        }
        self
    }

    pub async fn validate_and_insert_row(&mut self) -> &mut Self {
        self.current_tips.clear();
        while let Some(t) = self.current_templates.pop_front() {
            self.current_tips.insert(t.block.header.hash);
            self.validate_and_insert_block(t.block.to_immutable()).await;
        }
        self
    }

    pub async fn build_and_insert_disqualified_chain(&mut self, mut parents: Vec<Hash>, len: usize) -> Hash {
        // The chain will be disqualified since build_block_with_parents builds utxo-invalid blocks
        for _ in 0..len {
            self.simulated_time += self.consensus.params().target_time_per_block();
            let b = self.build_block_with_parents(parents, 0, self.simulated_time);
            parents = vec![b.header.hash];
            self.validate_and_insert_block(b.to_immutable()).await;
        }
        parents[0]
    }

    pub fn build_block_template(&self, nonce: u64, timestamp: u64) -> BlockTemplate {
        let mut t = self
            .consensus
            .build_block_template(
                self.miner_data.clone(),
                Box::new(OnetimeTxSelector::new(Default::default())),
                TemplateBuildMode::Standard,
            )
            .unwrap();
        t.block.header.timestamp = timestamp;
        t.block.header.nonce = nonce;
        t.block.header.finalize();
        t
    }

    pub fn build_block_with_parents(&self, parents: Vec<Hash>, nonce: u64, timestamp: u64) -> MutableBlock {
        let mut b = self.consensus.build_block_with_parents_and_transactions(blockhash::NONE, parents, Default::default());
        b.header.timestamp = timestamp;
        b.header.nonce = nonce;
        b.header.finalize(); // This overrides the NONE hash we passed earlier with the actual hash
        b
    }

    pub async fn validate_and_insert_block(&mut self, block: Block) -> &mut Self {
        let status = self.consensus.validate_and_insert_block(block).virtual_state_task.await.unwrap();
        assert!(status.has_block_body());
        self
    }

    pub fn assert_tips(&mut self) -> &mut Self {
        assert_eq!(BlockHashSet::from_iter(self.consensus.get_tips().into_iter()), self.current_tips);
        self
    }

    pub fn assert_tips_num(&mut self, expected_num: usize) -> &mut Self {
        assert_eq!(BlockHashSet::from_iter(self.consensus.get_tips().into_iter()).len(), expected_num);
        self
    }

    pub fn assert_virtual_parents_subset(&mut self) -> &mut Self {
        assert!(self.consensus.get_virtual_parents().is_subset(&self.current_tips));
        self
    }

    pub fn assert_valid_utxo_tip(&mut self) -> &mut Self {
        // Assert that at least one body tip was resolved with valid UTXO
        assert!(self.consensus.body_tips().iter().copied().any(|h| self.consensus.block_status(h) == BlockStatus::StatusUTXOValid));
        self
    }
}

#[tokio::test]
async fn template_mining_sanity_test() {
    let config = ConfigBuilder::new(MAINNET_PARAMS).skip_proof_of_work().build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let rounds = 10;
    let width = 3;
    for _ in 0..rounds {
        ctx.build_block_template_row(0..width)
            .assert_row_parents()
            .validate_and_insert_row()
            .await
            .assert_tips()
            .assert_virtual_parents_subset()
            .assert_valid_utxo_tip();
    }
}

#[tokio::test]
async fn antichain_merge_test() {
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Build a large 32-wide antichain
    ctx.build_block_template_row(0..32)
        .validate_and_insert_row()
        .await
        .assert_tips()
        .assert_virtual_parents_subset()
        .assert_valid_utxo_tip();

    // Mine a long enough chain s.t. the antichain is fully merged
    for _ in 0..32 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }
    ctx.assert_tips_num(1);
}

#[tokio::test]
async fn basic_utxo_disqualified_test() {
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Mine a valid chain
    for _ in 0..10 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }

    // Get current sink
    let sink = ctx.consensus.get_sink();

    // Mine a longer disqualified chain
    let disqualified_tip = ctx.build_and_insert_disqualified_chain(vec![config.genesis.hash], 20).await;

    assert_ne!(sink, disqualified_tip);
    assert_eq!(sink, ctx.consensus.get_sink());
    assert_eq!(BlockHashSet::from_iter([sink, disqualified_tip]), BlockHashSet::from_iter(ctx.consensus.get_tips().into_iter()));
    assert!(!ctx.consensus.get_virtual_parents().contains(&disqualified_tip));
}

#[tokio::test]
async fn double_search_disqualified_test() {
    // TODO: add non-coinbase transactions and concurrency in order to complicate the test

    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            p.min_difficulty_window_size = p.difficulty_window_size;
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Mine 3 valid blocks over genesis
    ctx.build_block_template_row(0..3)
        .validate_and_insert_row()
        .await
        .assert_tips()
        .assert_virtual_parents_subset()
        .assert_valid_utxo_tip();

    // Mark the one expected to remain on virtual chain
    let original_sink = ctx.consensus.get_sink();

    // Find the roots to be used for the disqualified chains
    let mut virtual_parents = ctx.consensus.get_virtual_parents();
    assert!(virtual_parents.remove(&original_sink));
    let mut iter = virtual_parents.into_iter();
    let root_1 = iter.next().unwrap();
    let root_2 = iter.next().unwrap();
    assert_eq!(iter.next(), None);

    // Mine a valid chain
    for _ in 0..10 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }

    // Get current sink
    let sink = ctx.consensus.get_sink();

    assert!(ctx.consensus.reachability_service().is_chain_ancestor_of(original_sink, sink));

    // Mine a long disqualified chain
    let disqualified_tip_1 = ctx.build_and_insert_disqualified_chain(vec![root_1], 30).await;

    // And another shorter disqualified chain
    let disqualified_tip_2 = ctx.build_and_insert_disqualified_chain(vec![root_2], 20).await;

    assert_eq!(ctx.consensus.get_block_status(root_1), Some(BlockStatus::StatusUTXOValid));
    assert_eq!(ctx.consensus.get_block_status(root_2), Some(BlockStatus::StatusUTXOValid));

    assert_ne!(sink, disqualified_tip_1);
    assert_ne!(sink, disqualified_tip_2);
    assert_eq!(sink, ctx.consensus.get_sink());
    assert_eq!(
        BlockHashSet::from_iter([sink, disqualified_tip_1, disqualified_tip_2]),
        BlockHashSet::from_iter(ctx.consensus.get_tips().into_iter())
    );
    assert!(!ctx.consensus.get_virtual_parents().contains(&disqualified_tip_1));
    assert!(!ctx.consensus.get_virtual_parents().contains(&disqualified_tip_2));

    // Mine a long enough valid chain s.t. both disqualified chains are fully merged
    for _ in 0..30 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }
    ctx.assert_tips_num(1);
}

/// The backfill has to reproduce, byte for byte, the shadow the pipeline built incrementally.
///
/// This is the one thing that must be true of it: a backfill that is subtly wrong produces a
/// shadow that looks fine and drifts silently, which is exactly the failure mode the shadow
/// exists to detect. So the test mines a chain with the shadow enabled, keeps the incrementally
/// accumulated value, wipes every stored entry, and asserts the backfill rebuilds the same value
/// at the sink -- and at the intermediate chain blocks, which the drift check and the reorg path
/// both depend on.
#[tokio::test]
async fn shadow_lthash_backfill_reproduces_the_incremental_shadow() {
    let config = ConfigBuilder::new(MAINNET_PARAMS).skip_proof_of_work().enable_shadow_lthash().build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Enough rows to give the chain real UTXO diffs to replay: every chain block spends nothing
    // but adds a coinbase output, and merged blocks contribute rewards of their own.
    for _ in 0..10 {
        ctx.build_block_template_row(0..3).validate_and_insert_row().await.assert_valid_utxo_tip();
    }

    let vp = ctx.consensus.virtual_processor().clone();
    let store = vp.shadow_lthash_store.as_ref().expect("the shadow is enabled for this config").clone();
    let genesis = ctx.consensus.params().genesis.hash;
    let sink = ctx.consensus.virtual_stores().read().state.get().unwrap().coloring_ghostdag_data.selected_parent;
    assert_ne!(sink, genesis, "the chain must have advanced for this test to mean anything");

    // The values the running pipeline produced, which the backfill has to match.
    let chain: Vec<Hash> = vp.reachability_service.forward_chain_iterator(genesis, sink, true).collect();
    let expected: Vec<_> = chain.iter().map(|&h| store.get(h).expect("a shadow per chain block").digest()).collect();

    // Wipe the shadow, leaving exactly the state of a chain synced without the flag.
    for &h in chain.iter() {
        store.delete(h).unwrap();
    }
    assert!(store.get(sink).is_err(), "the shadow must actually be gone for the backfill to be exercised");

    vp.backfill_shadow_if_needed();

    let rebuilt: Vec<_> = chain.iter().map(|&h| store.get(h).expect("the backfill writes every chain block").digest()).collect();
    assert_eq!(expected, rebuilt, "the backfilled shadow diverges from the incrementally accumulated one");
}

/// The backfill must leave a chain that already carries a shadow completely untouched, and must
/// do nothing at all when the flag is off. Both are the invariant-3 cases: it can only ever add a
/// shadow where there was none.
#[tokio::test]
async fn shadow_lthash_backfill_is_a_noop_when_not_needed() {
    let config = ConfigBuilder::new(MAINNET_PARAMS).skip_proof_of_work().enable_shadow_lthash().build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    for _ in 0..5 {
        ctx.build_block_template_row(0..3).validate_and_insert_row().await.assert_valid_utxo_tip();
    }

    let vp = ctx.consensus.virtual_processor().clone();
    let store = vp.shadow_lthash_store.as_ref().unwrap().clone();
    let sink = ctx.consensus.virtual_stores().read().state.get().unwrap().coloring_ghostdag_data.selected_parent;
    let before = store.get(sink).unwrap().digest();

    vp.backfill_shadow_if_needed();
    assert_eq!(before, store.get(sink).unwrap().digest());

    // And with the shadow disabled the store does not exist, so there is nothing to backfill.
    let plain_config = ConfigBuilder::new(MAINNET_PARAMS).skip_proof_of_work().build();
    let plain_ctx = TestContext::new(TestConsensus::new(&plain_config));
    let plain_vp = plain_ctx.consensus.virtual_processor().clone();
    assert!(plain_vp.shadow_lthash_store.is_none());
    plain_vp.backfill_shadow_if_needed();
}

/// The shape of the devnet procedure: a node runs with the shadow, then runs *without* it for a
/// while, then turns it back on. The earlier entries survive the gap -- pruning only deletes them
/// while the store exists -- so the replay lands on a stretch of states the pipeline accumulated
/// incrementally, and has to reproduce every one of them.
#[tokio::test]
async fn shadow_lthash_backfill_cross_checks_against_surviving_states() {
    let config = ConfigBuilder::new(MAINNET_PARAMS).skip_proof_of_work().enable_shadow_lthash().build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    for _ in 0..10 {
        ctx.build_block_template_row(0..3).validate_and_insert_row().await.assert_valid_utxo_tip();
    }

    let vp = ctx.consensus.virtual_processor().clone();
    let store = vp.shadow_lthash_store.as_ref().unwrap().clone();
    let genesis = ctx.consensus.params().genesis.hash;
    let sink = ctx.consensus.virtual_stores().read().state.get().unwrap().coloring_ghostdag_data.selected_parent;
    let chain: Vec<Hash> = vp.reachability_service.forward_chain_iterator(genesis, sink, true).collect();
    assert!(chain.len() > 4, "need a chain long enough to leave a surviving prefix");

    // Drop only the tail, as a shadow-less run would: the sink loses its state (which is what
    // triggers a backfill) while the earlier states remain as evidence.
    let dropped = 3;
    let expected_sink = store.get(sink).unwrap();
    for &h in chain.iter().rev().take(dropped) {
        store.delete(h).unwrap();
    }

    let outcome = vp.backfill_shadow_if_needed();

    // Every surviving state must have been reproduced exactly, or the backfill would have
    // abandoned instead of anchoring.
    let surviving = (chain.len() - dropped) as u64;
    assert_eq!(outcome, ShadowBackfillOutcome::Anchored { replayed: chain.len() as u64 - 1, agreed: surviving });
    assert_eq!(store.get(sink).unwrap(), expected_sink, "the re-derived sink state must match what was dropped");
}

/// A replayed state that disagrees with one the pipeline accumulated earlier must stop the
/// backfill dead: no shadow anchored at the sink, and the earlier states left untouched so the
/// disagreement can still be diagnosed. Writing on through a mismatch would replace a shadow that
/// may be the correct one with a chain of values that may not be.
#[tokio::test]
async fn shadow_lthash_backfill_abandons_on_a_mismatch() {
    let config = ConfigBuilder::new(MAINNET_PARAMS).skip_proof_of_work().enable_shadow_lthash().build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    for _ in 0..10 {
        ctx.build_block_template_row(0..3).validate_and_insert_row().await.assert_valid_utxo_tip();
    }

    let vp = ctx.consensus.virtual_processor().clone();
    let store = vp.shadow_lthash_store.as_ref().unwrap().clone();
    let genesis = ctx.consensus.params().genesis.hash;
    let sink = ctx.consensus.virtual_stores().read().state.get().unwrap().coloring_ghostdag_data.selected_parent;
    let chain: Vec<Hash> = vp.reachability_service.forward_chain_iterator(genesis, sink, true).collect();
    assert!(chain.len() > 3);

    // Corrupt a state partway along, and drop the sink's so a backfill is triggered at all.
    let corrupt_at = chain[chain.len() / 2];
    let mut wrong = LtHash::new(LtHashParams::default());
    wrong.add_element(b"a state that no UTXO set produces");
    store.insert(corrupt_at, &wrong).unwrap();
    store.delete(sink).unwrap();

    let outcome = vp.backfill_shadow_if_needed();

    assert!(matches!(outcome, ShadowBackfillOutcome::Abandoned { .. }), "a mismatch must abandon, got {outcome:?}");
    assert!(store.get(sink).is_err(), "no shadow may be anchored at the sink after a mismatch");
    assert_eq!(store.get(corrupt_at).unwrap(), wrong, "the disagreeing state must be left in place for diagnosis");
}

fn new_miner_data() -> MinerData {
    let secp = secp256k1::Secp256k1::new();
    let mut rng = rand::thread_rng();
    let (_sk, pk) = secp.generate_keypair(&mut rng);
    let script = ScriptVec::from_slice(&pk.serialize());
    MinerData::new(ScriptPublicKey::new(0, script), vec![])
}
