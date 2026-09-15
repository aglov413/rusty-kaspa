//! Deletes every row under the `ShadowLtHash` store prefix from a stopped node's database, so
//! the node rebuilds its shadow accumulator on the next start.
//!
//! # When you need this
//!
//! Whenever the LtHash **element expansion changes** (the `construction` tag in
//! `crypto/lthash/src/expand.rs`, currently `b2c2`). Values produced by two different
//! constructions are numerically unrelated, so a shadow accumulated under the old one is not
//! merely stale, it is meaningless under the new one.
//!
//! The node will not notice on its own. `backfill_shadow_if_needed`
//! (`consensus/src/pipeline/virtual_processor/processor.rs`) rebuilds only when the shadow is
//! *absent* at the sink:
//!
//! ```text
//! if store.get(sink).is_ok() { return ShadowBackfillOutcome::Skipped; }
//! ```
//!
//! So a node restarted on a new expansion against an existing database skips the backfill and
//! folds new-construction values into old-construction state. The drift check then reports
//! failures that are stale data rather than real divergence. Clearing the prefix restores the
//! absent case and lets the node rebuild from the pruning-point UTXO set.
//!
//! The alternative is `kaspad --reset-db`, which discards the entire database and resyncs from
//! scratch. This exists so operators running `--shadow-lthash` do not have to pay that for what
//! is a research-only store.
//!
//! # Why it is safe
//!
//! `ShadowLtHash = 200` is the highest discriminant in `DatabaseStorePrefixes` (the next
//! highest is `CirculatingSupply = 194`), so `[200] .. [201]` covers exactly this store and
//! nothing else. The shadow is also structurally unreachable from validation --
//! `ShadowedMuHash::finalize()` returns only the MuHash value -- so even a botched purge cannot
//! corrupt consensus state. Worst case the node rebuilds it, or you fall back to `--reset-db`.
//!
//! The node must be stopped: RocksDB holds an exclusive lock and this will refuse to open
//! otherwise, which is the guard against running it against a live node. That refusal arrives
//! as a panic carrying `IO error: While lock file ... Resource temporarily unavailable` --
//! it means the node is running, not that anything is wrong with the database.
//!
//! # Use
//!
//! ```bash
//! # stop the node first and wait for "Kaspad has stopped..."
//! cargo run --release -p kaspad --example purge_shadow_lthash -- \
//!     ~/.rusty-kaspa/kaspa-devnet/datadir/consensus/consensus-002
//! # review the count, then:
//! cargo run --release -p kaspad --example purge_shadow_lthash -- <datadir> --commit
//! ```
//!
//! Without `--commit` it only counts, so you can see what it would delete first. On the next
//! start, confirm the backfill actually runs rather than logging `Skipped`:
//!
//! ```bash
//! grep -E 'SHADOW-LTHASH|backfill' <logdir>/rusty-kaspa.log
//! ```

use std::path::PathBuf;

use kaspa_database::prelude::{ConnBuilder, DirectDbWriter};
use kaspa_database::registry::DatabaseStorePrefixes;

/// Inclusive lower / exclusive upper bound covering exactly the `ShadowLtHash` prefix.
const PREFIX: u8 = DatabaseStorePrefixes::ShadowLtHash as u8;

fn count_rows(db: &kaspa_database::prelude::DB) -> (usize, Option<Vec<u8>>) {
    let mut iter = db.raw_iterator();
    iter.seek([PREFIX]);
    let (mut count, mut first) = (0usize, None);
    while iter.valid() {
        match iter.key() {
            Some(key) if key.first() == Some(&PREFIX) => {
                if first.is_none() {
                    first = Some(key.to_vec());
                }
                count += 1;
                iter.next();
            }
            _ => break,
        }
    }
    (count, first)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let Some(datadir) = args.get(1) else {
        eprintln!("usage: purge_shadow_lthash <datadir> [--commit]");
        eprintln!("  <datadir> is the directory containing the consensus RocksDB,");
        eprintln!("  e.g. ~/.rusty-kaspa/kaspa-devnet/datadir/consensus/consensus-002");
        std::process::exit(2);
    };
    let commit = args.iter().any(|a| a == "--commit");

    println!("database      : {datadir}");
    println!("store prefix  : {PREFIX} (ShadowLtHash)");
    println!("range         : [{PREFIX}] .. [{}]", PREFIX + 1);
    println!("mode          : {}", if commit { "COMMIT - rows will be deleted" } else { "DRY RUN - counting only" });
    println!();

    // `ConnBuilder::build()` unwraps the RocksDB open internally, so a held lock surfaces as a
    // panic from conn_builder.rs rather than anything this program can dress up. Say what is
    // about to happen so that "IO error: While lock file ... Resource temporarily unavailable"
    // reads as "the node is still running" rather than as a bug in this tool.
    println!("opening the database (this fails with a LOCK error if the node is still running)...");
    let db = ConnBuilder::default()
        .with_db_path(PathBuf::from(datadir))
        .with_create_if_missing(false)
        .with_files_limit(128)
        .build()
        .expect("failed to open the database");
    println!();

    let (before, first) = count_rows(&db);
    println!("rows under prefix {PREFIX} before : {before}");
    if let Some(key) = &first {
        println!("first key                        : {}", key.iter().map(|b| format!("{b:02x}")).collect::<String>());
    }

    if before == 0 {
        println!("\nnothing to purge; the shadow store is already empty.");
        return;
    }
    if !commit {
        println!("\ndry run complete. re-run with --commit to delete these {before} rows.");
        return;
    }

    let mut writer = DirectDbWriter::new(&db);
    kaspa_database::prelude::DbWriter::delete_range(&mut writer, vec![PREFIX], vec![PREFIX + 1]).expect("delete_range failed");
    drop(writer);

    let (after, _) = count_rows(&db);
    println!("rows under prefix {PREFIX} after  : {after}");
    if after == 0 {
        println!("\npurge complete. restart the node and confirm the backfill runs:");
        println!("  grep -E 'SHADOW-LTHASH|backfill' <logdir>/rusty-kaspa.log");
    } else {
        eprintln!("\nWARNING: {after} rows remain under prefix {PREFIX}.");
        std::process::exit(1);
    }
}
