//! Live check of the Electrum source against public signet servers. Needs
//! network; run with `cargo test -p sb-indexer --release --test electrum_live -- --ignored --nocapture`.

use sb_indexer::ChainSource;
use sb_indexer::chain::electrum::Electrum;

fn check(url: &str) {
    let e = Electrum::new(url).unwrap();
    let tip = e.tip().unwrap();
    println!("{url}: tip {} {}", tip.height, tip.hash);
    assert!(tip.height > 300_000);
    let h = tip.height - 3;
    let hash = e.block_hash(h).unwrap().unwrap();
    let block = e.block(&hash).unwrap();
    assert_eq!(block.block_hash(), hash);
    println!(
        "  block {h}: {} txs, merkle root verified",
        block.txdata.len()
    );
    assert!(e.block_hash(tip.height + 100_000).unwrap().is_none());
}

#[test]
#[ignore]
fn mempool_space_signet() {
    check("ssl://mempool.space:60602");
}
