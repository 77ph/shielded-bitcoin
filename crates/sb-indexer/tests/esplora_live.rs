//! Live check of the Esplora source against public signet. Needs network;
//! run with `cargo test -p sb-indexer --release --test esplora_live -- --ignored --nocapture`.

use sb_indexer::ChainSource;
use sb_indexer::chain::esplora::Esplora;

#[test]
#[ignore]
fn signet_tip_and_block() {
    let e = Esplora::new("https://mempool.space/signet/api");
    let tip = e.tip().unwrap();
    println!("signet tip: {} {}", tip.height, tip.hash);
    assert!(tip.height > 200_000);
    let h = tip.height - 3;
    let hash = e.block_hash(h).unwrap().unwrap();
    let block = e.block(&hash).unwrap();
    assert_eq!(block.block_hash(), hash);
    println!(
        "block {h}: {} txs, {} op_return outputs",
        block.txdata.len(),
        block
            .txdata
            .iter()
            .flat_map(|t| &t.output)
            .filter(|o| o.script_pubkey.is_op_return())
            .count()
    );
    assert!(e.block_hash(tip.height + 100_000).unwrap().is_none());
}
