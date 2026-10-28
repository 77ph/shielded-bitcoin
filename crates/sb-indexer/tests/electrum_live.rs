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

/// Certificate pinning (`ssl-pin://`): the fingerprint is captured without
/// completing a handshake, a wrong pin fails the handshake, the right pin
/// connects. Checked against mempool.space (valid public certificate), then
/// best-effort against a self-signed public server.
#[test]
#[ignore]
fn certificate_pinning() {
    let host = "mempool.space";
    let fp = Electrum::fingerprint(host, 60602).unwrap();
    println!("{host} fingerprint sha256 {}", hex::encode(fp));
    let mut wrong = fp;
    wrong[0] ^= 1;
    let bad = Electrum::new(&format!("ssl-pin://{host}:60602/{}", hex::encode(wrong))).unwrap();
    assert!(bad.tip().is_err(), "wrong pin must fail the handshake");
    check(&format!("ssl-pin://{host}:60602/{}", hex::encode(fp)));

    // Self-signed server: public roots must reject it, the pin must accept it.
    let host = "signet-electrumx.wakiyamap.dev";
    match Electrum::fingerprint(host, 50002) {
        Ok(fp) => {
            println!("{host} fingerprint sha256 {}", hex::encode(fp));
            assert!(
                Electrum::new(&format!("ssl://{host}:50002"))
                    .unwrap()
                    .tip()
                    .is_err(),
                "public roots must reject a self-signed cert"
            );
            check(&format!("ssl-pin://{host}:50002/{}", hex::encode(fp)));
        }
        Err(e) => println!("{host} unreachable right now ({e}); self-signed check skipped"),
    }
}
