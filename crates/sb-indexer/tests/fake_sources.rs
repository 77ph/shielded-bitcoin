//! Esplora, Bitcoin Core RPC and Electrum sources against in-process fakes.

use bitcoin::ScriptBuf;
use bitcoin::hashes::Hash;

use sb_indexer::ChainSource;
use sb_indexer::chain::ChainError;
use sb_indexer::chain::electrum::Electrum;
use sb_indexer::chain::esplora::Esplora;
use sb_indexer::chain::fake::{FakeElectrum, FakeHttp, Shared};
use sb_indexer::chain::mock::MockChain;
use sb_indexer::chain::rpc::BitcoinCoreRpc;

fn chain() -> Shared {
    let mut c = MockChain::new(100);
    c.push_block(vec![]);
    c.push_block(vec![]);
    let s = Shared::new(c);
    s.fund(&ScriptBuf::from_bytes(vec![0x51]), 5000);
    s.mine(1);
    s
}

#[test]
fn esplora_source_and_errors() {
    let http = FakeHttp::start(chain());
    let e = Esplora::new(&http.esplora_url());
    let tip = e.tip().unwrap();
    assert_eq!(tip.height, 102);
    let hash = e.block_hash(101).unwrap().unwrap();
    let block = e.block(&hash).unwrap();
    assert_eq!(block.block_hash(), hash);
    assert_eq!(e.block_hash(500).unwrap(), None);
    assert!(e.block(&bitcoin::BlockHash::all_zeros()).is_err());
    // unreachable server → transport error
    let dead = Esplora::new("http://127.0.0.1:1");
    assert!(matches!(dead.tip(), Err(ChainError::Http(_))));
    assert_eq!(
        format!("{}", ChainError::NotFound("x".into())),
        "block x not found"
    );
}

#[test]
fn rpc_source_and_errors() {
    let http = FakeHttp::start(chain());
    let rpc = BitcoinCoreRpc::new(&http.rpc_url(), "u", "p");
    let tip = rpc.tip().unwrap();
    assert_eq!(tip.height, 102);
    let hash = rpc.block_hash(100).unwrap().unwrap();
    assert_eq!(rpc.block(&hash).unwrap().block_hash(), hash);
    assert_eq!(rpc.block_hash(999).unwrap(), None);
    assert!(matches!(
        rpc.call("nosuchmethod", serde_json::json!([])),
        Err(ChainError::Rpc(_))
    ));
    assert!(matches!(
        rpc.call("noresult", serde_json::json!([])),
        Err(ChainError::Rpc(_))
    ));
    assert!(rpc.block(&bitcoin::BlockHash::all_zeros()).is_err());
    // cookie files
    let dir = std::env::temp_dir().join(format!("sb-rpc-cov-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("cookie"), "__cookie__:secret\n").unwrap();
    let via_cookie = BitcoinCoreRpc::with_cookie(&http.rpc_url(), &dir.join("cookie")).unwrap();
    assert_eq!(via_cookie.tip().unwrap().height, 102);
    std::fs::write(dir.join("bad"), "nocolon").unwrap();
    assert!(BitcoinCoreRpc::with_cookie(&http.rpc_url(), &dir.join("bad")).is_err());
    assert!(BitcoinCoreRpc::with_cookie(&http.rpc_url(), &dir.join("missing")).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
    // unreachable
    assert!(matches!(
        BitcoinCoreRpc::new("http://127.0.0.1:1", "u", "p").tip(),
        Err(ChainError::Http(_))
    ));
}

#[test]
fn electrum_source_batching_merkle_and_reconnect() {
    let shared = chain();
    let srv = FakeElectrum::start(shared.clone());
    let e = Electrum::new(&srv.url()).unwrap();
    let tip = e.tip().unwrap();
    assert_eq!(tip.height, 102);
    let hash = e.block_hash(102).unwrap().unwrap();
    let block = e.block(&hash).unwrap();
    assert_eq!(block.txdata.len(), 2, "coinbase + funding tx");
    assert_eq!(block.block_hash(), hash);
    assert_eq!(e.block_hash(500).unwrap(), None);
    // unknown hash: height unknown
    assert!(matches!(
        e.block(&bitcoin::BlockHash::all_zeros()),
        Err(ChainError::NotFound(_))
    ));
    // listunspent / broadcast
    let script = ScriptBuf::from_bytes(vec![0x51]);
    let utxos = e.listunspent(&script).unwrap();
    assert_eq!(utxos.len(), 1);
    assert_eq!(utxos[0].2, 5000);
    assert!(utxos[0].3);
    assert_eq!(
        e.listunspent(&ScriptBuf::from_bytes(vec![0x52]))
            .unwrap()
            .len(),
        0
    );
    let tx = block.txdata[1].clone();
    assert_eq!(e.broadcast(&tx).unwrap(), tx.compute_txid());
    assert!(matches!(
        e.call(
            "blockchain.transaction.broadcast",
            serde_json::json!(["zz"])
        ),
        Err(ChainError::Rpc(_))
    ));
    assert!(matches!(
        e.call("nosuch", serde_json::json!([])),
        Err(ChainError::Rpc(_))
    ));
    assert_eq!(e.call_batch("x", &[]).unwrap().len(), 0);
    assert_eq!(Electrum::scripthash(&script).len(), 64);
    // the server drops the connection once: the client reconnects
    shared
        .drop_next
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(e.tip().unwrap().height, 102);
    // a server that hides a transaction fails the merkle check
    shared
        .truncate
        .store(true, std::sync::atomic::Ordering::SeqCst);
    match e.block(&hash) {
        Err(ChainError::Decode(msg)) => assert!(msg.contains("merkle"), "{msg}"),
        other => panic!("expected merkle mismatch, got {other:?}"),
    }
    shared
        .truncate
        .store(false, std::sync::atomic::Ordering::SeqCst);
    // URL parsing
    assert!(Electrum::new("ssl-pin://host:1").is_err());
    assert!(Electrum::new("ssl-pin://host:1/zz").is_err());
    assert!(Electrum::new("tcp://nocolon").is_err());
    assert!(Electrum::new("tcp://host:notaport").is_err());
    assert!(Electrum::new("ssl://host:1").is_ok());
    assert!(Electrum::new("host:1").is_ok());
    // unreachable server
    let dead = Electrum::new("tcp://127.0.0.1:1").unwrap();
    assert!(matches!(dead.tip(), Err(ChainError::Http(_))));
    assert!(
        Electrum::new("tcp://no.such.host.invalid:1")
            .unwrap()
            .tip()
            .is_err()
    );
    // an empty chain has no tip
    let empty = FakeElectrum::start(Shared::new(MockChain::new(1)));
    assert!(Electrum::new(&empty.url()).unwrap().tip().is_err());
}
