//! Publication privacy and wallet policy (`docs/PUBLICATION.md`) end to
//! end on the fake node: every connection through a SOCKS5 proxy and none
//! direct, a proxy that is down fails the command, a separate publication
//! route, a delayed broadcast, the deployment's anchor depth.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use bitcoin::ScriptBuf;
use sb_indexer::chain::fake::{FakeElectrum, FakeHttp, FakeSocks, Shared};
use sb_indexer::chain::mock::MockChain;

struct Cli {
    data: PathBuf,
    profile: PathBuf,
    chain: String,
    /// Extra global options (`--proxy`, `--publish-via`, `--delay`).
    global: Vec<String>,
}

impl Cli {
    fn run(&self, args: &[&str]) -> (bool, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_sb"))
            .arg("--profile")
            .arg(&self.profile)
            .arg("--data-dir")
            .arg(&self.data)
            .arg("--chain")
            .arg(&self.chain)
            .arg("--passphrase-file")
            .arg(self.data.join("pass"))
            .args(&self.global)
            .args(args)
            .env_remove("SB_PROXY")
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text)
    }

    fn ok(&self, args: &[&str]) -> String {
        let (ok, text) = self.run(args);
        assert!(ok, "`sb {}` failed:\n{text}", args.join(" "));
        text
    }

    fn fails(&self, args: &[&str], needle: &str) {
        let (ok, text) = self.run(args);
        assert!(
            !ok,
            "`sb {}` unexpectedly succeeded:\n{text}",
            args.join(" ")
        );
        assert!(
            text.contains(needle),
            "`sb {}` error lacks {needle:?}:\n{text}",
            args.join(" ")
        );
    }

    fn with(&self, global: &[&str]) -> Cli {
        Cli {
            data: self.data.clone(),
            profile: self.profile.clone(),
            chain: self.chain.clone(),
            global: global.iter().map(|s| s.to_string()).collect(),
        }
    }
}

fn field<'a>(text: &'a str, label: &str) -> &'a str {
    text.lines()
        .find(|l| l.starts_with(label))
        .unwrap_or_else(|| panic!("{label} not in:\n{text}"))
        .split_whitespace()
        .last()
        .unwrap()
}

fn script_of(addr: &str) -> ScriptBuf {
    addr.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
        .unwrap()
        .assume_checked()
        .script_pubkey()
}

fn balance(text: &str) -> u64 {
    text.lines()
        .find(|l| l.starts_with("balance"))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

fn outbox_label(text: &str) -> String {
    let path = field(text, "envelope (");
    Path::new(path)
        .file_stem()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

/// `proving (anchor H, tree size N)…` → H.
fn anchor_of(text: &str) -> u32 {
    let line = text
        .lines()
        .find(|l| l.starts_with("proving (anchor"))
        .unwrap_or_else(|| panic!("no proving line in:\n{text}"));
    line.split("anchor ")
        .nth(1)
        .unwrap()
        .split(',')
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn proxy_route_delay_and_anchor_policy() {
    let dir = std::env::temp_dir().join(format!("sb-publication-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pass"), "pw\n").unwrap();
    let mut chain = MockChain::new(10);
    chain.push_block(vec![]);
    chain.push_block(vec![]);
    let shared = Shared::new(chain);
    let http = FakeHttp::start(shared.clone());
    let esplora_port = http.addr.port().to_string();
    let socks = FakeSocks::start();
    let direct = Cli {
        data: dir.clone(),
        profile: dir.join("profile.json"),
        chain: format!("esplora:{}", http.esplora_url()),
        global: vec![],
    };
    let proxied = direct.with(&["--proxy", &socks.url()]);
    let mut salt = 100u32;
    let mut mine = |n: u32| {
        for _ in 0..n {
            salt += 1;
            shared.mine(salt);
        }
    };

    // a deployment whose wallets anchor two blocks below the tip (with a
    // dev boundary, so that the mint works)
    direct.ok(&[
        "profile-new",
        "--name",
        "tmp",
        "--network",
        "regtest",
        "--activation",
        "12",
    ]);
    let op = direct.ok(&["wallet-new", "--name", "operator"]);
    let op_shielded = field(&op, "shielded address:").to_string();
    let op_funding = field(&op, "funding address:").to_string();
    let written = direct.ok(&[
        "profile-new",
        "--name",
        "pub",
        "--network",
        "regtest",
        "--activation",
        "12",
        "--anchor-depth",
        "2",
        "--vault-script",
        &hex::encode(script_of(&op_funding).as_bytes()),
        "--operator-address",
        &op_shielded,
    ]);
    assert!(written.contains("\"anchor_depth\": 2"), "{written}");
    let alice = direct.ok(&["wallet-new", "--name", "alice"]);
    let alice_funding = field(&alice, "funding address:").to_string();
    let bob = direct.ok(&["wallet-new", "--name", "bob"]);
    let bob_shielded = field(&bob, "shielded address:").to_string();
    shared.fund(&script_of(&alice_funding), 300_000);
    mine(1);

    // 1. everything through the proxy: the sync and the mint's broadcast
    //    reach the fake Esplora only through the SOCKS CONNECTs
    let synced = proxied.ok(&["sync"]);
    assert!(synced.contains("blocks:"), "{synced}");
    let via_proxy = || {
        socks
            .targets
            .lock()
            .unwrap()
            .iter()
            .filter(|t| t.ends_with(&format!(":{esplora_port}")))
            .count()
    };
    let after_sync = via_proxy();
    assert!(
        after_sync >= 3,
        "sync made {after_sync} proxied connections"
    );
    proxied.ok(&[
        "mint",
        "--name",
        "alice",
        "--amount",
        "20000",
        "--fee-rate",
        "1",
    ]);
    assert!(
        via_proxy() > after_sync,
        "the broadcast went through the proxy"
    );
    assert_eq!(shared.mempool.lock().unwrap().len(), 1);
    // a proxy that is not there: no direct fallback
    direct
        .with(&["--proxy", "socks5://127.0.0.1:1"])
        .fails(&["sync"], "socks5 proxy");
    direct
        .with(&["--proxy", "http://127.0.0.1:1"])
        .fails(&["sync"], "only socks5");
    mine(3);
    direct.ok(&["sync"]);
    assert_eq!(balance(&direct.ok(&["scan", "--name", "alice"])), 20000);
    // the other kinds of egress: Electrum (raw TCP), Bitcoin Core RPC, and
    // a relayer, each reached only through the proxy
    let electrum = FakeElectrum::start(shared.clone());
    let electrum_port = electrum.addr.port();
    let via = |port: u16| {
        socks
            .targets
            .lock()
            .unwrap()
            .iter()
            .filter(|t| t.ends_with(&format!(":{port}")))
            .count()
    };
    let mut over_electrum = proxied.with(&["--proxy", &socks.url()]);
    over_electrum.chain = format!("electrum:{}", electrum.url());
    assert!(over_electrum.ok(&["sync"]).contains("blocks:"));
    assert!(via(electrum_port) >= 1, "electrum through the proxy");
    let mut over_rpc = proxied.with(&["--proxy", &socks.url()]);
    over_rpc.chain = format!("rpc:{}:user:pass", http.rpc_url());
    let rpc_port: u16 = http.addr.port();
    let before = via(rpc_port);
    assert!(over_rpc.ok(&["sync"]).contains("blocks:"));
    assert!(via(rpc_port) > before, "rpc through the proxy");
    // a relayer in its own data directory, submitted to through the proxy
    let relay_dir = dir.join("relay");
    std::fs::create_dir_all(&relay_dir).unwrap();
    std::fs::write(relay_dir.join("pass"), "relay pw\n").unwrap();
    let relay_cli = Cli {
        data: relay_dir.clone(),
        profile: direct.profile.clone(),
        chain: direct.chain.clone(),
        global: vec![],
    };
    let relay_wallet = relay_cli.ok(&["wallet-new", "--name", "relay"]);
    shared.fund(
        &script_of(field(&relay_wallet, "funding address:")),
        100_000,
    );
    mine(1);
    let server = Command::new(env!("CARGO_BIN_EXE_sb"))
        .arg("--profile")
        .arg(&relay_cli.profile)
        .arg("--data-dir")
        .arg(&relay_cli.data)
        .arg("--chain")
        .arg(&relay_cli.chain)
        .arg("--passphrase-file")
        .arg(relay_dir.join("pass"))
        .args([
            "relay-serve",
            "--name",
            "relay",
            "--listen",
            "127.0.0.1:0",
            "--fee-rate",
            "1",
            "--max-requests",
            "1",
        ])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    struct KillOnDrop(std::process::Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut server = KillOnDrop(server);
    let relay_url = {
        use std::io::BufRead;
        let mut line = String::new();
        std::io::BufReader::new(server.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let start = line.find("http://").unwrap();
        line[start..].split_whitespace().next().unwrap().to_string()
    };
    let relay_port: u16 = relay_url.rsplit(':').next().unwrap().parse().unwrap();
    direct.ok(&["sync"]);
    let relayed = proxied.ok(&[
        "send",
        "--name",
        "alice",
        "--to",
        &bob_shielded,
        "--amount",
        "700",
        "--fee-rate",
        "1",
        "--relay",
        &relay_url,
    ]);
    assert!(relayed.contains("relayed by"), "{relayed}");
    assert_eq!(
        via(relay_port),
        1,
        "the relayer was reached through the proxy"
    );
    drop(server);
    mine(3);
    direct.ok(&["sync"]);
    assert_eq!(balance(&direct.ok(&["scan", "--name", "bob"])), 700);

    // 2. the anchor is the deployment's depth below the tip
    let status = direct.ok(&["status"]);
    let tip: u32 = status
        .lines()
        .find(|l| l.starts_with("replayed to Some("))
        .unwrap_or_else(|| panic!("no tip in:\n{status}"))
        .split("Some(")
        .nth(1)
        .unwrap()
        .split(')')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let sent = direct.ok(&[
        "send",
        "--name",
        "alice",
        "--to",
        &bob_shielded,
        "--amount",
        "1000",
        "--fee-rate",
        "1",
        "--no-broadcast",
    ]);
    // depth 2 before the next block: the anchor is one block below the tip
    assert_eq!(anchor_of(&sent), tip - 1, "{sent}");
    let label = outbox_label(&sent);

    // 3. a separate publication route: a dead one fails the broadcast, the
    //    sync source untouched; a live one publishes
    direct
        .with(&["--publish-via", "esplora:http://127.0.0.1:1"])
        .fails(
            &["publish", &label, "--name", "alice", "--fee-rate", "1"],
            "127.0.0.1:1",
        );
    assert_eq!(shared.mempool.lock().unwrap().len(), 0);
    let second = FakeHttp::start(shared.clone());
    let routed = direct.with(&[
        "--publish-via",
        &format!("esplora:{}", second.esplora_url()),
        "--delay",
        "1-2",
    ]);
    let t0 = Instant::now();
    let published = routed.ok(&["publish", &label, "--name", "alice", "--fee-rate", "1"]);
    assert!(
        published.contains("holding the carrier for") && published.contains("--delay 1-2"),
        "{published}"
    );
    assert!(t0.elapsed().as_secs() >= 1, "the delay was observed");
    assert_eq!(shared.mempool.lock().unwrap().len(), 1);
    mine(3);
    direct.ok(&["sync"]);
    assert_eq!(balance(&direct.ok(&["scan", "--name", "bob"])), 1700);

    // 4. a delay that outlives the window is refused after it elapses: the
    //    profile's window is 100 blocks, so mine past it while holding
    let stale = direct.ok(&[
        "send",
        "--name",
        "alice",
        "--to",
        &bob_shielded,
        "--amount",
        "500",
        "--fee-rate",
        "1",
        "--no-broadcast",
    ]);
    let stale_label = outbox_label(&stale);
    mine(101);
    direct.with(&["--delay", "1"]).fails(
        &[
            "publish",
            &stale_label,
            "--name",
            "alice",
            "--fee-rate",
            "1",
        ],
        "outside the window",
    );
    assert_eq!(shared.mempool.lock().unwrap().len(), 0);
    // a bad delay spec
    direct
        .with(&["--delay", "5-2"])
        .fails(&["status"], "hi below lo");
    let _ = std::fs::remove_dir_all(&dir);
}
