//! The `sb` binary end to end against in-process fake Esplora / RPC /
//! Electrum servers over a mock chain: profile, wallets, mint, private
//! payment, withdraw, operator payout, every backend and the error paths.

use std::path::{Path, PathBuf};
use std::process::Command;

use bitcoin::ScriptBuf;
use sb_indexer::chain::fake::{FakeElectrum, FakeHttp, Shared};
use sb_indexer::chain::mock::MockChain;

struct Cli {
    data: PathBuf,
    profile: PathBuf,
    chain: String,
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
            .args(args)
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
    field(text, "balance").parse().unwrap_or_else(|_| {
        text.lines()
            .find(|l| l.starts_with("balance"))
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap()
    })
}

#[test]
fn full_cycle_on_fake_node() {
    let dir = std::env::temp_dir().join(format!("sb-cli-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pass"), "test passphrase\n").unwrap();
    let mut chain = MockChain::new(10);
    chain.push_block(vec![]);
    chain.push_block(vec![]);
    let shared = Shared::new(chain);
    let http = FakeHttp::start(shared.clone());
    let electrum = FakeElectrum::start(shared.clone());
    let cli = Cli {
        data: dir.clone(),
        profile: dir.join("profile.json"),
        chain: format!("esplora:{}", http.esplora_url()),
    };

    // profile and wallets
    cli.fails(
        &[
            "profile-new",
            "--name",
            "e2e",
            "--network",
            "mainnet",
            "--activation",
            "12",
        ],
        "mainnet",
    );
    cli.fails(
        &[
            "profile-new",
            "--name",
            "e2e",
            "--network",
            "moon",
            "--activation",
            "12",
        ],
        "unknown network",
    );
    cli.ok(&[
        "profile-new",
        "--name",
        "e2e",
        "--network",
        "regtest",
        "--activation",
        "12",
    ]);
    cli.fails(&["address", "--name", "nobody"], "wallet nobody");
    let op = cli.ok(&["wallet-new", "--name", "operator"]);
    assert!(op.contains("encrypted"));
    cli.fails(&["wallet-new", "--name", "operator"], "exists");
    let op_shielded = field(&op, "shielded address:").to_string();
    let op_funding = field(&op, "funding address:").to_string();
    let vault_hex = hex::encode(script_of(&op_funding).as_bytes());
    cli.ok(&[
        "profile-new",
        "--name",
        "e2e",
        "--network",
        "regtest",
        "--activation",
        "12",
        "--vault-script",
        &vault_hex,
        "--operator-address",
        &op_shielded,
    ]);
    let alice = cli.ok(&["wallet-new", "--name", "alice"]);
    let alice_funding = field(&alice, "funding address:").to_string();
    let bob = cli.ok(&["wallet-new", "--name", "bob"]);
    let bob_shielded = field(&bob, "shielded address:").to_string();
    let bob_funding = field(&bob, "funding address:").to_string();
    let fresh = cli.ok(&["address", "--name", "alice", "--new"]);
    assert!(fresh.contains("receive path"));
    // plaintext wallet loads with a warning; re-keying an encrypted wallet works
    let plain = cli.ok(&["wallet-new", "--name", "plain", "--no-encrypt"]);
    assert!(plain.contains("plaintext"));
    assert!(cli.ok(&["address", "--name", "plain"]).contains("warning"));
    cli.ok(&["wallet-encrypt", "--name", "plain"]);
    assert!(!cli.ok(&["address", "--name", "plain"]).contains("warning"));
    // wrong passphrase
    std::fs::write(dir.join("pass2"), "wrong\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sb"))
        .args(["--profile"])
        .arg(&cli.profile)
        .args(["--data-dir"])
        .arg(&dir)
        .args(["--passphrase-file"])
        .arg(dir.join("pass2"))
        .args(["address", "--name", "alice"])
        .output()
        .unwrap();
    assert!(!out.status.success());

    // nothing yet
    assert!(cli.ok(&["status"]).contains("replayed to None"));
    cli.fails(
        &[
            "send",
            "--name",
            "alice",
            "--to",
            &bob_shielded,
            "--amount",
            "1",
        ],
        "sync",
    );
    shared.mine(0); // height 12 = activation
    cli.ok(&["sync"]);
    cli.fails(
        &[
            "send",
            "--name",
            "alice",
            "--to",
            &bob_shielded,
            "--amount",
            "1",
        ],
        "insufficient",
    );
    cli.fails(
        &["mint", "--name", "alice", "--amount", "100"],
        "no confirmed coins",
    );

    // fund alice transparently, mint 5000 into the shielded pool
    shared.fund(&script_of(&alice_funding), 100_000);
    shared.mine(1);
    assert!(
        cli.ok(&[
            "mint",
            "--name",
            "alice",
            "--amount",
            "5000",
            "--fee-rate",
            "1",
            "--no-broadcast"
        ])
        .contains("outbox")
    );
    let m = cli.ok(&[
        "mint",
        "--name",
        "alice",
        "--amount",
        "5000",
        "--fee-rate",
        "1",
    ]);
    assert!(m.contains("broadcast"), "{m}");
    shared.mine(2);
    cli.ok(&["sync"]);
    assert_eq!(balance(&cli.ok(&["scan", "--name", "alice"])), 5000);
    assert!(cli.ok(&["status"]).contains("Mint"));

    // private payment alice -> bob (anchor depth: two more blocks)
    shared.mine(3);
    shared.mine(4);
    cli.ok(&["sync"]);
    cli.fails(&["send", "--name", "alice", "--to", "tsb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq2k0ahk", "--amount", "1"], "bech32m");
    let s = cli.ok(&[
        "send",
        "--name",
        "alice",
        "--to",
        &bob_shielded,
        "--amount",
        "2000",
        "--fee-rate",
        "1",
    ]);
    assert!(s.contains("broadcast") && s.contains("locked"), "{s}");
    assert_eq!(
        balance(&cli.ok(&["scan", "--name", "alice"])),
        0,
        "inputs locked"
    );
    shared.mine(5);
    cli.ok(&["sync"]);
    assert_eq!(balance(&cli.ok(&["scan", "--name", "alice"])), 3000);
    assert_eq!(balance(&cli.ok(&["scan", "--name", "bob"])), 2000);
    // an unpublished transfer leaves a lock that unlock releases
    shared.mine(50);
    shared.mine(51);
    cli.ok(&["sync"]);
    cli.ok(&[
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
    assert_eq!(balance(&cli.ok(&["scan", "--name", "alice"])), 0);
    assert_eq!(balance(&cli.ok(&["unlock", "--name", "alice"])), 3000);

    // bob needs fee coins: alice pays transparently
    cli.ok(&[
        "fund-send",
        "--name",
        "alice",
        "--to",
        &bob_funding,
        "--amount",
        "20000",
        "--fee-rate",
        "1",
    ]);
    shared.mine(6);
    shared.mine(7);
    cli.ok(&["sync"]);
    // withdraw: dust refused, then 1000 to alice's funding address
    cli.fails(
        &[
            "withdraw",
            "--name",
            "bob",
            "--amount",
            "100",
            "--to",
            &alice_funding,
        ],
        "dust",
    );
    cli.fails(
        &[
            "withdraw",
            "--name",
            "bob",
            "--amount",
            "1000",
            "--to",
            "tb1qxtws5pnknuvxqhp9w6uvvcq6uyc3frszw83xjz",
        ],
        "not valid on",
    );
    let w = cli.ok(&[
        "withdraw",
        "--name",
        "bob",
        "--amount",
        "1000",
        "--to",
        &alice_funding,
        "--fee-rate",
        "1",
    ]);
    assert!(w.contains("operator pays"), "{w}");
    shared.mine(8);
    cli.ok(&["sync"]);
    assert_eq!(balance(&cli.ok(&["scan", "--name", "bob"])), 1000);
    let listed = cli.ok(&["payouts", "--name", "operator", "--no-broadcast"]);
    assert!(listed.contains("1 pending"), "{listed}");
    let paid = cli.ok(&["payouts", "--name", "operator", "--fee-rate", "1"]);
    assert!(paid.contains("paid in"), "{paid}");
    shared.mine(9);
    let got: Vec<u64> = shared
        .utxos(&script_of(&alice_funding))
        .into_iter()
        .map(|(_, v, _)| v)
        .collect();
    assert!(got.contains(&1000), "{got:?}");
    assert!(
        cli.ok(&["payouts", "--name", "operator"])
            .contains("0 pending")
    );

    // other backends over the same fake node (top alice up first)
    shared.fund(&script_of(&alice_funding), 50_000);
    shared.mine(20);
    let rpc = Cli {
        data: dir.clone(),
        profile: dir.join("profile.json"),
        chain: format!("rpc:{}:user:pass", http.rpc_url()),
    };
    assert!(rpc.ok(&["sync"]).contains("SyncReport"));
    rpc.ok(&[
        "fund-send",
        "--name",
        "alice",
        "--to",
        &bob_funding,
        "--amount",
        "1000",
        "--fee-rate",
        "1",
    ]);
    shared.mine(21);
    std::fs::write(dir.join("cookie"), "__cookie__:tok").unwrap();
    let cookie = Cli {
        data: dir.clone(),
        profile: dir.join("profile.json"),
        chain: format!(
            "rpc-cookie:{}:{}",
            http.rpc_url(),
            dir.join("cookie").display()
        ),
    };
    cookie.ok(&["status"]);
    cookie.ok(&[
        "fund-send",
        "--name",
        "alice",
        "--to",
        &bob_funding,
        "--amount",
        "1000",
        "--fee-rate",
        "1",
    ]);
    shared.mine(22);
    let el = Cli {
        data: dir.clone(),
        profile: dir.join("profile.json"),
        chain: format!("electrum:{}", electrum.url()),
    };
    shared.mine(10);
    assert!(el.ok(&["sync"]).contains("SyncReport"));
    el.ok(&[
        "fund-send",
        "--name",
        "alice",
        "--to",
        &bob_funding,
        "--amount",
        "1000",
        "--fee-rate",
        "1",
    ]);
    let bad = Cli {
        data: dir.clone(),
        profile: dir.join("profile.json"),
        chain: "carrier-pigeon:1".into(),
    };
    bad.fails(&["sync"], "unknown chain spec");
    bad.fails(
        &[
            "fund-send",
            "--name",
            "alice",
            "--to",
            &bob_funding,
            "--amount",
            "1",
        ],
        "unknown chain spec",
    );
    let bad_rpc = Cli {
        data: dir.clone(),
        profile: dir.join("profile.json"),
        chain: "rpc:nocolons".into(),
    };
    bad_rpc.fails(&["sync"], "rpc:");
    let bad_cookie = Cli {
        data: dir.clone(),
        profile: dir.join("profile.json"),
        chain: "rpc-cookie:nocolon".into(),
    };
    bad_cookie.fails(&["sync"], "rpc-cookie");
    cli.fails(&["electrum-fingerprint", "nocolon"], "host:port");

    // a profile written for another version is refused
    let other = std::fs::read_to_string(&cli.profile).unwrap().replace(
        &format!("\"profile\": \"{}\"", sb_core::PROFILE_VERSION),
        "\"profile\": \"0.0\"",
    );
    std::fs::write(dir.join("old.json"), other).unwrap();
    let old = Cli {
        data: dir.clone(),
        profile: dir.join("old.json"),
        chain: cli.chain.clone(),
    };
    old.fails(&["status"], "profile 0.0");
    // PostgreSQL state when a database is available
    if let Ok(conn) = std::env::var("SB_TEST_PG") {
        let text = cli.ok(&["--db", &conn, "sync"]);
        assert!(text.contains("SyncReport"));
        assert!(cli.ok(&["--db", &conn, "status"]).contains("Mint"));
    }
    std::fs::remove_dir_all(&dir).unwrap();
    let _ = Path::new("");
}
