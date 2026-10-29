//! The swap protocol end to end through the `sb` binary on the fake node
//! (`docs/SWAP.md` §9, §14): a completed swap out, a double refund, and
//! the refusals that keep the mixed endings impossible. The fake node
//! does not validate scripts; the HTLC paths proper are checked on the
//! private signet (RUNS.md).

use std::path::{Path, PathBuf};
use std::process::Command;

use bitcoin::ScriptBuf;
use sb_indexer::chain::fake::{FakeHttp, Shared};
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
        (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
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
            "`sb {}` lacks {needle:?}:\n{text}",
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
    text.lines()
        .find(|l| l.starts_with("balance"))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

fn hash_of(offer: &Path) -> String {
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(offer).unwrap()).unwrap();
    v["hash"].as_str().unwrap().to_string()
}

#[test]
fn swap_out_completes_and_a_second_one_refunds_on_both_sides() {
    let dir = std::env::temp_dir().join(format!("sb-swap-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pass"), "pw\n").unwrap();
    let mut chain = MockChain::new(10);
    chain.push_block(vec![]);
    chain.push_block(vec![]);
    let shared = Shared::new(chain);
    let http = FakeHttp::start(shared.clone());
    let cli = Cli {
        data: dir.clone(),
        profile: dir.join("profile.json"),
        chain: format!("esplora:{}", http.esplora_url()),
    };
    let p = |s: &str| dir.join(s).display().to_string();
    let tip = |shared: &Shared| shared.chain.lock().unwrap().height().unwrap();

    // a profile with the extension, three wallets, coins on both sides
    cli.ok(&[
        "profile-new",
        "--name",
        "tmp",
        "--network",
        "regtest",
        "--activation",
        "12",
    ]);
    let op = cli.ok(&["wallet-new", "--name", "operator"]);
    let vault = hex::encode(script_of(field(&op, "funding address:")).as_bytes());
    let written = cli.ok(&[
        "profile-new",
        "--name",
        "swap",
        "--network",
        "regtest",
        "--activation",
        "12",
        "--vault-script",
        &vault,
        "--swap-insecure",
    ]);
    assert!(written.contains("\"swap\""), "{written}");
    let alice = cli.ok(&["wallet-new", "--name", "alice"]);
    let alice_funding = field(&alice, "funding address:").to_string();
    assert_eq!(
        field(&cli.ok(&["address", "--name", "alice"]), "swap pubkey:").len(),
        66
    );
    let lp = cli.ok(&["wallet-new", "--name", "lp"]);
    let lp_funding = field(&lp, "funding address:").to_string();
    shared.fund(&script_of(&alice_funding), 100_000);
    shared.fund(&script_of(&lp_funding), 100_000);
    shared.mine(1);
    cli.ok(&[
        "mint",
        "--name",
        "alice",
        "--amount",
        "5000",
        "--fee-rate",
        "1",
    ]);
    for i in 2..5 {
        shared.mine(i);
    }
    cli.ok(&["sync"]);
    assert_eq!(balance(&cli.ok(&["scan", "--name", "alice"])), 5000);

    // ---- swap out: alice (X) → lp (Y), completed ----
    let t = tip(&shared);
    cli.fails(
        &[
            "swap",
            "offer",
            "--name",
            "alice",
            "--v-sh",
            "2000",
            "--v-btc",
            "10000",
            "--t-refund",
            &(t + 5).to_string(),
            "--t-htlc",
            &(t + 1).to_string(),
            "--out",
            &p("bad.json"),
        ],
        "timeouts",
    );
    cli.ok(&[
        "swap",
        "offer",
        "--name",
        "alice",
        "--v-sh",
        "2000",
        "--v-btc",
        "10000",
        "--t-refund",
        &(t + 40).to_string(),
        "--t-htlc",
        &(t + 20).to_string(),
        "--out",
        &p("offer1.json"),
    ]);
    let h1 = hash_of(&dir.join("offer1.json"));
    cli.fails(
        &["swap", "lock", "--name", "alice", "--in", &p("offer1.json")],
        "not accepted",
    );
    cli.ok(&[
        "swap",
        "accept",
        "--name",
        "lp",
        "--in",
        &p("offer1.json"),
        "--out",
        &p("accept1.json"),
    ]);
    cli.fails(
        &[
            "swap",
            "accept",
            "--name",
            "lp",
            "--in",
            &p("offer1.json"),
            "--out",
            &p("x.json"),
        ],
        "already has swap",
    );
    cli.fails(
        &["htlc", "fund", "--name", "lp", "--hash", &h1],
        "check the locked note first",
    );
    cli.fails(
        &["swap", "check", "--name", "lp", "--hash", &h1],
        "no locked note",
    );
    let locked = cli.ok(&[
        "swap",
        "lock",
        "--name",
        "alice",
        "--in",
        &p("accept1.json"),
        "--fee-rate",
        "1",
    ]);
    assert!(
        locked.contains("broadcast") && locked.contains("locked 2000 sat"),
        "{locked}"
    );
    shared.mine(5);
    cli.ok(&["sync"]);
    assert_eq!(
        balance(&cli.ok(&["scan", "--name", "alice"])),
        3000,
        "the change; the lock is not alice's"
    );
    let lp_scan = cli.ok(&["scan", "--name", "lp"]);
    assert_eq!(balance(&lp_scan), 0, "a locked note is not plain balance");
    assert!(lp_scan.contains("hash-locked 2000 sat"), "{lp_scan}");
    assert!(
        cli.ok(&["swap", "check", "--name", "lp", "--hash", &h1])
            .contains("fund the HTLC")
    );
    let funded = cli.ok(&[
        "htlc",
        "fund",
        "--name",
        "lp",
        "--hash",
        &h1,
        "--fee-rate",
        "1",
    ]);
    let outpoint = funded
        .lines()
        .find(|l| l.starts_with("HTLC funded"))
        .unwrap()
        .split(" at ")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    assert!(outpoint.contains(':'), "{funded}");
    shared.mine(6);
    let htlc_addr = cli.ok(&["htlc", "address", "--name", "lp", "--hash", &h1]);
    let htlc_script = script_of(htlc_addr.lines().next().unwrap().trim());
    assert_eq!(shared.utxos(&htlc_script).len(), 1);
    // lp cannot claim before the preimage is on chain
    cli.fails(
        &["swap", "claim", "--name", "lp", "--hash", &h1],
        "has not been claimed yet",
    );
    cli.fails(
        &[
            "swap",
            "claim",
            "--name",
            "lp",
            "--hash",
            &h1,
            "--secret",
            &"11".repeat(32),
        ],
        "does not hash",
    );
    // alice claims the HTLC, revealing the secret
    let alice_receive =
        field(&cli.ok(&["address", "--name", "alice"]), "funding address:").to_string();
    cli.fails(
        &[
            "htlc",
            "claim",
            "--name",
            "alice",
            "--hash",
            &h1,
            "--outpoint",
            &format!("{}:0", "aa".repeat(32)),
        ],
        "not an unspent output",
    );
    let claimed = cli.ok(&[
        "htlc",
        "claim",
        "--name",
        "alice",
        "--hash",
        &h1,
        "--outpoint",
        &outpoint,
        "--fee-rate",
        "1",
    ]);
    assert!(claimed.contains("preimage is now on chain"), "{claimed}");
    shared.mine(7);
    assert!(shared.utxos(&htlc_script).is_empty());
    assert!(
        shared
            .utxos(&script_of(&alice_receive))
            .iter()
            .any(|(_, v, _)| *v == 10_000 - 160)
    );
    // lp reads the preimage from the chain and claims the note
    cli.ok(&["sync"]);
    let claimed = cli.ok(&[
        "swap",
        "claim",
        "--name",
        "lp",
        "--hash",
        &h1,
        "--fee-rate",
        "1",
    ]);
    assert!(
        claimed.contains("preimage revealed") && claimed.contains("broadcast"),
        "{claimed}"
    );
    shared.mine(8);
    let synced = cli.ok(&["sync"]);
    assert!(synced.contains("accepted: 1"), "{synced}");
    assert_eq!(balance(&cli.ok(&["scan", "--name", "lp"])), 2000);
    // alice's refund is now impossible, and says why
    for i in 9..60 {
        shared.mine(i);
    }
    cli.ok(&["sync"]);
    cli.fails(
        &["swap", "refund", "--name", "alice", "--hash", &h1],
        "already claimed",
    );
    let list = cli.ok(&["swap", "list", "--name", "lp"]);
    assert!(list.contains("role y claimed"), "{list}");

    // ---- second swap: nobody claims, both sides refund ----
    let t = tip(&shared);
    cli.ok(&[
        "swap",
        "offer",
        "--name",
        "alice",
        "--v-sh",
        "1000",
        "--v-btc",
        "8000",
        "--t-refund",
        &(t + 16).to_string(),
        "--t-htlc",
        &(t + 6).to_string(),
        "--out",
        &p("offer2.json"),
    ]);
    let h2 = hash_of(&dir.join("offer2.json"));
    cli.ok(&[
        "swap",
        "accept",
        "--name",
        "lp",
        "--in",
        &p("offer2.json"),
        "--out",
        &p("accept2.json"),
    ]);
    cli.ok(&[
        "swap",
        "lock",
        "--name",
        "alice",
        "--in",
        &p("accept2.json"),
        "--fee-rate",
        "1",
    ]);
    shared.mine(100);
    cli.ok(&["sync"]);
    cli.ok(&["swap", "check", "--name", "lp", "--hash", &h2]);
    let funded = cli.ok(&[
        "htlc",
        "fund",
        "--name",
        "lp",
        "--hash",
        &h2,
        "--fee-rate",
        "1",
    ]);
    assert!(funded.contains("HTLC funded"), "{funded}");
    shared.mine(101);
    // too early for either refund
    cli.fails(
        &["swap", "refund", "--name", "alice", "--hash", &h2],
        "wait for height",
    );
    while tip(&shared) < t + 6 {
        shared.mine(102);
    }
    cli.ok(&["sync"]);
    let refunded = cli.ok(&[
        "htlc",
        "refund",
        "--name",
        "lp",
        "--hash",
        &h2,
        "--fee-rate",
        "1",
    ]);
    assert!(refunded.contains("HTLC refunded"), "{refunded}");
    shared.mine(103);
    // alice refunds the note once her anchor reaches t_refund
    while tip(&shared) < t + 16 + 3 {
        shared.mine(104);
    }
    cli.ok(&["sync"]);
    let before = balance(&cli.ok(&["scan", "--name", "alice"]));
    let refund = cli.ok(&[
        "swap",
        "refund",
        "--name",
        "alice",
        "--hash",
        &h2,
        "--fee-rate",
        "1",
    ]);
    assert!(refund.contains("refund of 1000 sat published"), "{refund}");
    shared.mine(105);
    let synced = cli.ok(&["sync"]);
    assert!(synced.contains("accepted: 1"), "{synced}");
    assert_eq!(
        balance(&cli.ok(&["scan", "--name", "alice"])),
        before + 1000
    );
    // lp's note claim is impossible now (the note is spent)
    cli.fails(
        &[
            "swap",
            "claim",
            "--name",
            "lp",
            "--hash",
            &h2,
            "--secret",
            &"22".repeat(32),
        ],
        "does not hash",
    );
    let list = cli.ok(&["swap", "list", "--name", "alice"]);
    assert!(
        list.contains("role x refunded") && list.contains("role x htlc-claimed"),
        "{list}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
