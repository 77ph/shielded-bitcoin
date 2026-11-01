//! Variant A end to end through the `sb` binary (docs/VARIANT-A.md §7, S4):
//! a family-A profile routes every command to `sba-cli`; mint, private
//! payment and change on an in-process fake Esplora over a mock chain, on
//! the OP_RETURN carrier and on the witness carrier; the paper profile's
//! commands stay untouched.

use std::path::PathBuf;
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
    text.lines()
        .find(|l| l.starts_with("balance"))
        .unwrap_or_else(|| panic!("no balance in:\n{text}"))
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

fn cycle(carrier: &str, tag: &str) {
    let dir = std::env::temp_dir().join(format!("sb-a-e2e-{tag}-{}", std::process::id()));
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
        profile: dir.join("profile-a.json"),
        chain: format!("esplora:{}", http.esplora_url()),
    };
    let mut salt = 100u32;
    let mut mine = |n: u32| {
        for _ in 0..n {
            salt += 1;
            shared.mine(salt);
        }
    };

    // a family-A profile: the operator wallet first for the vault script
    cli.ok(&[
        "profile-new",
        "--family",
        "a-halo2",
        "--name",
        "a-e2e",
        "--network",
        "regtest",
        "--activation",
        "12",
    ]);
    let op = cli.ok(&["wallet-new", "--name", "operator"]);
    let op_funding = field(&op, "funding address:").to_string();
    let op_shielded = field(&op, "shielded address:").to_string();
    assert!(op_shielded.starts_with("rsba1"), "{op_shielded}");
    let written = cli.ok(&[
        "profile-new",
        "--family",
        "a-halo2",
        "--name",
        "a-e2e",
        "--network",
        "regtest",
        "--activation",
        "12",
        "--vault-script",
        &hex::encode(script_of(&op_funding).as_bytes()),
        "--operator-address",
        &op_shielded,
        "--carrier",
        carrier,
    ]);
    assert!(written.contains("\"family\": \"a-halo2\""), "{written}");
    assert!(written.contains("\"transfer_k\": 14"), "{written}");
    cli.fails(
        &[
            "profile-new",
            "--family",
            "b-stark",
            "--name",
            "x",
            "--network",
            "regtest",
            "--activation",
            "12",
        ],
        "unknown family",
    );
    let alice = cli.ok(&["wallet-new", "--name", "alice"]);
    let alice_funding = field(&alice, "funding address:").to_string();
    let bob = cli.ok(&["wallet-new", "--name", "bob"]);
    let bob_shielded = field(&bob, "shielded address:").to_string();
    let bob_funding = field(&bob, "funding address:").to_string();
    assert!(
        cli.ok(&["address", "--name", "bob", "--new"])
            .contains("receive path")
    );
    // a paper-profile address (HRP `rsb`) is refused by the family's codec
    let paper_addr = sb_core::keys::WalletKeys::from_seed(&sb_core::keys::Seed([9u8; 32]))
        .ivk
        .find_address(0)
        .1
        .encode(sb_core::address::Network::Regtest);
    cli.fails(
        &[
            "send",
            "--name",
            "alice",
            "--to",
            &paper_addr,
            "--amount",
            "1",
        ],
        "human-readable",
    );

    assert!(cli.ok(&["status"]).contains("family a-halo2"));
    mine(1); // 12 = activation
    assert!(cli.ok(&["sync"]).contains("replayed to Some(12)"));
    cli.fails(
        &["mint", "--name", "alice", "--amount", "5000"],
        "no confirmed coins",
    );
    shared.fund(&script_of(&alice_funding), 300_000);
    mine(1);
    let minted = cli.ok(&["mint", "--name", "alice", "--amount", "5000"]);
    assert!(minted.contains("envelope (89 bytes)"), "{minted}");
    mine(3);
    let synced = cli.ok(&["sync"]);
    assert!(synced.contains("accepted: 1"), "{synced}");
    let scan = cli.ok(&["scan", "--name", "alice"]);
    assert_eq!(balance(&scan), 5000, "{scan}");

    // alice pays bob 2000 (change 3000)
    let sent = cli.ok(&[
        "send",
        "--name",
        "alice",
        "--to",
        &bob_shielded,
        "--amount",
        "2000",
    ]);
    assert!(sent.contains("envelope (4924 bytes)"), "{sent}");
    if carrier == "witness" {
        assert!(sent.contains("vB for the pair"), "{sent}");
    } else {
        assert!(sent.contains("broadcast"), "{sent}");
    }
    assert_eq!(
        balance(&cli.ok(&["scan", "--name", "alice"])),
        0,
        "inputs locked while pending"
    );
    mine(3);
    let synced = cli.ok(&["sync"]);
    assert!(synced.contains("accepted: 1"), "{synced}");
    assert_eq!(balance(&cli.ok(&["scan", "--name", "alice"])), 3000);
    assert_eq!(balance(&cli.ok(&["scan", "--name", "bob"])), 2000);
    // bob pays the operator 500 with change back, his own fee coins paying the carrier
    shared.fund(&script_of(&bob_funding), 100_000);
    mine(1);
    let sent = cli.ok(&[
        "send",
        "--name",
        "bob",
        "--to",
        &op_shielded,
        "--amount",
        "500",
    ]);
    assert!(sent.contains("envelope (4924 bytes)"), "{sent}");
    mine(3);
    cli.ok(&["sync"]);
    assert_eq!(balance(&cli.ok(&["scan", "--name", "bob"])), 1500);
    assert_eq!(balance(&cli.ok(&["scan", "--name", "operator"])), 500);
    let status = cli.ok(&["status"]);
    assert!(status.contains("accepted 3, rejected 0"), "{status}");
    // --no-broadcast writes the outbox only; unlock releases the inputs
    let out = cli.ok(&[
        "send",
        "--name",
        "bob",
        "--to",
        &op_shielded,
        "--amount",
        "100",
        "--no-broadcast",
    ]);
    assert!(out.contains("not broadcast"), "{out}");
    assert_eq!(balance(&cli.ok(&["scan", "--name", "bob"])), 0);
    assert_eq!(balance(&cli.ok(&["unlock", "--name", "bob"])), 1500);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn variant_a_cycle_on_the_op_return_carrier() {
    cycle("op-return", "opret");
}

#[test]
fn variant_a_cycle_on_the_witness_carrier() {
    cycle("witness", "wit");
}
