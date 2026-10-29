//! A witness-carrier deployment through the `sb` binary on the fake node
//! (`docs/WITNESS-CARRIER.md`): mint, private payment, withdraw with its
//! memo and the operator payout, external funding of a commit output and
//! `publish --reveal`, a relayer publishing pairs, and an OP_RETURN
//! deployment that sees none of it.

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

fn outbox_label(text: &str) -> String {
    let path = field(text, "envelope (");
    Path::new(path)
        .file_stem()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

struct KillOnDrop(std::process::Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn witness_deployment_end_to_end() {
    let dir = std::env::temp_dir().join(format!("sb-witness-e2e-{}", std::process::id()));
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

    // profile in witness mode, wallets, coins
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
    let op_shielded = field(&op, "shielded address:").to_string();
    let op_funding = field(&op, "funding address:").to_string();
    let vault = hex::encode(script_of(&op_funding).as_bytes());
    let written = cli.ok(&[
        "profile-new",
        "--name",
        "wit",
        "--network",
        "regtest",
        "--activation",
        "12",
        "--vault-script",
        &vault,
        "--operator-address",
        &op_shielded,
        "--carrier",
        "witness",
    ]);
    assert!(written.contains("\"carrier\": \"witness\""), "{written}");
    let alice = cli.ok(&["wallet-new", "--name", "alice"]);
    let alice_funding = field(&alice, "funding address:").to_string();
    let bob = cli.ok(&["wallet-new", "--name", "bob"]);
    let bob_shielded = field(&bob, "shielded address:").to_string();
    let bob_funding = field(&bob, "funding address:").to_string();
    shared.fund(&script_of(&alice_funding), 200_000);
    shared.fund(&script_of(&bob_funding), 100_000);
    shared.mine(1);

    // mint: a commit and a reveal, the vault paid by the reveal
    let minted = cli.ok(&[
        "mint",
        "--name",
        "alice",
        "--amount",
        "5000",
        "--fee-rate",
        "1",
    ]);
    assert!(
        minted.contains("commit ") && minted.contains("reveal "),
        "{minted}"
    );
    let pair_vb: u64 = minted
        .lines()
        .find(|l| l.starts_with("commit "))
        .unwrap()
        .split("): ")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        pair_vb < 400,
        "the pair for an 89-byte mint is small: {pair_vb} vB"
    );
    assert_eq!(shared.mempool.lock().unwrap().len(), 2);
    shared.mine(2);
    assert!(
        shared
            .utxos(&script_of(&op_funding))
            .iter()
            .any(|(_, v, _)| *v == 5000),
        "vault paid"
    );
    for i in 3..6 {
        shared.mine(i);
    }
    let synced = cli.ok(&["sync"]);
    assert!(synced.contains("accepted: 1"), "{synced}");
    assert_eq!(balance(&cli.ok(&["scan", "--name", "alice"])), 5000);

    // a private payment: 700-byte envelope in the witness
    let sent = cli.ok(&[
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
    let pair_vb: u64 = sent
        .lines()
        .find(|l| l.starts_with("commit "))
        .unwrap()
        .split("): ")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    println!("700-byte envelope as a witness pair: {pair_vb} vB");
    assert!(pair_vb < 600, "{pair_vb} vB");
    shared.mine(6);
    cli.ok(&["sync"]);
    assert_eq!(balance(&cli.ok(&["scan", "--name", "bob"])), 2000);
    assert_eq!(balance(&cli.ok(&["scan", "--name", "alice"])), 3000);

    // an OP_RETURN deployment over the same chain sees nothing
    let plain = std::fs::read_to_string(&cli.profile)
        .unwrap()
        .replace("\"carrier\": \"witness\"", "\"carrier\": \"op-return\"");
    std::fs::write(dir.join("plain.json"), plain).unwrap();
    let plain_dir = dir.join("plain");
    std::fs::create_dir_all(&plain_dir).unwrap();
    std::fs::copy(dir.join("pass"), plain_dir.join("pass")).unwrap();
    let plain = Cli {
        data: plain_dir,
        profile: dir.join("plain.json"),
        chain: cli.chain.clone(),
    };
    let s = plain.ok(&["sync"]);
    assert!(
        s.contains("accepted: 0") && s.contains("rejected: 0"),
        "{s}"
    );

    // withdraw: the memo rides in an OP_RETURN output of the reveal; the
    // operator pays it out
    shared.mine(7);
    shared.mine(8);
    cli.ok(&["sync"]);
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
    shared.mine(9);
    cli.ok(&["sync"]);
    assert_eq!(balance(&cli.ok(&["scan", "--name", "bob"])), 1000);
    let paid = cli.ok(&["payouts", "--name", "operator", "--fee-rate", "1"]);
    assert!(paid.contains("paid in"), "{paid}");
    shared.mine(10);
    assert!(
        shared
            .utxos(&script_of(&alice_funding))
            .iter()
            .any(|(_, v, _)| *v == 1000)
    );

    // external funding: alice writes the entry, bob funds the commit
    // address, alice reveals
    shared.mine(11);
    shared.mine(12);
    cli.ok(&["sync"]);
    let built = cli.ok(&[
        "send",
        "--name",
        "alice",
        "--to",
        &bob_shielded,
        "--amount",
        "500",
        "--no-broadcast",
    ]);
    assert!(built.contains("witness carrier: commit output"), "{built}");
    let label = outbox_label(&built);
    let commit_line = built
        .lines()
        .find(|l| l.starts_with("witness carrier"))
        .unwrap();
    let value: u64 = commit_line
        .split_whitespace()
        .nth(4)
        .unwrap()
        .parse()
        .unwrap();
    let commit_addr = commit_line
        .split(" to ")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    assert!(commit_addr.starts_with("bcrt1p"), "{commit_addr}");
    cli.fails(
        &["publish", &label, "--name", "alice", "--reveal"],
        "nothing at the commit address",
    );
    cli.ok(&[
        "fund-send",
        "--name",
        "bob",
        "--to",
        &commit_addr,
        "--amount",
        &value.to_string(),
        "--fee-rate",
        "1",
    ]);
    shared.mine(13);
    let revealed = cli.ok(&[
        "publish",
        &label,
        "--name",
        "alice",
        "--reveal",
        "--fee-rate",
        "1",
    ]);
    assert!(revealed.contains("reveal "), "{revealed}");
    shared.mine(14);
    cli.ok(&["sync"]);
    assert_eq!(balance(&cli.ok(&["scan", "--name", "bob"])), 1500);
    let plain_same_data = Cli {
        data: dir.clone(),
        profile: dir.join("plain.json"),
        chain: cli.chain.clone(),
    };
    plain_same_data.fails(
        &["publish", &label, "--name", "alice", "--reveal"],
        "for witness-carrier",
    );

    // a relayer in witness mode publishes pairs from its own coins
    let relay_dir = dir.join("relay");
    std::fs::create_dir_all(&relay_dir).unwrap();
    std::fs::write(relay_dir.join("pass"), "rp\n").unwrap();
    let relay_cli = Cli {
        data: relay_dir.clone(),
        profile: dir.join("profile.json"),
        chain: cli.chain.clone(),
    };
    let rw = relay_cli.ok(&["wallet-new", "--name", "relay"]);
    shared.fund(&script_of(field(&rw, "funding address:")), 100_000);
    shared.mine(15);
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
    shared.mine(17);
    shared.mine(18);
    cli.ok(&["sync"]);
    let relayed = cli.ok(&[
        "send",
        "--name",
        "alice",
        "--to",
        &bob_shielded,
        "--amount",
        "300",
        "--relay",
        &relay_url,
    ]);
    assert!(relayed.contains("relayed by"), "{relayed}");
    assert!(server.0.wait().unwrap().success());
    assert_eq!(
        shared.mempool.lock().unwrap().len(),
        2,
        "commit and reveal from the relayer"
    );
    shared.mine(16);
    cli.ok(&["sync"]);
    assert_eq!(balance(&cli.ok(&["scan", "--name", "bob"])), 1800);
    std::fs::remove_dir_all(&dir).unwrap();
}
