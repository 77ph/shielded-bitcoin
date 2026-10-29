//! The fee vault (`docs/FEE-VAULT.md`) end to end on the fake node: a
//! deposit, draws for a transfer and a withdraw, every refusal of the
//! rule, a restart with a pending draw (I3), the operator's backing guard
//! (I2), a top-up and a reclaim.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use bitcoin::ScriptBuf;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use sb_indexer::chain::fake::{FakeHttp, Shared};
use sb_indexer::chain::mock::MockChain;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

struct Cli {
    data: PathBuf,
    profile: PathBuf,
    chain: String,
}

impl Cli {
    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_sb"));
        c.arg("--profile")
            .arg(&self.profile)
            .arg("--data-dir")
            .arg(&self.data)
            .arg("--chain")
            .arg(&self.chain)
            .arg("--passphrase-file")
            .arg(self.data.join("pass"))
            .args(args);
        c
    }

    fn run(&self, args: &[&str]) -> (bool, String) {
        let out = self.command(args).output().unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text)
    }

    /// Run with `input` on stdin (the backing guard's confirmation).
    fn run_with_stdin(&self, args: &[&str], input: &str) -> (bool, String) {
        let mut child = self
            .command(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
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

/// `(charged N sat, credit left M sat)` from a draw's output.
fn charged(text: &str) -> (u64, u64) {
    let line = text
        .lines()
        .find(|l| l.contains("charged "))
        .unwrap_or_else(|| panic!("no charge line in:\n{text}"));
    let after = |marker: &str| -> u64 {
        line.split(marker)
            .nth(1)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap()
    };
    (after("charged "), after("credit left "))
}

struct KillOnDrop(std::process::Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start a vault on `cli`'s data directory; returns the process and its URL.
fn start_vault(cli: &Cli) -> (KillOnDrop, String) {
    let server = cli
        .command(&[
            "fee-vault",
            "serve",
            "--name",
            "vault",
            "--listen",
            "127.0.0.1:0",
            "--fee-rate",
            "1",
            "--margin",
            "10",
            "--sync-interval",
            "0",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut server = KillOnDrop(server);
    let url = {
        use std::io::BufRead;
        let mut line = String::new();
        std::io::BufReader::new(server.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let start = line.find("http://").unwrap();
        line[start..].split_whitespace().next().unwrap().to_string()
    };
    (server, url)
}

fn get(url: &str) -> Value {
    ureq::get(url).call().unwrap().into_json().unwrap()
}

fn post(url: &str, body: &Value) -> (u16, Value) {
    match ureq::post(url).send_json(body) {
        Ok(r) => (200, r.into_json().unwrap()),
        Err(ureq::Error::Status(c, r)) => (c, r.into_json().unwrap_or(Value::Null)),
        Err(e) => panic!("{e}"),
    }
}

/// BIP 340 tagged hash and the draw message of FEE-VAULT.md §3, written
/// here independently of the implementation.
fn tagged(tag: &str, msg: &[u8]) -> [u8; 32] {
    let t: [u8; 32] = Sha256::digest(tag.as_bytes()).into();
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h.update(msg);
    h.finalize().into()
}

fn draw_message(name: &str, h_body: &[u8; 32], max_fee: u64, memo: &[u8]) -> [u8; 32] {
    let mut m = Vec::new();
    m.extend_from_slice(&(name.len() as u16).to_le_bytes());
    m.extend_from_slice(name.as_bytes());
    m.extend_from_slice(h_body);
    m.extend_from_slice(&max_fee.to_le_bytes());
    m.extend_from_slice(&(memo.len() as u16).to_le_bytes());
    m.extend_from_slice(memo);
    tagged("sb/v1/feeauth/draw", &m)
}

#[test]
fn fee_vault_end_to_end() {
    let dir = std::env::temp_dir().join(format!("sb-fee-vault-e2e-{}", std::process::id()));
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
    let mut salt = 100u32;
    let mut mine = |n: u32| {
        for _ in 0..n {
            salt += 1;
            shared.mine(salt);
        }
    };

    // profile with a dev boundary (for the withdraw), wallets, coins
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
    cli.ok(&[
        "profile-new",
        "--name",
        "fv",
        "--network",
        "regtest",
        "--activation",
        "12",
        "--vault-script",
        &hex::encode(script_of(&op_funding).as_bytes()),
        "--operator-address",
        &op_shielded,
    ]);
    let alice = cli.ok(&["wallet-new", "--name", "alice"]);
    let alice_funding = field(&alice, "funding address:").to_string();
    let bob = cli.ok(&["wallet-new", "--name", "bob"]);
    let bob_shielded = field(&bob, "shielded address:").to_string();
    let bob_funding = field(&bob, "funding address:").to_string();
    // the vault: its own wallet and data directory, the same profile
    let vault_dir = dir.join("vault");
    std::fs::create_dir_all(&vault_dir).unwrap();
    std::fs::write(vault_dir.join("pass"), "vault pw\n").unwrap();
    let vault_cli = Cli {
        data: vault_dir.clone(),
        profile: cli.profile.clone(),
        chain: cli.chain.clone(),
    };
    let vault_wallet = vault_cli.ok(&["wallet-new", "--name", "vault"]);
    let vault_funding = field(&vault_wallet, "funding address:").to_string();
    shared.fund(&script_of(&alice_funding), 300_000);
    shared.fund(&script_of(&vault_funding), 300_000);
    mine(1);
    cli.ok(&[
        "mint",
        "--name",
        "alice",
        "--amount",
        "20000",
        "--fee-rate",
        "1",
    ]);
    mine(3);
    assert!(cli.ok(&["sync"]).contains("accepted: 1"));
    assert_eq!(balance(&cli.ok(&["scan", "--name", "alice"])), 20000);

    // the vault comes up
    let (server, url) = start_vault(&vault_cli);
    let info = get(&format!("{url}/info"));
    assert_eq!(info["deployment"], "fv");
    assert_eq!(info["margin"], 10);
    assert_eq!(info["min_depth"], 1);
    assert_eq!(info["carrier"], "opreturn");
    let est_transfer = info["fee_estimate"]["transfer"].as_u64().unwrap();
    let est_withdraw = info["fee_estimate"]["withdraw"].as_u64().unwrap();
    assert!(est_transfer > 800 && est_transfer < 900, "{info}");
    assert!(est_withdraw > est_transfer, "{info}");
    let deposit_address = info["deposit_address"].as_str().unwrap().to_string();
    assert!(deposit_address.starts_with("rsb1"), "{deposit_address}");

    // no deposit yet: the client does not even ask
    cli.fails(
        &[
            "send",
            "--name",
            "alice",
            "--to",
            &bob_shielded,
            "--amount",
            "1000",
            "--fee-rate",
            "1",
            "--fee-vault",
            &url,
        ],
        "no deposit at",
    );
    cli.ok(&["unlock", "--name", "alice"]);

    // 1. the deposit: an ordinary transfer to the vault's address
    let dep = cli.ok(&[
        "fee-vault",
        "deposit",
        "--name",
        "alice",
        "--vault",
        &url,
        "--amount",
        "2500",
        "--fee-rate",
        "1",
    ]);
    assert!(dep.contains("deposit of 2500 sat"), "{dep}");
    let dep_label = outbox_label(&dep);
    assert_eq!(shared.mempool.lock().unwrap().len(), 1);
    // not settled: in the mempool, then one block deep (min_depth 1 means
    // a block below the tip)
    let acc = cli.ok(&["fee-vault", "accounts", "--name", "alice", "--vault", &url]);
    assert!(acc.contains("credit 0"), "{acc}");
    mine(1);
    let acc = cli.ok(&["fee-vault", "accounts", "--name", "alice", "--vault", &url]);
    assert!(
        acc.contains("unsettled 2500") && acc.contains("credit 0"),
        "{acc}"
    );
    mine(3);
    assert!(cli.ok(&["sync"]).contains("accepted: 1"));
    let acc = cli.ok(&["fee-vault", "accounts", "--name", "alice", "--vault", &url]);
    assert!(
        acc.contains("deposited 2500") && acc.contains("credit 2500"),
        "{acc}"
    );
    // 2. refusals before any charge
    let dep_hex =
        std::fs::read_to_string(dir.join("outbox").join(format!("{dep_label}.hex"))).unwrap();
    let secp = Secp256k1::new();
    let stranger = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[7u8; 32]).unwrap());
    let stranger_pk = stranger.x_only_public_key().0.serialize();
    // R1: a bad signature under a well-formed key
    let (code, body) = post(
        &format!("{url}/draw"),
        &json!({"envelope": dep_hex.trim(), "key": hex::encode(stranger_pk), "max_fee": 5000, "sig": "00".repeat(64)}),
    );
    assert_eq!(code, 400, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("bad signature"),
        "{body}"
    );
    // R2: a valid signature under a key nobody deposited for
    let profile: Value =
        serde_json::from_str(&std::fs::read_to_string(&cli.profile).unwrap()).unwrap();
    let const_salt: [u8; 32] = hex::decode(profile["const_salt"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let envelope = hex::decode(dep_hex.trim()).unwrap();
    let h_body = sb_primitives::encoding::fr_to_bytes(&sb_core::envelope::h_body(
        &const_salt,
        &envelope[..sb_core::envelope::BODY_LEN],
    ));
    let m = draw_message("fv", &h_body, 5000, &[]);
    let sig = secp
        .sign_schnorr(&Message::from_digest(m), &stranger)
        .serialize();
    let (code, body) = post(
        &format!("{url}/draw"),
        &json!({"envelope": dep_hex.trim(), "key": hex::encode(stranger_pk), "max_fee": 5000, "sig": hex::encode(sig)}),
    );
    assert_eq!(code, 400, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("no deposit for this key"),
        "{body}"
    );
    // a mint is not a transfer
    let (code, body) = post(
        &format!("{url}/draw"),
        &json!({"envelope": "00", "key": hex::encode(stranger_pk), "max_fee": 1, "sig": hex::encode(sig)}),
    );
    assert_eq!(code, 400);
    assert!(
        body["error"].as_str().unwrap().contains("malformed"),
        "{body}"
    );
    // R4: a ceiling below the fee
    cli.fails(
        &[
            "send",
            "--name",
            "alice",
            "--to",
            &bob_shielded,
            "--amount",
            "1000",
            "--fee-rate",
            "1",
            "--fee-vault",
            &url,
            "--max-fee",
            "1",
        ],
        "exceeds max_fee 1",
    );
    cli.ok(&["unlock", "--name", "alice"]);

    // 3. a transfer drawn from the credit
    let sent = cli.ok(&[
        "send",
        "--name",
        "alice",
        "--to",
        &bob_shielded,
        "--amount",
        "1000",
        "--fee-rate",
        "1",
        "--fee-vault",
        &url,
    ]);
    assert!(sent.contains("published by the fee vault"), "{sent}");
    let (fee1, left1) = charged(&sent);
    assert_eq!(fee1, est_transfer, "{sent}");
    assert_eq!(left1, 2500 - fee1);
    let sent_label = outbox_label(&sent);
    cli.fails(
        &[
            "publish",
            &sent_label,
            "--name",
            "alice",
            "--fee-vault",
            &url,
            "--max-fee",
            "5000",
        ],
        "already published",
    );
    assert_eq!(shared.mempool.lock().unwrap().len(), 1);
    mine(3);
    assert!(cli.ok(&["sync"]).contains("accepted: 1"));
    assert_eq!(balance(&cli.ok(&["scan", "--name", "bob"])), 1000);
    let ledger: Value = serde_json::from_str(
        &std::fs::read_to_string(vault_dir.join("fee-vault-vault.json")).unwrap(),
    )
    .unwrap();
    let account = ledger["accounts"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .clone();
    assert_eq!(account["released"], fee1);
    assert_eq!(account["draws"].as_array().unwrap().len(), 1);

    // 4. a withdraw drawn from the credit, left in the mempool; then the
    //    vault restarts with it pending (I3)
    let wd = cli.ok(&[
        "withdraw",
        "--name",
        "alice",
        "--amount",
        "2000",
        "--to",
        &bob_funding,
        "--fee-rate",
        "1",
        "--fee-vault",
        &url,
    ]);
    assert!(wd.contains("published by the fee vault"), "{wd}");
    let (fee2, left2) = charged(&wd);
    // the estimate assumes a 46-byte memo (a P2TR payout script); bob's
    // P2WPKH memo is 12 bytes shorter
    assert!(fee2 > fee1 && fee2 <= est_withdraw, "{wd}");
    assert_eq!(left2, left1 - fee2);
    let wd_label = outbox_label(&wd);
    assert_eq!(shared.mempool.lock().unwrap().len(), 1);
    drop(server);
    let (server, url) = start_vault(&vault_cli);
    // the pending draw was re-broadcast (the node already had it) and is
    // still pending: the same envelope is not charged again
    assert_eq!(shared.mempool.lock().unwrap().len(), 1);
    cli.fails(
        &[
            "publish",
            &wd_label,
            "--name",
            "alice",
            "--fee-vault",
            &url,
            "--max-fee",
            "5000",
        ],
        "already published",
    );
    let (_, left_now) = {
        let acc = cli.ok(&["fee-vault", "accounts", "--name", "alice", "--vault", &url]);
        assert!(acc.contains(&format!("credit {left2}")), "{acc}");
        (0, left2)
    };
    mine(3);
    assert!(cli.ok(&["sync"]).contains("accepted: 1"));

    // 5. R4 on the vault's side: credit below the fee (the client's own
    //    pre-check is skipped when --max-fee is explicit)
    assert!(
        left_now < est_transfer,
        "credit {left_now} should be below one fee"
    );
    let nb = cli.ok(&[
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
    let nb_label = outbox_label(&nb);
    cli.fails(
        &[
            "publish",
            &nb_label,
            "--name",
            "alice",
            "--fee-vault",
            &url,
            "--max-fee",
            "5000",
        ],
        "insufficient credit",
    );
    cli.fails(
        &["publish", &nb_label, "--name", "alice", "--fee-vault", &url],
        "below the estimated fee",
    );
    cli.ok(&["unlock", "--name", "alice"]);
    // a remainder below the reclaim fee cannot be reclaimed on its own
    cli.fails(
        &["fee-vault", "reclaim", "--name", "alice", "--vault", &url],
        "does not cover the reclaim fee",
    );

    // 6. the operator's backing guard (I2): the vault wallet holds the
    //    2500-sat deposit note, outstanding credit is what is left of it
    drop(server);
    let status = vault_cli.ok(&["fee-vault", "status", "--name", "vault"]);
    assert!(
        status.contains(&format!("outstanding credit (upper bound): {left_now} sat")),
        "{status}"
    );
    assert!(status.contains("backing: ok"), "{status}");
    vault_cli.fails(
        &[
            "send",
            "--name",
            "vault",
            "--to",
            &bob_shielded,
            "--amount",
            "2400",
            "--no-broadcast",
        ],
        "under-back",
    );
    let (ok, text) = vault_cli.run_with_stdin(
        &[
            "send",
            "--name",
            "vault",
            "--to",
            &bob_shielded,
            "--amount",
            "2400",
            "--no-broadcast",
            "--force",
        ],
        "no\n",
    );
    assert!(!ok && text.contains("not confirmed"), "{text}");
    let short = left_now - (2500 - 2400);
    let (ok, text) = vault_cli.run_with_stdin(
        &[
            "send",
            "--name",
            "vault",
            "--to",
            &bob_shielded,
            "--amount",
            "2400",
            "--no-broadcast",
            "--force",
        ],
        &format!("under-back {short}\n"),
    );
    assert!(ok, "{text}");
    vault_cli.ok(&["unlock", "--name", "vault"]);
    // spending within the bound needs no confirmation
    vault_cli.ok(&[
        "send",
        "--name",
        "vault",
        "--to",
        &bob_shielded,
        "--amount",
        "100",
        "--no-broadcast",
    ]);
    vault_cli.ok(&["unlock", "--name", "vault"]);

    // 7. top-up under the same key, then reclaim everything
    let (server, url) = start_vault(&vault_cli);
    let top = cli.ok(&[
        "fee-vault",
        "deposit",
        "--name",
        "alice",
        "--vault",
        &url,
        "--amount",
        "2000",
        "--fee-rate",
        "1",
        "--index",
        "0",
    ]);
    assert!(top.contains("key 0 ("), "{top}");
    mine(4);
    assert!(cli.ok(&["sync"]).contains("accepted: 1"));
    let acc = cli.ok(&["fee-vault", "accounts", "--name", "alice", "--vault", &url]);
    assert!(
        acc.contains(&format!("credit {}", left_now + 2000)),
        "{acc}"
    );
    let before = balance(&cli.ok(&["scan", "--name", "alice"]));
    let rc = cli.ok(&["fee-vault", "reclaim", "--name", "alice", "--vault", &url]);
    assert!(rc.contains("reclaimed "), "{rc}");
    let paid: u64 = rc
        .split("reclaimed ")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(paid, left_now + 2000 - est_transfer, "{rc}");
    // a second reclaim finds nothing
    cli.fails(
        &["fee-vault", "reclaim", "--name", "alice", "--vault", &url],
        "no deposit with credit",
    );
    assert_eq!(shared.mempool.lock().unwrap().len(), 1);
    mine(3);
    assert!(cli.ok(&["sync"]).contains("accepted: 1"));
    assert_eq!(
        balance(&cli.ok(&["scan", "--name", "alice"])),
        before + paid
    );
    let acc = cli.ok(&["fee-vault", "accounts", "--name", "alice", "--vault", &url]);
    assert!(acc.contains("credit 0"), "{acc}");
    drop(server);
    let status = vault_cli.ok(&["fee-vault", "status", "--name", "vault"]);
    assert!(
        status.contains("outstanding credit (upper bound): 0 sat"),
        "{status}"
    );
    assert!(
        status.contains(&format!("earned: {} sat", fee1 + fee2 + est_transfer)),
        "{status}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
