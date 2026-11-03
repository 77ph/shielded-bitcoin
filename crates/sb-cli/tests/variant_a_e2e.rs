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

struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The outbox label of a `--no-broadcast` or relayed command's output.
fn label_of(text: &str) -> String {
    text.lines()
        .find(|l| l.contains("written to"))
        .and_then(|l| l.rsplit('/').next())
        .map(|f| f.trim_end_matches(".json").to_string())
        .expect("outbox label")
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

/// `full`: also the parts that do not depend on the carrier (third-party
/// publication, the relayer, the indexer API and the light client); run
/// once, on the deployment's default carrier, to keep the test's proving
/// time in bounds.
fn cycle(carrier: &str, tag: &str, full: bool) {
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
    // the development boundary's exit: bob withdraws 600 to alice's funding
    // address (dust and a foreign-network address refused first); the
    // operator finds the request next to the envelope and pays it
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
            "600",
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
        "600",
        "--to",
        &alice_funding,
    ]);
    assert!(w.contains("operator pays"), "{w}");
    mine(3);
    cli.ok(&["sync"]);
    assert_eq!(balance(&cli.ok(&["scan", "--name", "bob"])), 900);
    let listed = cli.ok(&["payouts", "--name", "operator", "--no-broadcast"]);
    assert!(listed.contains("1 pending"), "{listed}");
    let paid = cli.ok(&["payouts", "--name", "operator"]);
    assert!(paid.contains("paid in"), "{paid}");
    mine(1);
    let got: Vec<u64> = shared
        .utxos(&script_of(&alice_funding))
        .into_iter()
        .map(|(_, v, _)| v)
        .collect();
    assert!(got.contains(&600), "{got:?}");
    assert!(
        cli.ok(&["payouts", "--name", "operator"])
            .contains("0 pending")
    );
    assert_eq!(balance(&cli.ok(&["scan", "--name", "operator"])), 1100);
    if !full {
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    // --no-broadcast writes the outbox only; a third party (alice's fee
    // coins) publishes it later; bob's inputs stay locked until then
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
    let label = out
        .lines()
        .find(|l| l.contains("written to"))
        .and_then(|l| l.rsplit('/').next())
        .map(|f| f.trim_end_matches(".json").to_string())
        .expect("outbox label");
    cli.fails(&["publish", "nothing"], "writes it");
    let published = cli.ok(&["publish", &label, "--name", "alice", "--fee-rate", "1"]);
    assert!(
        published.contains("broadcast") || published.contains("vB for the pair"),
        "{published}"
    );
    mine(3);
    cli.ok(&["sync"]);
    assert_eq!(balance(&cli.ok(&["scan", "--name", "bob"])), 800);
    assert_eq!(balance(&cli.ok(&["scan", "--name", "operator"])), 1200);
    // an unpublished transfer leaves a lock that unlock releases
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
    assert_eq!(balance(&cli.ok(&["unlock", "--name", "bob"])), 800);

    // a sponsored relayer with its own data directory and fee wallet: a
    // transfer relayed end to end, the client-side refusals, the server's
    // answers to a tampered envelope, junk and an unknown path
    let relay_dir = dir.join("relay");
    std::fs::create_dir_all(&relay_dir).unwrap();
    std::fs::write(relay_dir.join("pass"), "pw\n").unwrap();
    let relay_cli = Cli {
        data: relay_dir.clone(),
        profile: cli.profile.clone(),
        chain: cli.chain.clone(),
    };
    let relay_wallet = relay_cli.ok(&["wallet-new", "--name", "relay"]);
    let relay_funding = field(&relay_wallet, "funding address:").to_string();
    shared.fund(&script_of(&relay_funding), 100_000);
    mine(1);
    relay_cli.fails(
        &["relay-serve", "--name", "relay", "--listen", "256.0.0.1:1"],
        "listen on",
    );
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
            "6",
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
    let info: serde_json::Value = ureq::get(&format!("{relay_url}/info"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(info["deployment"], "a-e2e");
    assert_eq!(info["family"], "a-halo2");
    assert_eq!(info["network"], "regtest");
    cli.fails(
        &[
            "send",
            "--name",
            "alice",
            "--to",
            &bob_shielded,
            "--amount",
            "50",
            "--relay",
            &relay_url,
            "--no-broadcast",
        ],
        "cannot be used with",
    );
    let relayed = cli.ok(&[
        "send",
        "--name",
        "alice",
        "--to",
        &bob_shielded,
        "--amount",
        "50",
        "--relay",
        &relay_url,
    ]);
    assert!(relayed.contains("relayed by"), "{relayed}");
    let relayed_label = label_of(&relayed);
    cli.fails(
        &["publish", &relayed_label, "--relay", &relay_url],
        "already relayed",
    );
    let mint_label = label_of(&cli.ok(&[
        "mint",
        "--name",
        "alice",
        "--amount",
        "70",
        "--no-broadcast",
    ]));
    cli.fails(
        &["publish", &mint_label, "--relay", &relay_url],
        "pays the vault",
    );
    let mut tampered = hex::decode(
        std::fs::read_to_string(dir.join("outbox").join(format!("{relayed_label}.hex"))).unwrap(),
    )
    .unwrap();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let post = |body: &str| -> (u16, String) {
        match ureq::post(&format!("{relay_url}/relay")).send_string(body) {
            Ok(r) => (200, r.into_string().unwrap()),
            Err(ureq::Error::Status(c, r)) => (c, r.into_string().unwrap()),
            Err(e) => panic!("{e}"),
        }
    };
    let (code, text) = post(&format!("{{\"envelope\":\"{}\"}}", hex::encode(&tampered)));
    assert!(code == 400 && text.contains("rejected"), "{code} {text}");
    let (code, text) = post("not json");
    assert!(code == 400 && text.contains("bad request"), "{code} {text}");
    let status = ureq::get(&format!("{relay_url}/nothing"))
        .call()
        .unwrap_err();
    assert!(matches!(status, ureq::Error::Status(404, _)));
    assert!(server.0.wait().unwrap().success());
    mine(3);
    cli.ok(&["sync"]);
    assert_eq!(balance(&cli.ok(&["scan", "--name", "alice"])), 2950);
    assert_eq!(balance(&cli.ok(&["scan", "--name", "bob"])), 850);

    // verified sync: `sb serve` over the fake node, a fresh data directory
    // replays from its API with and without a header source and reaches
    // the same state; the API answers by hash and refuses junk; a bare
    // light source cannot publish
    let api = Command::new(env!("CARGO_BIN_EXE_sb"))
        .arg("--profile")
        .arg(&cli.profile)
        .arg("--data-dir")
        .arg(&cli.data)
        .arg("--chain")
        .arg(&cli.chain)
        .arg("--passphrase-file")
        .arg(dir.join("pass"))
        .args(["serve", "--listen", "127.0.0.1:0", "--max-requests", "400"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut api = KillOnDrop(api);
    let api_url = {
        use std::io::BufRead;
        let mut line = String::new();
        std::io::BufReader::new(api.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let start = line.find("http://").unwrap();
        line[start..].split_whitespace().next().unwrap().to_string()
    };
    cli.ok(&["sync"]);
    let full_status = cli.ok(&["status"]);
    let light_dir = dir.join("light");
    std::fs::create_dir_all(&light_dir).unwrap();
    std::fs::copy(dir.join("pass"), light_dir.join("pass")).unwrap();
    for spec in [
        format!("light:{api_url}|{}", cli.chain),
        format!("light:{api_url}"),
    ] {
        let _ = std::fs::remove_file(light_dir.join("state-a-e2e.json"));
        let light = Cli {
            data: light_dir.clone(),
            profile: cli.profile.clone(),
            chain: spec.clone(),
        };
        let synced = light.ok(&["sync"]);
        assert!(synced.contains("claimed roots agree"), "{synced}");
        // the trust label at the point of use
        if spec.contains('|') {
            assert!(synced.contains("cross-checked against"), "{synced}");
        } else {
            assert!(synced.contains("bare light sync"), "{synced}");
        }
        let a = light.ok(&["status"]);
        assert_eq!(
            a.lines().skip(1).collect::<Vec<_>>(),
            full_status.lines().skip(1).collect::<Vec<_>>(),
            "light replay differs from full replay for {spec}"
        );
        let state_full = std::fs::read_to_string(dir.join("state-a-e2e.json")).unwrap();
        let state_light = std::fs::read_to_string(light_dir.join("state-a-e2e.json")).unwrap();
        assert_eq!(state_full, state_light);
    }
    let tip: serde_json::Value = ureq::get(&format!("{api_url}/tip"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    let by_hash: serde_json::Value = ureq::get(&format!(
        "{api_url}/block/{}",
        tip["hash"].as_str().unwrap()
    ))
    .call()
    .unwrap()
    .into_json()
    .unwrap();
    assert_eq!(by_hash["height"], tip["height"]);
    assert!(matches!(
        ureq::get(&format!("{api_url}/block/zzz"))
            .call()
            .unwrap_err(),
        ureq::Error::Status(400, _)
    ));
    assert!(matches!(
        ureq::get(&format!("{api_url}/block/1")).call().unwrap_err(),
        ureq::Error::Status(404, _)
    ));
    assert!(matches!(
        ureq::post(&format!("{api_url}/tip"))
            .send_string("")
            .unwrap_err(),
        ureq::Error::Status(404, _)
    ));
    let bare = Cli {
        data: dir.clone(),
        profile: cli.profile.clone(),
        chain: format!("light:{api_url}"),
    };
    bare.fails(
        &[
            "fund-send",
            "--name",
            "alice",
            "--to",
            &bob_funding,
            "--amount",
            "1000",
        ],
        "no publisher",
    );
    drop(api);
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
    // the development boundary's exit: bob withdraws 600 to alice's funding
    // address (dust and a foreign-network address refused first); the
    // operator finds the request next to the envelope and pays it
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
            "600",
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
        "600",
        "--to",
        &alice_funding,
    ]);
    assert!(w.contains("operator pays"), "{w}");
    mine(3);
    cli.ok(&["sync"]);
    assert_eq!(balance(&cli.ok(&["scan", "--name", "bob"])), 900);
    let listed = cli.ok(&["payouts", "--name", "operator", "--no-broadcast"]);
    assert!(listed.contains("1 pending"), "{listed}");
    let paid = cli.ok(&["payouts", "--name", "operator"]);
    assert!(paid.contains("paid in"), "{paid}");
    mine(1);
    let got: Vec<u64> = shared
        .utxos(&script_of(&alice_funding))
        .into_iter()
        .map(|(_, v, _)| v)
        .collect();
    assert!(got.contains(&600), "{got:?}");
    assert!(
        cli.ok(&["payouts", "--name", "operator"])
            .contains("0 pending")
    );
    assert_eq!(balance(&cli.ok(&["scan", "--name", "operator"])), 1100);
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
    assert_eq!(balance(&cli.ok(&["unlock", "--name", "bob"])), 900);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn variant_a_cycle_on_the_op_return_carrier() {
    cycle("op-return", "opret", false);
}

#[test]
fn variant_a_cycle_on_the_witness_carrier() {
    cycle("witness", "wit", true);
}
