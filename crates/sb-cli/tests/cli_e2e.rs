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

/// A child process that does not outlive the test, whatever happens.
struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The outbox label from a `written to …/outbox/<label>.json` line.
fn outbox_label(text: &str) -> String {
    let path = field(text, "envelope (");
    Path::new(path)
        .file_stem()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
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
    cli.fails(
        &[
            "profile-new",
            "--name",
            "e2e",
            "--network",
            "regtest",
            "--activation",
            "12",
            "--setup-seed",
            "abcd",
        ],
        "32 bytes",
    );
    // a profile in a directory that does not exist yet, on testnet, with an explicit setup seed
    let nested = Cli {
        data: dir.clone(),
        profile: dir.join("sub/dir/p.json"),
        chain: cli.chain.clone(),
    };
    nested.ok(&[
        "profile-new",
        "--name",
        "nested",
        "--network",
        "testnet",
        "--activation",
        "12",
        "--setup-seed",
        &"11".repeat(32),
    ]);
    cli.fails(&["address", "--name", "nobody"], "wallet nobody");
    let op = cli.ok(&["wallet-new", "--name", "operator"]);
    assert!(op.contains("encrypted"));
    cli.fails(&["wallet-new", "--name", "operator"], "exists");
    assert!(
        nested
            .ok(&["address", "--name", "operator"])
            .contains("funding address:  tb1")
    );
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

    // an operator address from another network is refused at withdraw time
    let foreign = Cli {
        data: dir.clone(),
        profile: dir.join("foreign.json"),
        chain: cli.chain.clone(),
    };
    let signet_op = sb_core::address::PaymentAddress::decode(&op_shielded)
        .unwrap()
        .1
        .encode(sb_core::address::Network::Signet);
    foreign.ok(&[
        "profile-new",
        "--name",
        "foreign",
        "--network",
        "regtest",
        "--activation",
        "12",
        "--vault-script",
        &vault_hex,
        "--operator-address",
        &signet_op,
    ]);

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
    // the mint spent the only coin on receive address 0 and its change went
    // to a fresh change address: nothing is left on the address that was
    // funded, so no address is used twice
    assert!(shared.utxos(&script_of(&alice_funding)).is_empty());

    // private payment alice -> bob (anchor depth: two more blocks)
    shared.mine(3);
    shared.mine(4);
    cli.ok(&["sync"]);
    cli.fails(&["send", "--name", "alice", "--to", "tsb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq2k0ahk", "--amount", "1"], "bech32m");
    let bob_signet = sb_core::address::PaymentAddress::decode(&bob_shielded)
        .unwrap()
        .1
        .encode(sb_core::address::Network::Signet);
    cli.fails(
        &[
            "send",
            "--name",
            "alice",
            "--to",
            &bob_signet,
            "--amount",
            "1",
        ],
        "address is for",
    );
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

    // third-party funding: alice builds, bob's fee coins publish
    cli.fails(&["publish", "nothing"], "writes it");
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
    assert!(built.contains("fundrawtransaction"), "{built}");
    let label = outbox_label(&built);
    // Core's framing of a transaction without inputs: version, 0 inputs,
    // 1 output (the OP_RETURN carrier), lock time
    let unfunded = std::fs::read_to_string(dir.join("outbox").join(format!("{label}.tx"))).unwrap();
    let envelope =
        std::fs::read_to_string(dir.join("outbox").join(format!("{label}.hex"))).unwrap();
    assert!(unfunded.starts_with("020000000001") && unfunded.ends_with("00000000"));
    assert!(unfunded.contains(&envelope));
    let published = cli.ok(&["publish", &label, "--name", "bob", "--fee-rate", "1"]);
    assert!(published.contains("broadcast"), "{published}");
    shared.mine(60);
    cli.ok(&["sync"]);
    assert_eq!(balance(&cli.ok(&["scan", "--name", "alice"])), 2500);
    assert_eq!(balance(&cli.ok(&["scan", "--name", "bob"])), 2500);
    // the same carrier again is a double spend: replay rejects it
    cli.ok(&["publish", &label, "--name", "bob", "--fee-rate", "1"]);
    shared.mine(61);
    assert!(cli.ok(&["sync"]).contains("rejected: 1"));

    // sponsored relayer with its own wallet and data directory
    let relay_dir = dir.join("relay");
    std::fs::create_dir_all(&relay_dir).unwrap();
    std::fs::write(relay_dir.join("pass"), "relay passphrase\n").unwrap();
    let relay_cli = Cli {
        data: relay_dir.clone(),
        profile: dir.join("profile.json"),
        chain: cli.chain.clone(),
    };
    let relay_wallet = relay_cli.ok(&["wallet-new", "--name", "relay"]);
    let relay_funding = field(&relay_wallet, "funding address:").to_string();
    shared.fund(&script_of(&relay_funding), 100_000);
    shared.mine(62);
    cli.ok(&["sync"]);
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
            "8",
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
    // 1. info
    let info: serde_json::Value = ureq::get(&format!("{relay_url}/info"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(info["deployment"], "e2e");
    assert_eq!(info["network"], "regtest");
    assert!(info["tip"].as_u64().is_some(), "{info}");
    // 2. a transfer relayed end to end
    cli.fails(
        &[
            "send",
            "--name",
            "alice",
            "--to",
            &bob_shielded,
            "--amount",
            "300",
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
        "300",
        "--relay",
        &relay_url,
    ]);
    assert!(relayed.contains("relayed by"), "{relayed}");
    let relayed_label = outbox_label(&relayed);
    // 3. the same envelope again, while it waits in the mempool
    cli.fails(
        &["publish", &relayed_label, "--relay", &relay_url],
        "already relayed",
    );
    // 4. a mint is refused before any request leaves the client
    let mint_label = outbox_label(&cli.ok(&[
        "mint",
        "--name",
        "alice",
        "--amount",
        "700",
        "--no-broadcast",
    ]));
    cli.fails(
        &["publish", &mint_label, "--relay", &relay_url],
        "pays the vault",
    );
    // …and by the server when posted directly
    let mint_hex =
        std::fs::read_to_string(dir.join("outbox").join(format!("{mint_label}.hex"))).unwrap();
    let post = |body: &str| -> (u16, String) {
        match ureq::post(&format!("{relay_url}/relay")).send_string(body) {
            Ok(r) => (200, r.into_string().unwrap()),
            Err(ureq::Error::Status(c, r)) => (c, r.into_string().unwrap()),
            Err(e) => panic!("{e}"),
        }
    };
    let (code, text) = post(&format!("{{\"envelope\":\"{mint_hex}\"}}"));
    assert!(
        code == 400 && text.contains("pays the vault"),
        "{code} {text}"
    );
    // 5. a tampered proof
    let mut tampered = hex::decode(
        std::fs::read_to_string(dir.join("outbox").join(format!("{relayed_label}.hex"))).unwrap(),
    )
    .unwrap();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let (code, text) = post(&format!("{{\"envelope\":\"{}\"}}", hex::encode(&tampered)));
    assert!(code == 400 && text.contains("rejected"), "{code} {text}");
    // 6. junk and 7. an unknown path
    let (code, text) = post("not json");
    assert!(code == 400 && text.contains("bad request"), "{code} {text}");
    let (code, _) = post("{\"envelope\":\"zz\"}");
    assert_eq!(code, 400);
    let status = ureq::get(&format!("{relay_url}/nothing"))
        .call()
        .unwrap_err();
    assert!(matches!(status, ureq::Error::Status(404, _)));
    assert!(server.0.wait().unwrap().success());
    shared.mine(63);
    cli.ok(&["sync"]);
    assert_eq!(balance(&cli.ok(&["scan", "--name", "alice"])), 2200);
    assert_eq!(balance(&cli.ok(&["scan", "--name", "bob"])), 2800);

    // fresh funding addresses: `--new` hands out the next receive index,
    // and coins sent there are found and spent
    let fresh_funding = field(
        &cli.ok(&["address", "--name", "alice", "--new"]),
        "funding address:",
    )
    .to_string();
    assert_ne!(fresh_funding, alice_funding);
    assert_eq!(
        field(&cli.ok(&["address", "--name", "alice"]), "funding address:"),
        fresh_funding
    );
    shared.fund(&script_of(&fresh_funding), 30_000);
    shared.mine(64);
    // more than any one coin: the payment needs the fresh coin too
    cli.ok(&[
        "fund-send",
        "--name",
        "alice",
        "--to",
        &bob_funding,
        "--amount",
        "100000",
        "--fee-rate",
        "1",
    ]);
    shared.mine(65);
    assert!(shared.utxos(&script_of(&fresh_funding)).is_empty());
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
    assert_eq!(balance(&cli.ok(&["scan", "--name", "bob"])), 1800);
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
    cookie.ok(&["sync"]);
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
    // a hand-written mainnet profile still derives mainnet funding addresses
    let mainnet = std::fs::read_to_string(&cli.profile)
        .unwrap()
        .replace("\"network\": \"regtest\"", "\"network\": \"mainnet\"");
    std::fs::write(dir.join("mainnet.json"), mainnet).unwrap();
    let mn = Cli {
        data: dir.clone(),
        profile: dir.join("mainnet.json"),
        chain: cli.chain.clone(),
    };
    assert!(
        mn.ok(&["address", "--name", "alice"])
            .contains("funding address:  bc1")
    );
    // no passphrase source and no terminal: the prompt fails cleanly
    let out = Command::new(env!("CARGO_BIN_EXE_sb"))
        .env_remove("SB_WALLET_PASSPHRASE")
        .args(["--profile"])
        .arg(&cli.profile)
        .args(["--data-dir"])
        .arg(&dir)
        .args(["address", "--name", "alice"])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    // read-only data directory: every command that writes reports the error
    use std::os::unix::fs::PermissionsExt;
    let ro = |p: &Path, mode: u32| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap()
    };
    ro(&dir.join("wallets"), 0o555);
    ro(&dir, 0o555);
    let writes = [
        vec!["scan", "--name", "alice"],
        vec!["unlock", "--name", "alice"],
        vec!["wallet-encrypt", "--name", "alice"],
        vec!["address", "--name", "alice", "--new"],
        vec!["wallet-new", "--name", "zzz"],
        vec!["sync"],
    ];
    let results: Vec<(Vec<&str>, bool, String)> = writes
        .iter()
        .map(|args| {
            let (ok, text) = cli.run(args);
            (args.clone(), ok, text)
        })
        .collect();
    ro(&dir, 0o755);
    ro(&dir.join("wallets"), 0o755);
    for (args, ok, text) in results {
        assert!(
            !ok,
            "{args:?} should fail on a read-only directory:\n{text}"
        );
    }
    // PostgreSQL state when a database is available
    if let Ok(conn) = std::env::var("SB_TEST_PG") {
        let text = cli.ok(&["--db", &conn, "sync"]);
        assert!(text.contains("SyncReport"));
        assert!(cli.ok(&["--db", &conn, "status"]).contains("Mint"));
    }
    std::fs::remove_dir_all(&dir).unwrap();
    let _ = Path::new("");
}
