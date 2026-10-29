//! Replay proofs end to end (`docs/REPLAY-PROOF.md` §4.5) on the fake
//! node: an indexer replays, proves its blocks and serves them; a light
//! client with `--chain proof:<url>` syncs from the proofs alone, sees the
//! same balances, spends from its own note tree, and refuses a tampered
//! proven block.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use bitcoin::ScriptBuf;
use sb_indexer::chain::fake::{FakeHttp, Shared};
use sb_indexer::chain::mock::MockChain;

struct Cli {
    data: PathBuf,
    profile: PathBuf,
    chain: String,
    global: Vec<String>,
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
            .args(&self.global)
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

struct KillOnDrop(std::process::Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_serve(cli: &Cli) -> (KillOnDrop, String) {
    let server = cli
        .command(&["serve", "--listen", "127.0.0.1:0"])
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

fn client(dir: &Path, name: &str, profile: &Path, chain: String) -> Cli {
    let d = dir.join(name);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("pass"), "pw\n").unwrap();
    Cli {
        data: d,
        profile: profile.to_path_buf(),
        chain,
        global: vec![],
    }
}

#[test]
fn light_client_syncs_from_proofs() {
    let dir = std::env::temp_dir().join(format!("sb-proof-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pass"), "pw\n").unwrap();
    let mut chain = MockChain::new(10);
    chain.push_block(vec![]);
    chain.push_block(vec![]);
    let shared = Shared::new(chain);
    let http = FakeHttp::start(shared.clone());
    let esplora = format!("esplora:{}", http.esplora_url());
    let indexer = Cli {
        data: dir.clone(),
        profile: dir.join("profile.json"),
        chain: esplora.clone(),
        global: vec![],
    };
    let mut salt = 100u32;
    let mut mine = |n: u32| {
        for _ in 0..n {
            salt += 1;
            shared.mine(salt);
        }
    };

    // a deployment with a two-slot batch circuit and a dev boundary
    indexer.ok(&[
        "profile-new",
        "--name",
        "tmp",
        "--network",
        "regtest",
        "--activation",
        "12",
    ]);
    let op = indexer.ok(&["wallet-new", "--name", "operator"]);
    let op_shielded = field(&op, "shielded address:").to_string();
    let op_funding = field(&op, "funding address:").to_string();
    let written = indexer.ok(&[
        "profile-new",
        "--name",
        "proof",
        "--network",
        "regtest",
        "--activation",
        "12",
        "--vault-script",
        &hex::encode(script_of(&op_funding).as_bytes()),
        "--operator-address",
        &op_shielded,
        "--batch-insecure",
        "2",
    ]);
    assert!(written.contains("\"batch\""), "{written}");
    let alice = indexer.ok(&["wallet-new", "--name", "alice"]);
    let alice_funding = field(&alice, "funding address:").to_string();

    // the light client's wallet lives in its own data directory; its chain
    // is the indexer's proven blocks
    let (server, url) = start_serve(&indexer);
    let light = client(&dir, "light", &indexer.profile, format!("proof:{url}"));
    let bob = light.ok(&["wallet-new", "--name", "bob"]);
    let bob_shielded = field(&bob, "shielded address:").to_string();
    let bob_funding = field(&bob, "funding address:").to_string();
    shared.fund(&script_of(&alice_funding), 300_000);
    shared.fund(&script_of(&bob_funding), 100_000);
    mine(1);

    // history: a mint, two payments to bob in one block, empty blocks between
    indexer.ok(&[
        "mint",
        "--name",
        "alice",
        "--amount",
        "20000",
        "--fee-rate",
        "1",
    ]);
    mine(3);
    indexer.ok(&["sync"]);
    indexer.ok(&[
        "send",
        "--name",
        "alice",
        "--to",
        &bob_shielded,
        "--amount",
        "1000",
        "--fee-rate",
        "1",
    ]);
    mine(3);
    indexer.ok(&["sync"]);
    indexer.ok(&[
        "send",
        "--name",
        "alice",
        "--to",
        &bob_shielded,
        "--amount",
        "500",
        "--fee-rate",
        "1",
    ]);
    mine(3);
    let synced = indexer.ok(&["sync"]);
    assert!(synced.contains("accepted: 1"), "{synced}");
    assert_eq!(balance(&indexer.ok(&["scan", "--name", "alice"])), 18500);

    // nothing proven yet: the light client has nothing to sync
    let before = light.ok(&["sync"]);
    assert!(before.contains("blocks: 0"), "{before}");
    // the indexer proves its blocks (empty ones without a proof)
    let proven = indexer.ok(&["prove-batches"]);
    assert!(proven.contains("proven in"), "{proven}");
    assert!(proven.contains("block(s) written"), "{proven}");
    let batches = dir.join("batches").join("proof");
    let files = std::fs::read_dir(&batches).unwrap().count();
    assert!(files >= 10, "{files} proven blocks");
    indexer.ok(&["prove-batches"]); // idempotent: nothing new

    // the light client syncs from the proofs and sees bob's notes
    let synced = light.ok(&["sync"]);
    assert!(synced.contains("accepted: 3"), "{synced}");
    assert!(synced.contains("light client"), "{synced}");
    assert_eq!(balance(&light.ok(&["scan", "--name", "bob"])), 1500);
    let again = light.ok(&["sync"]);
    assert!(again.contains("blocks: 0"), "{again}");
    // the light state has no envelopes and no nullifier tree
    let state = std::fs::read_to_string(light.data.join("state-proof.json")).unwrap();
    assert!(state.contains("\"light\""), "a light state");
    assert!(
        !state.contains("\"raw\":\"62746301"),
        "no envelope bytes kept"
    );

    // the light client spends from its own tree, through a full source
    let mut publishing = Cli {
        data: light.data.clone(),
        profile: light.profile.clone(),
        chain: light.chain.clone(),
        global: vec!["--publish-via".into(), esplora.clone()],
    };
    light.fails(
        &[
            "send",
            "--name",
            "bob",
            "--to",
            &op_shielded,
            "--amount",
            "700",
            "--fee-rate",
            "1",
        ],
        "has no publisher",
    );
    light.ok(&["unlock", "--name", "bob"]);
    publishing.ok(&[
        "send",
        "--name",
        "bob",
        "--to",
        &op_shielded,
        "--amount",
        "700",
        "--fee-rate",
        "1",
    ]);
    publishing.global.clear();
    mine(3);
    let synced = indexer.ok(&["sync"]);
    assert!(synced.contains("accepted: 1"), "{synced}");
    indexer.ok(&["prove-batches"]);
    let synced = light.ok(&["sync"]);
    assert!(synced.contains("accepted: 1"), "{synced}");
    assert_eq!(balance(&light.ok(&["scan", "--name", "bob"])), 800);
    assert_eq!(balance(&indexer.ok(&["scan", "--name", "operator"])), 700);

    // a tampered proven block is refused by a fresh client; the original
    // syncs it
    let fresh = client(&dir, "fresh", &indexer.profile, format!("proof:{url}"));
    let send_height: u32 = synced
        .lines()
        .find(|l| l.contains("accepted Transfer"))
        .map(|_| 0)
        .unwrap_or(0);
    let _ = send_height;
    let mut tampered = None;
    for entry in std::fs::read_dir(&batches).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        if text.contains("\"kind\":\"transfer\"") {
            tampered = Some((path, text));
            break;
        }
    }
    let (path, original) = tampered.expect("a block with a transfer");
    let edited = original.replacen("\"kind\":\"transfer\"", "\"kind\":\"swap\"", 1);
    std::fs::write(&path, &edited).unwrap();
    fresh.fails(&["sync"], "swap");
    let edited = original.replacen("\"empty\":false", "\"empty\":true", 1);
    std::fs::write(&path, &edited).unwrap();
    fresh.fails(&["sync"], "not ours");
    std::fs::write(&path, &original).unwrap();
    let synced = fresh.ok(&["sync"]);
    assert!(synced.contains("accepted: 4"), "{synced}");
    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
}
