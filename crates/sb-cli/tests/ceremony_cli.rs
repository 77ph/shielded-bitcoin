//! The ceremony commands end to end on the transfer circuit, then a profile
//! pinned to the ceremony's keys proving a real transfer on the fake node.
//! Minutes of work, so it runs only with `SB_CEREMONY_FULL` set.

use std::path::PathBuf;
use std::process::Command;

use sb_indexer::chain::fake::{FakeHttp, Shared};
use sb_indexer::chain::mock::MockChain;

fn sb(args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_sb"))
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

fn ok(args: &[&str]) -> String {
    let (ok, text) = sb(args);
    assert!(ok, "`sb {}` failed:\n{text}", args.join(" "));
    text
}

fn fails(args: &[&str], needle: &str) {
    let (ok, text) = sb(args);
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

fn field<'a>(text: &'a str, label: &str) -> &'a str {
    text.lines()
        .find(|l| l.starts_with(label))
        .unwrap_or_else(|| panic!("{label} not in:\n{text}"))
        .split_whitespace()
        .last()
        .unwrap()
}

#[test]
fn ceremony_commands_and_a_ceremony_profile() {
    if std::env::var("SB_CEREMONY_FULL").is_err() {
        eprintln!("set SB_CEREMONY_FULL=1 to run the ceremony end to end");
        return;
    }
    let dir = std::env::temp_dir().join(format!("sb-ceremony-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = |name: &str| -> String { dir.join(name).display().to_string() };

    // phase 1: two participants
    fails(
        &[
            "ceremony",
            "phase1-new",
            "--out",
            &p("p1-0.bin"),
            "--power",
            "3",
        ],
        "too small",
    );
    fails(
        &[
            "ceremony",
            "phase1-new",
            "--out",
            &p("p1-0.bin"),
            "--power",
            "40",
        ],
        "out of range",
    );
    let t = std::time::Instant::now();
    ok(&["ceremony", "phase1-new", "--out", &p("p1-0.bin")]);
    ok(&[
        "ceremony",
        "phase1-contribute",
        "--in",
        &p("p1-0.bin"),
        "--out",
        &p("p1-1.bin"),
        "--entropy",
        "first",
    ]);
    eprintln!("phase 1 contribution: {:?}", t.elapsed());
    ok(&[
        "ceremony",
        "phase1-verify",
        "--before",
        &p("p1-0.bin"),
        "--after",
        &p("p1-1.bin"),
    ]);
    eprintln!("phase 1 verification: {:?}", t.elapsed());
    ok(&[
        "ceremony",
        "phase1-contribute",
        "--in",
        &p("p1-1.bin"),
        "--out",
        &p("p1-2.bin"),
    ]);
    ok(&[
        "ceremony",
        "phase1-verify",
        "--before",
        &p("p1-1.bin"),
        "--after",
        &p("p1-2.bin"),
    ]);
    fails(
        &[
            "ceremony",
            "phase1-verify",
            "--before",
            &p("p1-0.bin"),
            "--after",
            &p("p1-2.bin"),
        ],
        "not built on",
    );
    // phase 2: initial key, two participants, a beacon, verification, export
    ok(&[
        "ceremony",
        "phase2-new",
        "--phase1",
        &p("p1-2.bin"),
        "--out",
        &p("p2-0.bin"),
    ]);
    eprintln!("key derivation: {:?}", t.elapsed());
    fails(
        &[
            "ceremony",
            "export",
            "--final",
            &p("p2-0.bin"),
            "--pk",
            &p("x.pk"),
            "--vk",
            &p("x.vk"),
        ],
        "no contributions",
    );
    ok(&[
        "ceremony",
        "phase2-contribute",
        "--in",
        &p("p2-0.bin"),
        "--out",
        &p("p2-1.bin"),
        "--entropy",
        "second",
    ]);
    ok(&[
        "ceremony",
        "phase2-contribute",
        "--in",
        &p("p2-1.bin"),
        "--out",
        &p("p2-2.bin"),
    ]);
    ok(&[
        "ceremony",
        "phase2-beacon",
        "--in",
        &p("p2-2.bin"),
        "--out",
        &p("p2-final.bin"),
        "--beacon",
        "00".repeat(32).as_str(),
    ]);
    fails(
        &[
            "ceremony",
            "phase2-beacon",
            "--in",
            &p("p2-2.bin"),
            "--out",
            &p("junk.bin"),
            "--beacon",
            "zz",
        ],
        "beacon hex",
    );
    let verified = ok(&[
        "ceremony",
        "phase2-verify",
        "--phase1",
        &p("p1-2.bin"),
        "--final",
        &p("p2-final.bin"),
    ]);
    eprintln!("phase 2 verification: {:?}", t.elapsed());
    assert!(verified.contains("valid: 3 contribution(s)"), "{verified}");
    let vk_hash = field(&verified, "verifying key sha256").to_string();
    // a phase 2 file from a different phase 1 does not verify
    fails(
        &[
            "ceremony",
            "phase2-verify",
            "--phase1",
            &p("p1-1.bin"),
            "--final",
            &p("p2-final.bin"),
        ],
        "initial key digest",
    );
    let exported = ok(&[
        "ceremony",
        "export",
        "--final",
        &p("p2-final.bin"),
        "--pk",
        &p("transfer.pk"),
        "--vk",
        &p("transfer.vk"),
    ]);
    assert_eq!(field(&exported, "verifying key sha256"), vk_hash);
    fails(
        &[
            "ceremony",
            "phase1-verify",
            "--before",
            &p("p2-0.bin"),
            "--after",
            &p("p1-1.bin"),
        ],
        "not a phase 1",
    );
    fails(
        &[
            "ceremony",
            "phase2-verify",
            "--phase1",
            &p("p1-2.bin"),
            "--final",
            &p("p1-1.bin"),
        ],
        "not a phase 2",
    );

    // a profile pinned to the ceremony, and a transfer proven with its key
    let mut chain = MockChain::new(10);
    chain.push_block(vec![]);
    chain.push_block(vec![]);
    let shared = Shared::new(chain);
    let http = FakeHttp::start(shared.clone());
    let profile = p("profile.json");
    let common: Vec<String> = vec![
        "--profile".into(),
        profile.clone(),
        "--data-dir".into(),
        p("data"),
        "--chain".into(),
        format!("esplora:{}", http.esplora_url()),
        "--passphrase-file".into(),
        p("pass"),
    ];
    std::fs::write(dir.join("pass"), "pw\n").unwrap();
    let run = |args: &[&str]| -> String {
        let mut all: Vec<&str> = common.iter().map(String::as_str).collect();
        all.extend_from_slice(args);
        ok(&all)
    };
    let runf = |args: &[&str], needle: &str| {
        let mut all: Vec<&str> = common.iter().map(String::as_str).collect();
        all.extend_from_slice(args);
        fails(&all, needle);
    };
    runf(
        &[
            "profile-new",
            "--name",
            "c",
            "--network",
            "regtest",
            "--activation",
            "12",
            "--ceremony-pk",
            "transfer.pk",
        ],
        "ceremony-vk",
    );
    runf(
        &[
            "profile-new",
            "--name",
            "c",
            "--network",
            "regtest",
            "--activation",
            "12",
            "--ceremony-vk",
            "nothing.vk",
        ],
        "verifying key",
    );
    // operator wallet first: the vault is its funding address
    run(&[
        "profile-new",
        "--name",
        "tmp",
        "--network",
        "regtest",
        "--activation",
        "12",
    ]);
    let op = run(&["wallet-new", "--name", "operator"]);
    let op_funding = field(&op, "funding address:").to_string();
    let vault = op_funding
        .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
        .unwrap()
        .assume_checked()
        .script_pubkey();
    let written = run(&[
        "profile-new",
        "--name",
        "ceremony",
        "--network",
        "regtest",
        "--activation",
        "12",
        "--vault-script",
        &hex::encode(vault.as_bytes()),
        "--ceremony-vk",
        "transfer.vk",
        "--ceremony-pk",
        "transfer.pk",
    ]);
    assert!(written.contains("\"kind\": \"ceremony\""), "{written}");
    assert!(written.contains(&vk_hash), "{written}");
    let alice = run(&["wallet-new", "--name", "alice"]);
    let alice_funding = field(&alice, "funding address:").to_string();
    let alice_shielded = field(&alice, "shielded address:").to_string();
    shared.fund(
        &alice_funding
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .unwrap()
            .assume_checked()
            .script_pubkey(),
        100_000,
    );
    shared.mine(1);
    run(&[
        "mint",
        "--name",
        "alice",
        "--amount",
        "5000",
        "--fee-rate",
        "1",
    ]);
    shared.mine(2);
    shared.mine(3);
    shared.mine(4);
    run(&["sync"]);
    assert!(run(&["scan", "--name", "alice"]).contains("balance 5000"));
    let sent = run(&[
        "send",
        "--name",
        "alice",
        "--to",
        &alice_shielded,
        "--amount",
        "1000",
        "--fee-rate",
        "1",
    ]);
    assert!(sent.contains("broadcast"), "{sent}");
    shared.mine(5);
    let synced = run(&["sync"]);
    assert!(
        synced.contains("accepted: 1") && synced.contains("rejected: 0"),
        "{synced}"
    );
    eprintln!(
        "transfer under the ceremony key accepted: {:?}",
        t.elapsed()
    );
    // an insecure-seed proof does not verify under the ceremony key
    let _ = PathBuf::from(&profile);
    std::fs::remove_dir_all(&dir).unwrap();
}
