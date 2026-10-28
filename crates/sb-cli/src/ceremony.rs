//! `sb ceremony …`: the multi-party setup of the transfer circuit's
//! Groth16 parameters (crate `sb-ceremony`, docs/CEREMONY.md). Every
//! command works on files, so participants exchange them however they
//! like and anyone can verify the whole chain afterwards.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

use sb_ceremony::keygen::{domain_size, initial_proving_key};
use sb_ceremony::phase1::Phase1;
use sb_ceremony::phase2::Phase2;
use sb_ceremony::transcript::digest;
use sb_circuit::{TransferCircuit, TransferParams, vk_sha256, vk_to_bytes};

#[derive(Subcommand)]
pub enum CeremonyCmd {
    /// Write the initial phase 1 accumulator sized for the transfer circuit.
    Phase1New {
        #[arg(long)]
        out: PathBuf,
        /// Domain size as a power of two (default: what the transfer circuit needs).
        #[arg(long)]
        power: Option<u32>,
    },
    /// Apply fresh secrets to a phase 1 accumulator (and forget them).
    Phase1Contribute {
        #[arg(long = "in")]
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// Extra entropy mixed into the secrets (type anything).
        #[arg(long)]
        entropy: Option<String>,
    },
    /// Check that `after` is a valid contribution on top of `before`.
    Phase1Verify {
        #[arg(long)]
        before: PathBuf,
        #[arg(long)]
        after: PathBuf,
    },
    /// Derive the transfer circuit's initial phase 2 key from a final phase 1 accumulator.
    Phase2New {
        #[arg(long)]
        phase1: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Apply a fresh delta to a phase 2 key (and forget it).
    Phase2Contribute {
        #[arg(long = "in")]
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        entropy: Option<String>,
    },
    /// Apply the final, publicly reproducible delta derived from a random beacon.
    Phase2Beacon {
        #[arg(long = "in")]
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// The beacon value, hex (for example a Bitcoin block hash agreed on by height).
        #[arg(long)]
        beacon: String,
    },
    /// Recompute the initial key from phase 1 and verify every phase 2 contribution.
    Phase2Verify {
        #[arg(long)]
        phase1: PathBuf,
        #[arg(long = "final")]
        final_: PathBuf,
    },
    /// Write the proving and verifying keys of a finished phase 2 (pin the printed hash in the profile).
    Export {
        #[arg(long = "final")]
        final_: PathBuf,
        #[arg(long)]
        pk: PathBuf,
        #[arg(long)]
        vk: PathBuf,
    },
}

/// Secrets come from the OS plus whatever the participant typed.
fn rng(entropy: Option<&str>) -> ChaCha20Rng {
    let mut os = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut os);
    let mut h = Sha256::new();
    h.update(os);
    h.update(entropy.unwrap_or("").as_bytes());
    ChaCha20Rng::from_seed(h.finalize().into())
}

fn read_phase1(path: &Path) -> Result<(Phase1, [u8; 32])> {
    let bytes = std::fs::read(path).with_context(|| path.display().to_string())?;
    let p = Phase1::read(&bytes[..]).with_context(|| path.display().to_string())?;
    Ok((p, digest(&bytes)))
}

fn read_phase2(path: &Path) -> Result<Phase2> {
    let bytes = std::fs::read(path).with_context(|| path.display().to_string())?;
    Phase2::read(&bytes[..]).with_context(|| path.display().to_string())
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<[u8; 32]> {
    std::fs::write(path, bytes).with_context(|| path.display().to_string())?;
    Ok(digest(bytes))
}

pub fn run(cmd: CeremonyCmd) -> Result<()> {
    let mut rng_for_checks = rng(None);
    match cmd {
        CeremonyCmd::Phase1New { out, power } => {
            let n = match power {
                Some(p) if (1..=28).contains(&p) => 1usize << p,
                Some(p) => bail!("power {p} is out of range (1..=28)"),
                None => domain_size(TransferCircuit::default())?,
            };
            let needed = domain_size(TransferCircuit::default())?;
            if n < needed {
                bail!("the transfer circuit needs a domain of {needed}; {n} is too small");
            }
            let p = Phase1::new(n)?;
            let d = write_file(&out, &p.to_bytes()?)?;
            println!(
                "phase 1 accumulator for a domain of {n} written to {}",
                out.display()
            );
            println!("digest {}", hex::encode(d));
        }
        CeremonyCmd::Phase1Contribute {
            input,
            out,
            entropy,
        } => {
            let (p, d) = read_phase1(&input)?;
            eprintln!(
                "contributing to a domain of {} (digest {})…",
                p.n,
                hex::encode(d)
            );
            let next = p.contribute(d, &mut rng(entropy.as_deref()));
            let d2 = write_file(&out, &next.to_bytes()?)?;
            println!("contribution written to {}", out.display());
            println!("digest {}", hex::encode(d2));
            println!("publish this digest; the secrets were never written anywhere");
        }
        CeremonyCmd::Phase1Verify { before, after } => {
            let (b, d) = read_phase1(&before)?;
            let (a, d2) = read_phase1(&after)?;
            Phase1::verify_transition(&b, d, &a, &mut rng_for_checks)?;
            println!("valid: {} -> {}", hex::encode(d), hex::encode(d2));
        }
        CeremonyCmd::Phase2New { phase1, out } => {
            let (p, d) = read_phase1(&phase1)?;
            eprintln!("checking the accumulator's shape…");
            p.verify_shape(&mut rng_for_checks)?;
            eprintln!("deriving the transfer circuit's key (domain {})…", p.n);
            let pk = initial_proving_key(TransferCircuit::default(), &p)?;
            let q = Phase2::new(pk)?;
            let d2 = write_file(&out, &q.to_bytes()?)?;
            println!(
                "phase 2 initial key written to {} (from phase 1 digest {})",
                out.display(),
                hex::encode(d)
            );
            println!("initial key digest {}", hex::encode(q.cs_hash));
            println!("file digest {}", hex::encode(d2));
        }
        CeremonyCmd::Phase2Contribute {
            input,
            out,
            entropy,
        } => {
            let q = read_phase2(&input)?;
            eprintln!(
                "contributing (after {} contribution(s))…",
                q.contributions.len()
            );
            let next = q.contribute(&mut rng(entropy.as_deref()))?;
            let key = next.contributions.last().expect("just added");
            write_file(&out, &next.to_bytes()?)?;
            println!("contribution written to {}", out.display());
            println!("contribution hash {}", hex::encode(key.hash()));
            println!("publish this hash; the secret was never written anywhere");
        }
        CeremonyCmd::Phase2Beacon { input, out, beacon } => {
            let q = read_phase2(&input)?;
            let beacon = hex::decode(&beacon).context("beacon hex")?;
            let next = q.beacon(&beacon)?;
            let key = next.contributions.last().expect("just added");
            write_file(&out, &next.to_bytes()?)?;
            println!("beacon contribution written to {}", out.display());
            println!("contribution hash {}", hex::encode(key.hash()));
        }
        CeremonyCmd::Phase2Verify { phase1, final_ } => {
            let (p, _) = read_phase1(&phase1)?;
            p.verify_shape(&mut rng_for_checks)?;
            let q = read_phase2(&final_)?;
            eprintln!("recomputing the initial key…");
            let initial = initial_proving_key(TransferCircuit::default(), &p)?;
            let hashes = q.verify(&initial, &mut rng_for_checks)?;
            println!("valid: {} contribution(s)", hashes.len());
            for (i, h) in hashes.iter().enumerate() {
                println!("  {i}: {}", hex::encode(h));
            }
            println!("verifying key sha256 {}", hex::encode(vk_sha256(&q.pk.vk)));
        }
        CeremonyCmd::Export { final_, pk, vk } => {
            let q = read_phase2(&final_)?;
            if q.contributions.is_empty() {
                bail!("this key has no contributions: delta is 1 and anyone can forge proofs");
            }
            let params = TransferParams::from_pk(q.pk);
            std::fs::write(&pk, params.pk_to_bytes()?).with_context(|| pk.display().to_string())?;
            std::fs::write(&vk, vk_to_bytes(params.vk()))
                .with_context(|| vk.display().to_string())?;
            println!("proving key written to {}", pk.display());
            println!("verifying key written to {}", vk.display());
            println!(
                "verifying key sha256 {}",
                hex::encode(vk_sha256(params.vk()))
            );
            println!(
                "profile: sb profile-new … --ceremony-vk {} --ceremony-pk {}",
                vk.display(),
                pk.display()
            );
        }
    }
    std::io::stdout().flush()?;
    Ok(())
}
