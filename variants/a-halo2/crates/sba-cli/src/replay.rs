//! `sb a replay-prove` / `replay-decide`: the accumulated replay proof's
//! chain (`docs/REPLAY-PROOF-A.md` §3.8) run block by block. The prover
//! keeps its own replay of the chain (`replay-<deployment>/indexer.json`),
//! its state between runs (`chain.state`) and the proven steps
//! (`steps/`); the decider keeps the client's state (`client.state`).
//! Keys are made at start, minutes each run: a function of the circuits'
//! structure, so every run agrees on them (`ChainKeys::id`).

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use sba_indexer::{Indexer, JsonStore, ReplayState, StateStore};
use sba_primitives::encoding::fp_to_bytes;
use sba_replay::chain::{ChainDecider, ChainKeys, ChainProver, prove_next_step, reconcile};
use sba_replay::persist::{ChainState, ClientState};
use sba_replay::wire::ProvenStep;

use crate::Ctx;

/// The fragment and circuit sizes a key set is made for.
#[derive(Clone, Copy, Debug)]
pub struct Sizes {
    pub proofs: usize,
    pub slots: usize,
    /// Blocks without events a step may close before its block (§3.9).
    pub empty: usize,
    pub k_q: u32,
    pub k_p: u32,
}

struct Dir(PathBuf);

impl Dir {
    fn of(ctx: &Ctx) -> Result<Self> {
        let d = ctx.data_dir.join(format!("replay-{}", ctx.deployment.name));
        std::fs::create_dir_all(d.join("steps"))?;
        Ok(Dir(d))
    }
    fn indexer(&self) -> PathBuf {
        self.0.join("indexer.json")
    }
    fn chain_state(&self) -> PathBuf {
        self.0.join("chain.state")
    }
    fn client_state(&self) -> PathBuf {
        self.0.join("client.state")
    }
    fn step(&self, index: u32, height: u32) -> PathBuf {
        self.0
            .join("steps")
            .join(format!("step-{index:06}-{height}.bin"))
    }
    /// The proven steps on disk, by index.
    fn steps(&self) -> Result<Vec<(u32, u32, PathBuf)>> {
        let mut v = Vec::new();
        for e in std::fs::read_dir(self.0.join("steps"))? {
            let p = e?.path();
            let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(rest) = name
                .strip_prefix("step-")
                .and_then(|r| r.strip_suffix(".bin"))
            else {
                continue;
            };
            let Some((i, h)) = rest.split_once('-') else {
                continue;
            };
            if let (Ok(i), Ok(h)) = (i.parse::<u32>(), h.parse::<u32>()) {
                v.push((i, h, p));
            }
        }
        v.sort();
        Ok(v)
    }
}

/// Write through a temporary file: a run killed mid-write leaves the old file.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// The key set of these sizes: read from `dir/keys` when it is there,
/// otherwise generated (minutes) and written for the next run.
fn keys(ctx: &Ctx, dir: &Dir, sizes: Sizes) -> Result<ChainKeys> {
    let genesis = ReplayState::new().opening(ctx.deployment.activation_height);
    let verifier = ctx.deployment.verifier()?;
    let params = Indexer::new(ctx.deployment.clone(), verifier, ReplayState::new()).batch_params();
    let kdir = dir.0.join("keys");
    if ChainKeys::on_disk(
        &kdir,
        sizes.proofs,
        sizes.slots,
        sizes.empty,
        sizes.k_q,
        sizes.k_p,
    ) {
        println!(
            "chain keys: {} proofs over {} slots, {} empty blocks a step, k = {}/{}; reading them …",
            sizes.proofs, sizes.slots, sizes.empty, sizes.k_q, sizes.k_p
        );
        let t = Instant::now();
        let keys = ChainKeys::read(
            &kdir,
            sizes.proofs,
            sizes.slots,
            sizes.empty,
            sizes.k_q,
            sizes.k_p,
            params,
            &genesis,
        )
        .map_err(|e| anyhow::anyhow!("chain keys on disk: {e}"))?;
        println!(
            "chain keys: read in {:.0} s, id {}",
            t.elapsed().as_secs_f64(),
            hex::encode(keys.id())
        );
        return Ok(keys);
    }
    println!(
        "chain keys: {} proofs over {} slots, {} empty blocks a step, k = {}/{}; making them (minutes) …",
        sizes.proofs, sizes.slots, sizes.empty, sizes.k_q, sizes.k_p
    );
    let t = Instant::now();
    let keys = ChainKeys::generate(
        sizes.proofs,
        sizes.slots,
        sizes.empty,
        sizes.k_q,
        sizes.k_p,
        params,
        &genesis,
    )
    .map_err(|e| anyhow::anyhow!("chain keys: {e}"))?;
    println!(
        "chain keys: {:.0} s, id {}",
        t.elapsed().as_secs_f64(),
        hex::encode(keys.id())
    );
    let t = Instant::now();
    keys.write(&kdir)
        .with_context(|| format!("writing the keys under {}", kdir.display()))?;
    println!("chain keys: written in {:.0} s", t.elapsed().as_secs_f64());
    Ok(keys)
}

/// Prove the next steps of the chain: `steps` of them, or — following —
/// every step the chain offers, looking again every `poll` when it
/// offers none.
pub fn prove(
    ctx: &Ctx,
    sizes: Sizes,
    steps: Option<u32>,
    poll: std::time::Duration,
    settle: std::time::Duration,
) -> Result<()> {
    let dir = Dir::of(ctx)?;
    let keys = keys(ctx, &dir, sizes)?;
    let mut store: Box<dyn StateStore> = Box::new(JsonStore::new(dir.indexer()));
    let state = store.load()?;
    let mut idx = Indexer::new(ctx.deployment.clone(), ctx.deployment.verifier()?, state);
    let chain = ctx.chain_source()?;
    let (mut prover, next) = match std::fs::read(dir.chain_state()) {
        Ok(b) => {
            let st = ChainState::from_bytes(&b).map_err(|e| anyhow::anyhow!("chain.state: {e}"))?;
            let p = ChainProver::resume(&keys, &st).map_err(|e| anyhow::anyhow!("{e}"))?;
            println!(
                "chain state: {} steps, next block {}, digest {}",
                st.index,
                st.next_height,
                hex::encode(fp_to_bytes(&st.s))
            );
            (p, st.next_height)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let p = ChainProver::new(&keys);
            println!(
                "chain state: none; starting at block {} from the genesis digest {}",
                ctx.deployment.activation_height,
                hex::encode(fp_to_bytes(&p.s))
            );
            (p, ctx.deployment.activation_height)
        }
        Err(e) => return Err(e).context("chain.state"),
    };
    reconcile(&mut idx, Some(store.as_mut()), next).map_err(|e| anyhow::anyhow!("{e}"))?;
    write_atomic(&dir.chain_state(), &prover.state(next).to_bytes())?;
    let decider = ChainDecider { keys: &keys };
    let mut done = 0u32;
    loop {
        if let Some(n) = steps {
            if done >= n {
                break;
            }
        }
        let height = idx.next_height();
        let s_prev = prover.s;
        let t = Instant::now();
        let Some((step, waited)) = prove_next_step(
            &mut prover,
            &mut idx,
            Some(store.as_mut()),
            chain.as_ref(),
            settle,
            poll,
        )
        .map_err(|e| anyhow::anyhow!("block {height}: {e}"))?
        else {
            if steps.is_some() {
                println!("block {height} is not on the chain yet");
                break;
            }
            std::thread::sleep(poll);
            continue;
        };
        done += 1;
        let proved = t.elapsed().saturating_sub(waited).as_secs_f64();
        let index = prover.steps as u32;
        let height = step.height;
        let bytes = step.to_bytes();
        write_atomic(&dir.step(index, height), &bytes)?;
        write_atomic(
            &dir.chain_state(),
            &prover.state(idx.next_height()).to_bytes(),
        )?;
        // the prover's own check, as the client will do it
        let t = Instant::now();
        let s = decider
            .decide(&step, index as usize, s_prev)
            .map_err(|e| anyhow::anyhow!("step {index} refused by the decider: {e}"))?;
        println!(
            "step {index}: blocks {}..={height} ({} without events), {} slots, {} bytes, proved in {proved:.1} s after waiting {:.0} s, decided in {:.2} s, digest {}",
            step.first_height,
            height - step.first_height,
            step.slots.iter().filter(|s| s.is_some()).count(),
            bytes.len(),
            waited.as_secs_f64(),
            t.elapsed().as_secs_f64(),
            hex::encode(fp_to_bytes(&s))
        );
    }
    Ok(())
}

/// Decide the steps on disk the client has not seen, from the keys and
/// the client's state alone; with `latest`, the newest step alone from
/// the genesis digest (one step attests the whole history).
pub fn decide(ctx: &Ctx, sizes: Sizes, latest: bool) -> Result<()> {
    let dir = Dir::of(ctx)?;
    let keys = keys(ctx, &dir, sizes)?;
    if latest {
        let (index, height, path) = dir.steps()?.into_iter().last().context("no step on disk")?;
        let step = ProvenStep::from_bytes(&std::fs::read(&path)?)
            .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        let decider = ChainDecider { keys: &keys };
        let t = Instant::now();
        let (h, s) = decider
            .decide_latest(&step)
            .map_err(|e| anyhow::anyhow!("step {index} (block {height}) refused: {e}"))?;
        println!(
            "step {index} alone, from the genesis: block {h} accepted in {:.2} s, digest {}",
            t.elapsed().as_secs_f64(),
            hex::encode(fp_to_bytes(&s))
        );
        write_atomic(
            &dir.client_state(),
            &ClientState {
                keys_id: keys.id(),
                index,
                s,
            }
            .to_bytes(),
        )?;
        return Ok(());
    }
    let mut client = match std::fs::read(dir.client_state()) {
        Ok(b) => {
            let c =
                ClientState::from_bytes(&b).map_err(|e| anyhow::anyhow!("client.state: {e}"))?;
            if c.keys_id != keys.id() {
                bail!("client.state is of another key set");
            }
            c
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ClientState {
            keys_id: keys.id(),
            index: 0,
            s: keys.genesis_digest(),
        },
        Err(e) => return Err(e).context("client.state"),
    };
    println!(
        "client: {} steps decided, digest {}",
        client.index,
        hex::encode(fp_to_bytes(&client.s))
    );
    let decider = ChainDecider { keys: &keys };
    let mut decided = 0;
    for (index, height, path) in dir.steps()? {
        if index <= client.index {
            continue;
        }
        if index != client.index + 1 {
            bail!("step {index} on disk but step {} missing", client.index + 1);
        }
        let step = ProvenStep::from_bytes(&std::fs::read(&path)?)
            .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        if step.height != height {
            bail!("{}: the step is of block {}", path.display(), step.height);
        }
        let t = Instant::now();
        let s = decider
            .decide(&step, index as usize, client.s)
            .map_err(|e| anyhow::anyhow!("step {index} (block {height}) refused: {e}"))?;
        println!(
            "step {index}: block {height} accepted in {:.2} s, digest {}",
            t.elapsed().as_secs_f64(),
            hex::encode(fp_to_bytes(&s))
        );
        client.index = index;
        client.s = s;
        write_atomic(&dir.client_state(), &client.to_bytes())?;
        decided += 1;
    }
    println!(
        "{decided} step(s) decided; the client stands after step {}",
        client.index
    );
    Ok(())
}
