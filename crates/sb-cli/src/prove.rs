//! `sb prove-batches`: the indexer's side of `docs/REPLAY-PROOF.md` §4.5.
//! For every replayed block not yet proven, the fragments of the batch
//! circuit are built from the replayed history, proven, and written with
//! the statements, the envelopes' own proofs and the block hash to
//! `batches/<deployment>/<height>.json`, which `sb serve` publishes at
//! `GET /batches/<height>`. An empty block is written without a proof:
//! the client steps over it by itself.

use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result, anyhow};

use sb_core::envelope::PROOF_LEN;
use sb_core::event::EventKind;
use sb_indexer::batch::build_block;
use sb_indexer::proof::{FragmentJson, OpeningJson, ProvenBlockJson, SlotJson};
use sb_indexer::state::ReplayState;
use sb_primitives::encoding::fr_to_bytes;

use crate::Ctx;

/// The directory of a deployment's proven blocks.
pub(crate) fn batches_dir(ctx: &Ctx) -> PathBuf {
    ctx.batches_dir()
}

/// The file of one proven block.
pub(crate) fn batch_path(ctx: &Ctx, height: u32) -> PathBuf {
    batches_dir(ctx).join(format!("{height}.json"))
}

/// Prove every replayed block from `from` (default: the first unproven
/// one) to the tip; returns how many were written.
pub(crate) fn run(ctx: &Ctx, from: Option<u32>, dry_run: bool) -> Result<usize> {
    let batch = ctx.deployment.batch.as_ref().ok_or_else(|| {
        anyhow!("this deployment has no batch circuit (profile-new --batch-insecure <n>)")
    })?;
    let (idx, _store) = ctx.indexer()?;
    let state = &idx.state;
    let Some(tip) = state.last_height() else {
        return Ok(0);
    };
    let dir = batches_dir(ctx);
    std::fs::create_dir_all(&dir)?;
    let first = match from {
        Some(h) => h,
        None => {
            let mut h = ctx.deployment.activation_height;
            while h <= tip && batch_path(ctx, h).exists() {
                h += 1;
            }
            h
        }
    };
    if first > tip {
        println!("every block up to {tip} is proven");
        return Ok(0);
    }
    let params = if dry_run {
        None
    } else {
        Some(ctx.batch_params()?)
    };
    let salt = ctx.deployment.const_salt_fr();
    let mut written = 0;
    for height in first..=tip {
        let t0 = Instant::now();
        let fragments = build_block(
            state,
            height,
            batch.n,
            ctx.deployment.activation_height,
            &salt,
        )?;
        let hash = state
            .blocks
            .iter()
            .find(|b| b.height == height)
            .map(|b| b.hash.to_string())
            .ok_or_else(|| anyhow!("block {height} not replayed"))?;
        let empty = fragments.len() == 1 && fragments[0].slots.iter().all(|s| s.is_none());
        let last_next = fragments.last().expect("one fragment at least").next;
        let mut out = ProvenBlockJson {
            height,
            hash,
            empty,
            next: OpeningJson::from(&last_next),
            fragments: Vec::new(),
        };
        if !empty {
            for f in &fragments {
                let proof = match &params {
                    Some(p) => p
                        .prove(&f.statement, &f.witness, &mut rand::thread_rng())
                        .with_context(|| format!("proving block {height}"))?,
                    None => [0u8; PROOF_LEN],
                };
                let mut slots = Vec::with_capacity(batch.n);
                for s in &f.slots {
                    let Some((st, txid)) = s else {
                        slots.push(None);
                        continue;
                    };
                    let ev = state
                        .events
                        .iter()
                        .find(|e| e.height == height && e.txid == *txid)
                        .ok_or_else(|| anyhow!("event for {} not found", hex::encode(txid)))?;
                    let (kind, proof) = match ev.kind {
                        EventKind::Mint => ("mint", None),
                        EventKind::Transfer => ("transfer", Some(envelope_proof(&ev.raw)?)),
                        EventKind::Swap => ("swap", Some(envelope_proof(&ev.raw)?)),
                    };
                    slots.push(Some(SlotJson {
                        elements: st
                            .to_elements()
                            .iter()
                            .map(|x| hex::encode(fr_to_bytes(x)))
                            .collect(),
                        kind: kind.into(),
                        txid: hex::encode(txid),
                        proof,
                        ct_out: ev.ct_out.map(hex::encode),
                    }));
                }
                out.fragments.push(FragmentJson {
                    s_prev: hex::encode(fr_to_bytes(&f.statement.s_prev)),
                    s_next: hex::encode(fr_to_bytes(&f.statement.s_next)),
                    d: hex::encode(fr_to_bytes(&f.statement.d)),
                    proof: hex::encode(proof),
                    next: OpeningJson::from(&f.next),
                    slots,
                });
            }
        }
        let path = batch_path(ctx, height);
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string(&out)?)?;
        std::fs::rename(&tmp, &path)?;
        written += 1;
        if empty {
            log::info!("block {height}: empty, no proof");
        } else {
            println!(
                "block {height}: {} fragment(s), {} statement(s), proven in {:.1} s",
                out.fragments.len(),
                out.fragments
                    .iter()
                    .map(|f| f.slots.iter().flatten().count())
                    .sum::<usize>(),
                t0.elapsed().as_secs_f64()
            );
        }
    }
    println!("{written} block(s) written to {}", dir.display());
    Ok(written)
}

/// The envelope's proof: its last `PROOF_LEN` bytes.
fn envelope_proof(raw: &[u8]) -> Result<String> {
    if raw.len() < PROOF_LEN {
        return Err(anyhow!("envelope shorter than a proof"));
    }
    Ok(hex::encode(&raw[raw.len() - PROOF_LEN..]))
}

/// The state view a proof client holds, for `print_status`-like summaries.
pub(crate) fn light_summary(state: &ReplayState) -> Option<String> {
    state.light.as_ref().map(|l| {
        format!(
            "light client: nullifier commitment size {} (not kept), {} proven block(s)",
            l.nf_size,
            l.history.len()
        )
    })
}
