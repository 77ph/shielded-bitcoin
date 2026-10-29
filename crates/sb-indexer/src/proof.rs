//! The light client of `docs/REPLAY-PROOF.md` §4.5: instead of blocks and
//! carriers, it fetches **proven blocks** from an indexer, checks the
//! chain of state digests through the batch proofs, batch-verifies the
//! transfer proofs behind the statements, and advances its own state
//! from the statements alone. It keeps the note tree (for the wallet's
//! paths) and the root tree (to step over empty blocks itself); it never
//! keeps or checks the nullifier tree, whose root and size it takes from
//! the openings the proofs commit to.
//!
//! What it does not check is the enumeration (§3): that the indexer's
//! statements are all the carriers of the block. A second indexer, or a
//! full replay, is the only check for that.

use ark_bls12_381::Bls12_381;
use ark_groth16::VerifyingKey;
use bitcoin::BlockHash;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use sb_circuit::groth16::verify_batch;
use sb_circuit::{BatchVerifier, SwapStatement, TransferStatement};
use sb_core::batch::{BatchStatement, SLOT_ELEMENTS, SlotStatement, StateOpening, batch_digest};
use sb_core::envelope::PROOF_LEN;
use sb_core::event::{AcceptedEvent, EventKind};
use sb_core::note::note_leaf_aux;
use sb_core::recovery::CT_OUT_LEN;
use sb_primitives::Fr;
use sb_primitives::encoding::{fr_from_bytes, fr_to_bytes};

use crate::chain::ChainError;
use crate::deployment::Deployment;
use crate::replay::SyncReport;
use crate::state::{BlockCheckpoint, LightView, ReplayState};
use crate::store::StateStore;

// ----------------------------------------------------------------- wire

/// One slot of a proven fragment as published: the statement's elements,
/// the carrier txid, the envelope's proof (none for a mint) and `ct_out`
/// (for the sender's own recovery; not bound by the batch).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlotJson {
    pub elements: Vec<String>,
    /// `transfer`, `mint` or `swap`: which verifying key the proof is under.
    pub kind: String,
    pub txid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ct_out: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpeningJson {
    pub root: String,
    pub size: u64,
    pub nf_root: String,
    pub nf_size: u64,
    pub h_root: String,
    pub height: u32,
    pub applied: u32,
}

impl From<&StateOpening> for OpeningJson {
    fn from(o: &StateOpening) -> Self {
        OpeningJson {
            root: hex::encode(fr_to_bytes(&o.root)),
            size: o.size,
            nf_root: hex::encode(fr_to_bytes(&o.nf_root)),
            nf_size: o.nf_size,
            h_root: hex::encode(fr_to_bytes(&o.h_root)),
            height: o.height,
            applied: o.applied,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FragmentJson {
    pub s_prev: String,
    pub s_next: String,
    pub d: String,
    pub proof: String,
    pub next: OpeningJson,
    pub slots: Vec<Option<SlotJson>>,
}

/// A proven block as the indexer publishes it (`GET /batches/<height>`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvenBlockJson {
    pub height: u32,
    pub hash: String,
    /// `true`: no carriers; the client advances by itself and `next` is
    /// the indexer's claim of the state after the block.
    pub empty: bool,
    pub next: OpeningJson,
    #[serde(default)]
    pub fragments: Vec<FragmentJson>,
}

fn fr(s: &str) -> Result<Fr, ChainError> {
    let b = hex::decode(s).map_err(|e| ChainError::Decode(e.to_string()))?;
    fr_from_bytes(&b).map_err(|e| ChainError::Decode(e.to_string()))
}

fn opening(o: &OpeningJson) -> Result<StateOpening, ChainError> {
    Ok(StateOpening {
        root: fr(&o.root)?,
        size: o.size,
        nf_root: fr(&o.nf_root)?,
        nf_size: o.nf_size,
        h_root: fr(&o.h_root)?,
        height: o.height,
        applied: o.applied,
    })
}

fn bytes<const N: usize>(s: &str, what: &str) -> Result<[u8; N], ChainError> {
    hex::decode(s)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| ChainError::Decode(format!("{what}: {N} bytes expected")))
}

// --------------------------------------------------------------- source

/// Where proven blocks come from.
pub trait ProofSource {
    /// `None`: the indexer has not proven this height (yet).
    fn proven_block(&self, height: u32) -> Result<Option<ProvenBlockJson>, ChainError>;
}

/// `proof:<url>`: an `sb serve` indexer's `/batches/<height>`.
pub struct ProofClient {
    base: String,
}

impl ProofClient {
    pub fn new(base: &str) -> Self {
        ProofClient {
            base: base.trim_end_matches('/').to_string(),
        }
    }
}

impl ProofSource for ProofClient {
    fn proven_block(&self, height: u32) -> Result<Option<ProvenBlockJson>, ChainError> {
        match crate::net::agent()
            .get(&format!("{}/batches/{height}", self.base))
            .call()
        {
            Ok(r) => Ok(Some(r.into_json().map_err(|e| {
                ChainError::Decode(format!("proven block {height}: {e}"))
            })?)),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

// ----------------------------------------------------------------- sync

#[derive(Debug, thiserror::Error)]
pub enum ProofSyncError {
    #[error("chain: {0}")]
    Chain(#[from] ChainError),
    #[error("store: {0}")]
    Store(#[from] crate::store::StoreError),
    #[error("proven block {height}: {what}")]
    Invalid { height: u32, what: String },
    #[error(
        "the indexer's history diverged below our state {0} blocks deep; a full replay is needed"
    )]
    DeepReorg(u32),
}

fn invalid(height: u32, what: impl Into<String>) -> ProofSyncError {
    ProofSyncError::Invalid {
        height,
        what: what.into(),
    }
}

/// The keys a client verifies against.
pub struct ProofVerifiers<'a> {
    pub batch: &'a BatchVerifier,
    pub transfer: &'a VerifyingKey<Bls12_381>,
    pub swap: Option<&'a VerifyingKey<Bls12_381>>,
}

/// How far back a client re-checks the indexer's digests for a
/// reorganisation before giving up.
const MAX_ROLLBACK: u32 = 100;

/// Advance `state` with the proven blocks `source` has, from the state's
/// next height, until the source has no more. `state` must be a light
/// state (or empty: it becomes one).
pub fn sync<R: RngCore + CryptoRng>(
    state: &mut ReplayState,
    source: &dyn ProofSource,
    deployment: &Deployment,
    v: &ProofVerifiers,
    mut store: Option<&mut dyn StateStore>,
    rng: &mut R,
) -> Result<SyncReport, ProofSyncError> {
    let activation = deployment.activation_height;
    if state.light.is_none() {
        if !state.blocks.is_empty() {
            return Err(invalid(
                activation,
                "this state was built by full replay; a proof client needs its own",
            ));
        }
        state.light = Some(LightView {
            nf_root: sb_core::imt::IndexedMerkleTree::new().root(),
            nf_size: 1,
            history: Vec::new(),
        });
    }
    let mut report = SyncReport::default();
    // reorganisation: the indexer's final digest of our last block must be
    // ours; otherwise roll back until they agree
    let mut rolled = 0u32;
    while let Some(last) = state.last_height() {
        let ours = state.opening(activation).digest();
        let theirs = match source.proven_block(last)? {
            Some(b) => opening(&b.next)?.digest(),
            None => Fr::from(0u64),
        };
        if theirs == ours {
            break;
        }
        rolled += 1;
        if rolled > MAX_ROLLBACK {
            return Err(ProofSyncError::DeepReorg(rolled));
        }
        let to = last - 1;
        state.rollback_to(to);
        if let Some(s) = store.as_deref_mut() {
            s.rollback_to(state, to)?;
        }
        report.rolled_back_to = Some(to);
    }
    loop {
        let height = state.last_height().map_or(activation, |h| h + 1);
        let Some(block) = source.proven_block(height)? else {
            break;
        };
        if block.height != height {
            return Err(invalid(height, "wrong height"));
        }
        let hash: BlockHash = block
            .hash
            .parse()
            .map_err(|_| invalid(height, "block hash"))?;
        let claimed = opening(&block.next)?;
        let cp = BlockCheckpoint {
            height,
            hash,
            leaf_count_before: state.tree.size(),
            events_before: state.events.len(),
            rejections_before: state.rejections.len(),
            nullifiers_added: Vec::new(),
        };
        let accepted = if block.empty {
            0
        } else {
            apply_fragments(state, &block, deployment, v, rng)?
        };
        // the block's root into the root tree, as replay does; the
        // checkpoint goes in first so that the opening sees this block as
        // replayed (its height is the next block in progress)
        let root = state.tree.root();
        state.roots.insert(height, root);
        state.root_tree.append(root);
        let mut cp = cp;
        cp.nullifiers_added = state.events[cp.events_before..]
            .iter()
            .flat_map(|e| e.nullifiers.iter().copied())
            .collect();
        state.blocks.push(cp);
        let ours = state.opening(activation);
        if ours.digest() != claimed.digest() {
            // undo what this block added before refusing it
            let cp = state.blocks.pop().expect("just pushed");
            for nf in &cp.nullifiers_added {
                state.nullifiers.remove(nf);
            }
            state.roots.remove(&height);
            state.tree.truncate(cp.leaf_count_before);
            state.events.truncate(cp.events_before);
            state.rebuild_commitments();
            return Err(invalid(
                height,
                if block.empty {
                    "the indexer's state after an empty block is not ours"
                } else {
                    "the state after the fragments is not the one the proofs end in"
                },
            ));
        }
        if let Some(l) = &mut state.light {
            l.history.push((
                height,
                hex::encode(fr_to_bytes(&ours.nf_root)),
                ours.nf_size,
            ));
        }
        if let Some(s) = store.as_deref_mut() {
            let i = state.blocks.len() - 1;
            s.commit_block(state, i)?;
        }
        report.blocks += 1;
        report.accepted += accepted;
        report.tip = Some(height);
    }
    if let Some(s) = store {
        s.flush(state)?;
    }
    Ok(report)
}

/// Verify and apply a block's fragments; returns the number of statements.
fn apply_fragments<R: RngCore + CryptoRng>(
    state: &mut ReplayState,
    block: &ProvenBlockJson,
    deployment: &Deployment,
    v: &ProofVerifiers,
    rng: &mut R,
) -> Result<usize, ProofSyncError> {
    let height = block.height;
    let activation = deployment.activation_height;
    let n = deployment.batch.as_ref().map(|b| b.n).unwrap_or(0);
    let salt = deployment.const_salt_fr();
    let bad = |what: &str| invalid(height, what);
    if block.fragments.is_empty() {
        return Err(bad("no fragments"));
    }
    // 1. the chain of digests and the batch proofs, before anything is applied
    let mut expected_prev = state.opening(activation).digest();
    let mut parsed: Vec<(BatchStatement, StateOpening, Vec<Option<SlotStatement>>)> = Vec::new();
    let mut transfers: Vec<(Vec<Fr>, [u8; PROOF_LEN])> = Vec::new();
    let mut swaps: Vec<(Vec<Fr>, [u8; PROOF_LEN])> = Vec::new();
    for (fi, f) in block.fragments.iter().enumerate() {
        if f.slots.len() != n {
            return Err(bad(&format!(
                "fragment {fi}: {} slots, the deployment's batch has {n}",
                f.slots.len()
            )));
        }
        let statement = BatchStatement {
            s_prev: fr(&f.s_prev)?,
            s_next: fr(&f.s_next)?,
            d: fr(&f.d)?,
        };
        if statement.s_prev != expected_prev {
            return Err(bad(&format!("fragment {fi} does not start from our state")));
        }
        let proof: [u8; PROOF_LEN] = bytes(&f.proof, "batch proof")?;
        if !v.batch.verify(&statement, &proof) {
            return Err(bad(&format!(
                "fragment {fi}: the batch proof does not verify"
            )));
        }
        let next = opening(&f.next)?;
        if next.digest() != statement.s_next {
            return Err(bad(&format!(
                "fragment {fi}: the opening is not the one the proof ends in"
            )));
        }
        let mut slots = Vec::with_capacity(n);
        for (si, s) in f.slots.iter().enumerate() {
            let Some(s) = s else {
                slots.push(None);
                continue;
            };
            if s.elements.len() != SLOT_ELEMENTS {
                return Err(bad(&format!(
                    "fragment {fi} slot {si}: {} elements",
                    s.elements.len()
                )));
            }
            let mut e = Vec::with_capacity(SLOT_ELEMENTS);
            for x in &s.elements {
                e.push(fr(x)?);
            }
            let st = SlotStatement::from_elements(&e)
                .ok_or_else(|| bad(&format!("fragment {fi} slot {si}: not a statement")))?;
            // the envelope's own proof, by kind
            let base = TransferStatement {
                const_salt: salt,
                r_anchor: st.r_anchor,
                nullifiers: st.nullifiers,
                pk_eph: st.pk_eph,
                ct_note: st.ct,
                h_body: st.h_body,
            };
            match (s.kind.as_str(), st.mint) {
                ("mint", true) => {}
                ("transfer", false) => {
                    let p = s
                        .proof
                        .as_deref()
                        .ok_or_else(|| bad("transfer without a proof"))?;
                    transfers.push((base.to_field_elements(), bytes(p, "transfer proof")?));
                }
                ("swap", false) => {
                    let p = s
                        .proof
                        .as_deref()
                        .ok_or_else(|| bad("swap without a proof"))?;
                    let sw = SwapStatement {
                        base,
                        h_anchor: st.h_anchor,
                    };
                    swaps.push((sw.to_field_elements(), bytes(p, "swap proof")?));
                }
                (k, _) => {
                    return Err(bad(&format!(
                        "fragment {fi} slot {si}: kind {k:?} does not match the statement"
                    )));
                }
            }
            slots.push(Some(st));
        }
        if batch_digest(&slots) != statement.d {
            return Err(bad(&format!(
                "fragment {fi}: the statements do not hash to D"
            )));
        }
        expected_prev = statement.s_next;
        parsed.push((statement, next, slots));
    }
    // 2. the transfer and swap proofs, batched per key (§4.3)
    if !verify_batch(v.transfer, &transfers, rng) {
        return Err(bad("a transfer proof does not verify"));
    }
    if !swaps.is_empty() {
        let Some(swap_vk) = v.swap else {
            return Err(bad("a swap in a deployment without the extension"));
        };
        if !verify_batch(swap_vk, &swaps, rng) {
            return Err(bad("a swap proof does not verify"));
        }
    }
    // 3. apply the statements: leaves into the note tree, events for the
    //    wallet, the nullifier view from the openings
    let mut count = 0usize;
    let mut tx_index = 0u32;
    let last = parsed.len() - 1;
    for (fi, (_, next, slots)) in parsed.into_iter().enumerate() {
        let json = &block.fragments[fi];
        for (si, st) in slots.into_iter().enumerate() {
            let Some(st) = st else { continue };
            let sj = json.slots[si].as_ref().expect("parsed above");
            let txid: [u8; 32] = bytes(&sj.txid, "txid")?;
            let ct_out: Option<[u8; CT_OUT_LEN]> = match &sj.ct_out {
                Some(c) => Some(bytes(c, "ct_out")?),
                None => None,
            };
            let n_out = if st.mint { 1 } else { 2 };
            let first_position = state.tree.size();
            let mut leaves = Vec::with_capacity(n_out);
            for j in 0..n_out {
                let leaf = note_leaf_aux(
                    &salt,
                    &st.h_body,
                    j as u64,
                    &st.pk_eph[j],
                    &st.ct[j],
                    &st.h_aux[j],
                );
                state.tree.append(leaf);
                leaves.push(leaf);
            }
            let kind = match (st.mint, sj.kind.as_str()) {
                (true, _) => EventKind::Mint,
                (false, "swap") => EventKind::Swap,
                _ => EventKind::Transfer,
            };
            let nullifiers = if st.mint {
                vec![]
            } else {
                st.nullifiers.to_vec()
            };
            for nf in &nullifiers {
                state.nullifiers.insert(*nf);
            }
            state.events.push(AcceptedEvent {
                kind,
                height,
                tx_index,
                txid,
                raw: Vec::new(),
                h_body: st.h_body,
                nullifiers,
                outputs: (0..n_out).map(|j| (st.pk_eph[j], st.ct[j])).collect(),
                ct_out,
                first_position,
                leaves,
                h_aux: st.h_aux[..n_out].to_vec(),
                memo: None,
            });
            tx_index += 1;
            count += 1;
        }
        // the nullifier commitment moves with the proven opening
        if let Some(l) = &mut state.light {
            l.nf_root = next.nf_root;
            l.nf_size = next.nf_size;
        }
        if next.root != state.tree.root() || next.size != state.tree.size() {
            return Err(bad(&format!(
                "fragment {fi}: the statements do not rebuild the proven note tree"
            )));
        }
        if fi == last && next.applied != 0 {
            return Err(bad("the last fragment does not close the block"));
        }
    }
    Ok(count)
}
