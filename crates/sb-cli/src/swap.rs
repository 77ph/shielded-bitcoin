//! `sb swap …` and `sb htlc …`: the two roles of the swap protocol of
//! `docs/SWAP.md` §9, as commands over an agreement exchanged as JSON
//! files. X holds the secret, locks the shielded note and claims the HTLC;
//! Y verifies the lock, funds the HTLC and claims the note with the
//! revealed preimage. Either side refunds after its height.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use clap::Subcommand;
use serde::{Deserialize, Serialize};

use sb_core::address::PaymentAddress;
use sb_core::lock::{LockOpening, Secret};
use sb_wallet::{K_WALLET, SwapRecord, anchor_for};

use crate::funding::Chain;
use crate::htlc::{Htlc, parse_outpoint};
use crate::{Ctx, OutboxEntry, PublishMode};

/// Reaction margin `R` of `docs/SWAP.md` §10.
pub const REACTION_MARGIN: u32 = 6;

/// The agreement as it travels between the parties (`docs/SWAP.md` §9 step 1).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Agreement {
    pub network: String,
    pub deployment: String,
    /// `SHA-256(s)`, hex.
    pub hash: String,
    pub v_sh: u64,
    pub v_btc: u64,
    pub t_refund: u32,
    pub t_htlc: u32,
    /// X's shielded refund address.
    pub refund_address: String,
    /// X's Bitcoin claim key, compressed hex.
    pub btc_pk_x: String,
    /// Y's shielded address, owner of the locked note (filled by `accept`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_address: Option<String>,
    /// Y's Bitcoin refund key (filled by `accept`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub btc_pk_y: Option<String>,
}

#[derive(Subcommand)]
pub enum SwapCmd {
    /// X: propose a swap; writes the offer and keeps the secret in the wallet.
    Offer {
        #[arg(long, default_value = "default")]
        name: String,
        /// Shielded amount locked to Y.
        #[arg(long)]
        v_sh: u64,
        /// Bitcoin amount Y puts in the HTLC.
        #[arg(long)]
        v_btc: u64,
        /// Height from which X may refund the note.
        #[arg(long)]
        t_refund: u32,
        /// Height from which Y may refund the HTLC (`t_htlc + Δ ≤ t_refund`).
        #[arg(long)]
        t_htlc: u32,
        #[arg(long)]
        out: PathBuf,
    },
    /// Y: accept an offer; checks the timeouts and adds Y's addresses.
    Accept {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long = "in")]
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// X: lock the shielded note to Y under the agreed hash-lock.
    Lock {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long = "in")]
        input: PathBuf,
        #[arg(long, default_value = "2")]
        fee_rate: u64,
        #[arg(long)]
        no_broadcast: bool,
        #[arg(long, conflicts_with = "no_broadcast")]
        relay: Option<String>,
    },
    /// Y: after `sync`, check that the locked note is there with the agreed lock.
    Check {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        hash: String,
    },
    /// Y: claim the locked note with the preimage (given, or read from the HTLC spend).
    Claim {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        hash: String,
        /// The preimage, hex (otherwise it is read from the HTLC's spend on chain).
        #[arg(long)]
        secret: Option<String>,
        /// Keep polling the chain for the HTLC spend this many seconds at most.
        #[arg(long, default_value = "0")]
        wait: u64,
        #[arg(long, default_value = "2")]
        fee_rate: u64,
        #[arg(long)]
        no_broadcast: bool,
        #[arg(long, conflicts_with = "no_broadcast")]
        relay: Option<String>,
    },
    /// X: take the locked note back after `t_refund`.
    Refund {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        hash: String,
        #[arg(long, default_value = "2")]
        fee_rate: u64,
        #[arg(long)]
        no_broadcast: bool,
        #[arg(long, conflicts_with = "no_broadcast")]
        relay: Option<String>,
    },
    /// The wallet's swap records.
    List {
        #[arg(long, default_value = "default")]
        name: String,
    },
}

#[derive(Subcommand)]
pub enum HtlcCmd {
    /// Y: fund the HTLC of an accepted swap from the fee wallet.
    Fund {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        hash: String,
        #[arg(long, default_value = "2")]
        fee_rate: u64,
    },
    /// X: claim the HTLC with the secret (reveals it on chain).
    Claim {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        hash: String,
        /// `txid:vout` of the HTLC output (as `htlc fund` printed it).
        #[arg(long)]
        outpoint: String,
        #[arg(long, default_value = "2")]
        fee_rate: u64,
    },
    /// Y: refund the HTLC after `t_htlc`.
    Refund {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        hash: String,
        #[arg(long, default_value = "2")]
        fee_rate: u64,
    },
    /// The HTLC address of an agreement (to inspect it on an explorer).
    Address {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        hash: String,
    },
}

/// `Δ = K_min + K_wallet + R` (`docs/SWAP.md` §10).
fn delta(ctx: &Ctx) -> u32 {
    ctx.deployment.k_min + K_WALLET + REACTION_MARGIN
}

fn check_timeouts(ctx: &Ctx, t_htlc: u32, t_refund: u32) -> Result<()> {
    let d = delta(ctx);
    if t_htlc.checked_add(d).is_none_or(|v| v > t_refund) {
        bail!(
            "timeouts: need t_htlc + {d} ≤ t_refund, got t_htlc = {t_htlc}, t_refund = {t_refund}"
        );
    }
    Ok(())
}

fn read_agreement(path: &PathBuf) -> Result<Agreement> {
    let text = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
    serde_json::from_str(&text).with_context(|| path.display().to_string())
}

fn write_agreement(path: &PathBuf, a: &Agreement) -> Result<()> {
    std::fs::write(path, serde_json::to_string_pretty(a)?)
        .with_context(|| path.display().to_string())
}

fn parse_hash(hex_hash: &str) -> Result<[u8; 32]> {
    hex::decode(hex_hash)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("hash: expected 32 bytes of hex"))
}

fn parse_pubkey(hex_pk: &str) -> Result<bitcoin::CompressedPublicKey> {
    let bytes = hex::decode(hex_pk).context("public key hex")?;
    bitcoin::CompressedPublicKey::from_slice(&bytes).context("public key")
}

fn shielded(ctx: &Ctx, s: &str) -> Result<PaymentAddress> {
    let (net, addr) = PaymentAddress::decode(s)?;
    if net != ctx.deployment.network {
        bail!(
            "address {s} is for {net:?}, the profile is {:?}",
            ctx.deployment.network
        );
    }
    Ok(addr)
}

/// The lock opening of a record (`docs/SWAP.md` §2).
fn opening(ctx: &Ctx, r: &SwapRecord) -> Result<LockOpening> {
    Ok(LockOpening {
        hash: parse_hash(&r.hash)?,
        pk_refund: shielded(ctx, &r.refund_address)?.pk_d,
        t_refund: r.t_refund,
    })
}

fn htlc_of(r: &SwapRecord) -> Result<Htlc> {
    if r.btc_pk_y.is_empty() {
        bail!("the swap has not been accepted yet (no Y key)");
    }
    Ok(Htlc {
        hash: parse_hash(&r.hash)?,
        claim_pk: parse_pubkey(&r.btc_pk_x)?,
        refund_pk: parse_pubkey(&r.btc_pk_y)?,
        timeout: r.t_htlc,
    })
}

/// The fee wallet's swap key (receive index 0).
fn btc_key(ctx: &Ctx, w: &sb_wallet::Wallet) -> Result<crate::funding::FundingKey> {
    ctx.funding(w)?.key(Chain::Receive, 0)
}

fn record(ctx: &Ctx, name: &str, hash: &str) -> Result<(sb_wallet::Wallet, SwapRecord)> {
    let w = ctx.wallet(name)?;
    let r = w
        .swap(hash)
        .cloned()
        .ok_or_else(|| anyhow!("wallet {name} has no swap {hash}"))?;
    Ok((w, r))
}

/// Replayed tip, anchor and tree size the wallet should build against.
fn anchor(ctx: &Ctx) -> Result<(sb_indexer::Indexer, u32, u32, u64)> {
    let (idx, _store) = ctx.indexer()?;
    let tip = idx
        .state
        .last_height()
        .ok_or_else(|| anyhow!("run `sb sync` first"))?;
    let h_anchor = anchor_for(tip, K_WALLET);
    let size = idx
        .state
        .size_at(h_anchor)
        .ok_or_else(|| anyhow!("anchor {h_anchor} not replayed"))?;
    Ok((idx, tip, h_anchor, size))
}

pub fn run_swap(ctx: &Ctx, cmd: SwapCmd) -> Result<()> {
    match cmd {
        SwapCmd::Offer {
            name,
            v_sh,
            v_btc,
            t_refund,
            t_htlc,
            out,
        } => {
            check_timeouts(ctx, t_htlc, t_refund)?;
            if v_btc < crate::funding::DUST_LIMIT {
                bail!("v_btc {v_btc} is below the dust limit");
            }
            let mut w = ctx.wallet(&name)?;
            let secret = Secret::random(&mut rand::thread_rng());
            let hash = hex::encode(secret.hash());
            let refund_address = w.default_address().encode(ctx.deployment.network);
            let btc_pk_x = hex::encode(btc_key(ctx, &w)?.pubkey().to_bytes());
            let a = Agreement {
                network: format!("{:?}", ctx.deployment.network).to_lowercase(),
                deployment: ctx.deployment.name.clone(),
                hash: hash.clone(),
                v_sh,
                v_btc,
                t_refund,
                t_htlc,
                refund_address: refund_address.clone(),
                btc_pk_x: btc_pk_x.clone(),
                owner_address: None,
                btc_pk_y: None,
            };
            write_agreement(&out, &a)?;
            w.swaps.push(SwapRecord {
                hash: hash.clone(),
                role: "x".into(),
                secret: Some(hex::encode(secret.0)),
                v_sh,
                v_btc,
                refund_address,
                owner_address: String::new(),
                t_refund,
                t_htlc,
                btc_pk_x,
                btc_pk_y: String::new(),
                h_aux: String::new(),
                status: "offered".into(),
                lock_txid: None,
                htlc_outpoint: None,
                spend_txid: None,
            });
            w.save(&ctx.wallet_path(&name))?;
            println!("offer written to {} (hash {hash})", out.display());
            println!("send it to the counterparty; the secret stays in wallet {name}");
        }
        SwapCmd::Accept { name, input, out } => {
            let mut a = read_agreement(&input)?;
            if a.deployment != ctx.deployment.name {
                bail!(
                    "the offer is for deployment {}, this profile is {}",
                    a.deployment,
                    ctx.deployment.name
                );
            }
            check_timeouts(ctx, a.t_htlc, a.t_refund)?;
            parse_hash(&a.hash)?;
            parse_pubkey(&a.btc_pk_x)?;
            let refund = shielded(ctx, &a.refund_address)?;
            let mut w = ctx.wallet(&name)?;
            if w.swap(&a.hash).is_some() {
                bail!("wallet {name} already has swap {}", a.hash);
            }
            let owner = w.default_address();
            let owner_address = owner.encode(ctx.deployment.network);
            let btc_pk_y = hex::encode(btc_key(ctx, &w)?.pubkey().to_bytes());
            a.owner_address = Some(owner_address.clone());
            a.btc_pk_y = Some(btc_pk_y.clone());
            write_agreement(&out, &a)?;
            let opening = LockOpening {
                hash: parse_hash(&a.hash)?,
                pk_refund: refund.pk_d,
                t_refund: a.t_refund,
            };
            w.swaps.push(SwapRecord {
                hash: a.hash.clone(),
                role: "y".into(),
                secret: None,
                v_sh: a.v_sh,
                v_btc: a.v_btc,
                refund_address: a.refund_address.clone(),
                owner_address,
                t_refund: a.t_refund,
                t_htlc: a.t_htlc,
                btc_pk_x: a.btc_pk_x.clone(),
                btc_pk_y,
                h_aux: hex::encode(sb_primitives::encoding::fr_to_bytes(&opening.commitment())),
                status: "accepted".into(),
                lock_txid: None,
                htlc_outpoint: None,
                spend_txid: None,
            });
            w.save(&ctx.wallet_path(&name))?;
            println!(
                "accepted: {} written; expected lock h_aux {}",
                out.display(),
                w.swap(&a.hash).unwrap().h_aux
            );
        }
        SwapCmd::Lock {
            name,
            input,
            fee_rate,
            no_broadcast,
            relay,
        } => {
            let a = read_agreement(&input)?;
            let (mut w, mut r) = record(ctx, &name, &a.hash)?;
            if r.role != "x" {
                bail!("only X (the offerer) locks the note");
            }
            let owner_s = a
                .owner_address
                .clone()
                .ok_or_else(|| anyhow!("the agreement has no owner address: Y has not accepted"))?;
            let btc_pk_y = a
                .btc_pk_y
                .clone()
                .ok_or_else(|| anyhow!("the agreement has no Y key"))?;
            parse_pubkey(&btc_pk_y)?;
            if a.v_sh != r.v_sh
                || a.v_btc != r.v_btc
                || a.t_refund != r.t_refund
                || a.t_htlc != r.t_htlc
                || a.refund_address != r.refund_address
                || a.btc_pk_x != r.btc_pk_x
            {
                bail!("the accepted agreement differs from the offer this wallet made");
            }
            let owner = shielded(ctx, &owner_s)?;
            let opening = opening(ctx, &r)?;
            let (idx, _tip, h_anchor, size) = anchor(ctx)?;
            w.scan(
                &ctx.deployment.const_salt_fr(),
                &idx.state.events,
                &idx.state.nullifiers,
            )?;
            eprintln!("loading the swap proving parameters…");
            let params = ctx.swap_params()?;
            eprintln!("proving the lock (anchor {h_anchor}, tree size {size})…");
            let built = w.build_lock(
                &params,
                &ctx.deployment.const_salt,
                &idx.state.tree,
                h_anchor,
                size,
                owner,
                r.v_sh,
                opening,
                &mut rand::thread_rng(),
            )?;
            r.owner_address = owner_s;
            r.btc_pk_y = btc_pk_y;
            r.h_aux = hex::encode(sb_primitives::encoding::fr_to_bytes(&built.h_aux[0]));
            r.status = "locked".into();
            *w.swap_mut(&a.hash).unwrap() = r.clone();
            w.save(&ctx.wallet_path(&name))?;
            let label = format!("swaplock-{}", &r.hash[..16]);
            let entry = OutboxEntry::new(&built.envelope.to_bytes(), None, vec![]);
            let txid = ctx.publish(
                Some((&mut w, &name)),
                &label,
                &entry,
                fee_rate,
                PublishMode::pick(no_broadcast, relay, None, None),
            )?;
            if let Some(t) = txid {
                w.swap_mut(&a.hash).unwrap().lock_txid = Some(t.to_string());
                w.save(&ctx.wallet_path(&name))?;
            }
            println!(
                "locked {} sat to {} under h_aux {}",
                r.v_sh, r.owner_address, r.h_aux
            );
        }
        SwapCmd::Check { name, hash } => {
            let (mut w, r) = record(ctx, &name, &hash)?;
            if r.role != "y" {
                bail!("only Y checks the lock");
            }
            let (idx, _tip, _h, _s) = anchor(ctx)?;
            w.scan(
                &ctx.deployment.const_salt_fr(),
                &idx.state.events,
                &idx.state.nullifiers,
            )?;
            w.save(&ctx.wallet_path(&name))?;
            let expected = hex::encode(sb_primitives::encoding::fr_to_bytes(
                &opening(ctx, &r)?.commitment(),
            ));
            let note = w
                .notes
                .iter()
                .find(|n| n.h_aux == expected && n.spent_at.is_none())
                .ok_or_else(|| {
                    anyhow!("no locked note with h_aux {expected} yet; sync and retry")
                })?;
            if note.value != r.v_sh {
                bail!(
                    "the locked note holds {} sat, the agreement says {}: do not fund",
                    note.value,
                    r.v_sh
                );
            }
            println!(
                "locked note at position {} holds {} sat under the agreed lock (height {}); fund the HTLC with `sb htlc fund --hash {hash}`",
                note.pos, note.value, note.height
            );
            w.swap_mut(&hash).unwrap().status = "verified".into();
            w.save(&ctx.wallet_path(&name))?;
        }
        SwapCmd::Claim {
            name,
            hash,
            secret,
            wait,
            fee_rate,
            no_broadcast,
            relay,
        } => {
            let (mut w, r) = record(ctx, &name, &hash)?;
            if r.role != "y" {
                bail!("only Y claims the note");
            }
            let htlc = htlc_of(&r)?;
            let s: [u8; 32] = match secret {
                Some(h) => parse_hash(&h)?,
                None => {
                    let outpoint = parse_outpoint(
                        r.htlc_outpoint
                            .as_deref()
                            .ok_or_else(|| anyhow!("no HTLC outpoint recorded; pass --secret"))?,
                    )?;
                    let from = r.lock_txid.as_ref().map(|_| 0).unwrap_or(0);
                    let _ = from;
                    let chain = ctx.chain_source()?;
                    let start = std::time::Instant::now();
                    loop {
                        let from_height = idx_from_height(ctx)?;
                        match htlc.find_preimage(chain.as_ref(), outpoint, from_height)? {
                            Some((h, s)) => {
                                println!("preimage revealed at height {h}");
                                break s;
                            }
                            None if start.elapsed().as_secs() < wait => {
                                std::thread::sleep(std::time::Duration::from_secs(5));
                            }
                            None => {
                                bail!("the HTLC has not been claimed yet; wait or pass --secret")
                            }
                        }
                    }
                }
            };
            if Secret(s).hash() != htlc.hash {
                bail!("the secret does not hash to the agreement's hash");
            }
            let opening = opening(ctx, &r)?;
            let (idx, _tip, h_anchor, size) = anchor(ctx)?;
            w.scan(
                &ctx.deployment.const_salt_fr(),
                &idx.state.events,
                &idx.state.nullifiers,
            )?;
            eprintln!("loading the swap proving parameters…");
            let params = ctx.swap_params()?;
            eprintln!("proving the claim (anchor {h_anchor}, tree size {size})…");
            let built = w.build_claim(
                &params,
                &ctx.deployment.const_salt,
                &idx.state.tree,
                h_anchor,
                size,
                opening,
                Secret(s),
                &mut rand::thread_rng(),
            )?;
            w.swap_mut(&hash).unwrap().status = "claimed".into();
            w.save(&ctx.wallet_path(&name))?;
            let label = format!("swapclaim-{}", &hash[..16]);
            let entry = OutboxEntry::new(&built.envelope.to_bytes(), None, vec![]);
            let txid = ctx.publish(
                Some((&mut w, &name)),
                &label,
                &entry,
                fee_rate,
                PublishMode::pick(no_broadcast, relay, None, None),
            )?;
            if let Some(t) = txid {
                w.swap_mut(&hash).unwrap().spend_txid = Some(t.to_string());
                w.save(&ctx.wallet_path(&name))?;
            }
            println!("claimed {} sat with the preimage", r.v_sh);
        }
        SwapCmd::Refund {
            name,
            hash,
            fee_rate,
            no_broadcast,
            relay,
        } => {
            let (mut w, r) = record(ctx, &name, &hash)?;
            if r.role != "x" {
                bail!("only X refunds the note");
            }
            let opening = opening(ctx, &r)?;
            let (idx, tip, h_anchor, size) = anchor(ctx)?;
            w.scan(
                &ctx.deployment.const_salt_fr(),
                &idx.state.events,
                &idx.state.nullifiers,
            )?;
            let h_aux_hex =
                hex::encode(sb_primitives::encoding::fr_to_bytes(&opening.commitment()));
            if let Ok(nf) = w.sent_lock_nullifier(&h_aux_hex) {
                if idx.state.nullifiers.contains(&nf) {
                    bail!(
                        "the counterparty already claimed this note with the preimage; nothing to refund"
                    );
                }
            }
            if h_anchor < r.t_refund {
                bail!(
                    "the refund opens at anchor {} and the wallet's anchor is {h_anchor} (tip {tip}); wait for height {}",
                    r.t_refund,
                    r.t_refund + K_WALLET - 1
                );
            }
            w.scan(
                &ctx.deployment.const_salt_fr(),
                &idx.state.events,
                &idx.state.nullifiers,
            )?;
            eprintln!("loading the swap proving parameters…");
            let params = ctx.swap_params()?;
            eprintln!("proving the refund (anchor {h_anchor}, tree size {size})…");
            let built = w.build_refund(
                &params,
                &ctx.deployment.const_salt,
                &idx.state.tree,
                h_anchor,
                size,
                opening,
                &mut rand::thread_rng(),
            )?;
            w.swap_mut(&hash).unwrap().status = "refunded".into();
            w.save(&ctx.wallet_path(&name))?;
            let label = format!("swaprefund-{}", &hash[..16]);
            let entry = OutboxEntry::new(&built.envelope.to_bytes(), None, vec![]);
            let txid = ctx.publish(
                Some((&mut w, &name)),
                &label,
                &entry,
                fee_rate,
                PublishMode::pick(no_broadcast, relay, None, None),
            )?;
            if let Some(t) = txid {
                w.swap_mut(&hash).unwrap().spend_txid = Some(t.to_string());
                w.save(&ctx.wallet_path(&name))?;
            }
            println!("refund of {} sat published", r.v_sh);
        }
        SwapCmd::List { name } => {
            let w = ctx.wallet(&name)?;
            println!("{} swap(s)", w.swaps.len());
            for r in &w.swaps {
                println!(
                    "  {} role {} {}: {} sat shielded / {} sat BTC, t_refund {}, t_htlc {}{}{}",
                    &r.hash[..16],
                    r.role,
                    r.status,
                    r.v_sh,
                    r.v_btc,
                    r.t_refund,
                    r.t_htlc,
                    r.htlc_outpoint
                        .as_ref()
                        .map(|o| format!(", HTLC {o}"))
                        .unwrap_or_default(),
                    r.spend_txid
                        .as_ref()
                        .map(|t| format!(", spend {t}"))
                        .unwrap_or_default(),
                );
            }
        }
    }
    Ok(())
}

/// The height to scan HTLC spends from: the deployment's activation
/// (cheap enough on test networks; a record of the funding height would
/// narrow it).
fn idx_from_height(ctx: &Ctx) -> Result<u32> {
    Ok(ctx.deployment.activation_height)
}

pub fn run_htlc(ctx: &Ctx, cmd: HtlcCmd) -> Result<()> {
    match cmd {
        HtlcCmd::Fund {
            name,
            hash,
            fee_rate,
        } => {
            let (mut w, r) = record(ctx, &name, &hash)?;
            if r.role != "y" {
                bail!("only Y funds the HTLC");
            }
            if r.status != "verified" {
                bail!(
                    "check the locked note first (`sb swap check --hash {hash}`); status is {}",
                    r.status
                );
            }
            let htlc = htlc_of(&r)?;
            let out = bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(r.v_btc),
                script_pubkey: htlc.script_pubkey(),
            };
            let tx = ctx.pay(&mut w, &name, vec![out], fee_rate)?;
            let vout = tx
                .output
                .iter()
                .position(|o| o.script_pubkey == htlc.script_pubkey())
                .expect("the output we just added") as u32;
            let outpoint = format!("{}:{vout}", tx.compute_txid());
            {
                let rec = w.swap_mut(&hash).unwrap();
                rec.htlc_outpoint = Some(outpoint.clone());
                rec.status = "funded".into();
            }
            w.save(&ctx.wallet_path(&name))?;
            println!(
                "HTLC funded with {} sat at {outpoint} ({}), refundable from height {}",
                r.v_btc,
                htlc.address(ctx.btc_network()),
                r.t_htlc
            );
        }
        HtlcCmd::Claim {
            name,
            hash,
            outpoint,
            fee_rate,
        } => {
            let (mut w, r) = record(ctx, &name, &hash)?;
            if r.role != "x" {
                bail!("only X claims the HTLC");
            }
            let secret = parse_hash(r.secret.as_deref().ok_or_else(|| anyhow!("no secret"))?)?;
            let htlc = htlc_of(&r)?;
            let outpoint = parse_outpoint(&outpoint)?;
            let publisher = ctx.publisher()?;
            let coins = publisher.utxos(&htlc.address(ctx.btc_network()))?;
            let coin = coins
                .iter()
                .find(|c| c.outpoint == outpoint)
                .ok_or_else(|| {
                    anyhow!("{outpoint} is not an unspent output of the HTLC address")
                })?;
            if coin.value != r.v_btc {
                bail!(
                    "the HTLC holds {} sat, the agreement says {}",
                    coin.value,
                    r.v_btc
                );
            }
            let key = btc_key(ctx, &w)?;
            let fw = ctx.funding(&w)?;
            let to = fw.receive_address(crate::funding::FundingState {
                receive: w.funding_receive,
                change: w.funding_change,
            })?;
            let tx = htlc.spend(outpoint, coin.value, &key, Some(secret), &to, fee_rate)?;
            let txid = publisher.broadcast(&tx)?;
            {
                let rec = w.swap_mut(&hash).unwrap();
                rec.htlc_outpoint = Some(outpoint.to_string());
                rec.spend_txid = Some(txid.to_string());
                rec.status = "htlc-claimed".into();
            }
            w.save(&ctx.wallet_path(&name))?;
            println!(
                "HTLC claimed in {txid}: the preimage is now on chain, {} sat to {to}",
                tx.output[0].value.to_sat()
            );
        }
        HtlcCmd::Refund {
            name,
            hash,
            fee_rate,
        } => {
            let (mut w, r) = record(ctx, &name, &hash)?;
            if r.role != "y" {
                bail!("only Y refunds the HTLC");
            }
            let htlc = htlc_of(&r)?;
            let outpoint = parse_outpoint(
                r.htlc_outpoint
                    .as_deref()
                    .ok_or_else(|| anyhow!("no HTLC funded"))?,
            )?;
            let publisher = ctx.publisher()?;
            let coins = publisher.utxos(&htlc.address(ctx.btc_network()))?;
            let coin = coins
                .iter()
                .find(|c| c.outpoint == outpoint)
                .ok_or_else(|| {
                    anyhow!(
                        "{outpoint} is not an unspent output of the HTLC address (claimed already?)"
                    )
                })?;
            let key = btc_key(ctx, &w)?;
            let fw = ctx.funding(&w)?;
            let to = fw.receive_address(crate::funding::FundingState {
                receive: w.funding_receive,
                change: w.funding_change,
            })?;
            let tx = htlc.spend(outpoint, coin.value, &key, None, &to, fee_rate)?;
            let txid = publisher.broadcast(&tx)?;
            {
                let rec = w.swap_mut(&hash).unwrap();
                rec.spend_txid = Some(txid.to_string());
                rec.status = "htlc-refunded".into();
            }
            w.save(&ctx.wallet_path(&name))?;
            println!(
                "HTLC refunded in {txid} ({} sat to {to})",
                tx.output[0].value.to_sat()
            );
        }
        HtlcCmd::Address { name, hash } => {
            let (_w, r) = record(ctx, &name, &hash)?;
            let htlc = htlc_of(&r)?;
            println!("{}", htlc.address(ctx.btc_network()));
            println!(
                "witness script: {}",
                hex::encode(htlc.witness_script().as_bytes())
            );
        }
    }
    Ok(())
}
