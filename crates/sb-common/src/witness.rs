//! The witness carrier's two-transaction publication
//! (`docs/WITNESS-CARRIER.md` §3): a commit transaction pays a P2TR output
//! whose only script path is the envelope tapscript; the reveal
//! transaction spends it through that path, so the envelope bytes sit in
//! its witness at one weight unit per byte. The internal key is the
//! BIP 341 unspendable point, so only the script path exists.

use anyhow::{Context, Result, bail};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    XOnlyPublicKey,
};

use crate::carrier::{envelope_tapscript, memo_output};

use crate::funding::{Coin, DUST_LIMIT, FundingKey, FundingState, FundingWallet, Publisher};

/// BIP 341's "nothing up my sleeve" x-only key, which nobody can sign for.
pub const NUMS_KEY: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// The commitment of an envelope: its tapscript, the taproot spend info and
/// the P2TR address that carries it.
pub struct Commitment {
    pub script: ScriptBuf,
    pub spend_info: TaprootSpendInfo,
    pub address: Address,
}

impl Commitment {
    pub fn new(envelope: &[u8], key: &XOnlyPublicKey, network: Network) -> Result<Self> {
        let secp = Secp256k1::new();
        let script = envelope_tapscript(envelope, key);
        let internal = XOnlyPublicKey::from_slice(&NUMS_KEY).expect("valid NUMS key");
        let spend_info = TaprootBuilder::new()
            .add_leaf(0, script.clone())
            .context("taproot leaf")?
            .finalize(&secp, internal)
            .map_err(|_| anyhow::anyhow!("taproot finalize"))?;
        let address = Address::p2tr_tweaked(spend_info.output_key(), network);
        Ok(Commitment {
            script,
            spend_info,
            address,
        })
    }

    pub fn script_pubkey(&self) -> ScriptBuf {
        self.address.script_pubkey()
    }

    fn control_block(&self) -> ControlBlock {
        self.spend_info
            .control_block(&(self.script.clone(), LeafVersion::TapScript))
            .expect("the leaf we built")
    }

    /// The reveal transaction spending `outpoint` (which holds `value`
    /// satoshis at our address): `extra` outputs first, an optional memo,
    /// then the remainder after `fee_rate` to `change`.
    #[allow(clippy::too_many_arguments)]
    pub fn reveal(
        &self,
        key: &FundingKey,
        outpoint: OutPoint,
        value: u64,
        extra: Vec<TxOut>,
        memo: Option<&[u8]>,
        change: &Address,
        fee_rate: u64,
    ) -> Result<Transaction> {
        let extra_sum: u64 = extra.iter().map(|o| o.value.to_sat()).sum();
        let mut outputs = extra;
        if let Some(m) = memo {
            outputs.push(memo_output(m));
        }
        outputs.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: change.script_pubkey(),
        });
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: outputs,
        };
        // size with a placeholder signature, then the fee and the remainder
        tx.input[0].witness = self.witness(&[0u8; 64]);
        let fee = tx.vsize() as u64 * fee_rate;
        if value < extra_sum + fee + DUST_LIMIT {
            bail!(
                "commit output holds {value} sat; the reveal needs {extra_sum} for its outputs, {fee} fee and {DUST_LIMIT} change"
            );
        }
        let last = tx.output.len() - 1;
        tx.output[last].value = Amount::from_sat(value - extra_sum - fee);
        let prevout = TxOut {
            value: Amount::from_sat(value),
            script_pubkey: self.script_pubkey(),
        };
        let sighash = SighashCache::new(&tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[prevout]),
                TapLeafHash::from_script(&self.script, LeafVersion::TapScript),
                TapSighashType::Default,
            )
            .context("taproot sighash")?;
        let secp = Secp256k1::new();
        let sig = secp.sign_schnorr(
            &Message::from_digest(sighash.to_byte_array()),
            &key.keypair(),
        );
        tx.input[0].witness = self.witness(sig.as_ref());
        Ok(tx)
    }

    fn witness(&self, sig: &[u8]) -> Witness {
        let mut w = Witness::new();
        w.push(sig);
        w.push(self.script.as_bytes());
        w.push(self.control_block().serialize());
        w
    }

    /// What the commit output must hold for a reveal with these outputs
    /// at `fee_rate`: their values, the reveal fee and a dust change.
    pub fn required_value(&self, extra: &[TxOut], memo: Option<&[u8]>, fee_rate: u64) -> u64 {
        let extra_sum: u64 = extra.iter().map(|o| o.value.to_sat()).sum();
        let mut outputs = extra.to_vec();
        if let Some(m) = memo {
            outputs.push(memo_output(m));
        }
        outputs.push(TxOut {
            value: Amount::from_sat(DUST_LIMIT),
            script_pubkey: self.address.script_pubkey(),
        });
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: outputs,
        };
        tx.input[0].witness = self.witness(&[0u8; 64]);
        extra_sum + tx.vsize() as u64 * fee_rate + DUST_LIMIT
    }
}

/// A published pair.
pub struct Published {
    pub commit: Transaction,
    pub reveal: Transaction,
    pub next: FundingState,
}

/// Build the commit from the fee wallet's coins and the reveal from it.
#[allow(clippy::too_many_arguments)]
pub fn build_pair(
    fw: &FundingWallet,
    key: &FundingKey,
    coins: &[Coin],
    state: FundingState,
    envelope: &[u8],
    extra: Vec<TxOut>,
    memo: Option<&[u8]>,
    fee_rate: u64,
    network: Network,
) -> Result<Published> {
    let commitment = Commitment::new(envelope, &key.keypair().x_only_public_key().0, network)?;
    let value = commitment.required_value(&extra, memo, fee_rate);
    let (commit, next) = fw.build_tx(
        coins,
        state,
        vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: commitment.script_pubkey(),
        }],
        fee_rate,
    )?;
    let vout = commit
        .output
        .iter()
        .position(|o| o.script_pubkey == commitment.script_pubkey())
        .expect("the output we added") as u32;
    let change = fw.key(crate::funding::Chain::Change, next.change)?.address;
    let next = FundingState {
        receive: next.receive,
        change: next.change + 1,
    };
    let reveal = commitment.reveal(
        key,
        OutPoint {
            txid: commit.compute_txid(),
            vout,
        },
        value,
        extra,
        memo,
        &change,
        fee_rate,
    )?;
    Ok(Published {
        commit,
        reveal,
        next,
    })
}

/// Attempts a reveal gets while the network answers that its input is not
/// known: a load-balanced broadcast endpoint can hand the commit to one
/// node and the reveal to another that has not seen the commit yet.
pub const REVEAL_ATTEMPTS: u32 = 5;
/// The pause between those attempts.
pub const REVEAL_PAUSE: std::time::Duration = std::time::Duration::from_secs(3);

/// Broadcast the pair in order: the commit, then the reveal, which is
/// retried `REVEAL_PAUSE` apart while the network has not seen the commit.
/// The error after the last attempt names the commit, which is on the
/// network by then: `publish <label> --reveal` spends it once it is seen.
pub fn broadcast(
    publisher: &dyn Publisher,
    p: &Published,
) -> Result<(bitcoin::Txid, bitcoin::Txid)> {
    broadcast_paced(publisher, p, REVEAL_PAUSE)
}

/// `broadcast` with the pause between reveal attempts given (the tests).
pub fn broadcast_paced(
    publisher: &dyn Publisher,
    p: &Published,
    pause: std::time::Duration,
) -> Result<(bitcoin::Txid, bitcoin::Txid)> {
    let c = publisher.broadcast(&p.commit)?;
    let mut attempt = 1;
    loop {
        match publisher.broadcast(&p.reveal) {
            Ok(r) => return Ok((c, r)),
            Err(e) if attempt < REVEAL_ATTEMPTS && commit_not_seen(&e) => {
                log::warn!(
                    "reveal refused ({e:#}): the commit {c} may not have reached that node yet; attempt {attempt} of {REVEAL_ATTEMPTS}"
                );
                std::thread::sleep(pause);
                attempt += 1;
            }
            Err(e) => {
                return Err(e.context(format!(
                    "commit {c} is published, the reveal is not: once the commit is seen, `sb publish <label> --reveal` spends it"
                )));
            }
        }
    }
}

/// Bitcoin Core's words for an input the node does not know
/// (`bad-txns-inputs-missingorspent`, `missing-inputs`).
fn commit_not_seen(e: &anyhow::Error) -> bool {
    let s = format!("{e:#}").to_lowercase();
    s.contains("missingorspent") || s.contains("missing-inputs") || s.contains("missing inputs")
}

#[cfg(test)]
mod tests {
    use super::*;
    const CANDIDATE_PREFIX: [u8; 4] = *b"btc\x01"; // the paper profile's prefix, for the tests
    use crate::funding::{Chain, Utxo};
    use bitcoin::Txid;

    #[test]
    fn commit_and_reveal_carry_the_envelope() {
        let fw = FundingWallet::new([3u8; 32], Network::Regtest);
        let key = fw.key(Chain::Receive, 0).unwrap();
        let mut env = vec![0u8; 700];
        env[..4].copy_from_slice(&CANDIDATE_PREFIX);
        let coins = vec![Coin {
            utxo: Utxo {
                outpoint: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 0,
                },
                value: 50_000,
                confirmed: true,
            },
            chain: Chain::Receive,
            index: 0,
        }];
        let extra = vec![TxOut {
            value: Amount::from_sat(5000),
            script_pubkey: ScriptBuf::new_op_return([9u8; 4]),
        }];
        let p = build_pair(
            &fw,
            &key,
            &coins,
            FundingState::default(),
            &env,
            extra.clone(),
            Some(b"sbx\x01m"),
            2,
            Network::Regtest,
        )
        .unwrap();
        // the commit pays a P2TR output; the reveal spends it by script path
        let commitment =
            Commitment::new(&env, &key.keypair().x_only_public_key().0, Network::Regtest).unwrap();
        assert!(
            p.commit
                .output
                .iter()
                .any(|o| o.script_pubkey == commitment.script_pubkey())
        );
        assert!(commitment.script_pubkey().is_p2tr());
        assert_eq!(
            p.reveal.input[0].previous_output.txid,
            p.commit.compute_txid()
        );
        let w = &p.reveal.input[0].witness;
        assert_eq!(w.len(), 3);
        assert_eq!(w[0].len(), 64);
        assert_eq!(&w[1], commitment.script.as_bytes());
        assert_eq!(w[2].len(), 33);
        // the indexer's witness rule finds the envelope and the memo
        let c = crate::carrier::CarrierMode::Witness
            .extract(&p.reveal, &CANDIDATE_PREFIX)
            .unwrap()
            .unwrap();
        assert_eq!(c.envelope, env);
        assert_eq!(c.memo, Some(b"sbx\x01m".to_vec()));
        // outputs: the extra one, the memo, the change; values add up
        assert_eq!(p.reveal.output.len(), 3);
        assert_eq!(p.reveal.output[0], extra[0]);
        let commit_value = p
            .commit
            .output
            .iter()
            .find(|o| o.script_pubkey == commitment.script_pubkey())
            .unwrap()
            .value
            .to_sat();
        let reveal_out: u64 = p.reveal.output.iter().map(|o| o.value.to_sat()).sum();
        assert_eq!(commit_value - reveal_out, p.reveal.vsize() as u64 * 2);
        assert!(p.reveal.output[2].value.to_sat() >= DUST_LIMIT);
        assert_eq!(p.next.change, 2, "commit change and reveal change");
        // the signature verifies under the key against the script-path sighash
        let prevout = TxOut {
            value: Amount::from_sat(commit_value),
            script_pubkey: commitment.script_pubkey(),
        };
        let sighash = SighashCache::new(&p.reveal)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[prevout]),
                TapLeafHash::from_script(&commitment.script, LeafVersion::TapScript),
                TapSighashType::Default,
            )
            .unwrap();
        let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&w[0]).unwrap();
        Secp256k1::verification_only()
            .verify_schnorr(
                &sig,
                &Message::from_digest(sighash.to_byte_array()),
                &key.keypair().x_only_public_key().0,
            )
            .unwrap();
        // the control block commits to the NUMS internal key
        let cb = ControlBlock::decode(&w[2]).unwrap();
        assert_eq!(cb.internal_key.serialize(), NUMS_KEY);
        assert!(cb.verify_taproot_commitment(
            &Secp256k1::verification_only(),
            commitment.spend_info.output_key().to_x_only_public_key(),
            &commitment.script
        ));
        // too small a commit output
        let e = commitment
            .reveal(&key, OutPoint::null(), 100, vec![], None, &key.address, 1)
            .unwrap_err()
            .to_string();
        assert!(e.contains("commit output holds"), "{e}");
    }

    /// A pair over one 50 000-sat coin, no extra output, no memo.
    fn pair() -> Published {
        let fw = FundingWallet::new([3u8; 32], Network::Regtest);
        let key = fw.key(Chain::Receive, 0).unwrap();
        let mut env = vec![0u8; 700];
        env[..4].copy_from_slice(&CANDIDATE_PREFIX);
        let coins = vec![Coin {
            utxo: Utxo {
                outpoint: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 0,
                },
                value: 50_000,
                confirmed: true,
            },
            chain: Chain::Receive,
            index: 0,
        }];
        build_pair(
            &fw,
            &key,
            &coins,
            FundingState::default(),
            &env,
            vec![],
            None,
            2,
            Network::Regtest,
        )
        .unwrap()
    }

    /// A network that refuses the reveal `refusals` times with `reason`
    /// and records every transaction handed to it.
    struct Flaky {
        reveal: Txid,
        refusals: std::cell::Cell<u32>,
        reason: &'static str,
        seen: std::cell::RefCell<Vec<Txid>>,
    }

    impl Publisher for Flaky {
        fn utxos(&self, _address: &Address) -> Result<Vec<Utxo>> {
            Ok(vec![])
        }
        fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
            let txid = tx.compute_txid();
            self.seen.borrow_mut().push(txid);
            if txid == self.reveal && self.refusals.get() > 0 {
                self.refusals.set(self.refusals.get() - 1);
                bail!("broadcast rejected (400): {}", self.reason);
            }
            Ok(txid)
        }
    }

    fn flaky(p: &Published, refusals: u32, reason: &'static str) -> Flaky {
        Flaky {
            reveal: p.reveal.compute_txid(),
            refusals: std::cell::Cell::new(refusals),
            reason,
            seen: std::cell::RefCell::new(vec![]),
        }
    }

    #[test]
    fn a_reveal_refused_before_the_commit_is_seen_is_retried() {
        let p = pair();
        let net = flaky(
            &p,
            2,
            "sendrawtransaction RPC error -25: bad-txns-inputs-missingorspent",
        );
        let (c, r) = broadcast_paced(&net, &p, std::time::Duration::ZERO).unwrap();
        assert_eq!(c, p.commit.compute_txid());
        assert_eq!(r, p.reveal.compute_txid());
        // the commit once, the reveal three times (two refusals, then accepted)
        assert_eq!(net.seen.borrow().as_slice(), &[c, r, r, r]);
    }

    #[test]
    fn a_reveal_refused_for_another_reason_fails_at_once_naming_the_commit() {
        let p = pair();
        let net = flaky(&p, 1, "bad-txns-in-belowout");
        let e = format!(
            "{:#}",
            broadcast_paced(&net, &p, std::time::Duration::ZERO).unwrap_err()
        );
        assert!(e.contains(&p.commit.compute_txid().to_string()), "{e}");
        assert!(e.contains("--reveal"), "{e}");
        assert!(e.contains("bad-txns-in-belowout"), "{e}");
        assert_eq!(net.seen.borrow().len(), 2);
    }

    #[test]
    fn a_commit_never_seen_gives_up_after_the_attempts() {
        let p = pair();
        let net = flaky(&p, 100, "missing-inputs");
        let e = format!(
            "{:#}",
            broadcast_paced(&net, &p, std::time::Duration::ZERO).unwrap_err()
        );
        assert!(e.contains("missing-inputs"), "{e}");
        assert_eq!(net.seen.borrow().len() as u32, 1 + REVEAL_ATTEMPTS);
    }
}
