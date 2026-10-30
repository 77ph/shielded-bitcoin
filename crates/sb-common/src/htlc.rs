//! The Bitcoin side of a swap (`docs/SWAP.md` §9): a P2WSH HTLC with the
//! shared SHA-256 hash-lock, funded, claimed with the preimage or refunded
//! after its height, and watched for the spend that reveals the preimage.
//!
//! ```text
//! OP_IF OP_SHA256 <H> OP_EQUALVERIFY <P_X> OP_CHECKSIG
//! OP_ELSE <T_htlc> OP_CHECKLOCKTIMEVERIFY OP_DROP <P_Y> OP_CHECKSIG OP_ENDIF
//! ```

use anyhow::{Context, Result, anyhow, bail};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::*;
use bitcoin::script::Builder;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, CompressedPublicKey, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Witness,
};

use crate::ChainSource;

use crate::funding::{DUST_LIMIT, FundingKey};

/// The HTLC's parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Htlc {
    pub hash: [u8; 32],
    pub claim_pk: CompressedPublicKey,
    pub refund_pk: CompressedPublicKey,
    pub timeout: u32,
}

impl Htlc {
    pub fn witness_script(&self) -> ScriptBuf {
        Builder::new()
            .push_opcode(OP_IF)
            .push_opcode(OP_SHA256)
            .push_slice(self.hash)
            .push_opcode(OP_EQUALVERIFY)
            .push_slice(self.claim_pk.to_bytes())
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ELSE)
            .push_int(self.timeout as i64)
            .push_opcode(OP_CLTV)
            .push_opcode(OP_DROP)
            .push_slice(self.refund_pk.to_bytes())
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ENDIF)
            .into_script()
    }

    pub fn address(&self, network: Network) -> Address {
        Address::p2wsh(&self.witness_script(), network)
    }

    pub fn script_pubkey(&self) -> ScriptBuf {
        self.witness_script().to_p2wsh()
    }

    /// Fee for a one-input one-output spend at `fee_rate` sat/vB
    /// (claim ≈ 150 vB, refund ≈ 140 vB).
    fn spend_fee(fee_rate: u64) -> u64 {
        160 * fee_rate
    }

    /// Spend the HTLC output `outpoint` of `value` to `to`: the claim path
    /// with `secret`, or the refund path (`secret = None`, lock time set to
    /// the timeout). `key` is the claim or refund key respectively.
    pub fn spend(
        &self,
        outpoint: OutPoint,
        value: u64,
        key: &FundingKey,
        secret: Option<[u8; 32]>,
        to: &Address,
        fee_rate: u64,
    ) -> Result<Transaction> {
        let fee = Self::spend_fee(fee_rate);
        if value < fee + DUST_LIMIT {
            bail!("HTLC value {value} does not cover the fee {fee} plus dust");
        }
        let script = self.witness_script();
        let expected = match secret {
            Some(_) => self.claim_pk,
            None => self.refund_pk,
        };
        if key.pubkey() != expected {
            bail!("this wallet does not hold the key of that path");
        }
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: match secret {
                Some(_) => LockTime::ZERO,
                None => LockTime::from_height(self.timeout).context("timeout height")?,
            },
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: match secret {
                    Some(_) => Sequence::ENABLE_RBF_NO_LOCKTIME,
                    None => Sequence::ENABLE_LOCKTIME_NO_RBF,
                },
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value - fee),
                script_pubkey: to.script_pubkey(),
            }],
        };
        let sighash = SighashCache::new(&tx)
            .p2wsh_signature_hash(0, &script, Amount::from_sat(value), EcdsaSighashType::All)
            .context("sighash")?;
        let sig = key.sign(sighash.to_byte_array());
        let mut w = Witness::new();
        w.push(sig.to_vec());
        match secret {
            Some(s) => {
                w.push(s);
                w.push([1u8]);
            }
            None => {
                w.push([]);
            }
        }
        w.push(script.as_bytes());
        tx.input[0].witness = w;
        Ok(tx)
    }

    /// The preimage revealed by a claim of `outpoint`, found by scanning
    /// blocks `from..=tip` through `chain`: `Some((height, secret))`.
    pub fn find_preimage(
        &self,
        chain: &dyn ChainSource,
        outpoint: OutPoint,
        from: u32,
    ) -> Result<Option<(u32, [u8; 32])>> {
        let tip = chain.tip()?.height;
        for h in from..=tip {
            let Some(hash) = chain.block_hash(h)? else {
                break;
            };
            let block = chain.block(&hash)?;
            for tx in &block.txdata {
                for input in &tx.input {
                    if input.previous_output != outpoint {
                        continue;
                    }
                    let w = &input.witness;
                    // claim witness: sig, secret, 1, script
                    if w.len() == 4 && w[1].len() == 32 {
                        let mut s = [0u8; 32];
                        s.copy_from_slice(&w[1]);
                        if bitcoin::hashes::sha256::Hash::hash(&s).to_byte_array() == self.hash {
                            return Ok(Some((h, s)));
                        }
                    }
                    bail!("HTLC {outpoint} was spent at height {h} without a preimage (refunded)");
                }
            }
        }
        Ok(None)
    }
}

/// Parse `txid:vout`.
pub fn parse_outpoint(s: &str) -> Result<OutPoint> {
    let (txid, vout) = s
        .split_once(':')
        .ok_or_else(|| anyhow!("expected txid:vout"))?;
    Ok(OutPoint {
        txid: txid.parse().context("txid")?,
        vout: vout.parse().context("vout")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::funding::{Chain, FundingWallet};
    use bitcoin::consensus::encode::serialize;
    use bitcoin::secp256k1::Secp256k1;
    use sha2::{Digest, Sha256};

    fn keys() -> (FundingKey, FundingKey) {
        let a = FundingWallet::new([1u8; 32], Network::Regtest);
        let b = FundingWallet::new([2u8; 32], Network::Regtest);
        (
            a.key(Chain::Receive, 0).unwrap(),
            b.key(Chain::Receive, 0).unwrap(),
        )
    }

    #[test]
    fn script_paths_and_witnesses() {
        let (x, y) = keys();
        let secret = [9u8; 32];
        let secret_hash: [u8; 32] = Sha256::digest(secret).into();
        let htlc = Htlc {
            hash: secret_hash,
            claim_pk: x.pubkey(),
            refund_pk: y.pubkey(),
            timeout: 150,
        };
        let script = htlc.witness_script();
        assert!(script.as_bytes().windows(32).any(|w| w == secret_hash));
        assert_eq!(
            htlc.address(Network::Regtest).script_pubkey(),
            htlc.script_pubkey()
        );
        assert!(htlc.script_pubkey().is_p2wsh());
        let outpoint = parse_outpoint(&format!("{}:1", bitcoin::Txid::all_zeros())).unwrap();
        let to = x.address.clone();
        // claim: witness [sig, secret, 1, script], no lock time
        let claim = htlc
            .spend(outpoint, 10_000, &x, Some(secret), &to, 2)
            .unwrap();
        let w = &claim.input[0].witness;
        assert_eq!(w.len(), 4);
        assert_eq!(w[1], secret);
        assert_eq!(w[2], [1u8]);
        assert_eq!(&w[3], script.as_bytes());
        assert_eq!(claim.lock_time, LockTime::ZERO);
        assert_eq!(claim.output[0].value.to_sat(), 10_000 - 320);
        // the signature verifies under the claim key
        let sighash = SighashCache::new(&claim)
            .p2wsh_signature_hash(0, &script, Amount::from_sat(10_000), EcdsaSighashType::All)
            .unwrap();
        let sig = bitcoin::ecdsa::Signature::from_slice(&w[0]).unwrap();
        Secp256k1::verification_only()
            .verify_ecdsa(
                &bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array()),
                &sig.signature,
                &x.pubkey().0,
            )
            .unwrap();
        // refund: witness [sig, <>, script], lock time = timeout
        let refund = htlc
            .spend(outpoint, 10_000, &y, None, &y.address, 1)
            .unwrap();
        let w = &refund.input[0].witness;
        assert_eq!(w.len(), 3);
        assert!(w[1].is_empty());
        assert_eq!(refund.lock_time, LockTime::from_height(150).unwrap());
        assert_eq!(refund.input[0].sequence, Sequence::ENABLE_LOCKTIME_NO_RBF);
        assert!(!serialize(&refund).is_empty());
        // the wrong key for a path, and a value that cannot pay the fee
        assert!(
            htlc.spend(outpoint, 10_000, &y, Some(secret), &to, 1)
                .is_err()
        );
        assert!(htlc.spend(outpoint, 10_000, &x, None, &to, 1).is_err());
        assert!(htlc.spend(outpoint, 500, &x, Some(secret), &to, 1).is_err());
        assert!(parse_outpoint("nocolon").is_err());
        assert!(parse_outpoint("zz:1").is_err());
    }
}
