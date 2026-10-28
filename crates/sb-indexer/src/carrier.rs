//! Publication carrier (paper §A.4; profile §10): locate the envelope bytes
//! in a Bitcoin transaction.

use bitcoin::blockdata::opcodes::all::OP_RETURN;
use bitcoin::blockdata::script::{Builder, Instruction, PushBytesBuf, ScriptBuf};
use bitcoin::{Amount, Transaction, TxOut};

use sb_core::envelope::is_candidate;

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum CarrierError {
    #[error("more than one OP_RETURN output carries an envelope")]
    MultipleEnvelopes,
    #[error("OP_RETURN script is not a single minimal push")]
    MalformedScript,
}

/// Parse an `OP_RETURN <push>` script into its payload, requiring exactly one
/// minimally encoded push.
fn op_return_payload(script: &ScriptBuf) -> Result<Option<Vec<u8>>, CarrierError> {
    if !script.is_op_return() {
        return Ok(None);
    }
    let mut it = script.instructions_minimal();
    match it.next() {
        Some(Ok(Instruction::Op(OP_RETURN))) => {}
        _ => return Err(CarrierError::MalformedScript),
    }
    let payload = match it.next() {
        Some(Ok(Instruction::PushBytes(p))) => p.as_bytes().to_vec(),
        None => return Ok(Some(Vec::new())),
        _ => return Err(CarrierError::MalformedScript),
    };
    if it.next().is_some() {
        return Err(CarrierError::MalformedScript);
    }
    Ok(Some(payload))
}

/// Prefix of the non-normative payout memo (docs/BOUNDARY.md), carried in a
/// second OP_RETURN that the carrier rule ignores.
pub const MEMO_MAGIC: [u8; 3] = *b"sbx";

/// A located envelope plus the optional memo next to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub envelope: Vec<u8>,
    pub memo: Option<Vec<u8>>,
}

/// The candidate envelope of a transaction, if any.
///
/// * `None`: the transaction carries no Shielded Bitcoin envelope.
/// * `Some(Ok(c))`: exactly one OP_RETURN output with a candidate payload.
/// * `Some(Err(_))`: the transaction looks like a carrier but violates the
///   carrier rule; replay records it as a rejection.
pub fn extract_envelope(tx: &Transaction) -> Option<Result<Candidate, CarrierError>> {
    let mut found: Option<Vec<u8>> = None;
    let mut memo: Option<Vec<u8>> = None;
    for out in &tx.output {
        if !out.script_pubkey.is_op_return() {
            continue;
        }
        match op_return_payload(&out.script_pubkey) {
            Ok(Some(payload)) if is_candidate(&payload) => {
                if found.is_some() {
                    return Some(Err(CarrierError::MultipleEnvelopes));
                }
                found = Some(payload);
            }
            Ok(Some(payload)) if payload.starts_with(&MEMO_MAGIC) => {
                if memo.is_none() {
                    memo = Some(payload);
                }
            }
            Ok(_) => {}
            Err(e) => {
                // A malformed OP_RETURN whose raw bytes start with our magic
                // is a probe; anything else is somebody else's data.
                if out.script_pubkey.as_bytes().windows(4).any(is_candidate) {
                    return Some(Err(e));
                }
            }
        }
    }
    found.map(|envelope| Ok(Candidate { envelope, memo }))
}

/// A memo output (second OP_RETURN, no protocol magic).
pub fn memo_output(memo: &[u8]) -> TxOut {
    debug_assert!(memo.starts_with(&MEMO_MAGIC));
    carrier_output(memo)
}

/// Build the carrier output for an envelope (one minimal push).
pub fn carrier_output(envelope: &[u8]) -> TxOut {
    let push = PushBytesBuf::try_from(envelope.to_vec()).expect("envelope fits a push");
    let script = Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(push)
        .into_script();
    TxOut {
        value: Amount::ZERO,
        script_pubkey: script,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use sb_core::envelope::{CANDIDATE_PREFIX, ENVELOPE_LEN};

    fn tx_with(outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: outputs,
        }
    }

    fn envelope() -> Vec<u8> {
        let mut e = vec![0u8; ENVELOPE_LEN];
        e[..4].copy_from_slice(&CANDIDATE_PREFIX);
        e
    }

    #[test]
    fn extracts_single_minimal_push() {
        let e = envelope();
        let tx = tx_with(vec![carrier_output(&e)]);
        assert_eq!(
            extract_envelope(&tx),
            Some(Ok(Candidate {
                envelope: e.clone(),
                memo: None
            }))
        );
        // PUSHDATA2 is the minimal encoding for a 700-byte envelope
        assert_eq!(tx.output[0].script_pubkey.as_bytes()[1], 0x4d);
    }

    #[test]
    fn ignores_unrelated_and_rejects_probes() {
        let e = envelope();
        let other = Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(b"hello")
            .into_script();
        let tx = tx_with(vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: other.clone(),
        }]);
        assert_eq!(extract_envelope(&tx), None);
        // one envelope plus an unrelated OP_RETURN is fine
        let tx = tx_with(vec![
            carrier_output(&e),
            TxOut {
                value: Amount::ZERO,
                script_pubkey: other,
            },
        ]);
        assert_eq!(
            extract_envelope(&tx),
            Some(Ok(Candidate {
                envelope: e.clone(),
                memo: None
            }))
        );
        // two envelopes
        let tx = tx_with(vec![carrier_output(&e), carrier_output(&e)]);
        assert_eq!(
            extract_envelope(&tx),
            Some(Err(CarrierError::MultipleEnvelopes))
        );
        // extra push after the envelope
        let mut script = Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(PushBytesBuf::try_from(e.clone()).unwrap());
        script = script.push_slice(b"x");
        let tx = tx_with(vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: script.into_script(),
        }]);
        assert_eq!(
            extract_envelope(&tx),
            Some(Err(CarrierError::MalformedScript))
        );
        // non-minimal push (PUSHDATA4) of the envelope
        let mut raw = vec![0x6a, 0x4e];
        raw.extend_from_slice(&(e.len() as u32).to_le_bytes());
        raw.extend_from_slice(&e);
        let tx = tx_with(vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(raw),
        }]);
        assert_eq!(
            extract_envelope(&tx),
            Some(Err(CarrierError::MalformedScript))
        );
    }

    #[test]
    fn bare_op_return_is_not_a_candidate() {
        let bare = Builder::new().push_opcode(OP_RETURN).into_script();
        let tx = tx_with(vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: bare,
        }]);
        assert_eq!(extract_envelope(&tx), None);
    }
}
