//! Publication carrier (paper §A.4; profile §10): locate the envelope bytes
//! in a Bitcoin transaction. Two carrier rules exist, one per deployment:
//! the base profile's single OP_RETURN output, and the witness-carried
//! alternative of `docs/WITNESS-CARRIER.md` (paper §22.1), where the
//! envelope sits in an unexecuted branch of a tapscript revealed by a
//! script-path spend.

use bitcoin::blockdata::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF, OP_PUSHBYTES_0, OP_RETURN};
use bitcoin::blockdata::script::{Builder, Instruction, PushBytesBuf, ScriptBuf};
use bitcoin::{Amount, Transaction, TxOut, XOnlyPublicKey};
use serde::{Deserialize, Serialize};

use sb_core::envelope::is_candidate;

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum CarrierError {
    #[error("more than one OP_RETURN output carries an envelope")]
    MultipleEnvelopes,
    #[error("OP_RETURN script is not a single minimal push")]
    MalformedScript,
    #[error("more than one input reveals an envelope tapscript")]
    MultipleWitnessEnvelopes,
    #[error("envelope tapscript is malformed")]
    MalformedTapscript,
}

/// Where a deployment's envelopes live (profile §10 or `docs/WITNESS-CARRIER.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CarrierMode {
    /// One OP_RETURN output with a single minimal push.
    #[default]
    OpReturn,
    /// A tapscript revealed by a script-path spend, the envelope in its
    /// unexecuted `OP_FALSE OP_IF … OP_ENDIF` branch.
    Witness,
}

impl CarrierMode {
    /// The candidate envelope of a transaction under this rule.
    pub fn extract(&self, tx: &Transaction) -> Option<Result<Candidate, CarrierError>> {
        match self {
            CarrierMode::OpReturn => extract_envelope(tx),
            CarrierMode::Witness => extract_envelope_witness(tx),
        }
    }

    pub fn is_carrier(&self, tx: &Transaction) -> bool {
        self.extract(tx).is_some()
    }
}

/// Largest push a script may carry.
pub const MAX_PUSH: usize = 520;

/// The tapscript that carries `envelope` (`docs/WITNESS-CARRIER.md` §2):
/// `<key> OP_CHECKSIG OP_FALSE OP_IF <chunks of at most 520 bytes> OP_ENDIF`.
pub fn envelope_tapscript(envelope: &[u8], key: &XOnlyPublicKey) -> ScriptBuf {
    let mut b = Builder::new()
        .push_x_only_key(key)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_PUSHBYTES_0)
        .push_opcode(OP_IF);
    for chunk in envelope.chunks(MAX_PUSH) {
        b = b.push_slice(PushBytesBuf::try_from(chunk.to_vec()).expect("≤ 520 bytes"));
    }
    b.push_opcode(OP_ENDIF).into_script()
}

/// The payload of an envelope tapscript, `None` if the script has another
/// shape (not a candidate), `Some(Err)` if it has the shape but breaks a
/// rule (non-minimal push, chunking, trailing opcodes).
fn tapscript_payload(script: &ScriptBuf) -> Result<Option<Vec<u8>>, CarrierError> {
    let mut it = script.instructions_minimal();
    // <32-byte key> OP_CHECKSIG OP_FALSE OP_IF
    match it.next() {
        Some(Ok(Instruction::PushBytes(p))) if p.len() == 32 => {}
        _ => return Ok(None),
    }
    match it.next() {
        Some(Ok(Instruction::Op(OP_CHECKSIG))) => {}
        _ => return Ok(None),
    }
    match it.next() {
        Some(Ok(Instruction::PushBytes(p))) if p.is_empty() => {}
        _ => return Ok(None),
    }
    match it.next() {
        Some(Ok(Instruction::Op(OP_IF))) => {}
        _ => return Ok(None),
    }
    let mut payload = Vec::new();
    loop {
        match it.next() {
            Some(Ok(Instruction::PushBytes(p))) => {
                if p.is_empty() {
                    return Err(CarrierError::MalformedTapscript);
                }
                // every chunk but the last is full
                if !payload.is_empty() && payload.len() % MAX_PUSH != 0 {
                    return Err(CarrierError::MalformedTapscript);
                }
                payload.extend_from_slice(p.as_bytes());
            }
            Some(Ok(Instruction::Op(OP_ENDIF))) => break,
            _ => return Err(CarrierError::MalformedTapscript),
        }
    }
    if it.next().is_some() {
        return Err(CarrierError::MalformedTapscript);
    }
    Ok(Some(payload))
}

/// The script of a taproot script-path spend: the second-to-last witness
/// item, or the third-to-last when a BIP 341 annex (a last item starting
/// with `0x50`) is present.
pub fn tapscript_of(witness: &bitcoin::Witness) -> Option<ScriptBuf> {
    let n = witness.len();
    let has_annex = n >= 2 && witness[n - 1].first() == Some(&0x50);
    let index = if has_annex {
        if n < 3 {
            return None;
        }
        n - 3
    } else {
        if n < 2 {
            return None;
        }
        n - 2
    };
    Some(ScriptBuf::from_bytes(witness[index].to_vec()))
}

/// The witness-carrier rule: exactly one input whose script-path witness
/// (`…, script, control block[, annex]`) reveals an envelope tapscript
/// whose payload starts with the magic. Memos stay in OP_RETURN outputs.
pub fn extract_envelope_witness(tx: &Transaction) -> Option<Result<Candidate, CarrierError>> {
    let mut found: Option<Vec<u8>> = None;
    for input in &tx.input {
        let Some(script) = tapscript_of(&input.witness) else {
            continue;
        };
        match tapscript_payload(&script) {
            Ok(Some(payload)) if is_candidate(&payload) => {
                if found.is_some() {
                    return Some(Err(CarrierError::MultipleWitnessEnvelopes));
                }
                found = Some(payload);
            }
            Ok(_) => {}
            Err(e) => {
                if script.as_bytes().windows(4).any(is_candidate) {
                    return Some(Err(e));
                }
            }
        }
    }
    let envelope = found?;
    let mut memo = None;
    for out in &tx.output {
        if let Ok(Some(payload)) = op_return_payload(&out.script_pubkey) {
            if payload.starts_with(&MEMO_MAGIC) && memo.is_none() {
                memo = Some(payload);
            }
        }
    }
    Some(Ok(Candidate { envelope, memo }))
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

    #[test]
    fn witness_rule_finds_one_envelope_and_rejects_the_rest() {
        use bitcoin::Witness;
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let key = bitcoin::secp256k1::Keypair::from_secret_key(
            &secp,
            &SecretKey::from_slice(&[7u8; 32]).unwrap(),
        )
        .x_only_public_key()
        .0;
        let mut env = vec![0u8; ENVELOPE_LEN];
        env[..4].copy_from_slice(&CANDIDATE_PREFIX);
        env[5] = 9;
        let script = envelope_tapscript(&env, &key);
        assert_eq!(script.len(), 1 + 32 + 1 + 1 + 1 + (3 + 520) + (2 + 180) + 1);
        let reveal_input = |script: &ScriptBuf| {
            let mut w = Witness::new();
            w.push([1u8; 64]);
            w.push(script.as_bytes());
            w.push([0xc0u8; 33]);
            bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: w,
            }
        };
        let tx = |inputs: Vec<bitcoin::TxIn>, outputs: Vec<TxOut>| Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        };
        let good = tx(vec![reveal_input(&script)], vec![]);
        let c = CarrierMode::Witness.extract(&good).unwrap().unwrap();
        assert_eq!(c.envelope, env);
        assert_eq!(c.memo, None);
        assert!(CarrierMode::Witness.is_carrier(&good));
        // the OP_RETURN rule does not see it, and vice versa
        assert!(CarrierMode::OpReturn.extract(&good).is_none());
        let op_return = tx(vec![], vec![carrier_output(&env)]);
        assert!(CarrierMode::Witness.extract(&op_return).is_none());
        assert!(CarrierMode::OpReturn.is_carrier(&op_return));
        // a memo output rides along
        let with_memo = tx(
            vec![reveal_input(&script)],
            vec![memo_output(b"sbx\x01hello")],
        );
        assert_eq!(
            CarrierMode::Witness
                .extract(&with_memo)
                .unwrap()
                .unwrap()
                .memo,
            Some(b"sbx\x01hello".to_vec())
        );
        // two revealing inputs
        let two = tx(vec![reveal_input(&script), reveal_input(&script)], vec![]);
        assert_eq!(
            CarrierMode::Witness.extract(&two).unwrap().unwrap_err(),
            CarrierError::MultipleWitnessEnvelopes
        );
        // a key-path spend (one witness item) and an unrelated script are not candidates
        let mut w = Witness::new();
        w.push([1u8; 64]);
        let keypath = tx(
            vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: w,
            }],
            vec![],
        );
        assert!(CarrierMode::Witness.extract(&keypath).is_none());
        let other = Builder::new().push_opcode(OP_CHECKSIG).into_script();
        assert!(
            CarrierMode::Witness
                .extract(&tx(vec![reveal_input(&other)], vec![]))
                .is_none()
        );
        // a tapscript with the magic but broken chunking is a probe: rejected
        let bad = Builder::new()
            .push_x_only_key(&key)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_PUSHBYTES_0)
            .push_opcode(OP_IF)
            .push_slice(PushBytesBuf::try_from(env[..100].to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from(env[100..].to_vec()).unwrap())
            .push_opcode(OP_ENDIF)
            .into_script();
        assert_eq!(
            CarrierMode::Witness
                .extract(&tx(vec![reveal_input(&bad)], vec![]))
                .unwrap()
                .unwrap_err(),
            CarrierError::MalformedTapscript
        );
        // trailing opcode after OP_ENDIF
        let mut trailing = script.to_bytes();
        trailing.push(OP_CHECKSIG.to_u8());
        let trailing = ScriptBuf::from_bytes(trailing);
        assert_eq!(
            CarrierMode::Witness
                .extract(&tx(vec![reveal_input(&trailing)], vec![]))
                .unwrap()
                .unwrap_err(),
            CarrierError::MalformedTapscript
        );
        // an empty push inside the branch
        let empty = Builder::new()
            .push_x_only_key(&key)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_PUSHBYTES_0)
            .push_opcode(OP_IF)
            .push_slice(
                PushBytesBuf::try_from(env.clone())
                    .unwrap_or_else(|_| PushBytesBuf::try_from(env[..520].to_vec()).unwrap()),
            )
            .push_slice(PushBytesBuf::new())
            .push_opcode(OP_ENDIF)
            .into_script();
        assert!(matches!(
            CarrierMode::Witness.extract(&tx(vec![reveal_input(&empty)], vec![])),
            Some(Err(CarrierError::MalformedTapscript))
        ));
        // a reveal with a BIP 341 annex: the script is the third-to-last item
        let mut with_annex = reveal_input(&script);
        with_annex.witness.push([0x50u8, 1, 2, 3]);
        assert_eq!(
            CarrierMode::Witness
                .extract(&tx(vec![with_annex], vec![]))
                .unwrap()
                .unwrap()
                .envelope,
            env
        );
        // an annex on a two-item witness leaves no script to read
        let mut w = Witness::new();
        w.push(script.as_bytes());
        w.push([0x50u8]);
        assert!(tapscript_of(&w).is_none());
        // a small envelope fits one push
        let mut small = vec![0u8; 89];
        small[..4].copy_from_slice(&CANDIDATE_PREFIX);
        let s1 = envelope_tapscript(&small, &key);
        assert_eq!(
            CarrierMode::Witness
                .extract(&tx(vec![reveal_input(&s1)], vec![]))
                .unwrap()
                .unwrap()
                .envelope,
            small
        );
        // serde of the mode
        assert_eq!(
            serde_json::to_string(&CarrierMode::Witness).unwrap(),
            "\"witness\""
        );
        assert_eq!(
            serde_json::from_str::<CarrierMode>("\"op-return\"").unwrap(),
            CarrierMode::OpReturn
        );
        assert_eq!(CarrierMode::default(), CarrierMode::OpReturn);
    }
}
