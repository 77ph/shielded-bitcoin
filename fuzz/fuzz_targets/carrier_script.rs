//! The two carrier rules (`sb-common::carrier`) over one script of any
//! bytes: as an OP_RETURN output (once, twice, beside a memo) and as the
//! tapscript of a script-path witness (with and without a signature and an
//! annex). Never panics; a located envelope starts with the prefix asked
//! for, a located memo with the memo magic; what the OP_RETURN rule locates
//! in a lone output is what `carrier_output` publishes for those bytes, and
//! what the witness rule locates is what `envelope_tapscript` builds for
//! them under the script's key — the rules accept only the canonical form.
#![no_main]
use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};
use libfuzzer_sys::fuzz_target;
use sb_common::carrier::{
    Candidate, CarrierError, CarrierMode, MEMO_MAGIC, carrier_output, envelope_tapscript,
    memo_output, tapscript_of,
};

fn located(r: &Option<Result<Candidate, CarrierError>>, prefix: &[u8]) -> Option<Candidate> {
    match r {
        Some(Ok(c)) => {
            assert!(c.envelope.starts_with(prefix));
            if let Some(m) = &c.memo {
                assert!(m.starts_with(&MEMO_MAGIC));
            }
            Some(c.clone())
        }
        _ => None,
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, script_bytes)) = data.split_first() else {
        return;
    };
    let prefix: &[u8] = if sel & 1 == 0 {
        &sb_core::envelope::CANDIDATE_PREFIX
    } else {
        &sba_core::envelope::CANDIDATE_PREFIX
    };
    let script = ScriptBuf::from_bytes(script_bytes.to_vec());
    let out = TxOut {
        value: Amount::ZERO,
        script_pubkey: script.clone(),
    };
    let mut outputs = vec![out.clone()];
    if sel & 2 != 0 {
        outputs.push(out);
    }
    if sel & 4 != 0 {
        outputs.push(memo_output(b"sbx\x01memo"));
    }
    let lone = outputs.len() == 1;

    // the OP_RETURN rule
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: outputs.clone(),
    };
    let r = CarrierMode::OpReturn.extract(&tx, prefix);
    assert_eq!(r.is_some(), CarrierMode::OpReturn.is_carrier(&tx, prefix));
    if let Some(c) = located(&r, prefix) {
        if lone {
            assert_eq!(
                carrier_output(&c.envelope).script_pubkey,
                script,
                "a lone OP_RETURN candidate is the canonical carrier output"
            );
            assert!(c.memo.is_none());
        }
    }

    // the witness rule: [signature,] script, control block[, annex]
    let mut w = Witness::new();
    if sel & 8 != 0 {
        w.push([0u8; 64]);
    }
    w.push(script_bytes);
    w.push([0xc0u8; 33]);
    if sel & 16 != 0 {
        w.push([0x50u8, 1, 2]);
    }
    let _ = tapscript_of(&w);
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: w,
        }],
        output: outputs,
    };
    let r = CarrierMode::Witness.extract(&tx, prefix);
    assert_eq!(r.is_some(), CarrierMode::Witness.is_carrier(&tx, prefix));
    if let Some(c) = located(&r, prefix) {
        // the key is the script's first push; a valid one rebuilds the script
        if let Ok(key) = XOnlyPublicKey::from_slice(&script_bytes[1..33.min(script_bytes.len())]) {
            assert_eq!(
                envelope_tapscript(&c.envelope, &key),
                script,
                "a located tapscript is the canonical one for its payload"
            );
        }
    }
});
