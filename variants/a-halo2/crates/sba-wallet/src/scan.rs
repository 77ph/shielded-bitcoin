//! Note detection and sender-side recovery over accepted transfers
//! (paper §16.1, §16.2).

use sba_core::address::PaymentAddress;
use sba_core::event::AcceptedEvent;
use sba_core::keys::{IncomingViewingKey, OutgoingViewingKey};
use sba_core::note::{
    NotePlaintext, check_note_consistency, decrypt_as_recipient, decrypt_as_sender, note_leaf,
};
use sba_core::recovery::{binding_digest, decrypt_recovery};
use sba_core::{Affine, Fp};

/// A received note that passed every §16.1 check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedNote {
    pub note: NotePlaintext,
    pub address: PaymentAddress,
    pub h_body_create: Fp,
    pub output_index: u64,
    pub pos: u64,
    pub leaf: Fp,
    pub height: u32,
    pub txid: [u8; 32],
}

/// A sent note reconstructed through `ct_out` (§16.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentNote {
    pub note: NotePlaintext,
    pub pk_d: Affine,
    pub output_index: u64,
    pub pos: u64,
    pub height: u32,
    pub txid: [u8; 32],
}

/// Shared post-decryption checks: `pk_eph` consistency and leaf equality.
fn passes_checks(const_salt: &Fp, event: &AcceptedEvent, j: usize, pt: &NotePlaintext) -> bool {
    let (pk_eph, ct) = &event.outputs[j];
    check_note_consistency(pt, pk_eph)
        && note_leaf(const_salt, &event.h_body, j as u64, pk_eph, ct) == event.leaves[j]
}

/// Try every output of an accepted transfer with the incoming viewing key.
pub fn scan_incoming(
    ivk: &IncomingViewingKey,
    const_salt: &Fp,
    event: &AcceptedEvent,
) -> Vec<ReceivedNote> {
    let mut found = Vec::new();
    for (j, (pk_eph, ct)) in event.outputs.iter().enumerate() {
        let Some(pt) = decrypt_as_recipient(&ivk.sk_view, pk_eph, ct) else {
            continue;
        };
        let Some(address) = ivk.address_for(pt.d) else {
            continue;
        };
        if !passes_checks(const_salt, event, j, &pt) {
            continue;
        }
        // the indexer assigns positions from its own tree; one that would
        // overflow is no position at all (fail closed, found by the fuzz
        // target over an arbitrary event, 24 November 2026)
        let Some(pos) = event.first_position.checked_add(j as u64) else {
            continue;
        };
        found.push(ReceivedNote {
            note: pt,
            address,
            h_body_create: event.h_body,
            output_index: j as u64,
            pos,
            leaf: event.leaves[j],
            height: event.height,
            txid: event.txid,
        });
    }
    found
}

/// Decrypt `ct_out` with the outgoing viewing key and reconstruct the sent
/// notes. Whether the transfer was really ours is decided by the caller.
pub fn scan_outgoing(
    ovk: &OutgoingViewingKey,
    const_salt: &Fp,
    event: &AcceptedEvent,
) -> Option<Vec<SentNote>> {
    let ct_out = event.ct_out.as_ref()?;
    if event.outputs.len() != 2 {
        return None;
    }
    let pk_eph = [event.outputs[0].0, event.outputs[1].0];
    let ct = [event.outputs[0].1, event.outputs[1].1];
    let digest = binding_digest(&pk_eph, &ct);
    let entries = decrypt_recovery(ovk, &digest, ct_out)?;
    let mut out = Vec::with_capacity(entries.len());
    for (j, entry) in entries.iter().enumerate() {
        let pt = decrypt_as_sender(&entry.sk_eph, &entry.pk_d, &pk_eph[j], &ct[j])?;
        if !passes_checks(const_salt, event, j, &pt) {
            return None;
        }
        let pos = event.first_position.checked_add(j as u64)?;
        out.push(SentNote {
            note: pt,
            pk_d: entry.pk_d,
            output_index: j as u64,
            pos,
            height: event.height,
            txid: event.txid,
        });
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sba_core::event::EventKind;
    use sba_core::keys::{Seed, WalletKeys};
    use sba_core::note::encrypt_note;
    use sba_core::recovery::{RecoveryEntry, encrypt_recovery};

    /// A first position the indexer could never assign (its tree is far
    /// smaller) still cannot make the scan panic: the output whose position
    /// would overflow is skipped, the outgoing scan returns nothing (the
    /// fuzz target `wallet_a` over an arbitrary event).
    #[test]
    fn a_position_that_would_overflow_is_refused_not_a_panic() {
        let keys = WalletKeys::from_seed(&Seed([7u8; 32]));
        let salt = Fp::from(5u64);
        let addr = keys.ivk.find_address(0).1;
        let pt = NotePlaintext {
            value: 10,
            d: addr.d,
            rseed: Fp::from(77u64),
        };
        let pt2 = NotePlaintext {
            value: 20,
            d: addr.d,
            rseed: Fp::from(78u64),
        };
        let (pk_eph, ct) = encrypt_note(&pt, &addr.pk_d).unwrap();
        let (pk_eph2, ct2) = encrypt_note(&pt2, &addr.pk_d).unwrap();
        let h_body = Fp::from(9u64);
        let outputs = vec![(pk_eph, ct), (pk_eph2, ct2)];
        let leaves: Vec<Fp> = (0..2)
            .map(|j| note_leaf(&salt, &h_body, j as u64, &outputs[j].0, &outputs[j].1))
            .collect();
        let digest = binding_digest(&[outputs[0].0, outputs[1].0], &[outputs[0].1, outputs[1].1]);
        let ct_out = encrypt_recovery(
            &keys.ovk,
            &digest,
            &[
                RecoveryEntry {
                    pk_d: addr.pk_d,
                    sk_eph: pt.sk_eph(),
                },
                RecoveryEntry {
                    pk_d: addr.pk_d,
                    sk_eph: pt2.sk_eph(),
                },
            ],
        );
        let mut event = AcceptedEvent {
            kind: EventKind::Transfer,
            height: 1,
            tx_index: 0,
            txid: [1u8; 32],
            raw: vec![],
            h_body,
            nullifiers: vec![],
            outputs,
            ct_out: Some(ct_out),
            first_position: 100,
            leaves,
            memo: None,
        };
        assert_eq!(scan_incoming(&keys.ivk, &salt, &event).len(), 2);
        assert_eq!(scan_outgoing(&keys.ovk, &salt, &event).unwrap().len(), 2);
        event.first_position = u64::MAX;
        let found = scan_incoming(&keys.ivk, &salt, &event);
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].output_index, found[0].pos), (0, u64::MAX));
        assert!(scan_outgoing(&keys.ovk, &salt, &event).is_none());
    }
}
