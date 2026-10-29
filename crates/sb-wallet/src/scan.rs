//! Note detection and sender-side recovery over accepted transfers
//! (paper §16.1, §16.2).

use sb_core::address::PaymentAddress;
use sb_core::event::AcceptedEvent;
use sb_core::keys::{IncomingViewingKey, OutgoingViewingKey};
use sb_core::note::{
    NotePlaintext, check_note_consistency, decrypt_as_recipient, decrypt_as_sender, note_leaf_aux,
};
use sb_core::recovery::{binding_digest, decrypt_recovery};
use sb_primitives::Fr;

/// A received note that passed every §16.1 check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedNote {
    pub note: NotePlaintext,
    pub address: PaymentAddress,
    pub h_body_create: Fr,
    pub output_index: u64,
    pub pos: u64,
    pub leaf: Fr,
    /// The leaf's `h_aux` slot: `0` for a plain note, a lock commitment
    /// for a locked one (`docs/SWAP.md`).
    pub h_aux: Fr,
    pub height: u32,
    pub txid: [u8; 32],
}

/// A sent note reconstructed through `ct_out` (§16.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentNote {
    pub note: NotePlaintext,
    pub pk_d: sb_primitives::JubjubAffine,
    pub output_index: u64,
    pub pos: u64,
    /// The output's `h_aux` slot (see [`ReceivedNote::h_aux`]).
    pub h_aux: Fr,
    pub height: u32,
    pub txid: [u8; 32],
}

/// Shared post-decryption checks: `pk_eph` consistency and leaf equality.
fn passes_checks(const_salt: &Fr, event: &AcceptedEvent, j: usize, pt: &NotePlaintext) -> bool {
    let (pk_eph, ct) = &event.outputs[j];
    check_note_consistency(pt, pk_eph)
        && note_leaf_aux(
            const_salt,
            &event.h_body,
            j as u64,
            pk_eph,
            ct,
            event.h_aux.get(j).unwrap_or(&Fr::from(0u64)),
        ) == event.leaves[j]
}

/// Try every output of an accepted transfer with the incoming viewing key.
pub fn scan_incoming(
    ivk: &IncomingViewingKey,
    const_salt: &Fr,
    event: &AcceptedEvent,
) -> Vec<ReceivedNote> {
    let mut found = Vec::new();
    for (j, (pk_eph, ct)) in event.outputs.iter().enumerate() {
        let Some(pt) = decrypt_as_recipient(&ivk.sk_view, pk_eph, ct) else {
            continue;
        };
        // d must identify a local receive path whose pk_d matches the one
        // the ciphertext was keyed to (the key schedule binds pk_d).
        let Some(address) = ivk.address_for(pt.d) else {
            continue;
        };
        if !passes_checks(const_salt, event, j, &pt) {
            continue;
        }
        found.push(ReceivedNote {
            note: pt,
            address,
            h_body_create: event.h_body,
            output_index: j as u64,
            pos: event.first_position + j as u64,
            leaf: event.leaves[j],
            h_aux: event.h_aux.get(j).copied().unwrap_or(Fr::from(0u64)),
            height: event.height,
            txid: event.txid,
        });
    }
    found
}

/// Decrypt `ct_out` with the outgoing viewing key and reconstruct the sent
/// notes. Whether the transfer was really ours is decided by the caller
/// (one of its nullifiers must belong to a wallet note).
pub fn scan_outgoing(
    ovk: &OutgoingViewingKey,
    const_salt: &Fr,
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
        out.push(SentNote {
            note: pt,
            pk_d: entry.pk_d,
            output_index: j as u64,
            pos: event.first_position + j as u64,
            h_aux: event.h_aux.get(j).copied().unwrap_or(Fr::from(0u64)),
            height: event.height,
            txid: event.txid,
        });
    }
    Some(out)
}
