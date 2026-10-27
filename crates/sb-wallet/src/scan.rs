//! Note detection and sender-side recovery over accepted transfers
//! (paper §16.1, §16.2).

use sb_core::address::PaymentAddress;
use sb_core::event::AcceptedTransfer;
use sb_core::keys::{IncomingViewingKey, OutgoingViewingKey};
use sb_core::note::{
    NotePlaintext, check_note_consistency, decrypt_as_recipient, decrypt_as_sender, note_leaf,
};
use sb_core::recovery::{N_OUT, binding_digest, decrypt_recovery};
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
    pub height: u32,
    pub txid: [u8; 32],
}

/// Shared post-decryption checks: `pk_eph` consistency and leaf equality.
fn passes_checks(const_salt: &Fr, event: &AcceptedTransfer, j: usize, pt: &NotePlaintext) -> bool {
    let body = &event.envelope.body;
    check_note_consistency(pt, &body.pk_eph[j])
        && note_leaf(
            const_salt,
            &event.h_body,
            j as u64,
            &body.pk_eph[j],
            &body.ct_note[j],
        ) == event.leaves[j]
}

/// Try every output of an accepted transfer with the incoming viewing key.
pub fn scan_incoming(
    ivk: &IncomingViewingKey,
    const_salt: &Fr,
    event: &AcceptedTransfer,
) -> Vec<ReceivedNote> {
    let body = &event.envelope.body;
    let mut found = Vec::new();
    for j in 0..N_OUT {
        let Some(pt) = decrypt_as_recipient(&ivk.sk_view, &body.pk_eph[j], &body.ct_note[j]) else {
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
    event: &AcceptedTransfer,
) -> Option<Vec<SentNote>> {
    let body = &event.envelope.body;
    let digest = binding_digest(&body.pk_eph, &body.ct_note);
    let entries = decrypt_recovery(ovk, &digest, &body.ct_out)?;
    let mut out = Vec::with_capacity(N_OUT);
    for (j, entry) in entries.iter().enumerate() {
        let pt = decrypt_as_sender(
            &entry.sk_eph,
            &entry.pk_d,
            &body.pk_eph[j],
            &body.ct_note[j],
        )?;
        if !passes_checks(const_salt, event, j, &pt) {
            return None;
        }
        out.push(SentNote {
            note: pt,
            pk_d: entry.pk_d,
            output_index: j as u64,
            pos: event.first_position + j as u64,
            height: event.height,
            txid: event.txid,
        });
    }
    Some(out)
}
