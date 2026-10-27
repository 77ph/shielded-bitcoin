//! Development withdraw path (docs/BOUNDARY.md): a transfer to the operator's
//! shielded address plus a payout memo in a second OP_RETURN.
//!
//! Memo: `"sbx" ‖ 0x01 ‖ amount (u64 LE) ‖ scriptPubKey`.

use sb_core::event::{AcceptedEvent, txid_hex};

use crate::wallet::{NoteRecord, Wallet};

pub const MEMO_MAGIC: [u8; 3] = *b"sbx";
pub const MEMO_VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutRequest {
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
}

pub fn build_payout_memo(amount: u64, script_pubkey: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(12 + script_pubkey.len());
    m.extend_from_slice(&MEMO_MAGIC);
    m.push(MEMO_VERSION);
    m.extend_from_slice(&amount.to_le_bytes());
    m.extend_from_slice(script_pubkey);
    m
}

pub fn parse_payout_memo(memo: &[u8]) -> Option<PayoutRequest> {
    if memo.len() < 12 || memo[..3] != MEMO_MAGIC || memo[3] != MEMO_VERSION {
        return None;
    }
    let amount = u64::from_le_bytes(memo[4..12].try_into().unwrap());
    let script_pubkey = memo[12..].to_vec();
    if script_pubkey.is_empty() || script_pubkey.len() > 83 {
        return None;
    }
    Some(PayoutRequest {
        amount,
        script_pubkey,
    })
}

/// A payout the operator still has to make: the received note and the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingPayout {
    pub note: NoteRecord,
    pub request: PayoutRequest,
}

impl Wallet {
    /// Received notes whose creating transfer carried a valid payout request
    /// not exceeding the note value, and that have not been paid yet.
    pub fn pending_payouts(&self, events: &[AcceptedEvent]) -> Vec<PendingPayout> {
        let mut out = Vec::new();
        for n in &self.notes {
            if self.payouts.iter().any(|p| p.txid == n.txid) {
                continue;
            }
            let Some(ev) = events.iter().find(|e| txid_hex(&e.txid) == n.txid) else {
                continue;
            };
            let Some(memo) = ev.memo.as_deref() else {
                continue;
            };
            let Some(request) = parse_payout_memo(memo) else {
                continue;
            };
            if request.amount == 0 || request.amount > n.value {
                continue;
            }
            out.push(PendingPayout {
                note: n.clone(),
                request,
            });
        }
        out
    }

    /// Remember a payout so it is never made twice.
    pub fn record_payout(
        &mut self,
        note_txid: &str,
        request: &PayoutRequest,
        paid_txid: Option<String>,
    ) {
        self.payouts.push(crate::wallet::PayoutRecord {
            txid: note_txid.to_string(),
            amount: request.amount,
            script_hex: hex::encode(&request.script_pubkey),
            paid_txid,
        });
    }
}
