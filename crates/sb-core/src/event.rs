//! An accepted envelope as recorded by replay (paper §15, "persists the
//! transfer event"). Shared by the indexer (producer) and wallets (consumers).
//! Transfers and development mints (see `envelope::MintEnvelope`) both create
//! note leaves, so wallets scan them uniformly.

use crate::Fr;
use crate::JubjubAffine;
use crate::envelope::{MintEnvelope, TransferEnvelope};
use crate::note::NoteCiphertext;
use crate::recovery::CT_OUT_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    Transfer,
    Mint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedEvent {
    pub kind: EventKind,
    /// Bitcoin block height of the carrier transaction.
    pub height: u32,
    /// Index of the carrier transaction inside its block.
    pub tx_index: u32,
    /// Carrier transaction id (internal byte order).
    pub txid: [u8; 32],
    /// The published envelope bytes.
    pub raw: Vec<u8>,
    pub h_body: Fr,
    pub nullifiers: Vec<Fr>,
    /// `(pk_eph, ct_note)` per created output, in output order.
    pub outputs: Vec<(JubjubAffine, NoteCiphertext)>,
    pub ct_out: Option<[u8; CT_OUT_LEN]>,
    /// Tree position of output 0; output `j` is at `first_position + j`.
    pub first_position: u64,
    /// Replay-derived leaves, one per output.
    pub leaves: Vec<Fr>,
    /// Opaque memo published next to the envelope (not covered by the proof;
    /// deployment extensions only, see docs/BOUNDARY.md).
    pub memo: Option<Vec<u8>>,
}

impl AcceptedEvent {
    pub fn from_transfer(
        height: u32,
        tx_index: u32,
        txid: [u8; 32],
        env: &TransferEnvelope,
        h_body: Fr,
        first_position: u64,
        leaves: Vec<Fr>,
    ) -> Self {
        let b = &env.body;
        AcceptedEvent {
            kind: EventKind::Transfer,
            height,
            tx_index,
            txid,
            raw: env.to_bytes(),
            h_body,
            nullifiers: b.nullifiers.to_vec(),
            outputs: (0..b.pk_eph.len())
                .map(|j| (b.pk_eph[j], b.ct_note[j]))
                .collect(),
            ct_out: Some(b.ct_out),
            first_position,
            leaves,
            memo: None,
        }
    }

    /// `derived` is `(pk_eph, ct_note)` recomputed from the mint plaintext.
    #[allow(clippy::too_many_arguments)]
    pub fn from_mint(
        height: u32,
        tx_index: u32,
        txid: [u8; 32],
        env: &MintEnvelope,
        h_body: Fr,
        derived: (JubjubAffine, NoteCiphertext),
        first_position: u64,
        leaf: Fr,
    ) -> Self {
        AcceptedEvent {
            kind: EventKind::Mint,
            height,
            tx_index,
            txid,
            raw: env.to_bytes(),
            h_body,
            nullifiers: Vec::new(),
            outputs: vec![derived],
            ct_out: None,
            first_position,
            leaves: vec![leaf],
            memo: None,
        }
    }
}
