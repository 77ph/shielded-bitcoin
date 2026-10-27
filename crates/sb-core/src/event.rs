//! An accepted transfer as recorded by replay (paper §15, "persists the
//! transfer event"). Shared by the indexer (producer) and wallets (consumers).

use crate::Fr;
use crate::envelope::TransferEnvelope;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedTransfer {
    /// Bitcoin block height of the carrier transaction.
    pub height: u32,
    /// Index of the carrier transaction inside its block.
    pub tx_index: u32,
    /// Carrier transaction id (internal byte order).
    pub txid: [u8; 32],
    pub envelope: TransferEnvelope,
    pub h_body: Fr,
    /// Tree position of output 0; output `j` is at `first_position + j`.
    pub first_position: u64,
    /// Replay-derived leaves, one per output.
    pub leaves: [Fr; crate::recovery::N_OUT],
}
