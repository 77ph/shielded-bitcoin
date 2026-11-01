//! Variant A wallet: scanning, recovery, note selection, anchor policy and
//! transfer construction (paper §10, §16, §C) over `sba-core` and
//! `sba-circuit`; the design is the paper wallet's (`sb-wallet`) without
//! the swap and fee-vault records, which come in their own slices.

pub mod builder;
pub mod payout;
pub mod scan;
pub mod wallet;

pub use builder::{BuildError, BuiltTransfer, Recipient, SpendableNote, build_transfer};
pub use payout::{PayoutRequest, PendingPayout, build_payout_memo, parse_payout_memo};
pub use scan::{ReceivedNote, SentNote, scan_incoming, scan_outgoing};
pub use wallet::{K_WALLET, NoteRecord, PayoutRecord, SentRecord, Wallet, WalletError, anchor_for};
