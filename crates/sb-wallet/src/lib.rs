//! Wallet: scanning, recovery, note selection, anchor policy and transfer
//! construction (paper §10, §16, §C).

pub mod builder;
pub mod scan;
pub mod wallet;

pub use builder::{BuildError, BuiltTransfer, Recipient, SpendableNote, build_transfer};
pub use scan::{ReceivedNote, SentNote, scan_incoming, scan_outgoing};
pub use wallet::{K_WALLET, NoteRecord, SentRecord, Wallet, WalletError, anchor_for};
