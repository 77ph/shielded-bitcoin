//! Wallet: scanning, recovery, note selection, anchor policy and transfer
//! construction (paper §10, §16, §C).

pub mod builder;
pub mod scan;

pub use builder::{BuildError, BuiltTransfer, Recipient, SpendableNote, build_transfer};
pub use scan::{ReceivedNote, SentNote, scan_incoming, scan_outgoing};
