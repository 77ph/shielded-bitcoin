//! Keys, addresses, notes, encryption, leaves, nullifiers, envelope codec and
//! the note tree (paper §5, §6, §9, §12, §13, §A.3, §A.5).

pub mod address;
pub mod envelope;
pub mod event;
pub mod feeauth;
pub mod imt;
pub mod keys;
pub mod lock;
pub mod note;
pub mod recovery;
pub mod tree;

pub use sb_primitives::{Fr, Jubjub, JubjubAffine, JubjubScalar};

/// Version of docs/PROFILE.md this code implements. A deployment profile
/// names the version it was written for and is refused on mismatch
/// (PROFILE.md §13).
pub const PROFILE_VERSION: &str = "0.2";
