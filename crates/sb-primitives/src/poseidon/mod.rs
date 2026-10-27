//! Poseidon over the BLS12-381 scalar field (profile §2.1).
//!
//! One permutation instance: width 3 (rate 2, capacity 1), S-box `x^5`,
//! 8 full rounds, 57 partial rounds, constants pinned in `params_hex.rs`.
//!
//! The hash mode `PH(tag, x_1..x_n)` is defined in [`native::hash`] and
//! mirrored constraint-for-constraint in [`gadget::hash_var`].

pub mod gadget;
pub mod native;
mod params_hex;

use std::sync::LazyLock;

use ark_ff::PrimeField;

use crate::Fr;

/// State width.
pub const T: usize = 3;
/// Rate (elements absorbed per permutation).
pub const RATE: usize = 2;
/// Number of full rounds (half before, half after the partial rounds).
pub const FULL_ROUNDS: usize = 8;
/// Number of partial rounds (S-box on `state[0]` only).
pub const PARTIAL_ROUNDS: usize = 57;
/// Total rounds.
pub const ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;

/// Parsed round constants and MDS matrix.
pub struct Params {
    pub round_constants: [[Fr; T]; ROUNDS],
    pub mds: [[Fr; T]; T],
}

fn parse(h: &str) -> Fr {
    let bytes = hex::decode(h).expect("pinned constant is valid hex");
    let f = Fr::from_le_bytes_mod_order(&bytes);
    debug_assert_eq!(
        crate::encoding::fr_to_bytes(&f)[..],
        bytes[..],
        "pinned constant is canonical"
    );
    f
}

static PARAMS: LazyLock<Params> = LazyLock::new(|| {
    let mut round_constants = [[Fr::from(0u64); T]; ROUNDS];
    for (r, row) in params_hex::ROUND_CONSTANTS_HEX.iter().enumerate() {
        for (i, h) in row.iter().enumerate() {
            round_constants[r][i] = parse(h);
        }
    }
    let mut mds = [[Fr::from(0u64); T]; T];
    for (r, row) in params_hex::MDS_HEX.iter().enumerate() {
        for (i, h) in row.iter().enumerate() {
            mds[r][i] = parse(h);
        }
    }
    Params {
        round_constants,
        mds,
    }
});

/// The pinned parameters.
pub fn params() -> &'static Params {
    &PARAMS
}

pub use native::{hash, permute};
