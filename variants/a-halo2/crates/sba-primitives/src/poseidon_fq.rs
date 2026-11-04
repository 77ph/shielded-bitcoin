//! The Poseidon permutation over `Fq` (Vesta's base field, where the
//! coordinates of the proof's commitments live), for the proof transcript
//! of `PROFILE-A.md` §1.1: the `P128Pow5T3` instance of the gadget crate for
//! `Fq` (width 3, `x^5`, 8 full and 56 partial rounds), re-implemented here
//! as the plain permutation so that a transcript can drive it as a duplex
//! sponge; the test checks it against the gadget crate's own sponge.

use std::sync::LazyLock;

use ff::Field;
use halo2_gadgets::poseidon::primitives::{P128Pow5T3, Spec};
pub use pasta_curves::vesta::Base as Fq;

pub const T: usize = 3;
pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 56;

struct Constants {
    round_constants: Vec<[Fq; T]>,
    mds: [[Fq; T]; T],
}

static CONSTANTS: LazyLock<Constants> = LazyLock::new(|| {
    let (round_constants, mds, _) = <P128Pow5T3 as Spec<Fq, 3, 2>>::constants();
    Constants {
        round_constants,
        mds,
    }
});

fn sbox(x: Fq) -> Fq {
    let x2 = x.square();
    x2.square() * x
}

fn mds(state: &mut [Fq; T]) {
    let m = &CONSTANTS.mds;
    let mut out = [Fq::ZERO; T];
    for i in 0..T {
        for j in 0..T {
            out[i] += m[i][j] * state[j];
        }
    }
    *state = out;
}

/// The permutation: `R_F/2` full rounds, `R_P` partial rounds (the S-box on
/// the first element only), `R_F/2` full rounds, each round adding its
/// constants first and ending with the MDS matrix, as the gadget crate.
pub fn permute(state: &mut [Fq; T]) {
    let c = &*CONSTANTS;
    let half = FULL_ROUNDS / 2;
    for (round, rc) in c.round_constants.iter().enumerate() {
        let full = round < half || round >= half + PARTIAL_ROUNDS;
        for (w, r) in state.iter_mut().zip(rc) {
            *w += r;
        }
        if full {
            for w in state.iter_mut() {
                *w = sbox(*w);
            }
        } else {
            state[0] = sbox(state[0]);
        }
        mds(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::PrimeField;
    use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash};

    #[test]
    fn permutation_is_the_gadget_crates() {
        // ConstantLength<2>: state [a, b, 2·2^64], one permutation, output state[0]
        let (a, b) = (Fq::from(7u64), Fq::from(11u64));
        let mut state = [a, b, Fq::from_u128(2u128 << 64)];
        permute(&mut state);
        let reference = Hash::<Fq, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([a, b]);
        assert_eq!(state[0], reference);
        assert_eq!(
            CONSTANTS.round_constants.len(),
            FULL_ROUNDS + PARTIAL_ROUNDS
        );
    }
}
