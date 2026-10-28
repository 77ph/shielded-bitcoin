//! Native Poseidon permutation and the `PH` hash mode.

use ark_ff::Field;

use super::{FULL_ROUNDS, PARTIAL_ROUNDS, RATE, T, params};
use crate::Fr;

#[inline]
fn pow5(x: Fr) -> Fr {
    let x2 = x.square();
    x2.square() * x
}

#[inline]
fn add_round_constants(state: &mut [Fr; T], rc: &[Fr; T]) {
    for i in 0..T {
        state[i] += rc[i];
    }
}

#[inline]
fn mix(state: &mut [Fr; T], mds: &[[Fr; T]; T]) {
    let mut out = [Fr::from(0u64); T];
    for (i, row) in mds.iter().enumerate() {
        let mut acc = Fr::from(0u64);
        for j in 0..T {
            acc += row[j] * state[j];
        }
        out[i] = acc;
    }
    *state = out;
}

/// The Poseidon permutation. Round `r` is: add `round_constants[r]`, apply the
/// S-box (to every element in a full round, to `state[0]` in a partial round),
/// multiply by the MDS matrix.
pub fn permute(state: &mut [Fr; T]) {
    let p = params();
    let half = FULL_ROUNDS / 2;
    let mut r = 0;
    for _ in 0..half {
        add_round_constants(state, &p.round_constants[r]);
        for s in state.iter_mut() {
            *s = pow5(*s);
        }
        mix(state, &p.mds);
        r += 1;
    }
    for _ in 0..PARTIAL_ROUNDS {
        add_round_constants(state, &p.round_constants[r]);
        state[0] = pow5(state[0]);
        mix(state, &p.mds);
        r += 1;
    }
    for _ in 0..half {
        add_round_constants(state, &p.round_constants[r]);
        for s in state.iter_mut() {
            *s = pow5(*s);
        }
        mix(state, &p.mds);
        r += 1;
    }
    debug_assert_eq!(r, super::ROUNDS);
}

/// `PH(tag, x_1, …, x_n)` (profile §2.1):
///
/// ```text
/// elems = [tag, x_1, …, x_n], zero-padded to even length
/// state = [len(elems before padding), 0, 0]
/// for each pair (a, b): state[1] += a; state[2] += b; permute
/// return state[1]
/// ```
pub fn hash(tag: Fr, inputs: &[Fr]) -> Fr {
    let len = inputs.len() + 1;
    let mut state = [Fr::from(len as u64), Fr::from(0u64), Fr::from(0u64)];
    let mut elems = Vec::with_capacity(len + 1);
    elems.push(tag);
    elems.extend_from_slice(inputs);
    if elems.len() % RATE != 0 {
        elems.push(Fr::from(0u64));
    }
    for chunk in elems.chunks(RATE) {
        state[1] += chunk[0];
        state[2] += chunk[1];
        permute(&mut state);
    }
    state[1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::fr_to_bytes;
    use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
    use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
    use ark_ff::UniformRand;
    use ark_std::rand::{SeedableRng, rngs::StdRng};

    fn ark_config() -> PoseidonConfig<Fr> {
        let p = params();
        PoseidonConfig::new(
            FULL_ROUNDS,
            PARTIAL_ROUNDS,
            5,
            p.mds.iter().map(|r| r.to_vec()).collect(),
            p.round_constants.iter().map(|r| r.to_vec()).collect(),
            RATE,
            1,
        )
    }

    /// Our permutation must agree with the arkworks reference permutation on
    /// the same constants (absorbing exactly `rate` elements into a fresh
    /// arkworks sponge and squeezing one element equals `permute([0, a, b])[1]`).
    #[test]
    fn permutation_matches_arkworks_reference() {
        let mut rng = StdRng::seed_from_u64(7);
        let cfg = ark_config();
        for _ in 0..20 {
            let a = Fr::rand(&mut rng);
            let b = Fr::rand(&mut rng);
            let mut sponge = PoseidonSponge::new(&cfg);
            sponge.absorb(&vec![a, b]);
            let out = sponge.squeeze_native_field_elements(1)[0];
            let mut st = [Fr::from(0u64), a, b];
            permute(&mut st);
            assert_eq!(st[1], out);
        }
    }

    #[test]
    fn hash_is_deterministic_and_length_separated() {
        let tag = Fr::from(1u64);
        let a = hash(tag, &[Fr::from(2u64)]);
        let b = hash(tag, &[Fr::from(2u64), Fr::from(0u64)]);
        assert_ne!(a, b, "explicit trailing zero must differ from padding");
        assert_eq!(a, hash(tag, &[Fr::from(2u64)]));
        assert_ne!(hash(tag, &[]), hash(Fr::from(2u64), &[]));
    }

    /// Known-answer vector pinned for cross-implementation checks.
    #[test]
    fn known_answer() {
        let out = hash(Fr::from(0u64), &[Fr::from(0u64), Fr::from(0u64)]);
        let hex = hex::encode(fr_to_bytes(&out));
        // If this changes, the profile changes. Update docs/TEST_VECTORS.md.
        assert_eq!(
            hex,
            "31ed53daa052afbd43b579abf13437315b400726ef191d551d55d95cc6ffc005"
        );
    }
}
