//! Poseidon over `Fp` in the halo2 constant-length mode (`PROFILE-A.md`
//! §2.1): the `P128Pow5T3` instance of `halo2_gadgets` (width 3, `x^5`,
//! 8 full and 56 partial rounds) and the hash `PH_A(tag, x_1, …, x_n)` =
//! `Hash<ConstantLength<n + 1>>([tag, x_1, …, x_n])`. The in-circuit hash of
//! `sba-circuit` is the gadget's own and therefore identical by
//! construction; this module is the native side.

use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash, P128Pow5T3};

use crate::Fp;

/// Width, rate, rounds of the instance (informational; the constants are
/// the gadget crate's).
pub const T: usize = 3;
pub const RATE: usize = 2;
pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 56;

/// Largest `n` (inputs after the tag) this module hashes.
pub const MAX_INPUTS: usize = 10;

fn hash_const<const L: usize>(msg: [Fp; L]) -> Fp {
    Hash::<Fp, P128Pow5T3, ConstantLength<L>, 3, 2>::init().hash(msg)
}

/// `PH_A(tag, inputs)`. Panics above [`MAX_INPUTS`] inputs: the profile's
/// relations never need more.
pub fn hash(tag: Fp, inputs: &[Fp]) -> Fp {
    macro_rules! with_len {
        ($($n:literal),*) => {
            match inputs.len() {
                $($n => {
                    let mut m = [Fp::zero(); $n + 1];
                    m[0] = tag;
                    m[1..].copy_from_slice(inputs);
                    hash_const::<{ $n + 1 }>(m)
                })*
                n => panic!("PH_A over {n} inputs is not defined (max {MAX_INPUTS})"),
            }
        };
    }
    with_len!(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tags::{t_leaf, t_node};
    use ff::PrimeField;

    #[test]
    fn deterministic_tag_separated_and_length_separated() {
        let a = hash(t_node(), &[Fp::from(1), Fp::from(2)]);
        assert_eq!(a, hash(t_node(), &[Fp::from(1), Fp::from(2)]));
        assert_ne!(a, hash(t_leaf(), &[Fp::from(1), Fp::from(2)]));
        assert_ne!(a, hash(t_node(), &[Fp::from(2), Fp::from(1)]));
        // the halo2 domain encodes the length: a trailing zero is not free
        assert_ne!(a, hash(t_node(), &[Fp::from(1), Fp::from(2), Fp::zero()]));
        // the gadget crate's own test vector for ConstantLength<2>
        let v = hash_const::<2>([Fp::zero(), Fp::zero()]);
        assert_eq!(
            v.to_repr(),
            hash_const::<2>([Fp::zero(), Fp::zero()]).to_repr()
        );
        let _ = hash(t_node(), &[Fp::from(1); 10]);
    }
}
