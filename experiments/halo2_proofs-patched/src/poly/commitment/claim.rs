use super::verifier::{compute_b, compute_s};
use super::{Coeff, Polynomial};
use crate::arithmetic::CurveAffine;
use ff::Field;
use std::marker::PhantomData;

/// The deferred claim an inner-product argument leaves behind: that the
/// point `g` equals `⟨s(u), params.g⟩`, where `s(X)` is the polynomial
/// `∏ (1 + u_{k−1−i} X^{2^i})` whose coefficients the challenges `u` fix.
///
/// Checking it directly costs a multi-scalar multiplication of `2^k`
/// terms; opening `g` as a commitment to `s(X)` inside a later proof's
/// multi-point argument (Halo's amortisation) folds it into that proof's
/// own claim instead. [`crate::plonk::create_proof_with_openings`] and
/// [`crate::plonk::verify_proof_with_openings`] do that.
#[derive(Debug, Clone)]
pub struct Claim<C: CurveAffine> {
    /// The claimed `⟨s(u), params.g⟩`.
    pub g: C,
    /// The challenges `u_0, …, u_{k−1}` of the argument that left the claim.
    pub u: Vec<C::Scalar>,
}

impl<C: CurveAffine> Claim<C> {
    /// `s(x)`, the value the commitment `g` must open to at `x`.
    pub fn b(&self, x: C::Scalar) -> C::Scalar {
        compute_b(x, &self.u)
    }

    /// `s(X)` as a polynomial of `n` coefficients (`n ≥ 2^k`), zero-padded.
    pub(crate) fn s_poly(&self, n: usize) -> Polynomial<C::Scalar, Coeff> {
        let mut values = compute_s(&self.u, C::Scalar::ONE);
        assert!(values.len() <= n, "claim larger than the parameters");
        values.resize(n, C::Scalar::ZERO);
        Polynomial {
            values,
            _marker: PhantomData,
        }
    }
}
