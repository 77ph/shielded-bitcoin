//! The field chip over either scalar field (`field_body.rs`, included once
//! per side): `fp` for the field side of Vesta-committed proofs (circuits
//! over `Fp`), `fq` for that of Pallas-committed proofs (over `Fq`).

/// Over `Fp`.
pub mod fp {
    use pasta_curves::vesta as curve;
    type F = curve::Scalar;
    include!("field_body.rs");
}

/// Over `Fq`.
pub mod fq {
    use pasta_curves::pallas as curve;
    type F = curve::Scalar;
    include!("field_body.rs");
}
