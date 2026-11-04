//! Fixed bases for the two chips' configurations (`fixed_body.rs`, included
//! once per side): `q` for the Vesta chip of a circuit over `Fq`, `p` for
//! `halo2_gadgets`' Pallas chip of a circuit over `Fp`.

/// The Vesta chip's.
pub mod q {
    use pasta_curves::vesta as curve;
    use vesta_ecc as ecc;
    include!("fixed_body.rs");
}

/// The Pallas chip's.
pub mod p {
    use halo2_gadgets as ecc;
    use pasta_curves::pallas as curve;
    include!("fixed_body.rs");
}
