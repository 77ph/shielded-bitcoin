//! Fixed bases for the ECC chip's configuration. The relation never
//! multiplies a fixed base, but the chip is generic over a set of them; this
//! stand-in is built like `halo2_gadgets`' own test bases.

use ff::PrimeField;
use group::{Curve, Group};
use halo2_gadgets::ecc::FixedPoints;
use halo2_gadgets::ecc::chip::{
    BaseFieldElem, FixedPoint, FullScalar, H, NUM_WINDOWS, NUM_WINDOWS_SHORT, ShortScalar,
    find_zs_and_us,
};
use pasta_curves::pallas;
use std::sync::LazyLock;

type Fp = pallas::Base;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Bases;
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FullWidth;
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BaseField;
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Short;

static BASE: LazyLock<pallas::Affine> = LazyLock::new(|| pallas::Point::generator().to_affine());
static ZS_AND_US: LazyLock<Vec<(u64, [Fp; H])>> =
    LazyLock::new(|| find_zs_and_us(*BASE, NUM_WINDOWS).unwrap());
static ZS_AND_US_SHORT: LazyLock<Vec<(u64, [Fp; H])>> =
    LazyLock::new(|| find_zs_and_us(*BASE, NUM_WINDOWS_SHORT).unwrap());

fn us_of(v: &[(u64, [Fp; H])]) -> Vec<[[u8; 32]; H]> {
    v.iter()
        .map(|(_, us)| core::array::from_fn(|i| us[i].to_repr()))
        .collect()
}

impl FixedPoint<pallas::Affine> for FullWidth {
    type FixedScalarKind = FullScalar;
    fn generator(&self) -> pallas::Affine {
        *BASE
    }
    fn u(&self) -> Vec<[[u8; 32]; H]> {
        us_of(&ZS_AND_US)
    }
    fn z(&self) -> Vec<u64> {
        ZS_AND_US.iter().map(|(z, _)| *z).collect()
    }
}
impl FixedPoint<pallas::Affine> for BaseField {
    type FixedScalarKind = BaseFieldElem;
    fn generator(&self) -> pallas::Affine {
        *BASE
    }
    fn u(&self) -> Vec<[[u8; 32]; H]> {
        us_of(&ZS_AND_US)
    }
    fn z(&self) -> Vec<u64> {
        ZS_AND_US.iter().map(|(z, _)| *z).collect()
    }
}
impl FixedPoint<pallas::Affine> for Short {
    type FixedScalarKind = ShortScalar;
    fn generator(&self) -> pallas::Affine {
        *BASE
    }
    fn u(&self) -> Vec<[[u8; 32]; H]> {
        us_of(&ZS_AND_US_SHORT)
    }
    fn z(&self) -> Vec<u64> {
        ZS_AND_US_SHORT.iter().map(|(z, _)| *z).collect()
    }
}
impl FixedPoints<pallas::Affine> for Bases {
    type FullScalar = FullWidth;
    type ShortScalar = Short;
    type Base = BaseField;
}
