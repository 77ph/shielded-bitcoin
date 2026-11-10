// Included twice by `fixed.rs`, with `curve` and `ecc` bound per side.
//
// Fixed bases for the chip's configuration: the verifier never multiplies a
// fixed base (every base is a commitment or a constant point multiplied as a
// variable base), but the chip is generic over a set of them; the stand-in
// of `sba-circuit/src/fixed.rs`. The window tables are never computed
// (`LazyLock`, never forced).

use ecc::ecc::chip::{
    find_zs_and_us, BaseFieldElem, FixedPoint, FullScalar, ShortScalar, H, NUM_WINDOWS,
    NUM_WINDOWS_SHORT,
};
use ecc::ecc::FixedPoints;
use ff::PrimeField;
use group::{Curve, Group};
use std::sync::LazyLock;

type Base = curve::Base;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Bases;
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FullWidth;
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BaseField;
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Short;

static BASE: LazyLock<curve::Affine> = LazyLock::new(|| curve::Point::generator().to_affine());
static ZS_AND_US: LazyLock<Vec<(u64, [Base; H])>> =
    LazyLock::new(|| find_zs_and_us(*BASE, NUM_WINDOWS).unwrap());
static ZS_AND_US_SHORT: LazyLock<Vec<(u64, [Base; H])>> =
    LazyLock::new(|| find_zs_and_us(*BASE, NUM_WINDOWS_SHORT).unwrap());

fn us_of(v: &[(u64, [Base; H])]) -> Vec<[[u8; 32]; H]> {
    v.iter()
        .map(|(_, us)| core::array::from_fn(|i| us[i].to_repr()))
        .collect()
}

impl FixedPoint<curve::Affine> for FullWidth {
    type FixedScalarKind = FullScalar;
    fn generator(&self) -> curve::Affine {
        *BASE
    }
    fn u(&self) -> Vec<[[u8; 32]; H]> {
        us_of(&ZS_AND_US)
    }
    fn z(&self) -> Vec<u64> {
        ZS_AND_US.iter().map(|(z, _)| *z).collect()
    }
}
impl FixedPoint<curve::Affine> for BaseField {
    type FixedScalarKind = BaseFieldElem;
    fn generator(&self) -> curve::Affine {
        *BASE
    }
    fn u(&self) -> Vec<[[u8; 32]; H]> {
        us_of(&ZS_AND_US)
    }
    fn z(&self) -> Vec<u64> {
        ZS_AND_US.iter().map(|(z, _)| *z).collect()
    }
}
impl FixedPoint<curve::Affine> for Short {
    type FixedScalarKind = ShortScalar;
    fn generator(&self) -> curve::Affine {
        *BASE
    }
    fn u(&self) -> Vec<[[u8; 32]; H]> {
        us_of(&ZS_AND_US_SHORT)
    }
    fn z(&self) -> Vec<u64> {
        ZS_AND_US_SHORT.iter().map(|(z, _)| *z).collect()
    }
}
impl FixedPoints<curve::Affine> for Bases {
    type FullScalar = FullWidth;
    type ShortScalar = Short;
    type Base = BaseField;
}
