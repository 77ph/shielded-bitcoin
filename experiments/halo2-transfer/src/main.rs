//! docs/VARIANT-A.md S1: this profile's transfer relation (PROFILE.md §8)
//! expressed in Halo 2 (PLONKish, IPA over Pasta) with `halo2_gadgets`,
//! structurally faithful to the R1CS circuit of `crates/sb-circuit`:
//! 2 inputs and 2 outputs, Poseidon (width 3, x^5, 8 + 56 rounds) for
//! every hash with the tag as first element, the position-bound
//! nullifier, DiversifyHash with a witnessed even coordinate and the
//! curve check, the diversified-address check `pk_d = [sk_view] G_d`,
//! the recipient channel (`pk_eph = [sk_eph] G_d`, `ss = [sk_eph] pk_d`,
//! Poseidon KDF, stream and MAC) proven in circuit for every input and
//! output, the leaf, a depth-32 Poseidon Merkle path skipped for a
//! zero-value dummy, 64- and 88-bit range checks, value conservation,
//! and the 17 public inputs in the profile's order. Differences forced by
//! the curve: Pallas has prime order, so the cofactor clearings of
//! Jubjub ([8]·) disappear; the even-coordinate rule applies to `y`
//! (short Weierstrass) instead of `x` (twisted Edwards).
//!
//! Prints the smallest `k`, the proof size, key generation, proving and
//! verification times. Synthetic witnesses; the native twins of every
//! derivation are computed here so that the circuit is satisfiable.

use ff::{Field, PrimeField};
use group::{Curve, Group};
use halo2_gadgets::{
    ecc::{
        chip::{CircuitVersion, EccChip, EccConfig},
        NonIdentityPoint, ScalarVar,
    },
    poseidon::{primitives as poseidon, Hash as PoseidonHash, Pow5Chip, Pow5Config},
    utilities::lookup_range_check::{
        LookupRangeCheck, LookupRangeCheckConfig, PallasLookupRangeCheckConfig,
    },
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{
        self, Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Expression, Fixed,
        Instance, Selector, SingleVerifier, TableColumn,
    },
    poly::{commitment::Params, Rotation},
    transcript::{Blake2bRead, Blake2bWrite},
};
use halo2_gadgets::ecc::{
    chip::{
        find_zs_and_us, BaseFieldElem, FixedPoint as FixedPointTrait, FullScalar, ShortScalar, H,
        NUM_WINDOWS, NUM_WINDOWS_SHORT,
    },
    FixedPoints,
};
use std::sync::LazyLock;
use pasta_curves::{arithmetic::CurveAffine, pallas, vesta};
use rand::rngs::OsRng;
use std::time::Instant;

type Fp = pallas::Base;
type Cell = AssignedCell<Fp, Fp>;

const DEPTH: usize = 32;
const N_IN: usize = 2;
const N_OUT: usize = 2;

// tags (the profile's are 32-byte strings embedded in the field; any
// distinct constants give the same circuit)
const T_SKNF: u64 = 1;
const T_VKIN: u64 = 2;
const T_VIEW: u64 = 3;
const T_RHO: u64 = 4;
const T_EPH: u64 = 5;
const T_DIV: u64 = 6;
const T_KDF: u64 = 7;
const T_STREAM: u64 = 8;
const T_MAC: u64 = 9;
const T_LEAF: u64 = 10;
const T_NODE: u64 = 11;
const T_NF: u64 = 12;

// ------------------------------------------------------------ fixed bases
//
// The ECC chip's configuration is generic over a set of fixed bases for
// fixed-base multiplication, which this relation never uses; a stand-in
// built like `halo2_gadgets`' own test bases satisfies the trait bounds.

#[derive(Debug, Clone, Eq, PartialEq)]
struct OrchardFixedBases;
#[derive(Debug, Clone, Eq, PartialEq)]
struct FullWidth;
#[derive(Debug, Clone, Eq, PartialEq)]
struct BaseField;
#[derive(Debug, Clone, Eq, PartialEq)]
struct Short;

static BASE: LazyLock<pallas::Affine> = LazyLock::new(|| pallas::Point::generator().to_affine());
static ZS_AND_US: LazyLock<Vec<(u64, [Fp; H])>> =
    LazyLock::new(|| find_zs_and_us(*BASE, NUM_WINDOWS).unwrap());
static ZS_AND_US_SHORT: LazyLock<Vec<(u64, [Fp; H])>> =
    LazyLock::new(|| find_zs_and_us(*BASE, NUM_WINDOWS_SHORT).unwrap());

fn us_of(v: &[(u64, [Fp; H])]) -> Vec<[[u8; 32]; H]> {
    v.iter().map(|(_, us)| core::array::from_fn(|i| us[i].to_repr())).collect()
}

impl FixedPointTrait<pallas::Affine> for FullWidth {
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
impl FixedPointTrait<pallas::Affine> for BaseField {
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
impl FixedPointTrait<pallas::Affine> for Short {
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
impl FixedPoints<pallas::Affine> for OrchardFixedBases {
    type FullScalar = FullWidth;
    type ShortScalar = Short;
    type Base = BaseField;
}

// ------------------------------------------------------------ native twins

fn ph<const L: usize>(msg: [Fp; L]) -> Fp {
    poseidon::Hash::<Fp, poseidon::P128Pow5T3, poseidon::ConstantLength<L>, 3, 2>::init()
        .hash(msg)
}

fn tag(t: u64) -> Fp {
    Fp::from(t)
}

/// Base-field element used as a scalar (the profile's `sk_view`, `sk_eph`
/// are hash outputs; Pallas's base field is smaller than its scalar field).
fn as_scalar(x: &Fp) -> pallas::Scalar {
    pallas::Scalar::from_repr(x.to_repr()).unwrap()
}

/// `DiversifyHash(d)` on Pallas: `x = PH(T_DIV, d)`, `y` the even square
/// root of `x³ + 5`; `None` for the diversifiers whose `x` is not on the curve.
fn diversify_hash(d: Fp) -> Option<pallas::Affine> {
    let x = ph([tag(T_DIV), d]);
    let y2 = x * x * x + Fp::from(5);
    let y = Option::<Fp>::from(y2.sqrt())?;
    let y = if y.is_odd().into() { -y } else { y };
    Option::from(pallas::Affine::from_xy(x, y))
}

struct Note {
    v: u64,
    d: Fp, // 88-bit
    rseed: Fp,
}

struct Channel {
    pk_eph: pallas::Affine,
    ct: [Fp; 3],
}

fn channel(note: &Note, g_d: pallas::Affine, pk_d: pallas::Affine) -> Channel {
    let sk_eph = ph([tag(T_EPH), note.rseed]);
    let s = as_scalar(&sk_eph);
    let pk_eph = (g_d * s).to_affine();
    let ss = (pk_d * s).to_affine();
    let (ssx, ssy) = coords(&ss);
    let (ex, ey) = coords(&pk_eph);
    let k = ph([tag(T_KDF), ssx, ssy, ex, ey]);
    let m0 = Fp::from(note.v) + note.d * Fp::from_u128(1u128 << 64);
    let c0 = m0 + ph([tag(T_STREAM), k, Fp::ZERO]);
    let c1 = note.rseed + ph([tag(T_STREAM), k, Fp::ONE]);
    let t = ph([tag(T_MAC), k, c0, c1]);
    Channel {
        pk_eph,
        ct: [c0, c1, t],
    }
}

fn coords(p: &pallas::Affine) -> (Fp, Fp) {
    let c = p.coordinates().unwrap();
    (*c.x(), *c.y())
}

fn leaf(salt: Fp, h_body: Fp, j: Fp, ch: &Channel) -> Fp {
    let (ex, ey) = coords(&ch.pk_eph);
    ph([
        tag(T_LEAF),
        salt,
        h_body,
        j,
        ex,
        ey,
        ch.ct[0],
        ch.ct[1],
        ch.ct[2],
        Fp::ZERO,
    ])
}

fn merkle_root(leaf: Fp, pos: u32, siblings: &[Fp; DEPTH]) -> Fp {
    let mut cur = leaf;
    for (i, s) in siblings.iter().enumerate() {
        let bit = (pos >> i) & 1 == 1;
        let (l, r) = if bit { (*s, cur) } else { (cur, *s) };
        cur = ph([tag(T_NODE), l, r]);
    }
    cur
}

// ------------------------------------------------------------ witness

#[derive(Clone)]
struct InputW {
    note: Note,
    pk_d: pallas::Affine,
    h_body_create: Fp,
    j: Fp,
    pos: u32,
    siblings: [Fp; DEPTH],
    g_y: Fp, // even y of DiversifyHash(d)
}

#[derive(Clone)]
struct OutputW {
    note: Note,
    pk_d: pallas::Affine,
    g_y: Fp,
}

impl Clone for Note {
    fn clone(&self) -> Self {
        Note {
            v: self.v,
            d: self.d,
            rseed: self.rseed,
        }
    }
}

#[derive(Clone)]
struct Witness {
    sk_spend: Fp,
    inputs: [InputW; N_IN],
    outputs: [OutputW; N_OUT],
}

/// The 17 public inputs in the profile's order.
struct Statement {
    const_salt: Fp,
    r_anchor: Fp,
    nullifiers: [Fp; N_IN],
    pk_eph: [pallas::Affine; N_OUT],
    ct: [[Fp; 3]; N_OUT],
    h_body: Fp,
}

impl Statement {
    fn to_vec(&self) -> Vec<Fp> {
        let mut v = vec![
            self.const_salt,
            self.r_anchor,
            Fp::from(N_IN as u64),
            Fp::from(N_OUT as u64),
        ];
        v.extend(self.nullifiers);
        for p in &self.pk_eph {
            let (x, y) = coords(p);
            v.push(x);
            v.push(y);
        }
        for c in &self.ct {
            v.extend(c);
        }
        v.push(self.h_body);
        assert_eq!(v.len(), 17);
        v
    }
}

/// A random, satisfiable transfer: one real input (value 1000) and one
/// dummy, two outputs (700 + 300), the real input's leaf at a random
/// position of a random path.
fn sample() -> (Witness, Statement) {
    let mut rng = OsRng;
    let sk_spend = Fp::random(&mut rng);
    let sk_nf = ph([tag(T_SKNF), sk_spend]);
    let vk_in = ph([tag(T_VKIN), sk_spend]);
    let sk_view = ph([tag(T_VIEW), vk_in]);
    let const_salt = Fp::random(&mut rng);
    let h_body = Fp::random(&mut rng);

    let fresh_d = |rng: &mut OsRng| loop {
        let d = Fp::from_u128(u128::from(rand::Rng::gen::<u64>(rng)) | (1u128 << 80));
        if let Some(g) = diversify_hash(d) {
            return (d, g);
        }
    };

    // inputs
    let mut inputs = Vec::new();
    let mut nullifiers = Vec::new();
    let mut r_anchor = Fp::ZERO;
    for i in 0..N_IN {
        let (d, g_d) = fresh_d(&mut rng);
        let note = Note {
            v: if i == 0 { 1000 } else { 0 },
            d,
            rseed: Fp::random(&mut rng),
        };
        let pk_d = (g_d * as_scalar(&sk_view)).to_affine();
        let ch = channel(&note, g_d, pk_d);
        let h_body_create = Fp::random(&mut rng);
        let j = Fp::from(1u64);
        let pos = if i == 0 { 123_457 } else { 0 };
        let siblings: [Fp; DEPTH] = core::array::from_fn(|_| Fp::random(&mut rng));
        let lf = leaf(const_salt, h_body_create, j, &ch);
        if i == 0 {
            r_anchor = merkle_root(lf, pos, &siblings);
        }
        let rho = ph([tag(T_RHO), note.rseed]);
        nullifiers.push(ph([tag(T_NF), sk_nf, rho, Fp::from(pos as u64)]));
        inputs.push(InputW {
            note,
            pk_d,
            h_body_create,
            j,
            pos,
            siblings,
            g_y: coords(&g_d).1,
        });
    }
    // outputs
    let mut outputs = Vec::new();
    let mut pk_ephs = Vec::new();
    let mut cts = Vec::new();
    for jx in 0..N_OUT {
        let (d, g_d) = fresh_d(&mut rng);
        let note = Note {
            v: if jx == 0 { 700 } else { 300 },
            d,
            rseed: Fp::random(&mut rng),
        };
        let pk_d = (pallas::Point::random(&mut rng)).to_affine();
        let ch = channel(&note, g_d, pk_d);
        pk_ephs.push(ch.pk_eph);
        cts.push(ch.ct);
        outputs.push(OutputW {
            note,
            pk_d,
            g_y: coords(&g_d).1,
        });
    }
    let w = Witness {
        sk_spend,
        inputs: inputs.try_into().ok().unwrap(),
        outputs: outputs.try_into().ok().unwrap(),
    };
    let st = Statement {
        const_salt,
        r_anchor,
        nullifiers: nullifiers.try_into().unwrap(),
        pk_eph: pk_ephs.try_into().unwrap(),
        ct: cts.try_into().unwrap(),
        h_body,
    };
    (w, st)
}

// ------------------------------------------------------------ circuit

#[derive(Clone, Debug)]
struct Config {
    advices: [Column<Advice>; 10],
    primary: Column<Instance>,
    fx: Column<Fixed>,
    q_lin: Selector,
    q_bits: Selector,
    q_swap: Selector,
    q_mul0: Selector,
    q_par: Selector,
    q_sum: Selector,
    ecc: EccConfig<OrchardFixedBases, PallasLookupRangeCheckConfig>,
    poseidon: Pow5Config<Fp, 3, 2>,
    range: PallasLookupRangeCheckConfig,
    table_idx: TableColumn,
}

#[derive(Clone, Default)]
struct TransferCircuit {
    w: Option<Witness>,
    st: Option<Vec<Fp>>,
}

struct Ctx<'a> {
    cfg: &'a Config,
    ecc: EccChip<OrchardFixedBases, PallasLookupRangeCheckConfig>,
}

impl<'a> Ctx<'a> {
    fn witness(&self, l: &mut impl Layouter<Fp>, v: Value<Fp>) -> Result<Cell, Error> {
        l.assign_region(
            || "w",
            |mut r| r.assign_advice(|| "w", self.cfg.advices[0], 0, || v),
        )
    }
    fn constant(&self, l: &mut impl Layouter<Fp>, c: Fp) -> Result<Cell, Error> {
        l.assign_region(
            || "c",
            |mut r| r.assign_advice_from_constant(|| "c", self.cfg.advices[0], 0, c),
        )
    }
    fn hash<const L: usize>(&self, l: &mut impl Layouter<Fp>, msg: [Cell; L]) -> Result<Cell, Error> {
        let chip = Pow5Chip::construct(self.cfg.poseidon.clone());
        PoseidonHash::<Fp, _, poseidon::P128Pow5T3, poseidon::ConstantLength<L>, 3, 2>::init(
            chip,
            l.namespace(|| "ph"),
        )?
        .hash(l.namespace(|| "ph"), msg)
    }
    /// `out = a + k·b + c`
    fn lin(&self, l: &mut impl Layouter<Fp>, a: &Cell, k: Fp, b: &Cell, c: &Cell) -> Result<Cell, Error> {
        let cfg = self.cfg;
        l.assign_region(
            || "lin",
            |mut r| {
                cfg.q_lin.enable(&mut r, 0)?;
                a.copy_advice(|| "a", &mut r, cfg.advices[0], 0)?;
                b.copy_advice(|| "b", &mut r, cfg.advices[1], 0)?;
                c.copy_advice(|| "c", &mut r, cfg.advices[2], 0)?;
                r.assign_fixed(|| "k", cfg.fx, 0, || Value::known(k))?;
                let out = a.value().copied() + b.value().map(|b| k * b) + c.value().copied();
                r.assign_advice(|| "out", cfg.advices[3], 0, || out)
            },
        )
    }
    /// Range check of a copied cell: `words` 10-bit words plus `short` bits.
    fn range(&self, l: &mut impl Layouter<Fp>, x: &Cell, words: usize, short: usize) -> Result<(), Error> {
        let zs = self.cfg.range.copy_check(l.namespace(|| "rc"), x.clone(), words, short == 0)?;
        if short > 0 {
            self.cfg
                .range
                .copy_short_check(l.namespace(|| "rc short"), zs[words].clone(), short)?;
        }
        Ok(())
    }
    /// 32 bits of `pos` (LSB first), constrained to recompose to it.
    fn bits32(&self, l: &mut impl Layouter<Fp>, pos: &Cell) -> Result<Vec<Cell>, Error> {
        let cfg = self.cfg;
        l.assign_region(
            || "bits",
            |mut r| {
                let val = pos.value().map(|p| {
                    let b = p.to_repr();
                    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
                });
                let mut acc = r.assign_advice_from_constant(|| "acc0", cfg.advices[1], 0, Fp::ZERO)?;
                let mut bits = vec![None; 32];
                for i in 0..32 {
                    cfg.q_bits.enable(&mut r, i)?;
                    let idx = 31 - i; // MSB first
                    let bit = val.map(|p| Fp::from(((p >> idx) & 1) as u64));
                    let b = r.assign_advice(|| "bit", cfg.advices[0], i, || bit)?;
                    let next = acc.value().copied() * Value::known(Fp::from(2)) + b.value().copied();
                    acc = r.assign_advice(|| "acc", cfg.advices[1], i + 1, || next)?;
                    bits[idx] = Some(b);
                }
                r.constrain_equal(acc.cell(), pos.cell())?;
                Ok(bits.into_iter().map(|b| b.unwrap()).collect())
            },
        )
    }
    /// `(l, r) = bit ? (sib, cur) : (cur, sib)`
    fn swap(&self, l: &mut impl Layouter<Fp>, cur: &Cell, sib: &Cell, bit: &Cell) -> Result<(Cell, Cell), Error> {
        let cfg = self.cfg;
        l.assign_region(
            || "swap",
            |mut r| {
                cfg.q_swap.enable(&mut r, 0)?;
                cur.copy_advice(|| "cur", &mut r, cfg.advices[0], 0)?;
                sib.copy_advice(|| "sib", &mut r, cfg.advices[1], 0)?;
                bit.copy_advice(|| "bit", &mut r, cfg.advices[2], 0)?;
                let sw = bit.value().map(|b| *b == Fp::ONE);
                let lv = cur.value().zip(sib.value()).zip(sw).map(|((c, s), b)| if b { *s } else { *c });
                let rv = cur.value().zip(sib.value()).zip(sw).map(|((c, s), b)| if b { *c } else { *s });
                let lo = r.assign_advice(|| "l", cfg.advices[3], 0, || lv)?;
                let ro = r.assign_advice(|| "r", cfg.advices[4], 0, || rv)?;
                Ok((lo, ro))
            },
        )
    }
    /// `G_d = DiversifyHash(d)`: `x = PH(T_DIV, d)`, witnessed `y` with
    /// `y = 2h`, `h < 2^254`, and the point witnessed on the curve.
    fn diversify(&self, l: &mut impl Layouter<Fp>, d: &Cell, y: Value<Fp>) -> Result<NonIdentityPoint<pallas::Affine, EccChip<OrchardFixedBases, PallasLookupRangeCheckConfig>>, Error> {
        let t = self.constant(l, tag(T_DIV))?;
        let x = self.hash(l, [t, d.clone()])?;
        let p = x.value().zip(y).map(|(x, y)| pallas::Affine::from_xy(*x, y).unwrap());
        let point = NonIdentityPoint::new(self.ecc.clone(), l.namespace(|| "G_d"), p)?;
        let cfg = self.cfg;
        let h = l.assign_region(
            || "parity",
            |mut r| {
                cfg.q_par.enable(&mut r, 0)?;
                let yc = point.inner().y();
                yc.copy_advice(|| "y", &mut r, cfg.advices[0], 0)?;
                let h = yc.value().map(|y| {
                    let mut b = y.to_repr();
                    // y / 2 as an integer: y is even by construction
                    let mut carry = 0u16;
                    for i in (0..32).rev() {
                        let cur = (carry << 8) | b[i] as u16;
                        b[i] = (cur >> 1) as u8;
                        carry = cur & 1;
                    }
                    Fp::from_repr(b).unwrap()
                });
                r.assign_advice(|| "h", cfg.advices[1], 0, || h)
            },
        )?;
        l.assign_region(
            || "x = hash",
            |mut r| r.constrain_equal(point.inner().x().cell(), x.cell()),
        )?;
        self.range(l, &h, 25, 4)?;
        Ok(point)
    }
    fn scalar(&self, l: &mut impl Layouter<Fp>, s: &Cell) -> Result<ScalarVar<pallas::Affine, EccChip<OrchardFixedBases, PallasLookupRangeCheckConfig>>, Error> {
        ScalarVar::from_base(self.ecc.clone(), l.namespace(|| "scalar"), s)
    }
    /// The recipient channel: `pk_eph = [sk_eph] G_d`, `ss = [sk_eph] pk_d`, `ct`.
    fn channel(
        &self,
        l: &mut impl Layouter<Fp>,
        rseed: &Cell,
        m0: &Cell,
        g_d: &NonIdentityPoint<pallas::Affine, EccChip<OrchardFixedBases, PallasLookupRangeCheckConfig>>,
        pk_d: &NonIdentityPoint<pallas::Affine, EccChip<OrchardFixedBases, PallasLookupRangeCheckConfig>>,
    ) -> Result<([Cell; 2], [Cell; 3]), Error> {
        let t = self.constant(l, tag(T_EPH))?;
        let sk_eph = self.hash(l, [t, rseed.clone()])?;
        let s1 = self.scalar(l, &sk_eph)?;
        let (pk_eph, _) = g_d.mul(l.namespace(|| "pk_eph"), s1)?;
        let s2 = self.scalar(l, &sk_eph)?;
        let (ss, _) = pk_d.mul(l.namespace(|| "ss"), s2)?;
        let t = self.constant(l, tag(T_KDF))?;
        let k = self.hash(l, [t, ss.inner().x(), ss.inner().y(), pk_eph.inner().x(), pk_eph.inner().y()])?;
        let zero = self.constant(l, Fp::ZERO)?;
        let one = self.constant(l, Fp::ONE)?;
        let t = self.constant(l, tag(T_STREAM))?;
        let s0 = self.hash(l, [t.clone(), k.clone(), zero.clone()])?;
        let s1 = self.hash(l, [t, k.clone(), one])?;
        let c0 = self.lin(l, m0, Fp::ONE, &s0, &zero)?;
        let c1 = self.lin(l, rseed, Fp::ONE, &s1, &zero)?;
        let t = self.constant(l, tag(T_MAC))?;
        let mac = self.hash(l, [t, k, c0.clone(), c1.clone()])?;
        Ok(([pk_eph.inner().x(), pk_eph.inner().y()], [c0, c1, mac]))
    }
}

impl Circuit<Fp> for TransferCircuit {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        TransferCircuit::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let advices: [Column<Advice>; 10] = core::array::from_fn(|_| meta.advice_column());
        for a in &advices {
            meta.enable_equality(*a);
        }
        let primary = meta.instance_column();
        meta.enable_equality(primary);
        let lagrange_coeffs: [Column<Fixed>; 8] = core::array::from_fn(|_| meta.fixed_column());
        meta.enable_constant(lagrange_coeffs[0]);
        let fx = meta.fixed_column();
        let table_idx = meta.lookup_table_column();
        let range = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);
        let ecc = EccChip::<OrchardFixedBases>::configure(meta, advices, lagrange_coeffs, range);
        let rc_a = lagrange_coeffs[2..5].try_into().unwrap();
        let rc_b = lagrange_coeffs[5..8].try_into().unwrap();
        let poseidon = Pow5Chip::configure::<poseidon::P128Pow5T3>(
            meta,
            advices[6..9].try_into().unwrap(),
            advices[5],
            rc_a,
            rc_b,
        );

        let q_lin = meta.selector();
        meta.create_gate("lin", |m| {
            let q = m.query_selector(q_lin);
            let a = m.query_advice(advices[0], Rotation::cur());
            let b = m.query_advice(advices[1], Rotation::cur());
            let c = m.query_advice(advices[2], Rotation::cur());
            let out = m.query_advice(advices[3], Rotation::cur());
            let k = m.query_fixed(fx);
            Constraints::with_selector(q, [("out = a + k b + c", a + k * b + c - out)])
        });
        let q_bits = meta.selector();
        meta.create_gate("bits", |m| {
            let q = m.query_selector(q_bits);
            let b = m.query_advice(advices[0], Rotation::cur());
            let acc = m.query_advice(advices[1], Rotation::cur());
            let next = m.query_advice(advices[1], Rotation::next());
            let one = Expression::Constant(Fp::ONE);
            Constraints::with_selector(
                q,
                [
                    ("bit", b.clone() * (b.clone() - one)),
                    ("acc", next - acc * Expression::Constant(Fp::from(2)) - b),
                ],
            )
        });
        let q_swap = meta.selector();
        meta.create_gate("swap", |m| {
            let q = m.query_selector(q_swap);
            let cur = m.query_advice(advices[0], Rotation::cur());
            let sib = m.query_advice(advices[1], Rotation::cur());
            let bit = m.query_advice(advices[2], Rotation::cur());
            let lo = m.query_advice(advices[3], Rotation::cur());
            let ro = m.query_advice(advices[4], Rotation::cur());
            Constraints::with_selector(
                q,
                [
                    ("l", cur.clone() + bit.clone() * (sib.clone() - cur.clone()) - lo),
                    ("r", sib.clone() + bit * (cur - sib) - ro),
                ],
            )
        });
        let q_mul0 = meta.selector();
        meta.create_gate("root or dummy", |m| {
            let q = m.query_selector(q_mul0);
            let root = m.query_advice(advices[0], Rotation::cur());
            let anchor = m.query_advice(advices[1], Rotation::cur());
            let v = m.query_advice(advices[2], Rotation::cur());
            Constraints::with_selector(q, [("(root - anchor) v", (root - anchor) * v)])
        });
        let q_par = meta.selector();
        meta.create_gate("y = 2h", |m| {
            let q = m.query_selector(q_par);
            let y = m.query_advice(advices[0], Rotation::cur());
            let h = m.query_advice(advices[1], Rotation::cur());
            Constraints::with_selector(q, [("y - 2h", y - h * Expression::Constant(Fp::from(2)))])
        });
        let q_sum = meta.selector();
        meta.create_gate("sum", |m| {
            let q = m.query_selector(q_sum);
            let a = m.query_advice(advices[0], Rotation::cur());
            let b = m.query_advice(advices[1], Rotation::cur());
            let c = m.query_advice(advices[2], Rotation::cur());
            let d = m.query_advice(advices[3], Rotation::cur());
            Constraints::with_selector(q, [("v_in = v_out", a + b - c - d)])
        });

        Config {
            advices,
            primary,
            fx,
            q_lin,
            q_bits,
            q_swap,
            q_mul0,
            q_par,
            q_sum,
            ecc,
            poseidon,
            range,
            table_idx,
        }
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        // the 10-bit lookup table (Orchard gets it from its Sinsemilla chip)
        layouter.assign_table(
            || "table_idx",
            |mut table| {
                for index in 0..(1usize << 10) {
                    table.assign_cell(
                        || "table_idx",
                        cfg.table_idx,
                        index,
                        || Value::known(Fp::from(index as u64)),
                    )?;
                }
                Ok(())
            },
        )?;
        let ecc = EccChip::construct(cfg.ecc.clone(), CircuitVersion::AnchoredBase);
        let ctx = Ctx { cfg: &cfg, ecc };
        let l = &mut layouter;
        let w = self.w.as_ref();
        let wv = |f: &dyn Fn(&Witness) -> Fp| -> Value<Fp> {
            match w {
                Some(w) => Value::known(f(w)),
                None => Value::unknown(),
            }
        };

        // public inputs as witnessed cells constrained to the instance column
        let st = |i: usize| -> Value<Fp> {
            match &self.st {
                Some(s) => Value::known(s[i]),
                None => Value::unknown(),
            }
        };
        let mut pub_cells = Vec::with_capacity(17);
        for i in 0..17 {
            let c = ctx.witness(l, st(i))?;
            l.constrain_instance(c.cell(), cfg.primary, i)?;
            pub_cells.push(c);
        }
        let const_salt = pub_cells[0].clone();
        let r_anchor = pub_cells[1].clone();
        // arity: the instance cells 2 and 3 are constrained to the constants
        let n = ctx.constant(l, Fp::from(N_IN as u64))?;
        let m = ctx.constant(l, Fp::from(N_OUT as u64))?;
        l.assign_region(
            || "arity",
            |mut r| {
                r.constrain_equal(n.cell(), pub_cells[2].cell())?;
                r.constrain_equal(m.cell(), pub_cells[3].cell())
            },
        )?;

        // spend authority
        let sk_spend = ctx.witness(l, wv(&|w| w.sk_spend))?;
        let t = ctx.constant(l, tag(T_SKNF))?;
        let sk_nf = ctx.hash(l, [t, sk_spend.clone()])?;
        let t = ctx.constant(l, tag(T_VKIN))?;
        let vk_in = ctx.hash(l, [t, sk_spend.clone()])?;
        let t = ctx.constant(l, tag(T_VIEW))?;
        let sk_view = ctx.hash(l, [t, vk_in])?;
        let zero = ctx.constant(l, Fp::ZERO)?;

        // inputs
        let mut v_in = Vec::new();
        for i in 0..N_IN {
            let iw = |f: &dyn Fn(&InputW) -> Fp| wv(&|w| f(&w.inputs[i]));
            let v = ctx.witness(l, iw(&|x| Fp::from(x.note.v)))?;
            ctx.range(l, &v, 6, 4)?;
            let d = ctx.witness(l, iw(&|x| x.note.d))?;
            ctx.range(l, &d, 8, 8)?;
            let rseed = ctx.witness(l, iw(&|x| x.note.rseed))?;
            let h_body_create = ctx.witness(l, iw(&|x| x.h_body_create))?;
            let j = ctx.witness(l, iw(&|x| x.j))?;
            let pos = ctx.witness(l, iw(&|x| Fp::from(x.pos as u64)))?;
            let pos_bits = ctx.bits32(l, &pos)?;
            let mut sibs = Vec::with_capacity(DEPTH);
            for k in 0..DEPTH {
                sibs.push(ctx.witness(l, iw(&|x| x.siblings[k]))?);
            }
            let g_d = ctx.diversify(l, &d, iw(&|x| x.g_y))?;
            let s = ctx.scalar(l, &sk_view)?;
            let (pk_d_mul, _) = g_d.mul(l.namespace(|| "pk_d"), s)?;
            let pk_d_val = match w {
                Some(w) => Value::known(w.inputs[i].pk_d),
                None => Value::unknown(),
            };
            let pk_d = NonIdentityPoint::new(ctx.ecc.clone(), l.namespace(|| "pk_d point"), pk_d_val)?;
            pk_d.constrain_equal(l.namespace(|| "pk_d = [sk_view] G_d"), &pk_d_mul)?;
            let m0 = ctx.lin(l, &v, Fp::from_u128(1u128 << 64), &d, &zero)?;
            let (pk_eph, ct) = ctx.channel(l, &rseed, &m0, &g_d, &pk_d)?;
            let t = ctx.constant(l, tag(T_LEAF))?;
            let lf = ctx.hash(
                l,
                [
                    t,
                    const_salt.clone(),
                    h_body_create,
                    j,
                    pk_eph[0].clone(),
                    pk_eph[1].clone(),
                    ct[0].clone(),
                    ct[1].clone(),
                    ct[2].clone(),
                    zero.clone(),
                ],
            )?;
            // Merkle path
            let mut cur = lf;
            for k in 0..DEPTH {
                let (lo, ro) = ctx.swap(l, &cur, &sibs[k], &pos_bits[k])?;
                let t = ctx.constant(l, tag(T_NODE))?;
                cur = ctx.hash(l, [t, lo, ro])?;
            }
            l.assign_region(
                || "root",
                |mut r| {
                    cfg.q_mul0.enable(&mut r, 0)?;
                    cur.copy_advice(|| "root", &mut r, cfg.advices[0], 0)?;
                    r_anchor.copy_advice(|| "anchor", &mut r, cfg.advices[1], 0)?;
                    v.copy_advice(|| "v", &mut r, cfg.advices[2], 0)?;
                    Ok(())
                },
            )?;
            // nullifier
            let t = ctx.constant(l, tag(T_RHO))?;
            let rho = ctx.hash(l, [t, rseed.clone()])?;
            let t = ctx.constant(l, tag(T_NF))?;
            let nf = ctx.hash(l, [t, sk_nf.clone(), rho, pos])?;
            l.assign_region(
                || "nf = public",
                |mut r| r.constrain_equal(nf.cell(), pub_cells[4 + i].cell()),
            )?;
            v_in.push(v);
        }

        // outputs
        let mut v_out = Vec::new();
        for jx in 0..N_OUT {
            let ow = |f: &dyn Fn(&OutputW) -> Fp| wv(&|w| f(&w.outputs[jx]));
            let v = ctx.witness(l, ow(&|x| Fp::from(x.note.v)))?;
            ctx.range(l, &v, 6, 4)?;
            let d = ctx.witness(l, ow(&|x| x.note.d))?;
            ctx.range(l, &d, 8, 8)?;
            let rseed = ctx.witness(l, ow(&|x| x.note.rseed))?;
            let pk_d_val = match w {
                Some(w) => Value::known(w.outputs[jx].pk_d),
                None => Value::unknown(),
            };
            let pk_d = NonIdentityPoint::new(ctx.ecc.clone(), l.namespace(|| "pk_d"), pk_d_val)?;
            let g_d = ctx.diversify(l, &d, ow(&|x| x.g_y))?;
            let m0 = ctx.lin(l, &v, Fp::from_u128(1u128 << 64), &d, &zero)?;
            let (pk_eph, ct) = ctx.channel(l, &rseed, &m0, &g_d, &pk_d)?;
            let base = 6 + 2 * jx;
            let cbase = 10 + 3 * jx;
            l.assign_region(
                || "output = public",
                |mut r| {
                    r.constrain_equal(pk_eph[0].cell(), pub_cells[base].cell())?;
                    r.constrain_equal(pk_eph[1].cell(), pub_cells[base + 1].cell())?;
                    for k in 0..3 {
                        r.constrain_equal(ct[k].cell(), pub_cells[cbase + k].cell())?;
                    }
                    Ok(())
                },
            )?;
            v_out.push(v);
        }

        // value conservation
        l.assign_region(
            || "sum",
            |mut r| {
                cfg.q_sum.enable(&mut r, 0)?;
                v_in[0].copy_advice(|| "a", &mut r, cfg.advices[0], 0)?;
                v_in[1].copy_advice(|| "b", &mut r, cfg.advices[1], 0)?;
                v_out[0].copy_advice(|| "c", &mut r, cfg.advices[2], 0)?;
                v_out[1].copy_advice(|| "d", &mut r, cfg.advices[3], 0)?;
                Ok(())
            },
        )?;
        // h_body is bound as an instance cell (no in-circuit use), as in the profile
        Ok(())
    }
}

// ------------------------------------------------------------ main

fn main() {
    let (w, st) = sample();
    let instance = st.to_vec();
    let circuit = TransferCircuit {
        w: Some(w),
        st: Some(instance.clone()),
    };

    // smallest k that fits, by the mock prover
    let mut k = 11u32;
    loop {
        let t = Instant::now();
        match MockProver::run(k, &circuit, vec![instance.clone()]) {
            Ok(p) => match p.verify() {
                Ok(()) => {
                    println!("k = {k}: mock prover satisfied ({:.1} s)", t.elapsed().as_secs_f64());
                    break;
                }
                Err(e) => {
                    println!("k = {k}: UNSATISFIED: {:?}", &e[..e.len().min(3)]);
                    std::process::exit(1);
                }
            },
            Err(e) => {
                println!("k = {k}: {e:?}");
                k += 1;
                if k > 20 {
                    std::process::exit(1);
                }
            }
        }
    }

    if std::env::args().any(|a| a == "--mock-only") {
        return;
    }
    let t = Instant::now();
    let params: Params<vesta::Affine> = Params::new(k);
    let empty = TransferCircuit::default();
    let vk = plonk::keygen_vk(&params, &empty).expect("vk");
    let pk = plonk::keygen_pk(&params, vk, &empty).expect("pk");
    println!("keygen (k = {k}): {:.1} s", t.elapsed().as_secs_f64());

    let t = Instant::now();
    let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
    plonk::create_proof(
        &params,
        &pk,
        &[circuit.clone()],
        &[&[&instance[..]]],
        OsRng,
        &mut transcript,
    )
    .expect("proof");
    let proof = transcript.finalize();
    println!("prove: {:.2} s, proof {} bytes", t.elapsed().as_secs_f64(), proof.len());

    let t = Instant::now();
    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::init(&proof[..]);
    let ok = plonk::verify_proof(&params, pk.get_vk(), strategy, &[&[&instance[..]]], &mut transcript).is_ok();
    println!("verify: {:.1} ms, ok {ok}", t.elapsed().as_secs_f64() * 1000.0);

    // two instances in one proof, as a 2-action Orchard bundle
    let (w2, st2) = sample();
    let instance2 = st2.to_vec();
    let circuit2 = TransferCircuit {
        w: Some(w2),
        st: Some(instance2.clone()),
    };
    let t = Instant::now();
    let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
    plonk::create_proof(
        &params,
        &pk,
        &[circuit, circuit2],
        &[&[&instance[..]], &[&instance2[..]]],
        OsRng,
        &mut transcript,
    )
    .expect("proof2");
    let proof2 = transcript.finalize();
    println!(
        "two transfers in one proof: prove {:.2} s, proof {} bytes",
        t.elapsed().as_secs_f64(),
        proof2.len()
    );
}
