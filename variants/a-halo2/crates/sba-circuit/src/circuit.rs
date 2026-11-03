//! The transfer circuit (PROFILE-A.md §8.3): PLONKish, ten advice columns
//! laid out as Orchard's, `halo2_gadgets` Poseidon, ECC and lookup chips,
//! and own gates for the linear combinations, the position bits, the
//! conditional swap, the dummy rule, the parity rule and the sum.

use ff::PrimeField;
use group::Curve;
use group::prime::PrimeCurveAffine;
use halo2_gadgets::{
    ecc::{
        NonIdentityPoint, ScalarVar,
        chip::{CircuitVersion, EccChip, EccConfig},
    },
    poseidon::{Hash as PoseidonHash, Pow5Chip, Pow5Config, primitives as poseidon},
    utilities::lookup_range_check::{
        LookupRangeCheck, LookupRangeCheckConfig, PallasLookupRangeCheckConfig,
    },
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Instance,
        Selector, TableColumn,
    },
    poly::Rotation,
};
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::pallas;

use sba_core::envelope::N_IN;
use sba_core::note::{NoteCiphertext, NotePlaintext};
use sba_core::recovery::N_OUT;
use sba_core::tree::DEPTH;
use sba_core::{Affine, Fp, xy};
use sba_primitives::diversify::{diversifier_to_fp, even_y_for_x};
use sba_primitives::poseidon::hash;
use sba_primitives::scalar::scalar_from_fp;
use sba_primitives::tags::{
    t_div, t_eph, t_kdf, t_leaf, t_mac, t_nf, t_node, t_rho, t_sknf, t_stream, t_view, t_vkin,
};

use crate::fixed::Bases;

/// Rows of the circuit: `2^K` (PROFILE-A.md §1).
pub const K: u32 = 14;
/// Number of public inputs (PROFILE-A.md §8.1).
pub const NUM_PUBLIC_INPUTS: usize = 1 + 1 + 2 + N_IN + 2 * N_OUT + 3 * N_OUT + 1;

type Cell = AssignedCell<Fp, Fp>;
type Ecc = EccChip<Bases, PallasLookupRangeCheckConfig>;
type Pt = NonIdentityPoint<pallas::Affine, Ecc>;

/// Private data for one spent note (PROFILE-A.md §8.2).
#[derive(Clone, Debug)]
pub struct InputWitness {
    pub note: NotePlaintext,
    /// `h_body` of the envelope that created the note.
    pub h_body_create: Fp,
    /// Output index `j` in that envelope.
    pub output_index: u64,
    /// Replay-assigned tree position.
    pub pos: u64,
    /// Authentication path under `r_anchor`, leaf level first.
    pub siblings: [Fp; DEPTH],
}

impl InputWitness {
    /// A zero-value dummy input (profile §8.2). `d` must be a valid
    /// diversifier; the wallet uses one of its own.
    pub fn dummy(d: [u8; 11], rseed: Fp) -> Self {
        InputWitness {
            note: NotePlaintext { value: 0, d, rseed },
            h_body_create: Fp::zero(),
            output_index: 0,
            pos: 0,
            siblings: [Fp::zero(); DEPTH],
        }
    }
}

/// Private data for one created note.
#[derive(Clone, Debug)]
pub struct OutputWitness {
    pub note: NotePlaintext,
    /// Recipient transmission key from the destination address.
    pub pk_d: Affine,
}

#[derive(Clone, Debug)]
pub struct TransferWitness {
    pub sk_spend: Fp,
    pub inputs: [InputWitness; N_IN],
    pub outputs: [OutputWitness; N_OUT],
}

/// The public statement (PROFILE-A.md §8.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferStatement {
    pub const_salt: Fp,
    pub r_anchor: Fp,
    pub nullifiers: [Fp; N_IN],
    pub pk_eph: [Affine; N_OUT],
    pub ct_note: [NoteCiphertext; N_OUT],
    pub h_body: Fp,
}

impl TransferStatement {
    /// The instance column, in profile order.
    pub fn to_field_elements(&self) -> Vec<Fp> {
        let mut v = Vec::with_capacity(NUM_PUBLIC_INPUTS);
        v.push(self.const_salt);
        v.push(self.r_anchor);
        v.push(Fp::from(N_IN as u64));
        v.push(Fp::from(N_OUT as u64));
        v.extend_from_slice(&self.nullifiers);
        for p in &self.pk_eph {
            let (x, y) = xy(p);
            v.push(x);
            v.push(y);
        }
        for c in &self.ct_note {
            v.extend_from_slice(&c.elements());
        }
        v.push(self.h_body);
        debug_assert_eq!(v.len(), NUM_PUBLIC_INPUTS);
        v
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    advices: [Column<Advice>; 10],
    primary: Column<Instance>,
    fx: Column<Fixed>,
    q_lin: Selector,
    q_bits: Selector,
    q_swap: Selector,
    q_mul0: Selector,
    q_par: Selector,
    q_sum: Selector,
    ecc: EccConfig<Bases, PallasLookupRangeCheckConfig>,
    poseidon: Pow5Config<Fp, 3, 2>,
    range: PallasLookupRangeCheckConfig,
    table_idx: TableColumn,
}

/// The circuit. Both fields are `None` for key generation.
#[derive(Clone, Default)]
pub struct TransferCircuit {
    pub statement: Option<TransferStatement>,
    pub witness: Option<TransferWitness>,
    /// Test hook: witness the odd root of every `G_d` instead of the even
    /// one. The parity rule must refuse it; nothing else sets this.
    #[doc(hidden)]
    pub negate_g_d: bool,
}

/// `2^253` as a field element.
fn two_pow_253() -> Fp {
    let mut b = [0u8; 32];
    b[31] = 0x20;
    Fp::from_repr(b).unwrap()
}

/// `K = 2^125 − c` with `c = (p + 1)/2 − 2^253`, the parity rule's constant.
fn parity_k() -> Fp {
    Fp::from_u128(0x0edc_b381_fb59_8372_3369_6789_7fff_ffff)
}

struct Ctx<'a> {
    cfg: &'a Config,
    ecc: Ecc,
    /// The test hook of [`TransferCircuit::negate_g_d`].
    negate_g_d: bool,
}

impl Ctx<'_> {
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

    fn hash<const L: usize>(
        &self,
        l: &mut impl Layouter<Fp>,
        msg: [Cell; L],
    ) -> Result<Cell, Error> {
        let chip = Pow5Chip::construct(self.cfg.poseidon.clone());
        PoseidonHash::<Fp, _, poseidon::P128Pow5T3, poseidon::ConstantLength<L>, 3, 2>::init(
            chip,
            l.namespace(|| "ph"),
        )?
        .hash(l.namespace(|| "ph"), msg)
    }

    /// `out = a + k·b + c`
    fn lin(
        &self,
        l: &mut impl Layouter<Fp>,
        a: &Cell,
        k: Fp,
        b: &Cell,
        c: &Cell,
    ) -> Result<Cell, Error> {
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
    fn range(
        &self,
        l: &mut impl Layouter<Fp>,
        x: &Cell,
        words: usize,
        short: usize,
    ) -> Result<(), Error> {
        let zs = self
            .cfg
            .range
            .copy_check(l.namespace(|| "rc"), x.clone(), words, short == 0)?;
        if short > 0 {
            self.cfg.range.copy_short_check(
                l.namespace(|| "rc short"),
                zs[words].clone(),
                short,
            )?;
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
                let mut acc =
                    r.assign_advice_from_constant(|| "acc0", cfg.advices[1], 0, Fp::zero())?;
                let mut bits: Vec<Option<Cell>> = vec![None; 32];
                for i in 0..32 {
                    cfg.q_bits.enable(&mut r, i)?;
                    let idx = 31 - i;
                    let bit = val.map(|p| Fp::from(((p >> idx) & 1) as u64));
                    let b = r.assign_advice(|| "bit", cfg.advices[0], i, || bit)?;
                    let next =
                        acc.value().copied() * Value::known(Fp::from(2)) + b.value().copied();
                    acc = r.assign_advice(|| "acc", cfg.advices[1], i + 1, || next)?;
                    bits[idx] = Some(b);
                }
                r.constrain_equal(acc.cell(), pos.cell())?;
                Ok(bits.into_iter().map(|b| b.unwrap()).collect())
            },
        )
    }

    /// `(l, r) = bit ? (sib, cur) : (cur, sib)`
    fn swap(
        &self,
        l: &mut impl Layouter<Fp>,
        cur: &Cell,
        sib: &Cell,
        bit: &Cell,
    ) -> Result<(Cell, Cell), Error> {
        let cfg = self.cfg;
        l.assign_region(
            || "swap",
            |mut r| {
                cfg.q_swap.enable(&mut r, 0)?;
                cur.copy_advice(|| "cur", &mut r, cfg.advices[0], 0)?;
                sib.copy_advice(|| "sib", &mut r, cfg.advices[1], 0)?;
                bit.copy_advice(|| "bit", &mut r, cfg.advices[2], 0)?;
                let sw = bit.value().map(|b| *b == Fp::one());
                let lv = cur
                    .value()
                    .zip(sib.value())
                    .zip(sw)
                    .map(|((c, s), b)| if b { *s } else { *c });
                let rv = cur
                    .value()
                    .zip(sib.value())
                    .zip(sw)
                    .map(|((c, s), b)| if b { *c } else { *s });
                let lo = r.assign_advice(|| "l", cfg.advices[3], 0, || lv)?;
                let ro = r.assign_advice(|| "r", cfg.advices[4], 0, || rv)?;
                Ok((lo, ro))
            },
        )
    }

    /// `G_d = DiversifyHash(d)`: `x = PH_A(T_DIV, d)`, the point witnessed on
    /// the curve with the even `y`, enforced as `y = 2h` with `h ≤ (p − 1)/2`
    /// so that `2h` never wraps modulo `p` (`PROFILE-A.md` §4.2): `h = h_hi ·
    /// 2^253 + h_lo` with `h_hi` boolean, `h_lo < 2^253`, and `z = h_hi ·
    /// (h_lo + K) < 2^125` where `K = 2^125 − c`, `c = (p + 1)/2 − 2^253`, so
    /// that `h_hi = 1` forces `h_lo < c`. A bound of `h < 2^254` alone would
    /// admit `h' = p − h`, i.e. the odd root (review finding, 3 November 2026).
    fn diversify(&self, l: &mut impl Layouter<Fp>, d: &Cell) -> Result<Pt, Error> {
        let t = self.constant(l, t_div())?;
        let x = self.hash(l, [t, d.clone()])?;
        let negate = self.negate_g_d;
        let p = x.value().map(|x| {
            let y = even_y_for_x(x).expect("the wallet never uses an invalid diversifier");
            let y = if negate { -y } else { y };
            pallas::Affine::from_xy(*x, y).unwrap()
        });
        let point = NonIdentityPoint::new(self.ecc.clone(), l.namespace(|| "G_d"), p)?;
        let cfg = self.cfg;
        let (h_lo, z) = l.assign_region(
            || "parity",
            |mut r| {
                cfg.q_par.enable(&mut r, 0)?;
                let yc = point.inner().y();
                yc.copy_advice(|| "y", &mut r, cfg.advices[0], 0)?;
                // h = y / 2 in the field (= the integer half when y is even;
                // for the odd root it is (y + p)/2, which the bound refuses)
                let h = yc.value().map(|y| *y * Fp::TWO_INV);
                let h_hi = h.map(|h| Fp::from(u64::from(h.to_repr()[31] >> 5 & 1)));
                let h_lo = h.zip(h_hi).map(|(h, hi)| h - hi * two_pow_253());
                let z = h_hi.zip(h_lo).map(|(hi, lo)| hi * (lo + parity_k()));
                r.assign_advice(|| "h", cfg.advices[1], 0, || h)?;
                r.assign_advice(|| "h_hi", cfg.advices[2], 0, || h_hi)?;
                let lo = r.assign_advice(|| "h_lo", cfg.advices[3], 0, || h_lo)?;
                let z = r.assign_advice(|| "z", cfg.advices[4], 0, || z)?;
                Ok((lo, z))
            },
        )?;
        l.assign_region(
            || "x = hash",
            |mut r| r.constrain_equal(point.inner().x().cell(), x.cell()),
        )?;
        self.range(l, &h_lo, 25, 3)?;
        self.range(l, &z, 12, 5)?;
        Ok(point)
    }

    fn scalar(
        &self,
        l: &mut impl Layouter<Fp>,
        s: &Cell,
    ) -> Result<ScalarVar<pallas::Affine, Ecc>, Error> {
        ScalarVar::from_base(self.ecc.clone(), l.namespace(|| "scalar"), s)
    }

    /// The recipient channel: `pk_eph = [sk_eph] G_d`, `ss = [sk_eph] pk_d`, `ct`.
    fn channel(
        &self,
        l: &mut impl Layouter<Fp>,
        rseed: &Cell,
        m0: &Cell,
        g_d: &Pt,
        pk_d: &Pt,
    ) -> Result<([Cell; 2], [Cell; 3]), Error> {
        let t = self.constant(l, t_eph())?;
        let sk_eph = self.hash(l, [t, rseed.clone()])?;
        let s1 = self.scalar(l, &sk_eph)?;
        let (pk_eph, _) = g_d.mul(l.namespace(|| "pk_eph"), s1)?;
        let s2 = self.scalar(l, &sk_eph)?;
        let (ss, _) = pk_d.mul(l.namespace(|| "ss"), s2)?;
        let t = self.constant(l, t_kdf())?;
        let k = self.hash(
            l,
            [
                t,
                ss.inner().x(),
                ss.inner().y(),
                pk_eph.inner().x(),
                pk_eph.inner().y(),
            ],
        )?;
        let zero = self.constant(l, Fp::zero())?;
        let one = self.constant(l, Fp::one())?;
        let t = self.constant(l, t_stream())?;
        let s0 = self.hash(l, [t.clone(), k.clone(), zero.clone()])?;
        let s1 = self.hash(l, [t, k.clone(), one])?;
        let c0 = self.lin(l, m0, Fp::one(), &s0, &zero)?;
        let c1 = self.lin(l, rseed, Fp::one(), &s1, &zero)?;
        let t = self.constant(l, t_mac())?;
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
        let ecc = EccChip::<Bases>::configure(meta, advices, lagrange_coeffs, range);
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
            let one = Expression::Constant(Fp::one());
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
                    (
                        "l",
                        cur.clone() + bit.clone() * (sib.clone() - cur.clone()) - lo,
                    ),
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
        meta.create_gate("y = 2h, h <= (p-1)/2", |m| {
            let q = m.query_selector(q_par);
            let y = m.query_advice(advices[0], Rotation::cur());
            let h = m.query_advice(advices[1], Rotation::cur());
            let h_hi = m.query_advice(advices[2], Rotation::cur());
            let h_lo = m.query_advice(advices[3], Rotation::cur());
            let z = m.query_advice(advices[4], Rotation::cur());
            let one = Expression::Constant(Fp::one());
            Constraints::with_selector(
                q,
                [
                    ("y - 2h", y - h.clone() * Expression::Constant(Fp::from(2))),
                    (
                        "h - h_hi 2^253 - h_lo",
                        h - h_hi.clone() * Expression::Constant(two_pow_253()) - h_lo.clone(),
                    ),
                    ("h_hi boolean", h_hi.clone() * (h_hi.clone() - one)),
                    (
                        "z - h_hi (h_lo + K)",
                        z - h_hi * (h_lo + Expression::Constant(parity_k())),
                    ),
                ],
            )
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
        // the 10-bit lookup table
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
        let ctx = Ctx {
            cfg: &cfg,
            ecc,
            negate_g_d: self.negate_g_d,
        };
        let l = &mut layouter;
        let w = self.witness.as_ref();
        let wv = |f: &dyn Fn(&TransferWitness) -> Fp| -> Value<Fp> {
            match w {
                Some(w) => Value::known(f(w)),
                None => Value::unknown(),
            }
        };
        let st = self.statement.as_ref().map(|s| s.to_field_elements());
        let sv = |i: usize| -> Value<Fp> {
            match &st {
                Some(s) => Value::known(s[i]),
                None => Value::unknown(),
            }
        };

        // public inputs as cells bound to the instance column
        let mut pub_cells = Vec::with_capacity(NUM_PUBLIC_INPUTS);
        for i in 0..NUM_PUBLIC_INPUTS {
            let c = ctx.witness(l, sv(i))?;
            l.constrain_instance(c.cell(), cfg.primary, i)?;
            pub_cells.push(c);
        }
        let const_salt = pub_cells[0].clone();
        let r_anchor = pub_cells[1].clone();
        let n = ctx.constant(l, Fp::from(N_IN as u64))?;
        let m = ctx.constant(l, Fp::from(N_OUT as u64))?;
        l.assign_region(
            || "arity",
            |mut r| {
                r.constrain_equal(n.cell(), pub_cells[2].cell())?;
                r.constrain_equal(m.cell(), pub_cells[3].cell())
            },
        )?;

        // spend authority (blocks 3, 4)
        let sk_spend = ctx.witness(l, wv(&|w| w.sk_spend))?;
        let t = ctx.constant(l, t_sknf())?;
        let sk_nf = ctx.hash(l, [t, sk_spend.clone()])?;
        let t = ctx.constant(l, t_vkin())?;
        let vk_in = ctx.hash(l, [t, sk_spend.clone()])?;
        let t = ctx.constant(l, t_view())?;
        let sk_view = ctx.hash(l, [t, vk_in])?;
        let zero = ctx.constant(l, Fp::zero())?;

        // inputs (blocks 1, 2, 3, 4)
        let mut v_in = Vec::new();
        for i in 0..N_IN {
            let iw = |f: &dyn Fn(&InputWitness) -> Fp| wv(&|w| f(&w.inputs[i]));
            let v = ctx.witness(l, iw(&|x| Fp::from(x.note.value)))?;
            ctx.range(l, &v, 6, 4)?;
            let d = ctx.witness(l, iw(&|x| diversifier_to_fp(&x.note.d)))?;
            ctx.range(l, &d, 8, 8)?;
            let rseed = ctx.witness(l, iw(&|x| x.note.rseed))?;
            let h_body_create = ctx.witness(l, iw(&|x| x.h_body_create))?;
            let j = ctx.witness(l, iw(&|x| Fp::from(x.output_index)))?;
            let pos = ctx.witness(l, iw(&|x| Fp::from(x.pos)))?;
            let pos_bits = ctx.bits32(l, &pos)?;
            let mut sibs = Vec::with_capacity(DEPTH);
            for k in 0..DEPTH {
                sibs.push(ctx.witness(l, iw(&|x| x.siblings[k]))?);
            }
            let g_d = ctx.diversify(l, &d)?;
            // pk_d = [sk_view] G_d, as a witnessed non-identity point equal to the product
            let s = ctx.scalar(l, &sk_view)?;
            let (pk_d_mul, _) = g_d.mul(l.namespace(|| "pk_d"), s)?;
            let pk_d_val = match w {
                Some(w) => {
                    let sk_view = scalar_from_fp(&hash(t_view(), &[hash(t_vkin(), &[w.sk_spend])]));
                    let g = w.inputs[i].note.g_d().expect("valid diversifier");
                    Value::known((g.to_curve() * sk_view).to_affine())
                }
                None => Value::unknown(),
            };
            let pk_d =
                NonIdentityPoint::new(ctx.ecc.clone(), l.namespace(|| "pk_d point"), pk_d_val)?;
            pk_d.constrain_equal(l.namespace(|| "pk_d = [sk_view] G_d"), &pk_d_mul)?;
            let m0 = ctx.lin(l, &v, Fp::from_u128(1u128 << 64), &d, &zero)?;
            let (pk_eph, ct) = ctx.channel(l, &rseed, &m0, &g_d, &pk_d)?;
            let t = ctx.constant(l, t_leaf())?;
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
            let mut cur = lf;
            for k in 0..DEPTH {
                let (lo, ro) = ctx.swap(l, &cur, &sibs[k], &pos_bits[k])?;
                let t = ctx.constant(l, t_node())?;
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
            let t = ctx.constant(l, t_rho())?;
            let rho = ctx.hash(l, [t, rseed.clone()])?;
            let t = ctx.constant(l, t_nf())?;
            let nf = ctx.hash(l, [t, sk_nf.clone(), rho, pos])?;
            l.assign_region(
                || "nf = public",
                |mut r| r.constrain_equal(nf.cell(), pub_cells[4 + i].cell()),
            )?;
            v_in.push(v);
        }

        // outputs (block 5)
        let mut v_out = Vec::new();
        for jx in 0..N_OUT {
            let ow = |f: &dyn Fn(&OutputWitness) -> Fp| wv(&|w| f(&w.outputs[jx]));
            let v = ctx.witness(l, ow(&|x| Fp::from(x.note.value)))?;
            ctx.range(l, &v, 6, 4)?;
            let d = ctx.witness(l, ow(&|x| diversifier_to_fp(&x.note.d)))?;
            ctx.range(l, &d, 8, 8)?;
            let rseed = ctx.witness(l, ow(&|x| x.note.rseed))?;
            let pk_d_val = match w {
                Some(w) => Value::known(w.outputs[jx].pk_d),
                None => Value::unknown(),
            };
            let pk_d = NonIdentityPoint::new(ctx.ecc.clone(), l.namespace(|| "pk_d"), pk_d_val)?;
            let g_d = ctx.diversify(l, &d)?;
            let m0 = ctx.lin(l, &v, Fp::from_u128(1u128 << 64), &d, &zero)?;
            let (pk_eph, ct) = ctx.channel(l, &rseed, &m0, &g_d, &pk_d)?;
            let base = 4 + N_IN + 2 * jx;
            let cbase = 4 + N_IN + 2 * N_OUT + 3 * jx;
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

        // value conservation (blocks 6, 7); h_body is bound by the instance (block 8)
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
        Ok(())
    }
}
