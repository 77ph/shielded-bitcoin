//! The batch relation of `docs/REPLAY-PROOF-A.md` §3.7 as a Halo 2 circuit
//! over `Fp`: the state opening behind `s_prev`, up to `n` slots applied in
//! order through the note tree, the indexed nullifier tree and the root
//! tree, the digest `D` of the slots, the opening behind `s_next`. Rule by
//! rule the native `sba_core::batch::BatchWitness::check`, which is its
//! specification; the gadgets are the transfer circuit's kind (the
//! family's Poseidon chip for `PH_A`, lookups for ranges, bits and swaps
//! for Merkle paths). A statement's elements are witnesses here; the step
//! circuit that embeds this one binds them to the transfer proofs'
//! statements.
//!
//! Comparisons of field elements (the nullifier tree's `low < nf < next`)
//! go through two limbs, `lo < 2^128` and `hi < 2^126` — so every
//! compared value is below `2^254`, which makes the limbs unique — and a
//! 128-bit comparison is one range check of `β (y − x − 1) + (1 − β)(x −
//! y)` for a witnessed bit `β`. A nullifier in `[2^254, p)` (probability
//! `2^-129`) cannot be inserted by this circuit: a completeness loss, not
//! a soundness one.

use ff::{Field, PrimeField};
use halo2_gadgets::poseidon::{primitives as poseidon, Hash as PoseidonHash, Pow5Chip, Pow5Config};
use halo2_gadgets::utilities::lookup_range_check::{
    LookupRangeCheck, PallasLookupRangeCheckConfig,
};
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Instance,
    Selector, TableColumn,
};
use halo2_proofs::poly::Rotation;

use sba_core::batch::{BatchParams, BatchWitness, SlotWitness, DIGEST_CHUNK, SLOT_ELEMENTS};
use sba_core::tree::{DEPTH, EMPTY_ROOTS};
use sba_primitives::tags::{t_batch, t_imt, t_leaf, t_node, t_state};
use sba_primitives::Fp;

pub type Cell = AssignedCell<Fp, Fp>;

#[derive(Clone, Debug)]
pub struct BatchConfig {
    pub advices: [Column<Advice>; 11],
    fx: Column<Fixed>,
    q_lin: Selector,
    q_mul: Selector,
    q_bits: Selector,
    q_swap: Selector,
    pub poseidon: Pow5Config<Fp, 3, 2>,
    pub range: PallasLookupRangeCheckConfig,
    pub table_idx: TableColumn,
    pub instance: Column<Instance>,
}

/// The circuit; `witness` is `None` for key generation. The shape is fixed
/// by `n` and the parameters.
#[derive(Clone, Debug)]
pub struct BatchCircuit {
    pub n: usize,
    pub params: BatchParams,
    pub witness: Option<BatchWitness>,
}

impl BatchConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let advices: [Column<Advice>; 11] = core::array::from_fn(|_| meta.advice_column());
        for a in &advices {
            meta.enable_equality(*a);
        }
        let fixed: [Column<Fixed>; 7] = core::array::from_fn(|_| meta.fixed_column());
        let fx = fixed[0];
        meta.enable_constant(fx);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        let table_idx = meta.lookup_table_column();
        let range = PallasLookupRangeCheckConfig::configure(meta, advices[10], table_idx);
        let poseidon = Pow5Chip::configure::<poseidon::P128Pow5T3>(
            meta,
            advices[0..3].try_into().unwrap(),
            advices[3],
            fixed[1..4].try_into().unwrap(),
            fixed[4..7].try_into().unwrap(),
        );
        let q_lin = meta.selector();
        meta.create_gate("out = a + k b + c", |m| {
            let q = m.query_selector(q_lin);
            let a = m.query_advice(advices[4], Rotation::cur());
            let b = m.query_advice(advices[5], Rotation::cur());
            let c = m.query_advice(advices[6], Rotation::cur());
            let out = m.query_advice(advices[7], Rotation::cur());
            let k = m.query_fixed(fx);
            Constraints::with_selector(q, [("lin", a + k * b + c - out)])
        });
        let q_mul = meta.selector();
        meta.create_gate("out = a b", |m| {
            let q = m.query_selector(q_mul);
            let a = m.query_advice(advices[4], Rotation::cur());
            let b = m.query_advice(advices[5], Rotation::cur());
            let out = m.query_advice(advices[7], Rotation::cur());
            Constraints::with_selector(q, [("mul", a * b - out)])
        });
        let q_bits = meta.selector();
        meta.create_gate("acc' = 2 acc + bit, bit boolean", |m| {
            let q = m.query_selector(q_bits);
            let bit = m.query_advice(advices[4], Rotation::cur());
            let acc = m.query_advice(advices[5], Rotation::cur());
            let next = m.query_advice(advices[5], Rotation::next());
            let two = Expression::Constant(Fp::from(2));
            Constraints::with_selector(
                q,
                [
                    (
                        "bool",
                        bit.clone() * (bit.clone() - Expression::Constant(Fp::ONE)),
                    ),
                    ("acc", acc * two + bit - next),
                ],
            )
        });
        let q_swap = meta.selector();
        meta.create_gate("(l, r) = bit ? (sib, cur) : (cur, sib)", |m| {
            let q = m.query_selector(q_swap);
            let cur = m.query_advice(advices[4], Rotation::cur());
            let sib = m.query_advice(advices[5], Rotation::cur());
            let bit = m.query_advice(advices[6], Rotation::cur());
            let l = m.query_advice(advices[7], Rotation::cur());
            let r = m.query_advice(advices[8], Rotation::cur());
            let one = Expression::Constant(Fp::ONE);
            Constraints::with_selector(
                q,
                [
                    ("bool", bit.clone() * (bit.clone() - one.clone())),
                    (
                        "l",
                        l - (cur.clone() * (one.clone() - bit.clone()) + sib.clone() * bit.clone()),
                    ),
                    ("r", r - (sib * (one - bit.clone()) + cur * bit)),
                ],
            )
        });
        BatchConfig {
            advices,
            fx,
            q_lin,
            q_mul,
            q_bits,
            q_swap,
            poseidon,
            range,
            table_idx,
            instance,
        }
    }

    pub fn assign_table(&self, l: &mut impl Layouter<Fp>) -> Result<(), Error> {
        l.assign_table(
            || "10-bit table",
            |mut t| {
                for i in 0..(1 << 10) {
                    t.assign_cell(
                        || "idx",
                        self.table_idx,
                        i,
                        || Value::known(Fp::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }
}

/// The gadgets, over a configuration.
pub struct Ctx<'c> {
    cfg: &'c BatchConfig,
    /// Rows of the small gates, for the measurement.
    pub rows: usize,
}

type Bits = Vec<Cell>;

impl<'c> Ctx<'c> {
    pub fn new(cfg: &'c BatchConfig) -> Self {
        Ctx { cfg, rows: 0 }
    }

    pub fn witness(&mut self, l: &mut impl Layouter<Fp>, v: Value<Fp>) -> Result<Cell, Error> {
        self.rows += 1;
        l.assign_region(
            || "w",
            |mut r| r.assign_advice(|| "w", self.cfg.advices[4], 0, || v),
        )
    }

    pub fn constant(&mut self, l: &mut impl Layouter<Fp>, c: Fp) -> Result<Cell, Error> {
        self.rows += 1;
        l.assign_region(
            || "c",
            |mut r| r.assign_advice_from_constant(|| "c", self.cfg.advices[4], 0, c),
        )
    }

    /// `out = a + k·b + c`
    pub fn lin(
        &mut self,
        l: &mut impl Layouter<Fp>,
        a: &Cell,
        k: Fp,
        b: &Cell,
        c: &Cell,
    ) -> Result<Cell, Error> {
        let cfg = self.cfg;
        self.rows += 1;
        l.assign_region(
            || "lin",
            |mut r| {
                cfg.q_lin.enable(&mut r, 0)?;
                a.copy_advice(|| "a", &mut r, cfg.advices[4], 0)?;
                b.copy_advice(|| "b", &mut r, cfg.advices[5], 0)?;
                c.copy_advice(|| "c", &mut r, cfg.advices[6], 0)?;
                r.assign_fixed(|| "k", cfg.fx, 0, || Value::known(k))?;
                let out = a.value().copied() + b.value().map(|b| k * b) + c.value().copied();
                r.assign_advice(|| "out", cfg.advices[7], 0, || out)
            },
        )
    }

    pub fn mul(&mut self, l: &mut impl Layouter<Fp>, a: &Cell, b: &Cell) -> Result<Cell, Error> {
        let cfg = self.cfg;
        self.rows += 1;
        l.assign_region(
            || "mul",
            |mut r| {
                cfg.q_mul.enable(&mut r, 0)?;
                a.copy_advice(|| "a", &mut r, cfg.advices[4], 0)?;
                b.copy_advice(|| "b", &mut r, cfg.advices[5], 0)?;
                let out = a.value().copied() * b.value().copied();
                r.assign_advice(|| "out", cfg.advices[7], 0, || out)
            },
        )
    }

    pub fn assert_equal(
        &mut self,
        l: &mut impl Layouter<Fp>,
        a: &Cell,
        b: &Cell,
    ) -> Result<(), Error> {
        l.assign_region(|| "eq", |mut r| r.constrain_equal(a.cell(), b.cell()))
    }

    pub fn assert_constant(
        &mut self,
        l: &mut impl Layouter<Fp>,
        a: &Cell,
        k: Fp,
    ) -> Result<(), Error> {
        l.assign_region(|| "const", |mut r| r.constrain_constant(a.cell(), k))
    }

    /// Range check: `words` 10-bit words plus `short` bits.
    pub fn range(
        &mut self,
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

    /// `PH_A(tag, msg)` as the family's hash: the tag first.
    pub fn hash<const L: usize>(
        &mut self,
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

    /// 32 bits of `pos` (LSB first), constrained to recompose to it.
    pub fn bits32(&mut self, l: &mut impl Layouter<Fp>, pos: &Cell) -> Result<Bits, Error> {
        let cfg = self.cfg;
        self.rows += 33;
        l.assign_region(
            || "bits",
            |mut r| {
                let val = pos.value().map(|p| {
                    let b = p.to_repr();
                    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
                });
                let mut acc =
                    r.assign_advice_from_constant(|| "acc0", cfg.advices[5], 0, Fp::ZERO)?;
                let mut bits: Vec<Option<Cell>> = vec![None; 32];
                for i in 0..32 {
                    cfg.q_bits.enable(&mut r, i)?;
                    let idx = 31 - i;
                    let bit = val.map(|p| Fp::from(((p >> idx) & 1) as u64));
                    let b = r.assign_advice(|| "bit", cfg.advices[4], i, || bit)?;
                    let next =
                        acc.value().copied() * Value::known(Fp::from(2)) + b.value().copied();
                    acc = r.assign_advice(|| "acc", cfg.advices[5], i + 1, || next)?;
                    bits[idx] = Some(b);
                }
                r.constrain_equal(acc.cell(), pos.cell())?;
                Ok(bits.into_iter().map(|b| b.unwrap()).collect())
            },
        )
    }

    /// `(l, r) = bit ? (sib, cur) : (cur, sib)`
    pub fn swap(
        &mut self,
        l: &mut impl Layouter<Fp>,
        cur: &Cell,
        sib: &Cell,
        bit: &Cell,
    ) -> Result<(Cell, Cell), Error> {
        let cfg = self.cfg;
        self.rows += 1;
        l.assign_region(
            || "swap",
            |mut r| {
                cfg.q_swap.enable(&mut r, 0)?;
                cur.copy_advice(|| "cur", &mut r, cfg.advices[4], 0)?;
                sib.copy_advice(|| "sib", &mut r, cfg.advices[5], 0)?;
                bit.copy_advice(|| "bit", &mut r, cfg.advices[6], 0)?;
                let sw = bit.value().map(|b| *b == Fp::ONE);
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
                let lo = r.assign_advice(|| "l", cfg.advices[7], 0, || lv)?;
                let ro = r.assign_advice(|| "r", cfg.advices[8], 0, || rv)?;
                Ok((lo, ro))
            },
        )
    }

    /// The root over `leaf` at the position of `bits` with the siblings.
    pub fn merkle_root(
        &mut self,
        l: &mut impl Layouter<Fp>,
        leaf: &Cell,
        bits: &[Cell],
        sibs: &[Cell],
    ) -> Result<Cell, Error> {
        let tag = self.constant(l, t_node())?;
        let mut cur = leaf.clone();
        for (bit, sib) in bits.iter().zip(sibs) {
            let (a, b) = self.swap(l, &cur, sib, bit)?;
            cur = self.hash(l, [tag.clone(), a, b])?;
        }
        Ok(cur)
    }

    // ---- booleans and selections

    pub fn add(&mut self, l: &mut impl Layouter<Fp>, a: &Cell, b: &Cell) -> Result<Cell, Error> {
        let zero = self.constant(l, Fp::ZERO)?;
        self.lin(l, a, Fp::ONE, b, &zero)
    }

    pub fn sub(&mut self, l: &mut impl Layouter<Fp>, a: &Cell, b: &Cell) -> Result<Cell, Error> {
        let zero = self.constant(l, Fp::ZERO)?;
        self.lin(l, a, -Fp::ONE, b, &zero)
    }

    /// `a + k` for a constant `k`.
    pub fn add_const(&mut self, l: &mut impl Layouter<Fp>, a: &Cell, k: Fp) -> Result<Cell, Error> {
        let kc = self.constant(l, k)?;
        let zero = self.constant(l, Fp::ZERO)?;
        self.lin(l, a, Fp::ONE, &kc, &zero)
    }

    /// `1 − b`
    pub fn not(&mut self, l: &mut impl Layouter<Fp>, b: &Cell) -> Result<Cell, Error> {
        let one = self.constant(l, Fp::ONE)?;
        self.sub(l, &one, b)
    }

    /// `a ∨ b` for booleans: `a + b − a b`.
    pub fn or(&mut self, l: &mut impl Layouter<Fp>, a: &Cell, b: &Cell) -> Result<Cell, Error> {
        let ab = self.mul(l, a, b)?;
        let s = self.add(l, a, b)?;
        self.sub(l, &s, &ab)
    }

    /// A witnessed boolean.
    pub fn bit(&mut self, l: &mut impl Layouter<Fp>, v: Value<bool>) -> Result<Cell, Error> {
        let b = self.witness(l, v.map(|b| Fp::from(b as u64)))?;
        let bb = self.mul(l, &b, &b)?;
        self.assert_equal(l, &bb, &b)?;
        Ok(b)
    }

    /// `bit ? a : b`
    pub fn select(
        &mut self,
        l: &mut impl Layouter<Fp>,
        bit: &Cell,
        a: &Cell,
        b: &Cell,
    ) -> Result<Cell, Error> {
        let d = self.sub(l, a, b)?;
        let t = self.mul(l, bit, &d)?;
        self.add(l, b, &t)
    }

    /// `bit ⇒ a = b`
    pub fn cond_eq(
        &mut self,
        l: &mut impl Layouter<Fp>,
        bit: &Cell,
        a: &Cell,
        b: &Cell,
    ) -> Result<(), Error> {
        let d = self.sub(l, a, b)?;
        let t = self.mul(l, bit, &d)?;
        self.assert_constant(l, &t, Fp::ZERO)
    }

    /// `bit ⇒ a = k`
    pub fn cond_eq_const(
        &mut self,
        l: &mut impl Layouter<Fp>,
        bit: &Cell,
        a: &Cell,
        k: Fp,
    ) -> Result<(), Error> {
        let kc = self.constant(l, k)?;
        self.cond_eq(l, bit, a, &kc)
    }

    /// `bit ⇒ x < 2^(10 words + short)`: the range check of `bit · x`.
    pub fn cond_range(
        &mut self,
        l: &mut impl Layouter<Fp>,
        bit: &Cell,
        x: &Cell,
        words: usize,
        short: usize,
    ) -> Result<(), Error> {
        let t = self.mul(l, bit, x)?;
        self.range(l, &t, words, short)
    }

    /// `x == 0` as a boolean.
    pub fn is_zero(&mut self, l: &mut impl Layouter<Fp>, x: &Cell) -> Result<Cell, Error> {
        let inv = self.witness(l, x.value().map(|x| x.invert().unwrap_or(Fp::ZERO)))?;
        let xi = self.mul(l, x, &inv)?;
        let z = self.not(l, &xi)?;
        let xz = self.mul(l, x, &z)?;
        self.assert_constant(l, &xz, Fp::ZERO)?;
        Ok(z)
    }

    /// `(lo, hi)` with `x = lo + 2^128 hi`, `lo < 2^128`, `hi < 2^126`.
    pub fn limbs(&mut self, l: &mut impl Layouter<Fp>, x: &Cell) -> Result<(Cell, Cell), Error> {
        let (lo_v, hi_v) = x
            .value()
            .map(|v| {
                let r = v.to_repr();
                let mut lo = [0u8; 32];
                lo[..16].copy_from_slice(&r[..16]);
                let mut hi = [0u8; 32];
                hi[..16].copy_from_slice(&r[16..]);
                (Fp::from_repr(lo).unwrap(), Fp::from_repr(hi).unwrap())
            })
            .unzip();
        let lo = self.witness(l, lo_v)?;
        let hi = self.witness(l, hi_v)?;
        self.range(l, &lo, 12, 8)?;
        self.range(l, &hi, 12, 6)?;
        let zero = self.constant(l, Fp::ZERO)?;
        let two_128 = Fp::from_u128(1u128 << 64).square();
        let back = self.lin(l, &lo, two_128, &hi, &zero)?;
        self.assert_equal(l, &back, x)?;
        Ok((lo, hi))
    }

    /// `x < y` as a boolean, for `x, y < 2^128`.
    pub fn lt128(&mut self, l: &mut impl Layouter<Fp>, x: &Cell, y: &Cell) -> Result<Cell, Error> {
        let lt_v = x.value().zip(y.value()).map(|(x, y)| {
            x.to_repr() < y.to_repr() && {
                // the reprs are little-endian: compare as integers
                let xi = u128::from_le_bytes(x.to_repr()[..16].try_into().unwrap());
                let yi = u128::from_le_bytes(y.to_repr()[..16].try_into().unwrap());
                xi < yi
            } || {
                let xi = u128::from_le_bytes(x.to_repr()[..16].try_into().unwrap());
                let yi = u128::from_le_bytes(y.to_repr()[..16].try_into().unwrap());
                xi < yi
            }
        });
        let b = self.bit(l, lt_v)?;
        // w = b (y − x − 1) + (1 − b)(x − y) < 2^128
        let minus_one = self.constant(l, -Fp::ONE)?;
        let d1 = self.lin(l, y, -Fp::ONE, x, &minus_one)?;
        let d2 = self.sub(l, x, y)?;
        let w = self.select(l, &b, &d1, &d2)?;
        self.range(l, &w, 12, 8)?;
        Ok(b)
    }

    /// `a < b` as a boolean for canonical limbs of both.
    pub fn lt(
        &mut self,
        l: &mut impl Layouter<Fp>,
        a: &(Cell, Cell),
        b: &(Cell, Cell),
    ) -> Result<Cell, Error> {
        let hi_lt = self.lt128(l, &a.1, &b.1)?;
        let d = self.sub(l, &a.1, &b.1)?;
        let hi_eq = self.is_zero(l, &d)?;
        let lo_lt = self.lt128(l, &a.0, &b.0)?;
        let t = self.mul(l, &hi_eq, &lo_lt)?;
        self.add(l, &hi_lt, &t)
    }
}

/// The state opening as cells.
struct Opening {
    root: Cell,
    size: Cell,
    nf_root: Cell,
    nf_size: Cell,
    h_root: Cell,
    height: Cell,
    applied: Cell,
}

impl Opening {
    fn digest(&self, ctx: &mut Ctx, l: &mut impl Layouter<Fp>) -> Result<Cell, Error> {
        let tag = ctx.constant(l, t_state())?;
        ctx.hash(
            l,
            [
                tag,
                self.root.clone(),
                self.size.clone(),
                self.nf_root.clone(),
                self.nf_size.clone(),
                self.h_root.clone(),
                self.height.clone(),
                self.applied.clone(),
            ],
        )
    }
}

impl BatchCircuit {
    /// The public inputs: `s_prev`, `s_next`, `D`.
    pub fn instance(&self) -> Vec<Fp> {
        let st = self
            .witness
            .as_ref()
            .expect("values")
            .check(&self.params)
            .expect("a witness the relation accepts");
        st.to_field_elements()
    }

    /// The relation, as a function of the configuration and a layouter;
    /// the slots' element cells are returned for an embedding circuit to
    /// bind, and the three public values follow in the instance column
    /// from `first_row` (or are only returned, without a column).
    pub fn synthesize_core(
        &self,
        cfg: &BatchConfig,
        l: &mut impl Layouter<Fp>,
        instance: Option<(Column<Instance>, usize)>,
    ) -> Result<(Vec<Vec<Cell>>, [Cell; 3]), Error> {
        let mut ctx = Ctx::new(cfg);
        let ctx = &mut ctx;
        let w = self.witness.as_ref();
        let p = &self.params;
        let f_u32 = |v: u32| Fp::from(v as u64);
        let wit = |ctx: &mut Ctx, l: &mut _, v: Option<Fp>| -> Result<Cell, Error> {
            ctx.witness(l, v.map(Value::known).unwrap_or(Value::unknown()))
        };
        let zero = ctx.constant(l, Fp::ZERO)?;
        let one = ctx.constant(l, Fp::ONE)?;

        // ---- the opening before
        let prev = Opening {
            root: wit(ctx, l, w.map(|w| w.prev.root))?,
            size: wit(ctx, l, w.map(|w| Fp::from(w.prev.size)))?,
            nf_root: wit(ctx, l, w.map(|w| w.prev.nf_root))?,
            nf_size: wit(ctx, l, w.map(|w| Fp::from(w.prev.nf_size)))?,
            h_root: wit(ctx, l, w.map(|w| w.prev.h_root))?,
            height: wit(ctx, l, w.map(|w| f_u32(w.prev.height)))?,
            applied: wit(ctx, l, w.map(|w| f_u32(w.prev.applied)))?,
        };
        ctx.range(l, &prev.height, 3, 2)?;
        let s_prev = prev.digest(ctx, l)?;

        let activation = f_u32(p.activation);
        let empty_root = EMPTY_ROOTS[DEPTH];
        let mut cur_root = prev.root.clone();
        let mut cur_size = prev.size.clone();
        let mut cur_nf_root = prev.nf_root.clone();
        let mut cur_nf_size = prev.nf_size.clone();
        let mut cur_applied = prev.applied.clone();
        let mut all_elems: Vec<Vec<Cell>> = Vec::with_capacity(self.n);

        for i in 0..self.n {
            let sw: Option<&SlotWitness> = w.and_then(|w| w.slots.get(i)).and_then(|s| s.as_ref());
            let known = w.is_some();
            let active = ctx.bit(
                l,
                if known {
                    Value::known(sw.is_some())
                } else {
                    Value::unknown()
                },
            )?;
            let inactive = ctx.not(l, &active)?;
            let elems_native = sw
                .map(|s| s.statement.to_elements())
                .unwrap_or([Fp::ZERO; SLOT_ELEMENTS]);
            let mut elems = Vec::with_capacity(SLOT_ELEMENTS);
            for e in &elems_native {
                let v = wit(ctx, l, known.then_some(*e))?;
                // an empty slot is all zeros, so that D is canonical
                ctx.cond_eq(l, &inactive, &v, &zero)?;
                elems.push(v);
            }
            let h_anchor = elems[0].clone();
            let r_anchor = elems[1].clone();
            let nfs = [elems[2].clone(), elems[3].clone()];
            let h_body = elems[SLOT_ELEMENTS - 2].clone();
            let kind = elems[SLOT_ELEMENTS - 1].clone();
            // the kind: 0 a transfer, 1 a mint; anything else refused
            let kk = ctx.mul(l, &kind, &kind)?;
            ctx.assert_equal(l, &kk, &kind)?;
            let not_mint = ctx.not(l, &kind)?;
            let active_tx = ctx.mul(l, &active, &not_mint)?;

            // ---- the anchor: in the window, its root in the root tree
            ctx.range(l, &h_anchor, 3, 2)?;
            let pre_v = sw.map(|s| !s.statement.mint && s.statement.h_anchor < p.activation);
            let pre = ctx.bit(
                l,
                if known {
                    Value::known(pre_v.unwrap_or(false))
                } else {
                    Value::unknown()
                },
            )?;
            let pre_anchor = ctx.mul(l, &active_tx, &pre)?;
            let not_pre = ctx.not(l, &pre)?;
            let in_tree = ctx.mul(l, &active_tx, &not_pre)?;
            // pre: activation − 1 ≥ h_anchor; the root is the initial one
            let act_m1 = ctx.constant(l, activation - Fp::ONE)?;
            let d = ctx.sub(l, &act_m1, &h_anchor)?;
            ctx.cond_range(l, &pre_anchor, &d, 3, 2)?;
            ctx.cond_eq_const(l, &pre_anchor, &r_anchor, empty_root)?;
            // in the tree: h_anchor ≥ activation, at leaf h_anchor − activation + 1
            let d = ctx.add_const(l, &h_anchor, -activation)?;
            ctx.cond_range(l, &in_tree, &d, 3, 2)?;
            let anchor_pos_v = sw.map(|s| {
                if s.statement.mint || s.statement.h_anchor < p.activation {
                    Fp::ZERO
                } else {
                    f_u32(s.statement.h_anchor - p.activation + 1)
                }
            });
            let anchor_pos = wit(ctx, l, known.then_some(anchor_pos_v.unwrap_or(Fp::ZERO)))?;
            let d1 = ctx.add_const(l, &d, Fp::ONE)?;
            ctx.cond_eq(l, &in_tree, &anchor_pos, &d1)?;
            let anchor_bits = ctx.bits32(l, &anchor_pos)?;
            let anchor_sibs = self.siblings(ctx, l, known, sw.map(|s| &s.anchor_siblings))?;
            let ar = ctx.merkle_root(l, &r_anchor, &anchor_bits, &anchor_sibs)?;
            ctx.cond_eq(l, &in_tree, &ar, &prev.h_root)?;
            // the window: h_anchor + w ≥ height ≥ h_anchor + k_min
            let hw = ctx.add_const(l, &h_anchor, f_u32(p.window_w))?;
            let d = ctx.sub(l, &hw, &prev.height)?;
            ctx.cond_range(l, &active_tx, &d, 3, 3)?;
            let hk = ctx.add_const(l, &h_anchor, f_u32(p.k_min))?;
            let d = ctx.sub(l, &prev.height, &hk)?;
            ctx.cond_range(l, &active_tx, &d, 3, 3)?;

            // ---- the nullifiers: absent, then inserted, in order
            for (k, nf) in nfs.iter().enumerate() {
                let ins = sw.map(|s| &s.nullifiers[k]);
                let lv = wit(
                    ctx,
                    l,
                    known.then_some(ins.map_or(Fp::ZERO, |i| i.low.value)),
                )?;
                let ln = wit(
                    ctx,
                    l,
                    known.then_some(ins.map_or(Fp::ZERO, |i| i.low.next)),
                )?;
                let low_pos = wit(
                    ctx,
                    l,
                    known.then_some(ins.map_or(Fp::ZERO, |i| Fp::from(i.low_path.position))),
                )?;
                let low_bits = ctx.bits32(l, &low_pos)?;
                let low_sibs = self.siblings(ctx, l, known, ins.map(|i| &i.low_path.siblings))?;
                let new_pos = wit(
                    ctx,
                    l,
                    known.then_some(ins.map_or(Fp::ZERO, |i| Fp::from(i.new_path.position))),
                )?;
                let new_bits = ctx.bits32(l, &new_pos)?;
                let new_sibs = self.siblings(ctx, l, known, ins.map(|i| &i.new_path.siblings))?;
                // low < nf < next (or next = 0)
                let lv_l = ctx.limbs(l, &lv)?;
                let nf_l = ctx.limbs(l, nf)?;
                let ln_l = ctx.limbs(l, &ln)?;
                let a = ctx.lt(l, &lv_l, &nf_l)?;
                let z = ctx.is_zero(l, &ln)?;
                let b = ctx.lt(l, &nf_l, &ln_l)?;
                let o = ctx.or(l, &z, &b)?;
                let ordered = ctx.mul(l, &a, &o)?;
                ctx.cond_eq(l, &active_tx, &ordered, &one)?;
                let tag = ctx.constant(l, t_imt())?;
                let low_leaf = ctx.hash(l, [tag.clone(), lv.clone(), ln.clone()])?;
                let before = ctx.merkle_root(l, &low_leaf, &low_bits, &low_sibs)?;
                ctx.cond_eq(l, &active_tx, &before, &cur_nf_root)?;
                let low_after = ctx.hash(l, [tag.clone(), lv.clone(), nf.clone()])?;
                let mid = ctx.merkle_root(l, &low_after, &low_bits, &low_sibs)?;
                ctx.cond_eq(l, &active_tx, &new_pos, &cur_nf_size)?;
                let empty = ctx.merkle_root(l, &zero, &new_bits, &new_sibs)?;
                ctx.cond_eq(l, &active_tx, &empty, &mid)?;
                let new_leaf = ctx.hash(l, [tag, nf.clone(), ln.clone()])?;
                let next = ctx.merkle_root(l, &new_leaf, &new_bits, &new_sibs)?;
                cur_nf_root = ctx.select(l, &active_tx, &next, &cur_nf_root)?;
                cur_nf_size = ctx.add(l, &cur_nf_size, &active_tx)?;
            }

            // ---- the output leaves, appended in order
            let salt = ctx.constant(l, p.const_salt)?;
            let tag = ctx.constant(l, t_leaf())?;
            for j in 0..2 {
                let base = 4 + j * 5;
                let jc = ctx.constant(l, Fp::from(j as u64))?;
                // leaf = PH_A(T_LEAF, salt, h_body, j, x, y, c0, c1, tag, h_aux = 0)
                let leaf = ctx.hash(
                    l,
                    [
                        tag.clone(),
                        salt.clone(),
                        h_body.clone(),
                        jc,
                        elems[base].clone(),
                        elems[base + 1].clone(),
                        elems[base + 2].clone(),
                        elems[base + 3].clone(),
                        elems[base + 4].clone(),
                        zero.clone(),
                    ],
                )?;
                let lp = sw.map(|s| &s.leaves[j]);
                let pos = wit(
                    ctx,
                    l,
                    known.then_some(lp.map_or(Fp::ZERO, |p| Fp::from(p.position))),
                )?;
                let bits = ctx.bits32(l, &pos)?;
                let sibs = self.siblings(ctx, l, known, lp.map(|p| &p.siblings))?;
                // a mint appends its one leaf (index 0) only
                let on = if j == 0 {
                    active.clone()
                } else {
                    active_tx.clone()
                };
                ctx.cond_eq(l, &on, &pos, &cur_size)?;
                let empty = ctx.merkle_root(l, &zero, &bits, &sibs)?;
                ctx.cond_eq(l, &on, &empty, &cur_root)?;
                let next = ctx.merkle_root(l, &leaf, &bits, &sibs)?;
                cur_root = ctx.select(l, &on, &next, &cur_root)?;
                cur_size = ctx.add(l, &cur_size, &on)?;
            }
            cur_applied = ctx.add(l, &cur_applied, &active)?;
            all_elems.push(elems);
        }

        // ---- the end of a block: the note root appended to the root tree
        let final_block = ctx.bit(
            l,
            if known_of(w) {
                Value::known(w.is_some_and(|w| w.final_block))
            } else {
                Value::unknown()
            },
        )?;
        let ra = w.and_then(|w| w.root_append.as_ref());
        let ra_pos = wit(
            ctx,
            l,
            w.map(|_| ra.map_or(Fp::ZERO, |p| Fp::from(p.position))),
        )?;
        let ra_bits = ctx.bits32(l, &ra_pos)?;
        let ra_sibs = self.siblings(ctx, l, w.is_some(), ra.map(|p| &p.siblings))?;
        let expected = ctx.add_const(l, &prev.height, -activation + Fp::ONE)?;
        ctx.cond_eq(l, &final_block, &ra_pos, &expected)?;
        let empty = ctx.merkle_root(l, &zero, &ra_bits, &ra_sibs)?;
        ctx.cond_eq(l, &final_block, &empty, &prev.h_root)?;
        let appended = ctx.merkle_root(l, &cur_root, &ra_bits, &ra_sibs)?;
        let next_h_root = ctx.select(l, &final_block, &appended, &prev.h_root)?;
        let next_height = ctx.add(l, &prev.height, &final_block)?;
        let next_applied = ctx.select(l, &final_block, &zero, &cur_applied)?;
        let next = Opening {
            root: cur_root,
            size: cur_size,
            nf_root: cur_nf_root,
            nf_size: cur_nf_size,
            h_root: next_h_root,
            height: next_height,
            applied: next_applied,
        };
        let s_next = next.digest(ctx, l)?;

        // ---- D: the chain over the elements in chunks of 8 from the slot count
        let tag = ctx.constant(l, t_batch())?;
        let mut acc = ctx.constant(l, Fp::from(self.n as u64))?;
        let flat: Vec<Cell> = all_elems.iter().flatten().cloned().collect();
        for chunk in flat.chunks(DIGEST_CHUNK) {
            let mut msg: Vec<Cell> = vec![tag.clone(), acc.clone()];
            msg.extend(chunk.iter().cloned());
            while msg.len() < DIGEST_CHUNK + 2 {
                msg.push(zero.clone());
            }
            acc = ctx.hash::<10>(l, msg.try_into().unwrap())?;
        }
        let d = acc;

        if let Some((col, first_row)) = instance {
            l.constrain_instance(s_prev.cell(), col, first_row)?;
            l.constrain_instance(s_next.cell(), col, first_row + 1)?;
            l.constrain_instance(d.cell(), col, first_row + 2)?;
        }
        eprintln!("batch relation: {} small rows, {} slots", ctx.rows, self.n);
        Ok((all_elems, [s_prev, s_next, d]))
    }

    fn siblings(
        &self,
        ctx: &mut Ctx,
        l: &mut impl Layouter<Fp>,
        known: bool,
        s: Option<&[Fp; DEPTH]>,
    ) -> Result<Vec<Cell>, Error> {
        (0..DEPTH)
            .map(|k| {
                let v = if known {
                    Value::known(s.map_or(Fp::ZERO, |s| s[k]))
                } else {
                    Value::unknown()
                };
                ctx.witness(l, v)
            })
            .collect()
    }
}

fn known_of(w: Option<&BatchWitness>) -> bool {
    w.is_some()
}

impl Circuit<Fp> for BatchCircuit {
    type Config = BatchConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        BatchCircuit {
            n: self.n,
            params: self.params,
            witness: None,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> BatchConfig {
        BatchConfig::configure(meta)
    }

    fn synthesize(&self, cfg: BatchConfig, mut l: impl Layouter<Fp>) -> Result<(), Error> {
        cfg.assign_table(&mut l)?;
        self.synthesize_core(&cfg, &mut l, Some((cfg.instance, 0)))
            .map(|_| ())
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    //! A synthetic history: trees driven as the indexer drives them, the
    //! witnesses taken the same way (`sba-indexer/src/replay.rs`).
    use super::*;
    use group::prime::PrimeCurveAffine;
    use pasta_curves::arithmetic::CurveAffine;
    use sba_core::batch::{no_path, NullifierInsert, SlotStatement, StateOpening, NO_CT};
    use sba_core::imt::IndexedMerkleTree;
    use sba_core::note::{note_leaf, NoteCiphertext};
    use sba_core::tree::NoteTree;
    use sba_core::xy;
    use sba_primitives::Affine;

    pub struct History {
        pub params: BatchParams,
        pub tree: NoteTree,
        pub nf_tree: IndexedMerkleTree,
        pub h_tree: NoteTree,
        pub height: u32,
        pub roots: Vec<Fp>,
    }

    impl History {
        pub fn new(params: BatchParams) -> Self {
            let mut h_tree = NoteTree::new();
            h_tree.append(EMPTY_ROOTS[DEPTH]);
            History {
                params,
                tree: NoteTree::new(),
                nf_tree: IndexedMerkleTree::new(),
                h_tree,
                height: params.activation,
                roots: vec![EMPTY_ROOTS[DEPTH]],
            }
        }

        pub fn opening(&self) -> StateOpening {
            StateOpening {
                root: self.tree.root(),
                size: self.tree.size(),
                nf_root: self.nf_tree.root(),
                nf_size: self.nf_tree.size(),
                h_root: self.h_tree.root(),
                height: self.height,
                applied: 0,
            }
        }

        /// `R[h]` as replay defines it.
        pub fn root_at(&self, h: u32) -> Fp {
            if h < self.params.activation {
                EMPTY_ROOTS[DEPTH]
            } else {
                self.roots[(h - self.params.activation) as usize + 1]
            }
        }

        fn point(seed: u64) -> Affine {
            use group::Curve;
            (Affine::generator() * sba_primitives::Scalar::from(seed + 7)).to_affine()
        }

        /// A transfer anchored at `h_anchor`, with fresh nullifiers.
        pub fn transfer(&mut self, h_anchor: u32, seed: u64) -> SlotWitness {
            let p = self.params;
            let st = SlotStatement {
                h_anchor,
                r_anchor: self.root_at(h_anchor),
                nullifiers: [Fp::from(1000 + seed * 3), Fp::from(5000 + seed * 7)],
                pk_eph: [xy(&Self::point(seed)), xy(&Self::point(seed + 100))],
                ct: [
                    NoteCiphertext {
                        c0: Fp::from(seed),
                        c1: Fp::from(seed + 1),
                        tag: Fp::from(2),
                    },
                    NoteCiphertext {
                        c0: Fp::from(seed + 3),
                        c1: Fp::from(seed + 4),
                        tag: Fp::from(5),
                    },
                ],
                h_body: Fp::from(77 + seed),
                mint: false,
            };
            let anchor_siblings = if h_anchor < p.activation {
                [Fp::ZERO; DEPTH]
            } else {
                self.h_tree
                    .path((h_anchor - p.activation) as u64 + 1)
                    .unwrap()
                    .siblings
            };
            let mut leaves = Vec::new();
            for j in 0..2 {
                let pk: Affine =
                    Option::from(Affine::from_xy(st.pk_eph[j].0, st.pk_eph[j].1)).unwrap();
                let leaf = note_leaf(&p.const_salt, &st.h_body, j as u64, &pk, &st.ct[j]);
                leaves.push(self.tree.append_path());
                self.tree.append(leaf);
            }
            let nullifiers: Vec<NullifierInsert> = st
                .nullifiers
                .iter()
                .map(|nf| NullifierInsert::from(&self.nf_tree.insert(*nf).unwrap()))
                .collect();
            SlotWitness {
                statement: st,
                anchor_siblings,
                nullifiers: nullifiers.try_into().unwrap(),
                leaves: leaves.try_into().unwrap(),
            }
        }

        pub fn mint(&mut self, seed: u64) -> SlotWitness {
            let p = self.params;
            let st = SlotStatement {
                h_anchor: 0,
                r_anchor: Fp::ZERO,
                nullifiers: [Fp::ZERO; 2],
                pk_eph: [xy(&Self::point(seed)), (Fp::ZERO, Fp::ZERO)],
                ct: [
                    NoteCiphertext {
                        c0: Fp::from(seed),
                        c1: Fp::from(9),
                        tag: Fp::from(8),
                    },
                    NO_CT,
                ],
                h_body: Fp::from(99 + seed),
                mint: true,
            };
            let pk: Affine = Option::from(Affine::from_xy(st.pk_eph[0].0, st.pk_eph[0].1)).unwrap();
            let leaf = note_leaf(&p.const_salt, &st.h_body, 0, &pk, &st.ct[0]);
            let path = self.tree.append_path();
            self.tree.append(leaf);
            SlotWitness {
                statement: st,
                anchor_siblings: [Fp::ZERO; DEPTH],
                nullifiers: [NullifierInsert::none(), NullifierInsert::none()],
                leaves: [path, no_path()],
            }
        }

        /// Close the block: its root into the root tree.
        pub fn end_block(&mut self) -> sba_core::tree::MerklePath {
            let path = self.h_tree.append_path();
            let root = self.tree.root();
            self.h_tree.append(root);
            self.roots.push(root);
            self.height += 1;
            path
        }
    }

    pub fn params() -> BatchParams {
        BatchParams {
            activation: 1000,
            window_w: 100,
            k_min: 1,
            const_salt: Fp::from(424242),
        }
    }

    /// Two blocks: a mint; then a transfer anchored at the first block and
    /// another mint. The witness of the second block, with `n` slots.
    pub fn two_blocks(n: usize) -> (BatchWitness, BatchParams) {
        let p = params();
        let mut h = History::new(p);
        let _ = h.mint(1);
        h.end_block();
        let prev = h.opening();
        let mut slots = vec![Some(h.transfer(1000, 2)), Some(h.mint(3))];
        let root_append = h.end_block();
        while slots.len() < n {
            slots.push(None);
        }
        (
            BatchWitness {
                prev,
                slots,
                final_block: true,
                root_append: Some(root_append),
            },
            p,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::{params, two_blocks, History};
    use super::*;
    use halo2_proofs::dev::MockProver;

    fn mock(witness: &BatchWitness, params: BatchParams, n: usize) -> Result<(), String> {
        let st = witness.check(&params).ok_or("native check refuses")?;
        let circuit = BatchCircuit {
            n,
            params,
            witness: Some(witness.clone()),
        };
        let prover = MockProver::run(17, &circuit, vec![st.to_field_elements()]).unwrap();
        prover
            .verify()
            .map_err(|e| format!("{} failures: {:?}", e.len(), &e[..e.len().min(3)]))
    }

    #[derive(Clone)]
    struct HashOnly {
        n: usize,
    }

    impl Circuit<Fp> for HashOnly {
        type Config = BatchConfig;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self {
            self.clone()
        }
        fn configure(meta: &mut ConstraintSystem<Fp>) -> BatchConfig {
            BatchConfig::configure(meta)
        }
        fn synthesize(&self, cfg: BatchConfig, mut l: impl Layouter<Fp>) -> Result<(), Error> {
            cfg.assign_table(&mut l)?;
            let mut ctx = Ctx::new(&cfg);
            let inputs: Vec<Fp> = (0..self.n as u64).map(|i| Fp::from(10 + i)).collect();
            let native = sba_primitives::poseidon::hash(inputs[0], &inputs[1..]);
            let cells: Vec<Cell> = inputs
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    if i == 0 || i == 3 {
                        ctx.constant(&mut l, *v)
                    } else {
                        ctx.witness(&mut l, Value::known(*v))
                    }
                })
                .collect::<Result<_, _>>()?;
            let out = match self.n {
                3 => ctx.hash::<3>(&mut l, cells.try_into().unwrap())?,
                8 => ctx.hash::<8>(&mut l, cells.try_into().unwrap())?,
                9 => ctx.hash::<9>(&mut l, cells.try_into().unwrap())?,
                10 => ctx.hash::<10>(&mut l, cells.try_into().unwrap())?,
                _ => unreachable!(),
            };
            ctx.assert_constant(&mut l, &out, native)
        }
    }

    #[test]
    fn the_hash_gadget_matches_native_for_every_length() {
        for n in [3usize, 8, 9, 10] {
            MockProver::run(11, &HashOnly { n }, vec![vec![]])
                .unwrap()
                .assert_satisfied();
        }
    }

    #[test]
    fn single_slot_blocks_of_every_kind_are_accepted() {
        let p = params();
        // (a) a block with one mint
        let mut h = History::new(p);
        let prev = h.opening();
        let slot = h.mint(1);
        let ra = h.end_block();
        let w = BatchWitness {
            prev,
            slots: vec![Some(slot)],
            final_block: true,
            root_append: Some(ra),
        };
        assert_eq!(mock(&w, p, 1), Ok(()), "mint only");
        // (b) a block with one transfer anchored before activation
        let mut h = History::new(p);
        let prev = h.opening();
        let slot = h.transfer(999, 2);
        let ra = h.end_block();
        let w = BatchWitness {
            prev,
            slots: vec![Some(slot)],
            final_block: true,
            root_append: Some(ra),
        };
        assert_eq!(mock(&w, p, 1), Ok(()), "transfer, pre-activation anchor");
        // (c) a transfer anchored in the tree, no final block
        let mut h = History::new(p);
        h.mint(1);
        h.end_block();
        let prev = h.opening();
        let slot = h.transfer(1000, 2);
        let w = BatchWitness {
            prev,
            slots: vec![Some(slot)],
            final_block: false,
            root_append: None,
        };
        assert_eq!(
            mock(&w, p, 1),
            Ok(()),
            "transfer, anchor in tree, open block"
        );
        // (d) an empty slot only
        let mut h = History::new(p);
        let prev = h.opening();
        let ra = h.end_block();
        let w = BatchWitness {
            prev,
            slots: vec![None],
            final_block: true,
            root_append: Some(ra),
        };
        assert_eq!(mock(&w, p, 1), Ok(()), "empty slot");
    }

    #[test]
    fn the_relation_accepts_a_synthetic_block_and_refuses_tampering() {
        let (witness, params) = two_blocks(2);
        let st = witness.check(&params).expect("the native check accepts");
        let circuit = BatchCircuit {
            n: 2,
            params,
            witness: Some(witness.clone()),
        };
        let instance = st.to_field_elements();
        let mut k = 16;
        let t = std::time::Instant::now();
        let prover = loop {
            match MockProver::run(k, &circuit, vec![instance.clone()]) {
                Ok(p) => break p,
                Err(_) => {
                    k += 1;
                    assert!(k <= 20);
                }
            }
        };
        println!(
            "batch relation, 2 slots: fits k = {k} (mock {:.1} s)",
            t.elapsed().as_secs_f64()
        );
        prover.assert_satisfied();
        println!(
            "{:?}",
            halo2_proofs::dev::CircuitCost::<pasta_curves::vesta::Point, _>::measure(k, &circuit)
        );
        // a wrong D, a wrong s_next
        let mut bad = instance.clone();
        bad[2] += Fp::ONE;
        assert!(MockProver::run(k, &circuit, vec![bad])
            .unwrap()
            .verify()
            .is_err());
        let mut bad = instance.clone();
        bad[1] += Fp::ONE;
        assert!(MockProver::run(k, &circuit, vec![bad])
            .unwrap()
            .verify()
            .is_err());
        // a nullifier out of order (below its low leaf) in the witness
        let mut tampered = witness.clone();
        tampered.slots[0].as_mut().unwrap().statement.nullifiers[0] = Fp::from(1u64);
        let bad = BatchCircuit {
            n: 2,
            params,
            witness: Some(tampered),
        };
        assert!(MockProver::run(k, &bad, vec![instance.clone()])
            .unwrap()
            .verify()
            .is_err());
        // the anchor outside the window
        let mut tampered = witness.clone();
        tampered.slots[0].as_mut().unwrap().statement.h_anchor = 900;
        tampered.slots[0].as_mut().unwrap().statement.r_anchor = EMPTY_ROOTS[DEPTH];
        let bad = BatchCircuit {
            n: 2,
            params,
            witness: Some(tampered),
        };
        assert!(MockProver::run(k, &bad, vec![instance])
            .unwrap()
            .verify()
            .is_err());
    }
}
