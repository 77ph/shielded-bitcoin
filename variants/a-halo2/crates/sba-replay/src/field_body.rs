// Field arithmetic over `F` as a chip, for the field side of the verifier
// (`docs/REPLAY-PROOF-A.md` §3.3, piece 3): cells carrying `F` values,
// the operations the verifier's algebra needs (add, multiply, scale by a
// constant, negate, invert, constant), and an evaluator of `halo2_proofs`'
// gate expressions over them. One gate per row:
//
// `q · (a · b · m + a · sa + b · sb + c · sc + k − d) = 0`
//
// with `m, sa, sb, sc, k` fixed per row, which covers every operation
// (`d = a·b`: m = 1; `d = a + s·b`: sa = 1, sb = s; `d = k`: constant;
// inversion as `a · b = 1` with `b` witnessed).

use ff::Field;
use halo2_proofs::circuit::{AssignedCell, Layouter, Value};
use halo2_proofs::plonk::{
    Advice, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Selector,
};
use halo2_proofs::poly::Rotation;

pub type Cell = AssignedCell<F, F>;

#[derive(Clone, Debug)]
pub struct FieldConfig {
    pub a: Column<Advice>,
    pub b: Column<Advice>,
    pub c: Column<Advice>,
    pub d: Column<Advice>,
    m: Column<Fixed>,
    sa: Column<Fixed>,
    sb: Column<Fixed>,
    sc: Column<Fixed>,
    k: Column<Fixed>,
    q: Selector,
}

impl FieldConfig {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advices: [Column<Advice>; 4],
        fixed: [Column<Fixed>; 5],
    ) -> Self {
        let [a, b, c, d] = advices;
        let [m, sa, sb, sc, k] = fixed;
        let q = meta.selector();
        meta.create_gate("a b m + a sa + b sb + c sc + k - d", |meta| {
            let q = meta.query_selector(q);
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());
            let d = meta.query_advice(d, Rotation::cur());
            let m = meta.query_fixed(m);
            let sa = meta.query_fixed(sa);
            let sb = meta.query_fixed(sb);
            let sc = meta.query_fixed(sc);
            let k = meta.query_fixed(k);
            Constraints::with_selector(
                q,
                [(
                    "row",
                    a.clone() * b.clone() * m + a * sa + b * sb + c * sc + k - d,
                )],
            )
        });
        FieldConfig {
            a,
            b,
            c,
            d,
            m,
            sa,
            sb,
            sc,
            k,
            q,
        }
    }
}

/// The chip: every operation is one row; `rows` counts them.
pub struct FieldChip<'c> {
    cfg: &'c FieldConfig,
    pub rows: usize,
}

/// A row's inputs: cells to copy in (or absent, meaning zero) and the
/// fixed coefficients.
struct Row<'a> {
    a: Option<&'a Cell>,
    b: Option<&'a Cell>,
    c: Option<&'a Cell>,
    m: F,
    sa: F,
    sb: F,
    sc: F,
    k: F,
}

impl<'c> FieldChip<'c> {
    pub fn new(cfg: &'c FieldConfig) -> Self {
        FieldChip { cfg, rows: 0 }
    }

    fn row(
        &mut self,
        layouter: &mut impl Layouter<F>,
        name: &'static str,
        r: Row,
    ) -> Result<Cell, Error> {
        let cfg = self.cfg;
        self.rows += 1;
        let v = |x: Option<&Cell>| {
            x.map(|c| c.value().copied())
                .unwrap_or(Value::known(F::ZERO))
        };
        let (va, vb, vc) = (v(r.a), v(r.b), v(r.c));
        let d = va
            .zip(vb)
            .zip(vc)
            .map(|((a, b), c)| a * b * r.m + a * r.sa + b * r.sb + c * r.sc + r.k);
        layouter.assign_region(
            || name,
            |mut region| {
                cfg.q.enable(&mut region, 0)?;
                for (col, cell) in [(cfg.a, r.a), (cfg.b, r.b), (cfg.c, r.c)] {
                    match cell {
                        Some(cell) => {
                            cell.copy_advice(|| "in", &mut region, col, 0)?;
                        }
                        None => {
                            region.assign_advice_from_constant(|| "zero", col, 0, F::ZERO)?;
                        }
                    }
                }
                for (col, val) in [
                    (cfg.m, r.m),
                    (cfg.sa, r.sa),
                    (cfg.sb, r.sb),
                    (cfg.sc, r.sc),
                    (cfg.k, r.k),
                ] {
                    region.assign_fixed(|| "coef", col, 0, || Value::known(val))?;
                }
                region.assign_advice(|| "d", cfg.d, 0, || d)
            },
        )
    }

    pub fn constant(&mut self, l: &mut impl Layouter<F>, k: F) -> Result<Cell, Error> {
        self.row(
            l,
            "constant",
            Row {
                a: None,
                b: None,
                c: None,
                m: F::ZERO,
                sa: F::ZERO,
                sb: F::ZERO,
                sc: F::ZERO,
                k,
            },
        )
    }

    /// A witnessed value (a public input to be, or a proof scalar).
    pub fn witness(&mut self, l: &mut impl Layouter<F>, v: Value<F>) -> Result<Cell, Error> {
        let cfg = self.cfg;
        layouter_assign(l, cfg.d, v)
    }

    pub fn add(&mut self, l: &mut impl Layouter<F>, a: &Cell, b: &Cell) -> Result<Cell, Error> {
        self.row(
            l,
            "add",
            Row {
                a: Some(a),
                b: Some(b),
                c: None,
                m: F::ZERO,
                sa: F::ONE,
                sb: F::ONE,
                sc: F::ZERO,
                k: F::ZERO,
            },
        )
    }

    pub fn sub(&mut self, l: &mut impl Layouter<F>, a: &Cell, b: &Cell) -> Result<Cell, Error> {
        self.row(
            l,
            "sub",
            Row {
                a: Some(a),
                b: Some(b),
                c: None,
                m: F::ZERO,
                sa: F::ONE,
                sb: -F::ONE,
                sc: F::ZERO,
                k: F::ZERO,
            },
        )
    }

    pub fn mul(&mut self, l: &mut impl Layouter<F>, a: &Cell, b: &Cell) -> Result<Cell, Error> {
        self.row(
            l,
            "mul",
            Row {
                a: Some(a),
                b: Some(b),
                c: None,
                m: F::ONE,
                sa: F::ZERO,
                sb: F::ZERO,
                sc: F::ZERO,
                k: F::ZERO,
            },
        )
    }

    /// `a · b + c`.
    pub fn mul_add(
        &mut self,
        l: &mut impl Layouter<F>,
        a: &Cell,
        b: &Cell,
        c: &Cell,
    ) -> Result<Cell, Error> {
        self.row(
            l,
            "mul_add",
            Row {
                a: Some(a),
                b: Some(b),
                c: Some(c),
                m: F::ONE,
                sa: F::ZERO,
                sb: F::ZERO,
                sc: F::ONE,
                k: F::ZERO,
            },
        )
    }

    /// `s · a + k`.
    pub fn affine(
        &mut self,
        l: &mut impl Layouter<F>,
        a: &Cell,
        s: F,
        k: F,
    ) -> Result<Cell, Error> {
        self.row(
            l,
            "affine",
            Row {
                a: Some(a),
                b: None,
                c: None,
                m: F::ZERO,
                sa: s,
                sb: F::ZERO,
                sc: F::ZERO,
                k,
            },
        )
    }

    pub fn neg(&mut self, l: &mut impl Layouter<F>, a: &Cell) -> Result<Cell, Error> {
        self.affine(l, a, -F::ONE, F::ZERO)
    }

    /// `a^{-1}`: `inv` witnessed and `a · inv = 1` enforced (`a ≠ 0`).
    pub fn invert(&mut self, l: &mut impl Layouter<F>, a: &Cell) -> Result<Cell, Error> {
        let inv = self.witness(l, a.value().map(|v| v.invert().unwrap_or(F::ZERO)))?;
        let one = self.mul(l, a, &inv)?;
        self.assert_constant(l, &one, F::ONE)?;
        Ok(inv)
    }

    /// `a == k`.
    pub fn assert_constant(
        &mut self,
        l: &mut impl Layouter<F>,
        a: &Cell,
        k: F,
    ) -> Result<(), Error> {
        let cfg = self.cfg;
        self.rows += 1;
        layouter_region_constant(l, cfg, a, k)
    }

    /// `a == b`.
    pub fn assert_equal(
        &mut self,
        l: &mut impl Layouter<F>,
        a: &Cell,
        b: &Cell,
    ) -> Result<(), Error> {
        l.assign_region(|| "eq", |mut r| r.constrain_equal(a.cell(), b.cell()))
    }

    /// Evaluate a gate expression at the given query evaluations.
    pub fn evaluate(
        &mut self,
        l: &mut impl Layouter<F>,
        e: &Expression<F>,
        fixed: &dyn Fn(usize) -> Cell,
        advice: &dyn Fn(usize) -> Cell,
        instance: &dyn Fn(usize) -> Cell,
    ) -> Result<Cell, Error> {
        Ok(match e {
            Expression::Constant(k) => self.constant(l, *k)?,
            Expression::Selector(_) => panic!("virtual selectors are removed during optimization"),
            Expression::Fixed(q) => fixed(q.index()),
            Expression::Advice(q) => advice(q.index()),
            Expression::Instance(q) => instance(q.index()),
            Expression::Negated(x) => {
                let x = self.evaluate(l, x, fixed, advice, instance)?;
                self.neg(l, &x)?
            }
            Expression::Sum(x, y) => {
                let x = self.evaluate(l, x, fixed, advice, instance)?;
                let y = self.evaluate(l, y, fixed, advice, instance)?;
                self.add(l, &x, &y)?
            }
            Expression::Product(x, y) => {
                let x = self.evaluate(l, x, fixed, advice, instance)?;
                let y = self.evaluate(l, y, fixed, advice, instance)?;
                self.mul(l, &x, &y)?
            }
            Expression::Scaled(x, s) => {
                let x = self.evaluate(l, x, fixed, advice, instance)?;
                self.affine(l, &x, *s, F::ZERO)?
            }
        })
    }
}

fn layouter_assign(
    l: &mut impl Layouter<F>,
    col: Column<Advice>,
    v: Value<F>,
) -> Result<Cell, Error> {
    l.assign_region(|| "witness", |mut r| r.assign_advice(|| "w", col, 0, || v))
}

fn layouter_region_constant(
    l: &mut impl Layouter<F>,
    cfg: &FieldConfig,
    a: &Cell,
    k: F,
) -> Result<(), Error> {
    l.assign_region(
        || "assert constant",
        |mut r| {
            let c = a.copy_advice(|| "a", &mut r, cfg.a, 0)?;
            r.constrain_constant(c.cell(), k)
        },
    )
}
