//! The proof transcript of `PROFILE-A.md` §1.1 as a gadget: the same duplex
//! Poseidon sponge over `Fq`, driven through `halo2_gadgets`' `Pow5Chip`,
//! squeezing 128-bit challenges as constrained cells. A circuit over `Fq`
//! that absorbs the elements of a proof in the verifier's order obtains
//! exactly the challenges the native verifier derives, which is the first
//! requirement of verifying such a proof in-circuit.
//!
//! Rule (as the native `sba_circuit::transcript::Sponge`): state
//! `[s0, s1, s2]` with `s2 = T_TRANSCRIPT`; absorb stores into a pending
//! rate slot, permuting first when both slots are taken; squeeze adds the
//! pending slots (zero for an empty one), permutes, clears them and returns
//! `s0`; the challenge is `s0 mod 2^128`, constrained by `s0 = c + 2^128 h`
//! with `c < 2^128` and `h < 2^127` through the 10-bit lookup table.

use std::iter;

use ff::{Field, PrimeField};
use halo2_gadgets::poseidon::primitives::{Absorbing, Domain, P128Pow5T3, State};
use halo2_gadgets::poseidon::{
    PaddedWord, PoseidonInstructions, PoseidonSpongeInstructions, Pow5Chip, Pow5Config,
};
use halo2_proofs::circuit::{AssignedCell, Layouter};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector};
use halo2_proofs::poly::Rotation;
use vesta_ecc::utilities::lookup_range_check::{LookupRangeCheck, VestaLookupRangeCheckConfig};

pub use sba_circuit::transcript::t_transcript;
pub use sba_primitives::poseidon_fq::Fq;

type Cell = AssignedCell<Fq, Fq>;
type Chip = Pow5Chip<Fq, 3, 2>;

/// The sponge domain: capacity initialised to the transcript tag, no padding
/// (the protocol fixes every message's length).
#[derive(Clone, Copy, Debug)]
pub struct TranscriptDomain;

impl Domain<Fq, 2> for TranscriptDomain {
    type Padding = iter::Empty<Fq>;

    fn name() -> String {
        "sb-a/v1/transcript".into()
    }

    fn initial_capacity_element() -> Fq {
        t_transcript()
    }

    fn padding(_input_len: usize) -> Self::Padding {
        iter::empty()
    }
}

#[derive(Clone, Debug)]
pub struct TranscriptConfig {
    pub poseidon: Pow5Config<Fq, 3, 2>,
    pub range: VestaLookupRangeCheckConfig,
    /// `[s0, c, h]` of the challenge split, one row.
    pub split: [Column<Advice>; 3],
    q_split: Selector,
}

impl TranscriptConfig {
    /// `advices`: three columns for the split gate (any, equality-enabled);
    /// `poseidon` and `range` configured by the caller (they are shared with
    /// the rest of a verifier circuit).
    pub fn configure(
        meta: &mut ConstraintSystem<Fq>,
        poseidon: Pow5Config<Fq, 3, 2>,
        range: VestaLookupRangeCheckConfig,
        split: [Column<Advice>; 3],
    ) -> Self {
        let q_split = meta.selector();
        meta.create_gate("s0 = c + 2^128 h", |m| {
            let q = m.query_selector(q_split);
            let s0 = m.query_advice(split[0], Rotation::cur());
            let c = m.query_advice(split[1], Rotation::cur());
            let h = m.query_advice(split[2], Rotation::cur());
            let two_128 = Expression::Constant(Fq::from_u128(1u128 << 64).square());
            Constraints::with_selector(q, [("split", s0 - c - h * two_128)])
        });
        TranscriptConfig {
            poseidon,
            range,
            split,
            q_split,
        }
    }
}

/// The sponge in the circuit.
pub struct Transcript<'c> {
    cfg: &'c TranscriptConfig,
    chip: Chip,
    state: State<<Chip as PoseidonInstructions<Fq, P128Pow5T3, 3, 2>>::Word, 3>,
    pending: Vec<Cell>,
    /// Permutations performed (for the measurement).
    pub permutations: usize,
}

impl<'c> Transcript<'c> {
    pub fn new(cfg: &'c TranscriptConfig, layouter: &mut impl Layouter<Fq>) -> Result<Self, Error> {
        let chip = Pow5Chip::construct(cfg.poseidon.clone());
        let state = <Chip as PoseidonSpongeInstructions<Fq, P128Pow5T3, TranscriptDomain, 3, 2>>::initial_state(
            &chip, layouter,
        )?;
        Ok(Transcript {
            cfg,
            chip,
            state,
            pending: Vec::with_capacity(2),
            permutations: 0,
        })
    }

    fn flush(&mut self, layouter: &mut impl Layouter<Fq>) -> Result<(), Error> {
        if !self.pending.is_empty() {
            let mut input = Absorbing::<PaddedWord<Fq>, 2>::init_empty();
            let n = self.pending.len();
            for cell in self.pending.drain(..) {
                input.absorb(PaddedWord::Message(cell)).ok().expect("at most two pending");
            }
            for _ in n..2 {
                input.absorb(PaddedWord::Padding(Fq::ZERO)).ok().expect("fits");
            }
            self.state = <Chip as PoseidonSpongeInstructions<Fq, P128Pow5T3, TranscriptDomain, 3, 2>>::add_input(
                &self.chip, layouter, &self.state, &input,
            )?;
        }
        self.state = <Chip as PoseidonInstructions<Fq, P128Pow5T3, 3, 2>>::permute(
            &self.chip,
            layouter,
            &self.state,
        )?;
        self.permutations += 1;
        Ok(())
    }

    /// Absorb one `Fq` cell: a coordinate, or an `Fp` scalar embedded in `Fq`.
    pub fn absorb(&mut self, layouter: &mut impl Layouter<Fq>, v: Cell) -> Result<(), Error> {
        if self.pending.len() == 2 {
            self.flush(layouter)?;
        }
        self.pending.push(v);
        Ok(())
    }

    /// Squeeze: the full `s0` (for tests) and the 128-bit challenge cell.
    pub fn squeeze(&mut self, layouter: &mut impl Layouter<Fq>) -> Result<(Cell, Cell), Error> {
        self.flush(layouter)?;
        let s0: Cell = self.state[0].clone().into();
        let cfg = self.cfg;
        let (c, h) = layouter.assign_region(
            || "challenge split",
            |mut r| {
                cfg.q_split.enable(&mut r, 0)?;
                s0.copy_advice(|| "s0", &mut r, cfg.split[0], 0)?;
                let (cv, hv) = s0
                    .value()
                    .map(|v| {
                        let repr = v.to_repr();
                        let mut lo = [0u8; 32];
                        lo[..16].copy_from_slice(&repr[..16]);
                        let mut hi = [0u8; 32];
                        hi[..16].copy_from_slice(&repr[16..]);
                        (Fq::from_repr(lo).unwrap(), Fq::from_repr(hi).unwrap())
                    })
                    .unzip();
                let c = r.assign_advice(|| "c", cfg.split[1], 0, || cv)?;
                let h = r.assign_advice(|| "h", cfg.split[2], 0, || hv)?;
                Ok((c, h))
            },
        )?;
        // c < 2^128: twelve 10-bit words and an 8-bit remainder
        let zs = cfg
            .range
            .copy_check(layouter.namespace(|| "c words"), c.clone(), 12, false)?;
        cfg.range
            .copy_short_check(layouter.namespace(|| "c short"), zs[12].clone(), 8)?;
        // h < 2^127: twelve words and a 7-bit remainder (s0 < q < 2^255)
        let zs = cfg
            .range
            .copy_check(layouter.namespace(|| "h words"), h.clone(), 12, false)?;
        cfg.range
            .copy_short_check(layouter.namespace(|| "h short"), zs[12].clone(), 7)?;
        Ok((s0, c))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_gadgets::poseidon::primitives as poseidon;
    use halo2_proofs::circuit::{SimpleFloorPlanner, Value};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk::{Circuit, Instance, TableColumn};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use sba_circuit::transcript::{Challenge128, Sponge};
    use sba_primitives::Fp;
    use halo2_proofs::transcript::EncodedChallenge;
    use ff::Field;

    /// A sequence of absorbs (Some(value)) and squeezes (None).
    #[derive(Clone)]
    struct Script(Vec<Option<Fq>>);

    #[derive(Clone)]
    struct Config {
        t: TranscriptConfig,
        advices: [Column<Advice>; 10],
        instance: Column<Instance>,
        table_idx: TableColumn,
    }

    #[derive(Clone, Default)]
    struct SpongeCircuit {
        script: Option<Script>,
    }

    impl Circuit<Fq> for SpongeCircuit {
        type Config = Config;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fq>) -> Config {
            let advices: [Column<Advice>; 10] = core::array::from_fn(|_| meta.advice_column());
            for a in &advices {
                meta.enable_equality(*a);
            }
            let instance = meta.instance_column();
            meta.enable_equality(instance);
            let fixed: [halo2_proofs::plonk::Column<halo2_proofs::plonk::Fixed>; 7] =
                core::array::from_fn(|_| meta.fixed_column());
            meta.enable_constant(fixed[0]);
            let table_idx = meta.lookup_table_column();
            let range = VestaLookupRangeCheckConfig::configure(meta, advices[9], table_idx);
            let poseidon = Pow5Chip::configure::<poseidon::P128Pow5T3>(
                meta,
                advices[6..9].try_into().unwrap(),
                advices[5],
                fixed[1..4].try_into().unwrap(),
                fixed[4..7].try_into().unwrap(),
            );
            let t = TranscriptConfig::configure(meta, poseidon, range, [advices[0], advices[1], advices[2]]);
            Config {
                t,
                advices,
                instance,
                table_idx,
            }
        }

        fn synthesize(&self, cfg: Config, mut layouter: impl Layouter<Fq>) -> Result<(), Error> {
            layouter.assign_table(
                || "10-bit table",
                |mut table| {
                    for i in 0..(1 << 10) {
                        table.assign_cell(|| "idx", cfg.table_idx, i, || Value::known(Fq::from(i as u64)))?;
                    }
                    Ok(())
                },
            )?;
            let mut t = Transcript::new(&cfg.t, &mut layouter)?;
            let script = self.script.clone().unwrap_or(Script(vec![]));
            let mut n_challenges = 0;
            for op in &script.0 {
                match op {
                    Some(v) => {
                        let v = *v;
                        let cell = layouter.assign_region(
                            || "absorbed value",
                            |mut r| r.assign_advice(|| "v", cfg.advices[3], 0, || Value::known(v)),
                        )?;
                        t.absorb(&mut layouter, cell)?;
                    }
                    None => {
                        let (_s0, c) = t.squeeze(&mut layouter)?;
                        layouter.constrain_instance(c.cell(), cfg.instance, n_challenges)?;
                        n_challenges += 1;
                    }
                }
            }
            eprintln!("permutations: {}", t.permutations);
            Ok(())
        }
    }

    /// The native sponge's challenges for the script.
    fn native(script: &Script) -> Vec<Fq> {
        let mut s = Sponge::default();
        let mut out = vec![];
        for op in &script.0 {
            match op {
                Some(v) => s.absorb(*v),
                None => {
                    let c = Challenge128::new(&s.squeeze());
                    // the challenge as an Fq integer: the same 128 bits
                    out.push(Fq::from_repr(Fp::to_repr(&c.get_scalar())).unwrap());
                }
            }
        }
        out
    }

    fn script(seed: u64, absorbs_then_squeezes: &[(usize, usize)]) -> Script {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut ops = vec![];
        for &(a, s) in absorbs_then_squeezes {
            for _ in 0..a {
                ops.push(Some(Fq::random(&mut rng)));
            }
            for _ in 0..s {
                ops.push(None);
            }
        }
        Script(ops)
    }

    #[test]
    fn gadget_matches_native_sponge_on_a_small_script() {
        let sc = script(1, &[(1, 1), (3, 2), (0, 1), (2, 1)]);
        let expected = native(&sc);
        let circuit = SpongeCircuit { script: Some(sc) };
        MockProver::run(12, &circuit, vec![expected.clone()])
            .unwrap()
            .assert_satisfied();
        // a wrong expected challenge is refused
        let mut wrong = expected;
        wrong[0] += Fq::ONE;
        assert!(MockProver::run(12, &circuit, vec![wrong]).unwrap().verify().is_err());
    }

    /// The shape of a transfer proof's transcript (REPLAY-PROOF-A.md §3.3):
    /// the vk representative, the instance commitment, 10 advice
    /// commitments, theta; 2 permuted-lookup commitments, beta, gamma; 3
    /// permutation products + 1 lookup product + the random commitment, y;
    /// 8 quotient chunks, x; 83 evaluations, x_1, x_2; q', x_3; 3 u's, x_4;
    /// the s-polynomial commitment, xi, z; 14 × (L, R, u_j); c, f.
    fn transfer_shape() -> Vec<(usize, usize)> {
        let mut v = vec![(1 + 2 + 20, 1), (4, 2), (10, 1), (16, 1), (83, 2), (2, 1), (3, 1), (2, 2)];
        for _ in 0..14 {
            v.push((4, 1));
        }
        v.push((2, 0));
        v
    }

    #[test]
    fn transfer_shaped_transcript_fits_and_matches() {
        let sc = script(2, &transfer_shape());
        let expected = native(&sc);
        println!("challenges: {}, absorbs: {}", expected.len(), sc.0.iter().filter(|o| o.is_some()).count());
        let circuit = SpongeCircuit { script: Some(sc) };
        let mut k = 10;
        loop {
            match MockProver::run(k, &circuit, vec![expected.clone()]) {
                Ok(p) => {
                    p.assert_satisfied();
                    println!("transfer-shaped transcript fits k = {k}");
                    break;
                }
                Err(_) => k += 1,
            }
            assert!(k <= 20);
        }
    }
}
