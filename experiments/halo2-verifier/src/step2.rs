//! The second step, and with it the loop closed (`docs/REPLAY-PROOF-A.md`
//! §3.4): `T_q(2)` over `Fq` = the `q` group side of a second transfer
//! proof + the `q` group side of `T_p(1)` (its instance values witnessed,
//! not exposed) + the field side of `T_q(1)` bound to those values, proven
//! as a Pallas proof opening `T_q(1)`'s claim; `T_p(2)` over `Fp` = the
//! field side of the second transfer proof + the `p` group side of `T_q(2)`
//! (instance values not exposed) + the field side of `T_p(1)`, both field
//! sides bound to `T_q(2)`'s instance values, proven as a Vesta proof
//! opening the transfer proof's claim and `T_p(1)`'s. The decider verifies
//! `T_q(2)` and `T_p(2)` natively with those claims: every proof of step 1
//! and both transfer proofs are then verified, none of them read.

use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
use pasta_curves::{pallas, vesta};

use crate::field;
use crate::fieldside;
use crate::verifier::{p, q};

/// Bind each field-side cell to the value its limbs (cells of the group
/// side's instance values) say: one cell is the value, two are `lo + 2^128 hi`.
pub fn bind<F: PrimeField>(
    ch: &mut impl Binder<F>,
    l: &mut impl Layouter<F>,
    cells: &[AssignedCell<F, F>],
    links: &[Vec<usize>],
    instance_values: &[Vec<AssignedCell<F, F>>],
    offset: usize,
) -> Result<(), Error> {
    let two_128 = ch.constant(l, F::from_u128(1u128 << 64).square())?;
    for (cell, m) in cells.iter().zip(links) {
        if m.is_empty() {
            // a value this side binds by other means (an evaluation under
            // the split transcript, bound by the sponge)
            continue;
        }
        let limbs: Vec<_> = m
            .iter()
            .flat_map(|i| instance_values[offset + *i].iter().cloned())
            .collect();
        let value = match limbs.len() {
            1 => limbs[0].clone(),
            2 => ch.mul_add(l, &limbs[1], &two_128, &limbs[0])?,
            n => panic!("{n} limbs"),
        };
        ch.assert_equal(l, cell, &value)?;
    }
    Ok(())
}

/// The field chip's three operations `bind` needs, over either field.
pub trait Binder<F: PrimeField> {
    fn constant(&mut self, l: &mut impl Layouter<F>, k: F) -> Result<AssignedCell<F, F>, Error>;
    fn mul_add(
        &mut self,
        l: &mut impl Layouter<F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
        c: &AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error>;
    fn assert_equal(
        &mut self,
        l: &mut impl Layouter<F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
    ) -> Result<(), Error>;
}

macro_rules! binder {
    ($chip:ty, $f:ty) => {
        impl<'c> Binder<$f> for $chip {
            fn constant(
                &mut self,
                l: &mut impl Layouter<$f>,
                k: $f,
            ) -> Result<AssignedCell<$f, $f>, Error> {
                <$chip>::constant(self, l, k)
            }
            fn mul_add(
                &mut self,
                l: &mut impl Layouter<$f>,
                a: &AssignedCell<$f, $f>,
                b: &AssignedCell<$f, $f>,
                c: &AssignedCell<$f, $f>,
            ) -> Result<AssignedCell<$f, $f>, Error> {
                <$chip>::mul_add(self, l, a, b, c)
            }
            fn assert_equal(
                &mut self,
                l: &mut impl Layouter<$f>,
                a: &AssignedCell<$f, $f>,
                b: &AssignedCell<$f, $f>,
            ) -> Result<(), Error> {
                <$chip>::assert_equal(self, l, a, b)
            }
        }
    };
}
binder!(field::fp::FieldChip<'c>, vesta::Scalar);
binder!(field::fq::FieldChip<'c>, pallas::Scalar);

/// `T_q(i)`, `i ≥ 2`, without the batch relation.
#[derive(Clone)]
pub struct StepQ {
    /// The `q` group side of the transfer proof (instance exposed).
    pub group_pi: q::VerifierCircuit,
    /// The `q` group side of `T_p(i−1)` (instance values not exposed).
    pub group_tp: q::VerifierCircuit,
    /// The field side of `T_q(i−1)`, whose values are `T_p(i−1)`'s instance values.
    pub field_tq: fieldside::fq::FieldSideCircuit,
    /// Its links into `T_p(i−1)`'s instance values.
    pub links_tq: Vec<Vec<usize>>,
}

#[derive(Clone, Debug)]
pub struct StepQConfig {
    pub group: q::VerifierConfig,
    pub field: field::fq::FieldConfig,
}

impl std::fmt::Debug for StepQ {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StepQ({} links)", self.links_tq.len())
    }
}

impl StepQ {
    /// The public inputs: the group side of the transfer proof's, then
    /// the group side of `T_p(i−1)`'s.
    pub fn instance(&self) -> Vec<pallas::Scalar> {
        let mut v = self
            .group_pi
            .instance(self.group_pi.capture.as_ref().expect("values"));
        v.extend(
            self.group_tp
                .instance(self.group_tp.capture.as_ref().expect("values")),
        );
        v
    }
}

impl Circuit<pallas::Scalar> for StepQ {
    type Config = StepQConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        StepQ {
            group_pi: self.group_pi.without_witnesses(),
            group_tp: self.group_tp.without_witnesses(),
            field_tq: self.field_tq.without_witnesses(),
            links_tq: self.links_tq.clone(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Scalar>) -> StepQConfig {
        StepQConfig {
            group: q::VerifierCircuit::configure(meta),
            field: fieldside::fq::FieldSideCircuit::configure_field(meta),
        }
    }

    fn synthesize(
        &self,
        cfg: StepQConfig,
        mut layouter: impl Layouter<pallas::Scalar>,
    ) -> Result<(), Error> {
        cfg.group.assign_table(&mut layouter)?;
        let ex_pi = self
            .group_pi
            .synthesize_core(&cfg.group, &mut layouter, 0)?;
        let ex_tp = self
            .group_tp
            .synthesize_core(&cfg.group, &mut layouter, ex_pi.cells.len())?;
        let (inputs, outputs) =
            self.field_tq
                .synthesize_core(&cfg.field, None, None, &mut layouter)?;
        let cells: Vec<_> = inputs.into_iter().chain(outputs).collect();
        let mut ch = field::fq::FieldChip::new(&cfg.field);
        bind(
            &mut ch,
            &mut layouter,
            &cells,
            &self.links_tq,
            &ex_tp.instance_values,
            0,
        )?;
        eprintln!("T_q step: {} links", self.links_tq.len());
        Ok(())
    }
}

/// `T_p(i)`, `i ≥ 2`, without the batch relation.
#[derive(Clone)]
pub struct StepP2 {
    /// The `p` group side of `T_q(i)` (instance values not exposed).
    pub group_tq: p::VerifierCircuit,
    /// The field side of the transfer proof, whose values are the first
    /// part of `T_q(i)`'s instance values.
    pub field_pi: fieldside::fp::FieldSideCircuit,
    pub links_pi: Vec<Vec<usize>>,
    /// The field side of `T_p(i−1)`, whose values are the second part.
    pub field_tp: fieldside::fp::FieldSideCircuit,
    pub links_tp: Vec<Vec<usize>>,
    /// Where the second part starts among `T_q(i)`'s instance values.
    pub offset_tp: usize,
}

#[derive(Clone, Debug)]
pub struct StepP2Config {
    pub group: p::VerifierConfig,
    pub field: field::fp::FieldConfig,
}

impl std::fmt::Debug for StepP2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "StepP2({} + {} links)",
            self.links_pi.len(),
            self.links_tp.len()
        )
    }
}

impl StepP2 {
    pub fn instance(&self) -> Vec<vesta::Scalar> {
        self.group_tq
            .instance(self.group_tq.capture.as_ref().expect("values"))
    }
}

impl Circuit<vesta::Scalar> for StepP2 {
    type Config = StepP2Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        StepP2 {
            group_tq: self.group_tq.without_witnesses(),
            field_pi: self.field_pi.without_witnesses(),
            links_pi: self.links_pi.clone(),
            field_tp: self.field_tp.without_witnesses(),
            links_tp: self.links_tp.clone(),
            offset_tp: self.offset_tp,
        }
    }

    fn configure(meta: &mut ConstraintSystem<vesta::Scalar>) -> StepP2Config {
        StepP2Config {
            group: p::VerifierCircuit::configure(meta),
            field: fieldside::fp::FieldSideCircuit::configure_field(meta),
        }
    }

    fn synthesize(
        &self,
        cfg: StepP2Config,
        mut layouter: impl Layouter<vesta::Scalar>,
    ) -> Result<(), Error> {
        cfg.group.assign_table(&mut layouter)?;
        let ex = self
            .group_tq
            .synthesize_core(&cfg.group, &mut layouter, 0)?;
        let mut ch = field::fp::FieldChip::new(&cfg.field);
        let (inputs, outputs) =
            self.field_pi
                .synthesize_core(&cfg.field, None, None, &mut layouter)?;
        let cells: Vec<_> = inputs.into_iter().chain(outputs).collect();
        bind(
            &mut ch,
            &mut layouter,
            &cells,
            &self.links_pi,
            &ex.instance_values,
            0,
        )?;
        let (inputs, outputs) =
            self.field_tp
                .synthesize_core(&cfg.field, None, None, &mut layouter)?;
        let cells: Vec<_> = inputs.into_iter().chain(outputs).collect();
        bind(
            &mut ch,
            &mut layouter,
            &cells,
            &self.links_tp,
            &ex.instance_values,
            self.offset_tp,
        )?;
        eprintln!(
            "T_p step: {} + {} links",
            self.links_pi.len(),
            self.links_tp.len()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{capture, Event};
    use crate::native::{PoseidonRead, PoseidonWrite};
    use crate::step::tests_support::{tp, tq};
    use crate::verifier::tests_support::{q_circuit, real_with_seed};
    use ff::Field;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk;
    use halo2_proofs::poly::commitment::Params;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// Two steps over two transfer proofs, mocked at every stage; with
    /// `SB_PROVE_STEP2=1` the second step's two proofs are made for real
    /// and decided (k = 18 and 17: the server's memory).
    /// `cargo test --release two_steps -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn two_steps_close_the_loop() {
        let (params, vk, cap1) = real_with_seed(5);
        let (_, _, cap2) = real_with_seed(6);
        // step 1 (real): T_q(1), T_p(1)
        let (outer, ovk, instance_q1, _proof_q1, cap_q1) = tq(&params, &vk, &cap1);
        let (step1, pparams, pvk, instance_p1, _proof_p1, cap_p1, claim_pi1) =
            tp(&params, &vk, &cap1, &outer, &ovk, &instance_q1, &cap_q1);
        let claim_q1 = cap_q1.claim();
        let claim_p1 = cap_p1.claim();
        let _ = claim_pi1;

        // ---- T_q(2)
        let group_pi = q_circuit(&params, &vk, &cap2);
        let (kinds, sources) = q::VerifierCircuit::shape(
            &cap_p1,
            &pparams,
            pvk.fixed_commitments(),
            pvk.permutation_commitments(),
        );
        // T_p(1) opened the first transfer proof's claim: its challenges are
        // T_q(1)'s last squeezes, among the T_q(1) instance values T_p(1)
        // exposed; T_q(2) re-exposes those for T_p(2)'s field side of T_p(1)
        let u_in_tq1 = q_circuit(&params, &vk, &cap1).ipa_challenge_slots(cap1.u.len());
        let u_in_tp1: Vec<usize> = u_in_tq1
            .iter()
            .map(|j| step1.group.instance_value_slots(*j)[0])
            .collect();
        for (i, j) in u_in_tp1.iter().enumerate() {
            assert_eq!(instance_p1[*j].to_repr(), cap1.u[i].to_repr(), "u {i}");
        }
        let group_tp = q::VerifierCircuit {
            kinds,
            sources,
            params_w: pparams.get_w(),
            params_u: pparams.get_u(),
            lagrange: pparams.get_g_lagrange()[..instance_p1.len()].to_vec(),
            instance_limbs: vec![1; instance_p1.len()],
            expose_instance: false,
            opened_u_slots: vec![u_in_tp1],
            capture: Some(cap_p1.clone()),
        };
        // the field side of T_q(1): its values are T_p(1)'s instance values,
        // laid out by T_p(1)'s group side (step1.group)
        let (_, sources_q1) = p::VerifierCircuit::shape(
            &cap_q1,
            &outer,
            ovk.fixed_commitments(),
            ovk.permutation_commitments(),
        );
        let (structure, shadow) =
            fieldside::fq::Structure::build(&outer, &ovk, &cap_q1, &sources_q1);
        let links_tq = step1.group.links_for_field_side();
        let field_tq = fieldside::fq::FieldSideCircuit {
            structure,
            shadow: Some(shadow),
        };
        // natively: the linked values agree
        let fv = field_tq.instance();
        assert_eq!(fv.len(), links_tq.len());
        for (v, m) in fv.iter().zip(&links_tq) {
            let got = <pallas::Affine as crate::native::Limbs>::from_limbs(
                &m.iter()
                    .map(|i| instance_p1[*i])
                    .chain([vesta::Scalar::ZERO])
                    .take(2)
                    .collect::<Vec<_>>(),
            );
            if m.len() == 2 {
                assert_eq!(got, *v, "link {m:?}");
            } else {
                assert_eq!(instance_p1[m[0]].to_repr(), v.to_repr(), "link {m:?}");
            }
        }
        let step_q2 = StepQ {
            group_pi,
            group_tp,
            field_tq,
            links_tq,
        };
        let instance_q2 = step_q2.instance();
        println!("T_q(2) public inputs: {}", instance_q2.len());
        let t = std::time::Instant::now();
        let k_q = 18;
        MockProver::run(k_q, &step_q2, vec![instance_q2.clone()])
            .unwrap()
            .assert_satisfied();
        println!(
            "T_q(2) mock at k = {k_q}: {:.1} s",
            t.elapsed().as_secs_f64()
        );
        println!(
            "{:?}",
            halo2_proofs::dev::CircuitCost::<pallas::Point, _>::measure(k_q, &step_q2)
        );

        // ---- T_q(2) for real (server), then T_p(2)
        if std::env::var("SB_PROVE_STEP2").is_err() {
            println!("SB_PROVE_STEP2 unset: stopping before the real proofs of step 2");
            return;
        }
        let t = std::time::Instant::now();
        let qparams: Params<pallas::Affine> = Params::new(k_q);
        let qvk = plonk::keygen_vk(&qparams, &step_q2.without_witnesses()).unwrap();
        let qpk = plonk::keygen_pk(&qparams, qvk.clone(), &step_q2.without_witnesses()).unwrap();
        println!(
            "T_q(2) keygen (k = {k_q}): {:.1} s",
            t.elapsed().as_secs_f64()
        );
        let t = std::time::Instant::now();
        let mut tr = PoseidonWrite::<_, pallas::Affine>::init(vec![]);
        plonk::create_proof_with_openings(
            &qparams,
            &qpk,
            &[step_q2.clone()],
            &[&[&instance_q2[..]]],
            &[claim_q1.clone()],
            &mut StdRng::seed_from_u64(31),
            &mut tr,
        )
        .unwrap();
        let proof_q2 = tr.finalize();
        println!(
            "T_q(2) prove: {:.1} s, proof {} bytes",
            t.elapsed().as_secs_f64(),
            proof_q2.len()
        );
        let cap_q2 = capture(&qparams, &qvk, &instance_q2, &proof_q2, &[claim_q1.clone()]).unwrap();
        let n = |f: &dyn Fn(&Event<pallas::Affine>) -> bool| {
            cap_q2.events.iter().filter(|e| f(e)).count()
        };
        println!(
            "T_q(2) capture: {} common points, {} points read, {} scalars read, {} challenges; msm terms {}",
            n(&|e| matches!(e, Event::CommonPoint(_))),
            n(&|e| matches!(e, Event::ReadPoint(_))),
            n(&|e| matches!(e, Event::ReadScalar(_))),
            n(&|e| matches!(e, Event::Squeeze(_))),
            cap_q2.terms.len()
        );

        // T_p(2)
        let (kinds, sources) = p::VerifierCircuit::shape(
            &cap_q2,
            &qparams,
            qvk.fixed_commitments(),
            qvk.permutation_commitments(),
        );
        let mut instance_limbs = step_q2.group_pi.instance_limbs_when_verified();
        instance_limbs.extend(step_q2.group_tp.instance_limbs_when_verified());
        assert_eq!(instance_limbs.len(), instance_q2.len());
        let group_tq = p::VerifierCircuit {
            kinds,
            sources,
            params_w: qparams.get_w(),
            params_u: qparams.get_u(),
            lagrange: qparams.get_g_lagrange()[..instance_q2.len()].to_vec(),
            instance_limbs,
            expose_instance: false,
            opened_u_slots: vec![],
            capture: Some(cap_q2.clone()),
        };
        let (_, sources2) = q::VerifierCircuit::shape(
            &cap2,
            &params,
            vk.fixed_commitments(),
            vk.permutation_commitments(),
        );
        let (structure, shadow) = fieldside::fp::Structure::build(&params, &vk, &cap2, &sources2);
        let field_pi = fieldside::fp::FieldSideCircuit {
            structure,
            shadow: Some(shadow),
        };
        let links_pi = step_q2.group_pi.links_for_field_side();
        let (_, sources_p1) = q::VerifierCircuit::shape(
            &cap_p1,
            &pparams,
            pvk.fixed_commitments(),
            pvk.permutation_commitments(),
        );
        let (structure, shadow) =
            fieldside::fp::Structure::build(&pparams, &pvk, &cap_p1, &sources_p1);
        let field_tp = fieldside::fp::FieldSideCircuit {
            structure,
            shadow: Some(shadow),
        };
        let links_tp = step_q2.group_tp.links_for_field_side();
        let offset_tp = step_q2.group_pi.layout().len();
        let step_p2 = StepP2 {
            group_tq,
            field_pi,
            links_pi,
            field_tp,
            links_tp,
            offset_tp,
        };
        let instance_p2 = step_p2.instance();
        println!("T_p(2) public inputs: {}", instance_p2.len());
        let t = std::time::Instant::now();
        let k_p = 17;
        MockProver::run(k_p, &step_p2, vec![instance_p2.clone()])
            .unwrap()
            .assert_satisfied();
        println!(
            "T_p(2) mock at k = {k_p}: {:.1} s",
            t.elapsed().as_secs_f64()
        );
        println!(
            "{:?}",
            halo2_proofs::dev::CircuitCost::<vesta::Point, _>::measure(k_p, &step_p2)
        );
        let t = std::time::Instant::now();
        let p2params: Params<vesta::Affine> = Params::new(k_p);
        let p2vk = plonk::keygen_vk(&p2params, &step_p2.without_witnesses()).unwrap();
        let p2pk = plonk::keygen_pk(&p2params, p2vk.clone(), &step_p2.without_witnesses()).unwrap();
        println!(
            "T_p(2) keygen (k = {k_p}): {:.1} s",
            t.elapsed().as_secs_f64()
        );
        let claims_p2 = [cap2.claim(), claim_p1.clone()];
        let t = std::time::Instant::now();
        let mut tr = PoseidonWrite::<_, vesta::Affine>::init(vec![]);
        plonk::create_proof_with_openings(
            &p2params,
            &p2pk,
            &[step_p2.clone()],
            &[&[&instance_p2[..]]],
            &claims_p2,
            &mut StdRng::seed_from_u64(32),
            &mut tr,
        )
        .unwrap();
        let proof_p2 = tr.finalize();
        println!(
            "T_p(2) prove: {:.1} s, proof {} bytes",
            t.elapsed().as_secs_f64(),
            proof_p2.len()
        );

        // the decider: T_q(2) with T_q(1)'s claim, T_p(2) with the transfer
        // proof's and T_p(1)'s, natively
        let t = std::time::Instant::now();
        let mut tr = PoseidonRead::<_, pallas::Affine>::init(&proof_q2[..]);
        plonk::verify_proof_with_openings(
            &qparams,
            &qvk,
            plonk::SingleVerifier::new(&qparams),
            &[&[&instance_q2[..]]],
            &mut tr,
            &[claim_q1.clone()],
        )
        .unwrap();
        let mut tr = PoseidonRead::<_, vesta::Affine>::init(&proof_p2[..]);
        plonk::verify_proof_with_openings(
            &p2params,
            &p2vk,
            plonk::SingleVerifier::new(&p2params),
            &[&[&instance_p2[..]]],
            &mut tr,
            &claims_p2,
        )
        .unwrap();
        println!(
            "decider (both): {:.1} ms",
            t.elapsed().as_secs_f64() * 1000.0
        );
        // a wrong claim for either is refused
        let mut tr = PoseidonRead::<_, pallas::Affine>::init(&proof_q2[..]);
        assert!(plonk::verify_proof_with_openings(
            &qparams,
            &qvk,
            plonk::SingleVerifier::new(&qparams),
            &[&[&instance_q2[..]]],
            &mut tr,
            &[],
        )
        .is_err());
        let mut wrong = claims_p2.clone();
        wrong[1].u[2] = wrong[1].u[2].double();
        let mut tr = PoseidonRead::<_, vesta::Affine>::init(&proof_p2[..]);
        assert!(plonk::verify_proof_with_openings(
            &p2params,
            &p2vk,
            plonk::SingleVerifier::new(&p2params),
            &[&[&instance_p2[..]]],
            &mut tr,
            &wrong,
        )
        .is_err());
    }
}
