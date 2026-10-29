//! docs/REMAINING.md: the cost of one level of **unbounded** recursion on
//! the MNT4-753 / MNT6-753 pairing cycle, the only pairing-friendly
//! construction where a proof can verify a proof of the same kind at any
//! depth natively. Both directions of the cycle are measured: a MNT4-753
//! Groth16 proof with 17 public inputs verified inside a MNT6-753 circuit,
//! and the converse. With `--prove`, the outer verification circuit is
//! also set up and proven once, to put a time and a memory on the level.

use ark_crypto_primitives::snark::constraints::SNARKGadget;
use ark_crypto_primitives::snark::{BooleanInputVar, SNARK};
use ark_groth16::constraints::{Groth16VerifierGadget, ProofVar, VerifyingKeyVar};
use ark_groth16::Groth16;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ark_ff::PrimeField;
use ark_ec::pairing::Pairing;
use std::marker::PhantomData;
use std::time::Instant;

const N_INPUTS: usize = 17;

#[derive(Clone)]
struct Inner<F: PrimeField> {
    inputs: Option<[F; N_INPUTS]>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for Inner<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let mut acc = FpVar::<F>::zero();
        for i in 0..N_INPUTS {
            let x = FpVar::new_input(cs.clone(), || {
                self.inputs.map(|v| v[i]).ok_or(SynthesisError::AssignmentMissing)
            })?;
            acc += &x * &x;
        }
        let _ = acc;
        Ok(())
    }
}

/// The outer circuit: verify one inner proof.
struct Outer<E: Pairing, P> {
    vk: ark_groth16::VerifyingKey<E>,
    proof: ark_groth16::Proof<E>,
    inputs: Vec<E::ScalarField>,
    _p: PhantomData<P>,
}

impl<E, P> ConstraintSynthesizer<E::BaseField> for Outer<E, P>
where
    E: Pairing,
    E::BaseField: PrimeField,
    P: ark_r1cs_std::pairing::PairingVar<E>,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<E::BaseField>) -> Result<(), SynthesisError> {
        let vk_var = VerifyingKeyVar::<E, P>::new_witness(cs.clone(), || Ok(self.vk.clone()))?;
        let proof_var = ProofVar::<E, P>::new_witness(cs.clone(), || Ok(self.proof.clone()))?;
        let input_var = BooleanInputVar::<E::ScalarField, E::BaseField>::new_witness(cs.clone(), || Ok(self.inputs.clone()))?;
        let ok = <Groth16VerifierGadget<E, P> as SNARKGadget<E::ScalarField, E::BaseField, Groth16<E>>>::verify(&vk_var, &input_var, &proof_var)?;
        ok.enforce_equal(&Boolean::TRUE)?;
        Ok(())
    }
}

fn level<E, P, O>(name: &str, prove: bool)
where
    E: Pairing,
    E::BaseField: PrimeField,
    P: ark_r1cs_std::pairing::PairingVar<E>,
    O: Pairing<ScalarField = E::BaseField>,
{
    let mut rng = StdRng::seed_from_u64(1);
    let (pk, vk) = Groth16::<E>::circuit_specific_setup(Inner::<E::ScalarField> { inputs: None }, &mut rng).unwrap();
    let inputs: [E::ScalarField; N_INPUTS] = core::array::from_fn(|i| E::ScalarField::from((i + 3) as u64));
    let proof = Groth16::<E>::prove(&pk, Inner { inputs: Some(inputs) }, &mut rng).unwrap();
    assert!(Groth16::<E>::verify(&vk, &inputs, &proof).unwrap());
    let outer = || Outer::<E, P> { vk: vk.clone(), proof: proof.clone(), inputs: inputs.to_vec(), _p: PhantomData };
    let cs = ConstraintSystem::<E::BaseField>::new_ref();
    let t = Instant::now();
    outer().generate_constraints(cs.clone()).unwrap();
    println!("{name}: outer constraints for one in-circuit verification ({N_INPUTS} inputs): {} (synthesis {:.1} s, satisfied {})",
        cs.num_constraints(), t.elapsed().as_secs_f64(), cs.is_satisfied().unwrap());
    if prove {
        let t = Instant::now();
        let (opk, ovk) = Groth16::<O>::circuit_specific_setup(outer(), &mut rng).unwrap();
        println!("{name}: outer setup {:.1} s", t.elapsed().as_secs_f64());
        let t = Instant::now();
        let oproof = Groth16::<O>::prove(&opk, outer(), &mut rng).unwrap();
        println!("{name}: outer prove {:.1} s", t.elapsed().as_secs_f64());
        let t = Instant::now();
        let ok = Groth16::<O>::verify(&ovk, &[], &oproof).unwrap();
        println!("{name}: outer verify {:.1} ms, ok {ok}", t.elapsed().as_secs_f64() * 1000.0);
    }
}

fn main() {
    let prove = std::env::args().any(|a| a == "--prove");
    level::<ark_mnt4_753::MNT4_753, ark_mnt4_753::constraints::PairingVar, ark_mnt6_753::MNT6_753>("MNT4-753 proof inside MNT6-753", prove);
    level::<ark_mnt6_753::MNT6_753, ark_mnt6_753::constraints::PairingVar, ark_mnt4_753::MNT4_753>("MNT6-753 proof inside MNT4-753", prove);
}
