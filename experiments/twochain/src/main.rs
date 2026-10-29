//! Appendix experiment of docs/REPLAY-PROOF.md §4.4 and docs/REMAINING.md:
//! the R1CS cost of verifying one Groth16 proof with 17 public inputs
//! inside a circuit over the outer curve of a 2-chain, with arkworks'
//! pairing gadgets, for the two 2-chains arkworks ships:
//!
//! * BLS12-377 inside BW6-761 (the SNARK-friendly 2-chain of Zexe /
//!   El Housni–Guillevic);
//! * BLS12-381 (this project's curve) inside BW6-767, the outer curve
//!   built for BLS12-381.
//!
//! The inner circuit is a stand-in with the same public-input count: the
//! verifier's cost depends on that count and on the pairing, not on the
//! inner relation. With `--prove`, the outer circuit is also set up and
//! proven once, to put a time and a memory on the level; an outer curve
//! whose scalar field has no FFT-friendly subgroup fails there, and the
//! failure is printed instead of a time.

use ark_crypto_primitives::snark::constraints::SNARKGadget;
use ark_crypto_primitives::snark::{BooleanInputVar, SNARK};
use ark_ec::pairing::Pairing;
use ark_ff::{FftField, PrimeField};
use ark_groth16::constraints::{Groth16VerifierGadget, ProofVar, VerifyingKeyVar};
use ark_groth16::Groth16;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_std::rand::{rngs::StdRng, SeedableRng};
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
                self.inputs
                    .map(|v| v[i])
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            acc += &x * &x;
        }
        let _ = acc;
        Ok(())
    }
}

struct Outer<E: Pairing, P: ark_r1cs_std::pairing::PairingVar<E>> {
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
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<E::BaseField>,
    ) -> Result<(), SynthesisError> {
        let before = cs.num_constraints();
        let vk_var = VerifyingKeyVar::<E, P>::new_witness(cs.clone(), || Ok(self.vk.clone()))?;
        let proof_var = ProofVar::<E, P>::new_witness(cs.clone(), || Ok(self.proof.clone()))?;
        let input_var =
            BooleanInputVar::<E::ScalarField, E::BaseField>::new_witness(cs.clone(), || {
                Ok(self.inputs.clone())
            })?;
        let alloc = cs.num_constraints() - before;
        let ok = <Groth16VerifierGadget<E, P> as SNARKGadget<
            E::ScalarField,
            E::BaseField,
            Groth16<E>,
        >>::verify(&vk_var, &input_var, &proof_var)?;
        ok.enforce_equal(&Boolean::TRUE)?;
        if !cs.is_in_setup_mode() && std::env::var("TWOCHAIN_QUIET").is_err() {
            println!(
                "  allocation of key, proof and inputs: {alloc}; verifier gadget: {}",
                cs.num_constraints() - before - alloc
            );
        }
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
    let (pk, vk) =
        Groth16::<E>::circuit_specific_setup(Inner::<E::ScalarField> { inputs: None }, &mut rng)
            .unwrap();
    let inputs: [E::ScalarField; N_INPUTS] =
        core::array::from_fn(|i| E::ScalarField::from((i + 3) as u64));
    let proof = Groth16::<E>::prove(
        &pk,
        Inner {
            inputs: Some(inputs),
        },
        &mut rng,
    )
    .unwrap();
    assert!(Groth16::<E>::verify(&vk, &inputs, &proof).unwrap());
    let outer = || Outer::<E, P> {
        vk: vk.clone(),
        proof: proof.clone(),
        inputs: inputs.to_vec(),
        _p: PhantomData,
    };
    let cs = ConstraintSystem::<E::BaseField>::new_ref();
    let t = Instant::now();
    println!(
        "{name} ({N_INPUTS} inner public inputs; outer scalar field: {} bits, 2-adicity {})",
        E::BaseField::MODULUS_BIT_SIZE,
        <E::BaseField as FftField>::TWO_ADICITY
    );
    outer().generate_constraints(cs.clone()).unwrap();
    println!(
        "  outer constraints for one in-circuit verification: {} (synthesis {:.1} s, satisfied {})",
        cs.num_constraints(),
        t.elapsed().as_secs_f64(),
        cs.is_satisfied().unwrap()
    );
    if prove {
        std::env::set_var("TWOCHAIN_QUIET", "1");
        let t = Instant::now();
        match Groth16::<O>::circuit_specific_setup(outer(), &mut rng) {
            Err(e) => {
                println!(
                    "  outer setup FAILED after {:.1} s: {e:?}",
                    t.elapsed().as_secs_f64()
                );
            }
            Ok((opk, ovk)) => {
                println!("  outer setup {:.1} s", t.elapsed().as_secs_f64());
                let t = Instant::now();
                let oproof = Groth16::<O>::prove(&opk, outer(), &mut rng).unwrap();
                println!("  outer prove {:.1} s", t.elapsed().as_secs_f64());
                let t = Instant::now();
                let ok = Groth16::<O>::verify(&ovk, &[], &oproof).unwrap();
                println!(
                    "  outer verify {:.1} ms, ok {ok}",
                    t.elapsed().as_secs_f64() * 1000.0
                );
            }
        }
        std::env::remove_var("TWOCHAIN_QUIET");
    }
}

fn main() {
    let prove = std::env::args().any(|a| a == "--prove");
    level::<ark_bls12_377::Bls12_377, ark_bls12_377::constraints::PairingVar, ark_bw6_761::BW6_761>(
        "BLS12-377 proof inside BW6-761",
        prove,
    );
    level::<
        ark_bls12_381::Bls12_381,
        ark_r1cs_std::pairing::bls12::PairingVar<ark_bls12_381::Config>,
        ark_bw6_767::BW6_767,
    >("BLS12-381 proof inside BW6-767", prove);
}
