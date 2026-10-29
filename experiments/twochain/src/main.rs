//! Appendix experiment of docs/REPLAY-PROOF.md §5 (slice 4): the R1CS cost
//! of verifying one BLS12-377 Groth16 proof with 17 public inputs inside a
//! BW6-761 circuit, with arkworks' pairing gadgets. The inner circuit is a
//! stand-in with the same public-input count: the verifier's cost depends
//! on that count and on the pairing, not on the inner relation.

use ark_bls12_377::{Bls12_377, Fr as InnerFr};
use ark_bw6_761::Fr as OuterFr;
use ark_crypto_primitives::snark::constraints::SNARKGadget;
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::constraints::{Groth16VerifierGadget, ProofVar, VerifyingKeyVar};
use ark_groth16::Groth16;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ark_crypto_primitives::snark::BooleanInputVar;
use ark_r1cs_std::prelude::*;

const N_INPUTS: usize = 17;

#[derive(Clone)]
struct Inner {
    inputs: Option<[InnerFr; N_INPUTS]>,
}

impl ConstraintSynthesizer<InnerFr> for Inner {
    fn generate_constraints(self, cs: ConstraintSystemRef<InnerFr>) -> Result<(), SynthesisError> {
        let mut acc = FpVar::<InnerFr>::zero();
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

fn main() {
    let mut rng = StdRng::seed_from_u64(1);
    let (pk, vk) = Groth16::<Bls12_377>::circuit_specific_setup(Inner { inputs: None }, &mut rng).unwrap();
    let inputs: [InnerFr; N_INPUTS] = core::array::from_fn(|i| InnerFr::from((i + 3) as u64));
    let proof = Groth16::<Bls12_377>::prove(&pk, Inner { inputs: Some(inputs) }, &mut rng).unwrap();
    assert!(Groth16::<Bls12_377>::verify(&vk, &inputs, &proof).unwrap());

    type Gadget = Groth16VerifierGadget<Bls12_377, ark_bls12_377::constraints::PairingVar>;
    let cs = ConstraintSystem::<OuterFr>::new_ref();
    let vk_var = VerifyingKeyVar::<Bls12_377, ark_bls12_377::constraints::PairingVar>::new_witness(cs.clone(), || Ok(vk.clone())).unwrap();
    let proof_var = ProofVar::<Bls12_377, ark_bls12_377::constraints::PairingVar>::new_witness(cs.clone(), || Ok(proof.clone())).unwrap();
    let input_var = BooleanInputVar::<InnerFr, OuterFr>::new_witness(cs.clone(), || Ok(inputs.to_vec())).unwrap();
    let before = cs.num_constraints();
    let ok = <Gadget as SNARKGadget<InnerFr, OuterFr, Groth16<Bls12_377>>>::verify(&vk_var, &input_var, &proof_var).unwrap();
    ok.enforce_equal(&Boolean::TRUE).unwrap();
    println!("inner public inputs: {N_INPUTS}");
    println!("outer constraints (BW6-761) for one in-circuit BLS12-377 Groth16 verification: {}", cs.num_constraints());
    println!("  of which the verifier gadget itself: {}", cs.num_constraints() - before);
    println!("satisfied: {}", cs.is_satisfied().unwrap());
}
