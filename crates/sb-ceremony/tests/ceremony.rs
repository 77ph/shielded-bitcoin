//! The whole ceremony on a small circuit: phase 1 contributions, key
//! derivation checked against arkworks' own generator, phase 2
//! contributions and a beacon, and proofs that verify. The transfer
//! circuit itself runs when `SB_CEREMONY_FULL` is set (minutes).

use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ec::PrimeGroup;
use ark_ff::{Field, UniformRand};
use ark_groth16::Groth16;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use sb_ceremony::keygen::{domain_size, initial_proving_key};
use sb_ceremony::phase1::Phase1;
use sb_ceremony::phase2::Phase2;
use sb_ceremony::transcript::digest;

/// `x · y = z` and `x + y = w`, with `z` and `w` public.
#[derive(Clone, Default)]
struct Tiny {
    x: Option<Fr>,
    y: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for Tiny {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let get = |v: Option<Fr>| v.ok_or(SynthesisError::AssignmentMissing);
        let x = FpVar::new_witness(cs.clone(), || get(self.x))?;
        let y = FpVar::new_witness(cs.clone(), || get(self.y))?;
        let z = FpVar::new_input(cs.clone(), || Ok(get(self.x)? * get(self.y)?))?;
        let w = FpVar::new_input(cs.clone(), || Ok(get(self.x)? + get(self.y)?))?;
        (&x * &y).enforce_equal(&z)?;
        (&x + &y).enforce_equal(&w)?;
        // a few more constraints so the domain is not trivial
        let mut acc = x.clone();
        for _ in 0..5 {
            acc = &acc * &y;
        }
        let _ = acc;
        Ok(())
    }
}

#[test]
fn derived_key_equals_a_plain_setup_with_the_same_secrets() {
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let n = domain_size(Tiny::default()).unwrap();
    let (tau, alpha, beta) = (Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng));
    let p0 = Phase1::new(n).unwrap();
    let p1 = p0.contribute_with(tau, alpha, beta, digest(&p0.to_bytes().unwrap()), &mut rng);
    let ours = initial_proving_key(Tiny::default(), &p1).unwrap();
    // arkworks evaluates at t = tau with gamma = delta = 1 over the same generators
    let theirs = Groth16::<Bls12_381>::generate_parameters_with_qap(
        Tiny::default(),
        alpha,
        beta,
        Fr::ONE,
        Fr::ONE,
        G1Projective::generator(),
        G2Projective::generator(),
        &mut ArkRng::new(tau),
    )
    .unwrap();
    assert_eq!(ours.a_query.len(), theirs.a_query.len());
    assert!(ours.a_query == theirs.a_query, "a_query");
    assert!(ours.b_g1_query == theirs.b_g1_query, "b_g1_query");
    assert!(ours.b_g2_query == theirs.b_g2_query, "b_g2_query");
    assert!(ours.h_query == theirs.h_query, "h_query");
    assert!(ours.beta_g1 == theirs.beta_g1, "beta_g1");
    assert!(ours.vk.alpha_g1 == theirs.vk.alpha_g1, "alpha_g1");
    assert!(ours.l_query == theirs.l_query, "l_query");
    assert!(ours.vk.gamma_abc_g1 == theirs.vk.gamma_abc_g1, "gamma_abc");
    assert_eq!(ours, theirs);
    // a bigger phase 1 serves the same circuit
    let big = Phase1::new(2 * n).unwrap();
    let big = big.contribute_with(tau, alpha, beta, [0u8; 32], &mut rng);
    assert_eq!(initial_proving_key(Tiny::default(), &big).unwrap(), theirs);
    // a smaller one does not
    let small = Phase1::new(n / 2).unwrap();
    assert!(initial_proving_key(Tiny::default(), &small).is_err());
}

/// An "rng" that yields `t` when arkworks samples its evaluation point:
/// `generate_parameters_with_qap` draws one field element
/// (`sample_element_outside_domain`), limb by limb, and `t` is below the
/// modulus, so the rejection sampler accepts it as is.
struct ArkRng {
    limbs: [u64; 4],
    next: usize,
}

impl ArkRng {
    fn new(t: Fr) -> Self {
        // `Fp::rand` builds the element straight from random limbs, which
        // it treats as the Montgomery representation: feed `t`'s own.
        ArkRng {
            limbs: t.0.0,
            next: 0,
        }
    }
}

impl rand::RngCore for ArkRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        let v = self.limbs[self.next % 4];
        self.next += 1;
        v
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let b = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&b[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[test]
fn full_ceremony_on_the_tiny_circuit() {
    let mut rng = ChaCha20Rng::seed_from_u64(5);
    let n = domain_size(Tiny::default()).unwrap();
    // phase 1: two participants, verified pairwise from files
    let p0 = Phase1::new(n).unwrap();
    let f0 = p0.to_bytes().unwrap();
    let p1 = Phase1::read(&f0[..])
        .unwrap()
        .contribute(digest(&f0), &mut rng);
    let f1 = p1.to_bytes().unwrap();
    Phase1::verify_transition(&p0, digest(&f0), &Phase1::read(&f1[..]).unwrap(), &mut rng).unwrap();
    let p2 = Phase1::read(&f1[..])
        .unwrap()
        .contribute(digest(&f1), &mut rng);
    let f2 = p2.to_bytes().unwrap();
    Phase1::verify_transition(&p1, digest(&f1), &Phase1::read(&f2[..]).unwrap(), &mut rng).unwrap();
    // phase 2: initial key from the final accumulator, two participants, a beacon
    let initial = initial_proving_key(Tiny::default(), &p2).unwrap();
    let q0 = Phase2::new(initial.clone()).unwrap();
    let q1 = Phase2::read(&q0.to_bytes().unwrap()[..])
        .unwrap()
        .contribute(&mut rng)
        .unwrap();
    assert_eq!(q1.verify(&initial, &mut rng).unwrap().len(), 1);
    let q2 = Phase2::read(&q1.to_bytes().unwrap()[..])
        .unwrap()
        .contribute(&mut rng)
        .unwrap();
    let q3 = q2.beacon(b"block 900000 hash").unwrap();
    assert_eq!(
        q3.beacon(b"block 900000 hash").unwrap().contributions.len(),
        4
    );
    assert_eq!(
        q2.beacon(b"block 900000 hash").unwrap(),
        q3,
        "the beacon step is reproducible"
    );
    let hashes = q3.verify(&initial, &mut rng).unwrap();
    assert_eq!(hashes.len(), 3);
    assert_eq!(hashes[0], q1.contributions[0].hash());
    // the final key proves and verifies
    let pk = q3.pk.clone();
    let x = Fr::from(6u64);
    let y = Fr::from(7u64);
    let proof = Groth16::<Bls12_381>::prove(
        &pk,
        Tiny {
            x: Some(x),
            y: Some(y),
        },
        &mut rng,
    )
    .unwrap();
    let pvk = Groth16::<Bls12_381>::process_vk(&pk.vk).unwrap();
    assert!(Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &[x * y, x + y], &proof).unwrap());
    assert!(
        !Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &[x * y, x + y + Fr::ONE], &proof)
            .unwrap()
    );
    // the initial key (delta = 1) also works but is worthless; the verifier
    // of the chain is what says the delta was randomised
    assert!(q0.verify(&initial, &mut rng).unwrap().is_empty());

    // tampering
    let bad = |q: Phase2, needle: &str| {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let e = q.verify(&initial, &mut rng).unwrap_err().to_string();
        assert!(e.contains(needle), "{e}");
    };
    let mut t = q3.clone();
    t.pk.a_query[1] = t.pk.a_query[0];
    bad(t, "circuit part");
    let mut t = q3.clone();
    t.pk.vk.gamma_abc_g1[0] = t.pk.a_query[0];
    bad(t, "circuit part");
    let mut t = q3.clone();
    t.cs_hash[0] ^= 1;
    bad(t, "initial key digest");
    let mut t = q3.clone();
    t.contributions.remove(1);
    bad(t, "not bound to the transcript");
    let mut t = q3.clone();
    t.contributions[1].s_delta = t.contributions[1].s;
    bad(t, "proof of knowledge");
    let mut t = q3.clone();
    t.contributions[2].delta_after = t.contributions[1].delta_after;
    bad(t, "delta was not applied");
    let mut t = q3.clone();
    t.pk.delta_g1 = q2.pk.delta_g1;
    bad(t, "final delta differs");
    let mut t = q3.clone();
    t.pk.vk.delta_g2 = q2.pk.vk.delta_g2;
    bad(t, "between G1 and G2");
    let mut t = q3.clone();
    t.pk.h_query[1] = q2.pk.h_query[1];
    bad(t, "H query");
    let mut t = q3.clone();
    t.pk.l_query[0] = q2.pk.l_query[0];
    bad(t, "L query");
    let mut t = q3.clone();
    t.pk.h_query.pop();
    bad(t, "length changed");
    // a key for another circuit does not verify against this one
    let other =
        Groth16::<Bls12_381>::generate_random_parameters_with_reduction(Tiny::default(), &mut rng)
            .unwrap();
    assert!(q3.verify(&other, &mut rng).is_err());
    // file checks
    assert!(Phase2::read(&b"sbp1"[..]).is_err());
    let bytes = q3.to_bytes().unwrap();
    assert!(Phase2::read(&bytes[..bytes.len() - 5]).is_err());
}

#[test]
fn the_transfer_circuit_when_asked() {
    if std::env::var("SB_CEREMONY_FULL").is_err() {
        eprintln!("set SB_CEREMONY_FULL=1 to run the ceremony on the transfer circuit");
        return;
    }
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let t = std::time::Instant::now();
    let n = domain_size(sb_circuit::TransferCircuit::default()).unwrap();
    eprintln!("domain {n}");
    let p0 = Phase1::new(n).unwrap();
    let d0 = digest(&p0.to_bytes().unwrap());
    let p1 = p0.contribute(d0, &mut rng);
    eprintln!("phase 1 contribution: {:?}", t.elapsed());
    Phase1::verify_transition(&p0, d0, &p1, &mut rng).unwrap();
    eprintln!("phase 1 verification: {:?}", t.elapsed());
    let initial = initial_proving_key(sb_circuit::TransferCircuit::default(), &p1).unwrap();
    eprintln!("key derivation: {:?}", t.elapsed());
    let q = Phase2::new(initial.clone())
        .unwrap()
        .contribute(&mut rng)
        .unwrap();
    eprintln!("phase 2 contribution: {:?}", t.elapsed());
    q.verify(&initial, &mut rng).unwrap();
    eprintln!("phase 2 verification: {:?}", t.elapsed());
    let params = sb_circuit::TransferParams::from_pk(q.pk);
    let bytes = params.pk_to_bytes().unwrap();
    eprintln!("proving key: {} bytes", bytes.len());
}
