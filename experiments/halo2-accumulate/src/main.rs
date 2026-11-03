//! Verification of n variant-A transfer proofs (Halo 2 / IPA, k = 14):
//! one by one, and accumulated into one multi-scalar multiplication
//! (`docs/REPLAY-PROOF-A.md`). Three verifiers:
//!
//! * `single`: `SingleVerifier`, one 2^k-sized MSM per proof;
//! * `batched`: every proof's deferred MSM (`Guard::use_challenges`, the
//!   `s` vector folded into the generator scalars) scaled by a random factor
//!   and added into one MSM, evaluated once;
//! * `accumulated`: the prover supplies `G = ⟨s, params.g⟩` with each
//!   proof; the verifier does only the succinct part per proof (transcript,
//!   `Guard::use_g`, a small MSM over the commitments) and checks the n
//!   claims `(G_i, u_i)` at the end with one random linear combination:
//!   `⟨Σ r_i s_i, params.g⟩ = Σ r_i G_i`, one 2^k MSM for all n. The
//!   per-proof succinct part is what a recursive verifier would carry
//!   in-circuit; the final MSM is what accumulation defers.
//!
//! Usage: `cargo run --release -- [n ...]` (default 1 4 16 64).

use std::time::Instant;

use ff::Field;
use group::Curve;
use halo2_proofs::arithmetic::best_multiexp;
use halo2_proofs::plonk::{self, Error, VerificationStrategy};
use halo2_proofs::poly::commitment::{Guard, Params, MSM};
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255, EncodedChallenge};
use pasta_curves::vesta;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sba_circuit::{InputWitness, OutputWitness, TransferCircuit, TransferStatement, TransferWitness, K};
use sba_core::envelope::TransferBody;
use sba_core::keys::{Seed, WalletKeys};
use sba_core::note::{encrypt_note, note_leaf, nullifier, NotePlaintext};
use sba_core::recovery::{binding_digest, encrypt_recovery, RecoveryEntry};
use sba_core::tree::NoteTree;
use sba_primitives::Fp;

type Scalar = <vesta::Affine as halo2_proofs::arithmetic::CurveAffine>::ScalarExt;

/// The sample transfer of `sba-circuit/tests/transfer.rs`.
fn sample() -> (TransferStatement, TransferWitness) {
    let mut rng = StdRng::seed_from_u64(42);
    let alice = WalletKeys::from_seed(&Seed([1u8; 32]));
    let bob = WalletKeys::from_seed(&Seed([2u8; 32]));
    let (_, a0) = alice.ivk.find_address(0);
    let (_, a1) = alice.ivk.find_address(1);
    let (_, b0) = bob.ivk.find_address(0);
    let const_salt = Fp::random(&mut rng);
    let hb0 = Fp::random(&mut rng);
    let note_in = NotePlaintext { value: 1000, d: a0.d, rseed: Fp::random(&mut rng) };
    let (pe, ct) = encrypt_note(&note_in, &a0.pk_d).unwrap();
    let leaf = note_leaf(&const_salt, &hb0, 1, &pe, &ct);
    let mut tree = NoteTree::new();
    for _ in 0..5 {
        tree.append(Fp::random(&mut rng));
    }
    let pos = tree.append(leaf);
    tree.append(Fp::random(&mut rng));
    let path = tree.path(pos).unwrap();
    let r_anchor = tree.root();
    let dummy = InputWitness::dummy(a1.d, Fp::random(&mut rng));
    let inputs = [
        InputWitness { note: note_in, h_body_create: hb0, output_index: 1, pos, siblings: path.siblings },
        dummy,
    ];
    let outs = [
        OutputWitness { note: NotePlaintext { value: 700, d: b0.d, rseed: Fp::random(&mut rng) }, pk_d: b0.pk_d },
        OutputWitness { note: NotePlaintext { value: 300, d: a1.d, rseed: Fp::random(&mut rng) }, pk_d: a1.pk_d },
    ];
    let (e0, c0) = encrypt_note(&outs[0].note, &outs[0].pk_d).unwrap();
    let (e1, c1) = encrypt_note(&outs[1].note, &outs[1].pk_d).unwrap();
    let digest = binding_digest(&[e0, e1], &[c0, c1]);
    let ct_out = encrypt_recovery(
        &alice.ovk,
        &digest,
        &[
            RecoveryEntry { pk_d: outs[0].pk_d, sk_eph: outs[0].note.sk_eph() },
            RecoveryEntry { pk_d: outs[1].pk_d, sk_eph: outs[1].note.sk_eph() },
        ],
    );
    let nullifiers = [
        nullifier(&alice.sk_nf, &inputs[0].note.rho(), inputs[0].pos),
        nullifier(&alice.sk_nf, &inputs[1].note.rho(), 0),
    ];
    let body = TransferBody { h_anchor: 100, nullifiers, pk_eph: [e0, e1], ct_note: [c0, c1], ct_out };
    let salt_bytes = sba_primitives::encoding::fp_to_bytes(&const_salt);
    let st = TransferStatement { const_salt, r_anchor, nullifiers, pk_eph: [e0, e1], ct_note: [c0, c1], h_body: body.h_body(&salt_bytes) };
    let w = TransferWitness { sk_spend: alice.sk_spend, inputs, outputs: outs };
    (st, w)
}

/// What the strategy does with the guard; the outputs carry no challenge
/// type, so the work that needs it happens inside `process`.
enum Mode {
    /// `Guard::compute_g` (the prover-side G of the accumulated mode).
    ComputeG,
    /// `Guard::use_challenges`: the deferred MSM with the `s` vector folded in.
    Batched,
    /// `Guard::use_g(g)`: the succinct part, plus the claim `(g, u)`.
    Accumulate(vesta::Affine),
}

enum Out<'p> {
    G(vesta::Affine),
    Msm(MSM<'p, vesta::Affine>),
    Claim(MSM<'p, vesta::Affine>, vesta::Affine, Vec<Scalar>),
}

struct Strat<'p>(&'p Params<vesta::Affine>, Mode);

impl<'p> VerificationStrategy<'p, vesta::Affine> for Strat<'p> {
    type Output = Out<'p>;
    fn process<E: EncodedChallenge<vesta::Affine>>(
        self,
        f: impl FnOnce(MSM<'p, vesta::Affine>) -> Result<Guard<'p, vesta::Affine, E>, Error>,
    ) -> Result<Self::Output, Error> {
        let guard = f(MSM::new(self.0))?;
        Ok(match self.1 {
            Mode::ComputeG => Out::G(guard.compute_g()),
            Mode::Batched => Out::Msm(guard.use_challenges()),
            Mode::Accumulate(g) => {
                let (msm, acc) = guard.use_g(g);
                let u = acc.u_packed.iter().map(|c| c.get_scalar()).collect();
                Out::Claim(msm, acc.g, u)
            }
        })
    }
}

fn run<'p>(
    params: &'p Params<vesta::Affine>,
    vk: &plonk::VerifyingKey<vesta::Affine>,
    instance: &[Fp],
    proof: &[u8],
    mode: Mode,
) -> Out<'p> {
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof);
    plonk::verify_proof(params, vk, Strat(params, mode), &[&[instance]], &mut transcript).unwrap()
}

fn main() {
    let ns: Vec<usize> = {
        let a: Vec<usize> = std::env::args().skip(1).filter_map(|s| s.parse().ok()).collect();
        if a.is_empty() { vec![1, 4, 16, 64] } else { a }
    };
    let params: Params<vesta::Affine> = Params::new(K);
    let empty = TransferCircuit::default();
    let t = Instant::now();
    let vk = plonk::keygen_vk(&params, &empty).unwrap();
    let pk = plonk::keygen_pk(&params, vk.clone(), &empty).unwrap();
    println!("keygen (k = {K}): {:.1} s", t.elapsed().as_secs_f64());
    let gens = params.get_g();
    let (st, w) = sample();
    let instance = st.to_field_elements();
    let n_max = *ns.iter().max().unwrap();
    let mut rng = StdRng::seed_from_u64(7);
    let t = Instant::now();
    let proofs: Vec<Vec<u8>> = (0..n_max)
        .map(|_| {
            let circuit = TransferCircuit { statement: Some(st.clone()), witness: Some(w.clone()), negate_g_d: false };
            let mut tr = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);
            plonk::create_proof(&params, &pk, &[circuit], &[&[&instance[..]]], &mut rng, &mut tr).unwrap();
            tr.finalize()
        })
        .collect();
    println!("{n_max} proofs of {} bytes in {:.1} s", proofs[0].len(), t.elapsed().as_secs_f64());
    // the prover-side G for the accumulated mode (what the prover would ship)
    let t = Instant::now();
    let gs: Vec<vesta::Affine> = proofs
        .iter()
        .map(|p| match run(&params, &vk, &instance, p, Mode::ComputeG) {
            Out::G(g) => g,
            _ => unreachable!(),
        })
        .collect();
    println!("prover-side G per proof: {:.1} ms", t.elapsed().as_secs_f64() * 1000.0 / n_max as f64);

    println!("\n| n | single, total / per proof | batched (use_challenges, one MSM), total / per proof | accumulated: succinct part per proof + final MSM, total / per proof |");
    println!("|---|---|---|---|");
    for &n in &ns {
        // single
        let t = Instant::now();
        for p in &proofs[..n] {
            let strategy = plonk::SingleVerifier::new(&params);
            let mut tr = Blake2bRead::<_, _, Challenge255<_>>::init(&p[..]);
            plonk::verify_proof(&params, &vk, strategy, &[&[&instance[..]]], &mut tr).unwrap();
        }
        let single = t.elapsed().as_secs_f64() * 1000.0;
        // batched: one MSM over all deferred terms
        let t = Instant::now();
        let mut acc = MSM::new(&params);
        for p in &proofs[..n] {
            let Out::Msm(mut m) = run(&params, &vk, &instance, p, Mode::Batched) else { unreachable!() };
            m.scale(Scalar::random(&mut rng));
            acc.add_msm(&m);
        }
        assert!(acc.eval());
        let batched = t.elapsed().as_secs_f64() * 1000.0;
        // accumulated: succinct part per proof, claims checked at the end
        let t = Instant::now();
        let mut claims = Vec::with_capacity(n);
        let mut small = MSM::new(&params);
        for (p, g) in proofs[..n].iter().zip(&gs) {
            let Out::Claim(mut m, g, u) = run(&params, &vk, &instance, p, Mode::Accumulate(*g)) else { unreachable!() };
            m.scale(Scalar::random(&mut rng));
            small.add_msm(&m);
            claims.push((g, u));
        }
        assert!(small.eval());
        let succinct = t.elapsed().as_secs_f64() * 1000.0;
        let t = Instant::now();
        // Σ r_i ⟨s_i, G⟩ = Σ r_i G_i with s_i from the packed challenges
        let mut s_sum = vec![Scalar::ZERO; 1 << K];
        let mut g_sum = vesta::Point::default();
        for (g, u) in &claims {
            let r = Scalar::random(&mut rng);
            let s = compute_s(u, r);
            for (x, y) in s_sum.iter_mut().zip(&s) {
                *x += y;
            }
            g_sum += *g * r;
        }
        let lhs = best_multiexp(&s_sum, &gens);
        assert_eq!(lhs.to_affine(), g_sum.to_affine());
        let final_msm = t.elapsed().as_secs_f64() * 1000.0;
        println!(
            "| {n} | {single:.1} ms / {:.2} ms | {batched:.1} ms / {:.2} ms | {succinct:.1} ms + {final_msm:.1} ms = {:.1} ms / {:.2} ms |",
            single / n as f64,
            batched / n as f64,
            succinct + final_msm,
            (succinct + final_msm) / n as f64
        );
    }
    println!("\naccumulator per proof: G (32 bytes) + {} challenges (32 bytes each)", K);
}

/// `s` of the inner-product argument for challenges `u` and scale `c`
/// (`halo2_proofs::poly::commitment::verifier::compute_s`, private there).
fn compute_s(u: &[Scalar], init: Scalar) -> Vec<Scalar> {
    assert!(!u.is_empty());
    let mut v = vec![Scalar::ZERO; 1 << u.len()];
    v[0] = init;
    for (len, u_j) in u.iter().rev().enumerate().map(|(i, u_j)| (1 << i, u_j)) {
        let (left, right) = v.split_at_mut(len);
        let right = &mut right[0..len];
        right.copy_from_slice(left);
        for v in right {
            *v *= u_j;
        }
    }
    v
}
