//! A proven step on the wire (`docs/REPLAY-PROOF-A.md` §3.4): what a light
//! client reads for one fragment of one block — the slot statements it
//! keeps, the state opening after, and the two proofs with their public
//! inputs — and the decider: `T_q` verified natively in full, the transfer
//! proofs' claims read out of `T_q`'s public inputs, `T_p` verified with
//! them, and its last three public values checked against the client's
//! own state digest, its own digest of the statements, and the opening.
//! The transfer proofs themselves are not on the wire.

use ff::{Field, PrimeField};
use halo2_proofs::plonk::{self, VerifyingKey};
use halo2_proofs::poly::commitment::{Claim, Params};
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::{pallas, vesta};

use crate::native::PoseidonRead;
use crate::step4::StepQN;
use crate::verifier::q::Slot;
use sba_core::batch::{SLOT_ELEMENTS, SlotStatement, StateOpening, batch_digest};
use sba_primitives::Fp;

type Fq = vesta::Base;

/// One fragment of one block, proven.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenStep {
    pub height: u32,
    /// The slots in replay order; an empty slot is all zeros.
    pub slots: Vec<Option<SlotStatement>>,
    pub opening_after: StateOpening,
    pub instance_q: Vec<Fq>,
    pub proof_q: Vec<u8>,
    /// The first instance column of `T_p` (the relation's own is empty).
    pub instance_p: Vec<Fp>,
    pub proof_p: Vec<u8>,
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u32(out, b.len() as u32);
    out.extend_from_slice(b);
}

struct Rd<'a>(&'a [u8]);
impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.0.len() < n {
            return Err("short read".into());
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn fp(&mut self) -> Result<Fp, String> {
        let b: [u8; 32] = self.take(32)?.try_into().unwrap();
        Option::from(Fp::from_repr(b)).ok_or_else(|| "non-canonical Fp".to_string())
    }
    fn fq(&mut self) -> Result<Fq, String> {
        let b: [u8; 32] = self.take(32)?.try_into().unwrap();
        Option::from(Fq::from_repr(b)).ok_or_else(|| "non-canonical Fq".to_string())
    }
    fn bytes(&mut self) -> Result<Vec<u8>, String> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
}

impl ProvenStep {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_u32(&mut out, 1); // version
        put_u32(&mut out, self.height);
        put_u32(&mut out, self.slots.len() as u32);
        for s in &self.slots {
            let e = s
                .map(|s| s.to_elements())
                .unwrap_or([Fp::ZERO; SLOT_ELEMENTS]);
            for v in e {
                out.extend_from_slice(&v.to_repr());
            }
        }
        let o = &self.opening_after;
        out.extend_from_slice(&o.root.to_repr());
        put_u64(&mut out, o.size);
        out.extend_from_slice(&o.nf_root.to_repr());
        put_u64(&mut out, o.nf_size);
        out.extend_from_slice(&o.h_root.to_repr());
        put_u32(&mut out, o.height);
        put_u32(&mut out, o.applied);
        put_u32(&mut out, self.instance_q.len() as u32);
        for v in &self.instance_q {
            out.extend_from_slice(&v.to_repr());
        }
        put_bytes(&mut out, &self.proof_q);
        put_u32(&mut out, self.instance_p.len() as u32);
        for v in &self.instance_p {
            out.extend_from_slice(&v.to_repr());
        }
        put_bytes(&mut out, &self.proof_p);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        let mut r = Rd(b);
        if r.u32()? != 1 {
            return Err("unknown version".into());
        }
        let height = r.u32()?;
        let n = r.u32()? as usize;
        let mut slots = Vec::with_capacity(n);
        for _ in 0..n {
            let mut e = [Fp::ZERO; SLOT_ELEMENTS];
            for v in e.iter_mut() {
                *v = r.fp()?;
            }
            if e.iter().all(|v| *v == Fp::ZERO) {
                slots.push(None);
            } else {
                slots.push(Some(
                    SlotStatement::from_elements(&e).ok_or("not a statement")?,
                ));
            }
        }
        let opening_after = StateOpening {
            root: r.fp()?,
            size: r.u64()?,
            nf_root: r.fp()?,
            nf_size: r.u64()?,
            h_root: r.fp()?,
            height: r.u32()?,
            applied: r.u32()?,
        };
        let n = r.u32()? as usize;
        let mut instance_q = Vec::with_capacity(n);
        for _ in 0..n {
            instance_q.push(r.fq()?);
        }
        let proof_q = r.bytes()?;
        let n = r.u32()? as usize;
        let mut instance_p = Vec::with_capacity(n);
        for _ in 0..n {
            instance_p.push(r.fp()?);
        }
        let proof_p = r.bytes()?;
        if !r.0.is_empty() {
            return Err("trailing bytes".into());
        }
        Ok(ProvenStep {
            height,
            slots,
            opening_after,
            instance_q,
            proof_q,
            instance_p,
            proof_p,
        })
    }
}

/// What a client holds per deployment to decide steps: the keys, and the
/// structure of `T_q` (its public inputs' layout, from which the transfer
/// proofs' claims are read).
pub struct Decider<'a> {
    pub outer: &'a Params<pallas::Affine>,
    pub ovk: &'a VerifyingKey<pallas::Affine>,
    pub pparams: &'a Params<vesta::Affine>,
    pub pvk: &'a VerifyingKey<vesta::Affine>,
    pub step_q: &'a StepQN,
    /// The transfer proofs' `k`: the length of a claim.
    pub transfer_k: usize,
}

/// The transfer proofs' claims as `T_q`'s public inputs carry them: each
/// group side's `G` and its last `transfer_k` challenges.
pub fn claims_of(
    step_q: &StepQN,
    transfer_k: usize,
    instance_q: &[Fq],
) -> Result<Vec<Claim<vesta::Affine>>, String> {
    let offsets = step_q.offsets();
    let mut claims = Vec::with_capacity(step_q.groups.len());
    for (g, off) in step_q.groups.iter().zip(offsets) {
        let layout = g.layout();
        let at = |slot: Slot| -> Result<Fq, String> {
            let p = layout
                .iter()
                .position(|s| *s == slot)
                .ok_or("slot not in the layout")?;
            instance_q
                .get(off + p)
                .copied()
                .ok_or_else(|| "short instance".into())
        };
        let gx = at(Slot::G(0))?;
        let gy = at(Slot::G(1))?;
        let g_point: vesta::Affine =
            Option::from(vesta::Affine::from_xy(gx, gy)).ok_or("G off the curve")?;
        let u: Vec<Fp> = g
            .ipa_challenge_slots(transfer_k)
            .iter()
            .map(|p| {
                let v = instance_q.get(off + *p).copied().ok_or("short instance")?;
                // a 128-bit challenge: the same integer in Fp
                Option::from(Fp::from_repr(v.to_repr())).ok_or_else(|| "challenge".to_string())
            })
            .collect::<Result<_, String>>()?;
        claims.push(Claim { g: g_point, u });
    }
    Ok(claims)
}

impl Decider<'_> {
    /// The transfer proofs' claims in a step's `T_q` public inputs.
    pub fn claims(&self, instance_q: &[Fq]) -> Result<Vec<Claim<vesta::Affine>>, String> {
        claims_of(self.step_q, self.transfer_k, instance_q)
    }

    /// Decide a step against the client's state digest `s_prev`; on success
    /// the digest after, which the client checks is the opening's.
    pub fn decide(&self, step: &ProvenStep, s_prev: Fp) -> Result<Fp, String> {
        let mut tr = PoseidonRead::<_, pallas::Affine>::init(&step.proof_q[..]);
        plonk::verify_proof(
            self.outer,
            self.ovk,
            plonk::SingleVerifier::new(self.outer),
            &[&[&step.instance_q[..]]],
            &mut tr,
        )
        .map_err(|e| format!("T_q: {e:?}"))?;
        let claims = self.claims(&step.instance_q)?;
        let mut tr = PoseidonRead::<_, vesta::Affine>::init(&step.proof_p[..]);
        plonk::verify_proof_with_openings(
            self.pparams,
            self.pvk,
            plonk::SingleVerifier::new(self.pparams),
            &[&[&step.instance_p[..]]],
            &mut tr,
            &claims,
        )
        .map_err(|e| format!("T_p: {e:?}"))?;
        let n = step.instance_p.len();
        if n < 3 {
            return Err("T_p instance too short".into());
        }
        let (got_prev, got_next, got_d) = (
            step.instance_p[n - 3],
            step.instance_p[n - 2],
            step.instance_p[n - 1],
        );
        if got_prev != s_prev {
            return Err("s_prev is not the client's state".into());
        }
        if got_d != batch_digest(&step.slots) {
            return Err("D is not the digest of the statements".into());
        }
        if got_next != step.opening_after.digest() {
            return Err("s_next is not the opening's digest".into());
        }
        Ok(got_next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use group::prime::PrimeCurveAffine;

    #[test]
    fn a_step_round_trips_through_bytes() {
        let st = SlotStatement {
            h_anchor: 7,
            r_anchor: Fp::from(8u64),
            nullifiers: [Fp::from(9u64), Fp::from(10u64)],
            pk_eph: [sba_core::xy(&sba_primitives::Affine::generator()); 2],
            ct: [sba_core::note::NoteCiphertext {
                c0: Fp::from(1u64),
                c1: Fp::from(2u64),
                tag: Fp::from(3u64),
            }; 2],
            h_body: Fp::from(14u64),
            mint: false,
        };
        let step = ProvenStep {
            height: 1001,
            slots: vec![Some(st), None],
            opening_after: StateOpening {
                root: Fp::from(1u64),
                size: 2,
                nf_root: Fp::from(3u64),
                nf_size: 4,
                h_root: Fp::from(5u64),
                height: 1002,
                applied: 0,
            },
            instance_q: vec![Fq::from(11u64), -Fq::ONE],
            proof_q: vec![1, 2, 3],
            instance_p: vec![Fp::from(12u64)],
            proof_p: vec![4, 5],
        };
        let bytes = step.to_bytes();
        assert_eq!(ProvenStep::from_bytes(&bytes).unwrap(), step);
        assert!(ProvenStep::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut bad = bytes.clone();
        bad[0] = 2;
        assert!(ProvenStep::from_bytes(&bad).is_err());
    }
}
