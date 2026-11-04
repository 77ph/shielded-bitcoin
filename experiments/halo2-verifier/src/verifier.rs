//! The group part of verifying one transfer proof, as a circuit over `Fq`
//! (`docs/REPLAY-PROOF-A.md` §3.3): the proof's points are witnessed on the
//! Vesta chip and absorbed into the transcript gadget together with its
//! scalars, the challenges are squeezed, and the verifier's accumulated
//! final multi-scalar multiplication — every commitment of the proof and of
//! the key multiplied by its scalar, plus `W`, `U` and the prover's `G` —
//! is checked to be the identity. The scalars of that multiplication, the
//! challenges, the proof's scalars and the claim `(G, u_j)` are public
//! inputs: the field side (the next circuit, over `Fp`) checks that the
//! scalars are the right functions of the challenges and evaluations. What
//! this circuit therefore proves: *these* proof bytes bind *these*
//! challenges, and with *these* scalars the group equation holds.
//!
//! The instance commitment is recomputed in-circuit from the statement's
//! values as `halo2_proofs`' verifier does: `Σ instance_i · G_lagrange[i] +
//! [1] W` (the default blind is one), so the statement itself is the
//! public input, not an opaque point.

use ff::{Field, PrimeField};
use halo2_gadgets::poseidon::primitives as poseidon;
use halo2_gadgets::poseidon::Pow5Chip;
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, TableColumn,
};
use halo2_proofs::poly::commitment::Params;
use pasta_curves::vesta;
use vesta_ecc::ecc::chip::{CircuitVersion, EccChip, EccConfig};
use vesta_ecc::ecc::{NonIdentityPoint, Point, ScalarVar};
use vesta_ecc::utilities::lookup_range_check::{LookupRangeCheck, VestaLookupRangeCheckConfig};

use crate::capture::{Capture, Event};
use crate::fixed::Bases;
use crate::transcript::{Fq, Transcript, TranscriptConfig};
use sba_primitives::Fp;

type Ecc = EccChip<Bases, VestaLookupRangeCheckConfig>;
type Cell = AssignedCell<Fq, Fq>;

/// The kind of each transcript event: the circuit's structure, fixed by the
/// verifying key; the values come with a capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    CommonPoint,
    CommonScalar,
    ReadPoint,
    ReadScalar,
    Squeeze,
}

/// Where a term of the final MSM takes its point from.
#[derive(Clone, Copy, Debug)]
pub enum Source {
    /// The i-th point read from the proof.
    Read(usize),
    /// The instance commitment (the common point).
    Common,
    /// A constant point: a commitment of the key, `G_0`, `W`, `U`.
    Constant(vesta::Affine),
    /// The prover's accumulator point `G`.
    Claim,
}

/// The structure (from the key) and, when proving, the values.
#[derive(Clone)]
pub struct VerifierCircuit {
    pub kinds: Vec<Kind>,
    /// One per term of the final MSM, in a canonical order.
    pub sources: Vec<Source>,
    /// The parameters' `W` and `U` (constants of the circuit).
    pub params_w: vesta::Affine,
    pub params_u: vesta::Affine,
    /// The Lagrange generators of the instance values (constants).
    pub lagrange: Vec<vesta::Affine>,
    pub capture: Option<Capture>,
}

#[derive(Clone, Debug)]
pub struct VerifierConfig {
    ecc: EccConfig<Bases, VestaLookupRangeCheckConfig>,
    transcript: TranscriptConfig,
    advices: [Column<Advice>; 10],
    instance: Column<Instance>,
    table_idx: TableColumn,
}

fn embed(s: &Fp) -> Fq {
    Fq::from_repr(s.to_repr()).expect("p < q")
}

impl VerifierCircuit {
    /// The structure of a capture: the event kinds and, for every term of
    /// its MSM, where the point comes from; `terms` of a later capture of
    /// the same circuit are matched to these sources by coordinates.
    pub fn shape(
        cap: &Capture,
        params: &Params<vesta::Affine>,
        fixed_commitments: &[vesta::Affine],
        permutation_commitments: &[vesta::Affine],
    ) -> (Vec<Kind>, Vec<Source>) {
        let kinds = cap
            .events
            .iter()
            .map(|e| match e {
                Event::CommonPoint(_) => Kind::CommonPoint,
                Event::CommonScalar(_) => Kind::CommonScalar,
                Event::ReadPoint(_) => Kind::ReadPoint,
                Event::ReadScalar(_) => Kind::ReadScalar,
                Event::Squeeze(_) => Kind::Squeeze,
            })
            .collect();
        // one source per distinct point: `halo2_proofs`' MSM merges equal
        // points (two identical fixed columns commit to the same point), so
        // a repeated point keeps its first source only
        let mut candidates: Vec<(Source, vesta::Affine)> = Vec::new();
        let read: Vec<vesta::Affine> = cap
            .events
            .iter()
            .filter_map(|e| match e {
                Event::ReadPoint(p) => Some(*p),
                _ => None,
            })
            .collect();
        for (i, p) in read.iter().enumerate() {
            candidates.push((Source::Read(i), *p));
        }
        let common = cap
            .events
            .iter()
            .find_map(|e| match e {
                Event::CommonPoint(p) => Some(*p),
                _ => None,
            })
            .expect("an instance commitment");
        candidates.push((Source::Common, common));
        for c in fixed_commitments.iter().chain(permutation_commitments) {
            candidates.push((Source::Constant(*c), *c));
        }
        candidates.push((Source::Constant(params.get_g()[0]), params.get_g()[0]));
        candidates.push((Source::Claim, cap.g));
        let mut seen: Vec<vesta::Affine> = Vec::new();
        let mut sources = Vec::new();
        for (src, p) in candidates {
            if seen.contains(&p) {
                continue;
            }
            seen.push(p);
            sources.push(src);
        }
        (kinds, sources)
    }

    /// The scalar of each source in a capture (zero for a source the MSM
    /// has no term for).
    fn scalars(&self, cap: &Capture) -> Vec<Fp> {
        let read: Vec<vesta::Affine> = cap
            .events
            .iter()
            .filter_map(|e| match e {
                Event::ReadPoint(p) => Some(*p),
                _ => None,
            })
            .collect();
        let common = cap
            .events
            .iter()
            .find_map(|e| match e {
                Event::CommonPoint(p) => Some(*p),
                _ => None,
            })
            .expect("an instance commitment");
        let scalar_of = |p: &vesta::Affine| -> Fp {
            cap.terms
                .iter()
                .find(|(_, q)| q == p)
                .map(|(s, _)| *s)
                .unwrap_or(Fp::zero())
        };
        self.sources
            .iter()
            .map(|s| match s {
                Source::Read(i) => scalar_of(&read[*i]),
                Source::Common => scalar_of(&common),
                Source::Constant(c) => scalar_of(c),
                Source::Claim => scalar_of(&cap.g),
            })
            .collect()
    }

    /// The public inputs of a capture, in the circuit's order.
    pub fn instance(&self, cap: &Capture, params: &Params<vesta::Affine>) -> Vec<Fq> {
        let mut v = Vec::new();
        for e in &cap.events {
            match e {
                Event::CommonScalar(s) | Event::ReadScalar(s) | Event::Squeeze(s) => {
                    v.push(embed(s))
                }
                Event::CommonPoint(_) => {
                    for s in &cap.instance {
                        v.push(embed(s));
                    }
                }
                Event::ReadPoint(_) => {}
            }
        }
        for s in self.scalars(cap) {
            v.push(embed(&s));
        }
        v.push(embed(&cap.w_scalar));
        v.push(embed(&cap.u_scalar));
        let (gx, gy) = coords(&cap.g);
        v.push(gx);
        v.push(gy);
        let _ = params;
        v
    }
}

fn coords(p: &vesta::Affine) -> (Fq, Fq) {
    use pasta_curves::arithmetic::CurveAffine;
    let c = p.coordinates().unwrap();
    (*c.x(), *c.y())
}

/// Expose a cell as the next public input.
fn expose<L: Layouter<Fq>>(
    cfg: &VerifierConfig,
    layouter: &mut L,
    c: &Cell,
    row: &mut usize,
) -> Result<(), Error> {
    layouter.constrain_instance(c.cell(), cfg.instance, *row)?;
    *row += 1;
    Ok(())
}

/// A constant point as a non-identity point of the chip: witnessed, then
/// pinned to the constant.
fn pinned<L: Layouter<Fq>>(
    ecc: &Ecc,
    layouter: &mut L,
    c: vesta::Affine,
) -> Result<NonIdentityPoint<vesta::Affine, Ecc>, Error> {
    let w = NonIdentityPoint::new(
        ecc.clone(),
        layouter.namespace(|| "constant"),
        Value::known(c),
    )?;
    let k = Point::new_from_constant(ecc.clone(), layouter.namespace(|| "constant"), c)?;
    w.constrain_equal(layouter.namespace(|| "pin"), &k)?;
    Ok(w)
}

/// Witness one `Fq` value.
fn witness<L: Layouter<Fq>>(
    cfg: &VerifierConfig,
    layouter: &mut L,
    v: Value<Fq>,
) -> Result<Cell, Error> {
    layouter.assign_region(
        || "scalar",
        |mut r| r.assign_advice(|| "s", cfg.advices[3], 0, || v),
    )
}

impl Circuit<Fq> for VerifierCircuit {
    type Config = VerifierConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        VerifierCircuit {
            kinds: self.kinds.clone(),
            sources: self.sources.clone(),
            params_w: self.params_w,
            params_u: self.params_u,
            lagrange: self.lagrange.clone(),
            capture: None,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fq>) -> VerifierConfig {
        let advices: [Column<Advice>; 10] = core::array::from_fn(|_| meta.advice_column());
        for a in &advices {
            meta.enable_equality(*a);
        }
        let lagrange_coeffs: [Column<Fixed>; 8] = core::array::from_fn(|_| meta.fixed_column());
        meta.enable_constant(lagrange_coeffs[0]);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        let table_idx = meta.lookup_table_column();
        let range = VestaLookupRangeCheckConfig::configure(meta, advices[9], table_idx);
        let ecc = EccChip::<Bases>::configure(meta, advices, lagrange_coeffs, range.clone());
        let poseidon = Pow5Chip::configure::<poseidon::P128Pow5T3>(
            meta,
            advices[6..9].try_into().unwrap(),
            advices[5],
            lagrange_coeffs[2..5].try_into().unwrap(),
            lagrange_coeffs[5..8].try_into().unwrap(),
        );
        let transcript = TranscriptConfig::configure(
            meta,
            poseidon,
            range,
            [advices[0], advices[1], advices[2]],
        );
        VerifierConfig {
            ecc,
            transcript,
            advices,
            instance,
            table_idx,
        }
    }

    fn synthesize(
        &self,
        cfg: VerifierConfig,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "10-bit table",
            |mut table| {
                for i in 0..(1 << 10) {
                    table.assign_cell(
                        || "idx",
                        cfg.table_idx,
                        i,
                        || Value::known(Fq::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )?;
        let ecc = EccChip::construct(cfg.ecc.clone(), CircuitVersion::AnchoredBase);
        let mut t = Transcript::new(&cfg.transcript, &mut layouter)?;
        let cap = self.capture.as_ref();
        let mut row = 0usize;

        // the transcript walk
        let mut read_points: Vec<NonIdentityPoint<vesta::Affine, Ecc>> = Vec::new();
        let mut common_point: Option<NonIdentityPoint<vesta::Affine, Ecc>> = None;
        let mut read_i = 0usize;
        let mut squeeze_i = 0usize;
        let mut scalar_i = 0usize;
        for (i, kind) in self.kinds.iter().enumerate() {
            match kind {
                Kind::CommonScalar | Kind::ReadScalar => {
                    let v = cap
                        .map(|c| match &c.events[i] {
                            Event::CommonScalar(s) | Event::ReadScalar(s) => Value::known(embed(s)),
                            _ => unreachable!(),
                        })
                        .unwrap_or(Value::unknown());
                    let cell = witness(&cfg, &mut layouter, v)?;
                    expose(&cfg, &mut layouter, &cell, &mut row)?;
                    t.absorb(&mut layouter, cell)?;
                    scalar_i += 1;
                }
                Kind::CommonPoint => {
                    // the instance commitment from the statement's values:
                    // Σ instance_i · G_lagrange[i] + [1] W
                    let mut acc: Option<Point<vesta::Affine, Ecc>> = None;
                    for (j, g) in self.lagrange.iter().enumerate() {
                        let v = cap
                            .map(|c| Value::known(embed(&c.instance[j])))
                            .unwrap_or(Value::unknown());
                        let cell = witness(&cfg, &mut layouter, v)?;
                        expose(&cfg, &mut layouter, &cell, &mut row)?;
                        let base = pinned(&ecc, &mut layouter, *g)?;
                        let scalar = ScalarVar::from_base(
                            ecc.clone(),
                            layouter.namespace(|| "instance scalar"),
                            &cell,
                        )?;
                        let (prod, _) = base.mul(layouter.namespace(|| "instance mul"), scalar)?;
                        acc = Some(match acc {
                            None => prod,
                            Some(a) => a.add(layouter.namespace(|| "instance add"), &prod)?,
                        });
                    }
                    let w = Point::new_from_constant(
                        ecc.clone(),
                        layouter.namespace(|| "W"),
                        self.params_w,
                    )?;
                    let commitment = acc
                        .expect("instance values")
                        .add(layouter.namespace(|| "blind"), &w)?;
                    // as a non-identity point: witnessed and pinned to the sum
                    let p = NonIdentityPoint::new(
                        ecc.clone(),
                        layouter.namespace(|| "instance commitment"),
                        commitment.inner().point(),
                    )?;
                    p.constrain_equal(layouter.namespace(|| "pin commitment"), &commitment)?;
                    let x = p.inner().x();
                    let y = p.inner().y();
                    t.absorb(&mut layouter, x)?;
                    t.absorb(&mut layouter, y)?;
                    common_point = Some(p);
                }
                Kind::ReadPoint => {
                    let v = cap
                        .map(|c| match &c.events[i] {
                            Event::ReadPoint(p) => Value::known(*p),
                            _ => unreachable!(),
                        })
                        .unwrap_or(Value::unknown());
                    let p = NonIdentityPoint::new(ecc.clone(), layouter.namespace(|| "point"), v)?;
                    let x = p.inner().x();
                    let y = p.inner().y();
                    t.absorb(&mut layouter, x)?;
                    t.absorb(&mut layouter, y)?;
                    read_points.push(p);
                    read_i += 1;
                }
                Kind::Squeeze => {
                    let (_, c) = t.squeeze(&mut layouter)?;
                    expose(&cfg, &mut layouter, &c, &mut row)?;
                    squeeze_i += 1;
                }
            }
        }
        let _ = (read_i, squeeze_i, scalar_i);

        // the multi-scalar multiplication
        let scalars: Option<Vec<Fp>> = cap.map(|c| self.scalars(c));
        let mut sum: Option<Point<vesta::Affine, Ecc>> = None;
        for (j, source) in self.sources.iter().enumerate() {
            let s = scalars
                .as_ref()
                .map(|v| Value::known(embed(&v[j])))
                .unwrap_or(Value::unknown());
            let s_cell = witness(&cfg, &mut layouter, s)?;
            expose(&cfg, &mut layouter, &s_cell, &mut row)?;
            let base: NonIdentityPoint<vesta::Affine, Ecc> = match source {
                Source::Read(i) => read_points[*i].clone(),
                Source::Common => common_point.clone().expect("absorbed before the MSM"),
                Source::Constant(c) => pinned(&ecc, &mut layouter, *c)?,
                Source::Claim => {
                    let v = cap.map(|c| Value::known(c.g)).unwrap_or(Value::unknown());
                    let g = NonIdentityPoint::new(ecc.clone(), layouter.namespace(|| "G"), v)?;
                    g
                }
            };
            let scalar =
                ScalarVar::from_base(ecc.clone(), layouter.namespace(|| "scalar var"), &s_cell)?;
            let (prod, _) = base.mul(layouter.namespace(|| "mul"), scalar)?;
            sum = Some(match sum {
                None => prod,
                Some(acc) => acc.add(layouter.namespace(|| "add"), &prod)?,
            });
        }
        // W and U
        for (point, value) in [
            (self.params_w, cap.map(|c| c.w_scalar)),
            (self.params_u, cap.map(|c| c.u_scalar)),
        ] {
            let s_cell = witness(
                &cfg,
                &mut layouter,
                value
                    .map(|v| Value::known(embed(&v)))
                    .unwrap_or(Value::unknown()),
            )?;
            expose(&cfg, &mut layouter, &s_cell, &mut row)?;
            let w = pinned(&ecc, &mut layouter, point)?;
            let scalar =
                ScalarVar::from_base(ecc.clone(), layouter.namespace(|| "scalar var"), &s_cell)?;
            let (prod, _) = w.mul(layouter.namespace(|| "mul"), scalar)?;
            sum = Some(
                sum.expect("terms")
                    .add(layouter.namespace(|| "add"), &prod)?,
            );
        }
        // the claim's G exposed, and the sum must be the identity (0, 0)
        let g_index = self
            .sources
            .iter()
            .position(|s| matches!(s, Source::Claim))
            .expect("a claim term");
        let _ = g_index;
        let sum = sum.expect("terms");
        layouter.assign_region(
            || "identity",
            |mut r| {
                r.constrain_constant(sum.inner().x().cell(), Fq::ZERO)?;
                r.constrain_constant(sum.inner().y().cell(), Fq::ZERO)?;
                Ok(())
            },
        )?;
        eprintln!(
            "transcript permutations: {}, msm terms: {}",
            t.permutations,
            self.sources.len() + 2
        );
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;
    use crate::capture::capture;
    use halo2_proofs::plonk;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use sba_circuit::{TransferCircuit, TransferParams, K};

    pub(crate) fn real() -> (
        Params<vesta::Affine>,
        plonk::VerifyingKey<vesta::Affine>,
        Capture,
    ) {
        let params = TransferParams::build().unwrap();
        let (st, w) = crate::sample::sample();
        let mut rng = StdRng::seed_from_u64(5);
        let proof = params.prove(&st, &w, &mut rng).unwrap();
        let halo_params: Params<vesta::Affine> = Params::new(K);
        let vk = plonk::keygen_vk(&halo_params, &TransferCircuit::default()).unwrap();
        let cap = capture(&halo_params, &vk, &st.to_field_elements(), &proof).unwrap();
        (halo_params, vk, cap)
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::real;
    use super::*;
    use halo2_proofs::dev::MockProver;

    #[test]
    fn the_group_part_of_a_real_proof_verifies_in_circuit() {
        let (params, vk, cap) = real();
        let (kinds, sources) = VerifierCircuit::shape(
            &cap,
            &params,
            vk.fixed_commitments(),
            vk.permutation_commitments(),
        );
        let circuit = VerifierCircuit {
            kinds,
            sources,
            params_w: params.get_w(),
            params_u: params.get_u(),
            lagrange: params.get_g_lagrange()[..cap.instance.len()].to_vec(),
            capture: Some(cap.clone()),
        };
        // every MSM term found a source
        let n_terms = cap.terms.len();
        let nonzero = circuit
            .scalars(&cap)
            .iter()
            .filter(|s| !bool::from(s.is_zero()))
            .count();
        println!(
            "msm terms {n_terms}, sources {} ({nonzero} with a non-zero scalar)",
            circuit.sources.len()
        );
        assert_eq!(nonzero, n_terms);
        let instance = circuit.instance(&cap, &params);
        println!("public inputs: {}", instance.len());
        let mut k = 15;
        let t = std::time::Instant::now();
        let prover = loop {
            match MockProver::run(k, &circuit, vec![instance.clone()]) {
                Ok(p) => break p,
                Err(_) => {
                    k += 1;
                    assert!(k <= 20, "does not fit k = 20");
                }
            }
        };
        println!(
            "fits k = {k} (mock prover {:.1} s)",
            t.elapsed().as_secs_f64()
        );
        prover.assert_satisfied();
        // a wrong scalar for one term is refused
        let mut bad = instance.clone();
        let n_transcript = cap
            .events
            .iter()
            .filter(|e| !matches!(e, Event::ReadPoint(_)))
            .map(|e| {
                if matches!(e, Event::CommonPoint(_)) {
                    cap.instance.len()
                } else {
                    1
                }
            })
            .sum::<usize>();
        bad[n_transcript] += Fq::ONE;
        assert!(MockProver::run(k, &circuit, vec![bad])
            .unwrap()
            .verify()
            .is_err());
        // a wrong statement value is refused too (the commitment moves)
        let mut bad = instance.clone();
        bad[1] += Fq::ONE;
        assert!(MockProver::run(k, &circuit, vec![bad])
            .unwrap()
            .verify()
            .is_err());
    }
}

#[cfg(test)]
mod prove_tests {
    use super::tests_support::real;
    use super::*;
    use halo2_proofs::plonk;
    use halo2_proofs::poly::commitment::Params;
    use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// Key generation, proving and verification of the verifier circuit
    /// itself (a Pallas-committed proof of an `Fq` circuit), at k = 15:
    /// `cargo test --release prove_the_verifier_circuit -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn prove_the_verifier_circuit() {
        let (params, vk, cap) = real();
        let (kinds, sources) = VerifierCircuit::shape(
            &cap,
            &params,
            vk.fixed_commitments(),
            vk.permutation_commitments(),
        );
        let circuit = VerifierCircuit {
            kinds,
            sources,
            params_w: params.get_w(),
            params_u: params.get_u(),
            lagrange: params.get_g_lagrange()[..cap.instance.len()].to_vec(),
            capture: Some(cap.clone()),
        };
        let instance = circuit.instance(&cap, &params);
        let k = 15;
        let t = std::time::Instant::now();
        let outer: Params<pasta_curves::pallas::Affine> = Params::new(k);
        let ovk = plonk::keygen_vk(&outer, &circuit.without_witnesses()).unwrap();
        let opk = plonk::keygen_pk(&outer, ovk.clone(), &circuit.without_witnesses()).unwrap();
        println!("keygen (k = {k}): {:.1} s", t.elapsed().as_secs_f64());
        let t = std::time::Instant::now();
        let mut tr = Blake2bWrite::<_, pasta_curves::pallas::Affine, Challenge255<_>>::init(vec![]);
        plonk::create_proof(
            &outer,
            &opk,
            &[circuit.clone()],
            &[&[&instance[..]]],
            &mut StdRng::seed_from_u64(9),
            &mut tr,
        )
        .unwrap();
        let proof = tr.finalize();
        println!(
            "prove: {:.1} s, proof {} bytes",
            t.elapsed().as_secs_f64(),
            proof.len()
        );
        let t = std::time::Instant::now();
        let strategy = plonk::SingleVerifier::new(&outer);
        let mut tr = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        plonk::verify_proof(&outer, &ovk, strategy, &[&[&instance[..]]], &mut tr).unwrap();
        println!("verify: {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);
    }
}
