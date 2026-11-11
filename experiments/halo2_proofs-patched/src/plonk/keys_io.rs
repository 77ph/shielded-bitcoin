//! Keys on disk — this fork's addition, read/write only, nothing of the
//! prover or verifier changes. A verifying key is written as its `k`,
//! fixed and permutation commitments, selector assignments and transcript
//! representative; reading it runs the circuit's `configure` again and
//! compresses the selectors as `keygen_vk` did, so the constraint system
//! is rebuilt rather than stored, and the representative read must equal
//! the one recomputed. A proving key is the verifying key with the fixed
//! and permutation columns' Lagrange values; their coefficient and coset
//! forms and `l_0`, `l_blind`, `l_last` are recomputed as `keygen_pk`
//! computes them (a key at `k = 18` is hundreds of megabytes without its
//! cosets, gigabytes with them).

use std::io::{self, Read, Write};

use group::ff::{Field, FromUniformBytes, PrimeField};
use group::GroupEncoding;

use super::{keygen::create_domain, permutation, Circuit, ProvingKey, VerifyingKey};
use crate::arithmetic::CurveAffine;
use crate::poly::commitment::Params;

const VK_TAG: &[u8; 8] = b"halo2vk1";
const PK_TAG: &[u8; 8] = b"halo2pk1";

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

fn write_u32<W: Write>(w: &mut W, v: u32) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}
fn write_u64<W: Write>(w: &mut W, v: u64) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}
fn read_u32<R: Read>(r: &mut R) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}
fn read_u64<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}
fn write_scalar<W: Write, F: PrimeField>(w: &mut W, s: &F) -> io::Result<()> {
    w.write_all(s.to_repr().as_ref())
}
fn read_scalar<R: Read, F: PrimeField>(r: &mut R) -> io::Result<F> {
    let mut repr = F::Repr::default();
    r.read_exact(repr.as_mut())?;
    Option::from(F::from_repr(repr)).ok_or_else(|| bad("a non-canonical scalar"))
}
fn write_point<W: Write, C: CurveAffine>(w: &mut W, p: &C) -> io::Result<()> {
    w.write_all(p.to_bytes().as_ref())
}
fn read_point<R: Read, C: CurveAffine>(r: &mut R) -> io::Result<C> {
    let mut repr = C::Repr::default();
    r.read_exact(repr.as_mut())?;
    Option::from(C::from_bytes(&repr)).ok_or_else(|| bad("not a point"))
}
fn write_points<W: Write, C: CurveAffine>(w: &mut W, ps: &[C]) -> io::Result<()> {
    write_u32(w, ps.len() as u32)?;
    for p in ps {
        write_point(w, p)?;
    }
    Ok(())
}
fn read_points<R: Read, C: CurveAffine>(r: &mut R) -> io::Result<Vec<C>> {
    let n = read_u32(r)? as usize;
    (0..n).map(|_| read_point(r)).collect()
}
/// A column of `n` scalars.
fn write_column<W: Write, F: PrimeField>(w: &mut W, values: &[F]) -> io::Result<()> {
    write_u64(w, values.len() as u64)?;
    for v in values {
        write_scalar(w, v)?;
    }
    Ok(())
}
fn read_column<R: Read, F: PrimeField>(r: &mut R, n: usize) -> io::Result<Vec<F>> {
    if read_u64(r)? as usize != n {
        return Err(bad("a column of another length"));
    }
    (0..n).map(|_| read_scalar(r)).collect()
}

impl<C: CurveAffine> VerifyingKey<C>
where
    C::Scalar: FromUniformBytes<64>,
{
    /// Write the key: the domain's `k`, the fixed and permutation
    /// commitments, the selector assignments (bit-packed) and the
    /// transcript representative.
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(VK_TAG)?;
        write_u32(w, self.domain.k())?;
        write_points(w, &self.fixed_commitments)?;
        write_points(w, &self.permutation.commitments)?;
        write_u32(w, self.selectors.len() as u32)?;
        write_u64(w, self.domain.n())?;
        for s in &self.selectors {
            if s.len() != self.domain.n() as usize {
                return Err(bad("a selector of another length"));
            }
            let mut bytes = vec![0u8; s.len().div_ceil(8)];
            for (i, on) in s.iter().enumerate() {
                if *on {
                    bytes[i / 8] |= 1 << (i % 8);
                }
            }
            w.write_all(&bytes)?;
        }
        write_scalar(w, &self.transcript_repr)
    }

    /// Read a key written by [`Self::write`] for `ConcreteCircuit` over
    /// `params`: the constraint system is the circuit's, with the stored
    /// selectors compressed as at key generation; the representative must
    /// agree, or the file is of another circuit.
    pub fn read<R: Read, ConcreteCircuit: Circuit<C::Scalar>>(
        r: &mut R,
        params: &Params<C>,
    ) -> io::Result<Self> {
        let mut tag = [0u8; 8];
        r.read_exact(&mut tag)?;
        if &tag != VK_TAG {
            return Err(bad("not a verifying key"));
        }
        if read_u32(r)? != params.k {
            return Err(bad("a key of another k"));
        }
        let fixed_commitments = read_points(r)?;
        let permutation_commitments = read_points(r)?;
        let n_selectors = read_u32(r)? as usize;
        let n = read_u64(r)? as usize;
        if n != params.n as usize {
            return Err(bad("a key of another domain"));
        }
        let mut selectors = Vec::with_capacity(n_selectors);
        for _ in 0..n_selectors {
            let mut bytes = vec![0u8; n.div_ceil(8)];
            r.read_exact(&mut bytes)?;
            selectors.push((0..n).map(|i| bytes[i / 8] & (1 << (i % 8)) != 0).collect());
        }
        let transcript_repr: C::Scalar = read_scalar(r)?;
        let (domain, cs, _config) = create_domain::<C, ConcreteCircuit>(params);
        if cs.num_selectors != n_selectors {
            return Err(bad("a key of another circuit (selectors)"));
        }
        let (cs, _selector_polys) = cs.compress_selectors(selectors.clone());
        let vk = VerifyingKey::from_parts(
            domain,
            fixed_commitments,
            permutation::VerifyingKey {
                commitments: permutation_commitments,
            },
            cs,
            selectors,
        );
        if vk.transcript_repr != transcript_repr {
            return Err(bad("a key of another circuit (representative)"));
        }
        Ok(vk)
    }
}

impl<C: CurveAffine> ProvingKey<C>
where
    C::Scalar: FromUniformBytes<64>,
{
    /// Write the key: the verifying key, then the fixed columns and the
    /// permutation columns as Lagrange values (no cosets).
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(PK_TAG)?;
        self.vk.write(w)?;
        write_u32(w, self.fixed_values.len() as u32)?;
        for poly in &self.fixed_values {
            write_column(w, poly)?;
        }
        let perms = self.permutation.permutations();
        write_u32(w, perms.len() as u32)?;
        for poly in perms {
            write_column(w, poly)?;
        }
        Ok(())
    }

    /// Read a key written by [`Self::write`]; the coefficient and coset
    /// forms and `l_0`, `l_blind`, `l_last` are recomputed.
    pub fn read<R: Read, ConcreteCircuit: Circuit<C::Scalar>>(
        r: &mut R,
        params: &Params<C>,
    ) -> io::Result<Self> {
        let mut tag = [0u8; 8];
        r.read_exact(&mut tag)?;
        if &tag != PK_TAG {
            return Err(bad("not a proving key"));
        }
        // HALO2_KEYS_IO_TIMING=1 prints where the time goes
        let timing = std::env::var_os("HALO2_KEYS_IO_TIMING").is_some();
        let mut t = std::time::Instant::now();
        let mut lap = |what: &str| {
            if timing {
                eprintln!("keys_io: {what} {:.1} s", t.elapsed().as_secs_f64());
                t = std::time::Instant::now();
            }
        };
        let vk = VerifyingKey::read::<R, ConcreteCircuit>(r, params)?;
        lap("verifying key");
        let n = params.n as usize;
        let n_fixed = read_u32(r)? as usize;
        if n_fixed != vk.cs.num_fixed_columns {
            return Err(bad("a key of another circuit (fixed columns)"));
        }
        let mut fixed_values = Vec::with_capacity(n_fixed);
        for _ in 0..n_fixed {
            fixed_values.push(vk.domain.lagrange_from_vec(read_column(r, n)?));
        }
        let n_perm = read_u32(r)? as usize;
        if n_perm != vk.cs.permutation.get_columns().len() {
            return Err(bad("a key of another circuit (permutation columns)"));
        }
        let mut permutations = Vec::with_capacity(n_perm);
        for _ in 0..n_perm {
            permutations.push(vk.domain.lagrange_from_vec(read_column(r, n)?));
        }
        lap("columns parsed");
        let fixed_polys: Vec<_> = fixed_values
            .iter()
            .map(|poly| vk.domain.lagrange_to_coeff(poly.clone()))
            .collect();
        lap("fixed polys (ifft)");
        let fixed_cosets = fixed_polys
            .iter()
            .map(|poly| vk.domain.coeff_to_extended(poly.clone()))
            .collect();
        lap("fixed cosets (extended fft)");
        let permutation = permutation::ProvingKey::from_permutations(&vk.domain, permutations);
        lap("permutation polys and cosets");
        // as keygen_pk: l_0, l_blind, l_last
        let mut l0 = vk.domain.empty_lagrange();
        l0[0] = C::Scalar::ONE;
        let l0 = vk.domain.lagrange_to_coeff(l0);
        let l0 = vk.domain.coeff_to_extended(l0);
        let blinding = vk.cs.blinding_factors();
        let mut l_blind = vk.domain.empty_lagrange();
        for evaluation in l_blind[..].iter_mut().rev().take(blinding) {
            *evaluation = C::Scalar::ONE;
        }
        let l_blind = vk.domain.lagrange_to_coeff(l_blind);
        let l_blind = vk.domain.coeff_to_extended(l_blind);
        let mut l_last = vk.domain.empty_lagrange();
        l_last[n - blinding - 1] = C::Scalar::ONE;
        let l_last = vk.domain.lagrange_to_coeff(l_last);
        let l_last = vk.domain.coeff_to_extended(l_last);
        Ok(ProvingKey {
            vk,
            l0,
            l_blind,
            l_last,
            fixed_values,
            fixed_polys,
            fixed_cosets,
            permutation,
        })
    }
}
