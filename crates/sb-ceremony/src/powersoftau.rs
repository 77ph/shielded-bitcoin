//! Import of a public powers-of-tau transcript in the `powersoftau`
//! **response** format of the Zcash Sapling MPC (also used, at a larger
//! size, by Filecoin's), so a deployment can skip its own phase 1 and run
//! only phase 2 on top of a ceremony that many independent participants
//! have already contributed to.
//!
//! Response layout, for a ceremony of `2^p` powers:
//!
//! ```text
//! BLAKE2b-512 of the challenge it answers           64 bytes
//! [τ^i]₁, i < 2^(p+1) − 1                           48 bytes each, compressed
//! [τ^i]₂, i < 2^p                                   96 bytes each, compressed
//! [ατ^i]₁, i < 2^p                                  48 bytes each
//! [βτ^i]₁, i < 2^p                                  48 bytes each
//! [β]₂                                              96 bytes
//! the contributor's public key                      1152 bytes, uncompressed
//! ```
//!
//! Points use the Zcash encoding, which arkworks' BLS12-381 shares, so
//! they are decoded directly. The importer keeps the first `2n − 1` and
//! `n` elements of each vector for the domain it is asked for, validates
//! them (curve and subgroup) and checks the accumulator's shape with the
//! same pairing checks as a native contribution. It cannot verify the
//! ceremony's own chain of contributions: that is what the public record
//! of the ceremony (its challenge/response hashes) is for, and the
//! importer prints the two hashes to compare with it.

use std::io::{Read, Seek, SeekFrom, Write};

use ark_bls12_381::{G1Affine, G2Affine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::{Blake2b512, Digest};

use crate::phase1::Phase1;
use crate::transcript::{valid_g1, valid_g2};
use crate::{CeremonyError, CeremonyResult};

pub const HASH_SIZE: usize = 64;
const G1_COMPRESSED: usize = 48;
const G2_COMPRESSED: usize = 96;
const G1_UNCOMPRESSED: usize = 96;
const G2_UNCOMPRESSED: usize = 192;
/// `(s, sτ), (s, sα), (s, sβ)` in `G1` and `τ, α, β` on hashed points in `G2`.
const PUBLIC_KEY_SIZE: usize = 6 * G1_UNCOMPRESSED + 3 * G2_UNCOMPRESSED;

/// Byte length of a response file for `2^power` powers.
pub fn response_len(power: u32) -> u64 {
    let n = 1u64 << power;
    HASH_SIZE as u64
        + (2 * n - 1) * G1_COMPRESSED as u64
        + n * G2_COMPRESSED as u64
        + 2 * n * G1_COMPRESSED as u64
        + G2_COMPRESSED as u64
        + PUBLIC_KEY_SIZE as u64
}

fn read_g1<R: Read>(r: &mut R, count: usize) -> CeremonyResult<Vec<G1Affine>> {
    let mut out = Vec::with_capacity(count);
    let mut buf = [0u8; G1_COMPRESSED];
    for _ in 0..count {
        r.read_exact(&mut buf)?;
        out.push(G1Affine::deserialize_compressed_unchecked(&buf[..])?);
    }
    Ok(out)
}

fn read_g2<R: Read>(r: &mut R, count: usize) -> CeremonyResult<Vec<G2Affine>> {
    let mut out = Vec::with_capacity(count);
    let mut buf = [0u8; G2_COMPRESSED];
    for _ in 0..count {
        r.read_exact(&mut buf)?;
        out.push(G2Affine::deserialize_compressed_unchecked(&buf[..])?);
    }
    Ok(out)
}

/// What an import returns besides the accumulator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Imported {
    pub phase1: Phase1,
    /// The hash the response carries: BLAKE2b-512 of the challenge it answered.
    pub challenge_hash: [u8; HASH_SIZE],
    /// BLAKE2b-512 of the whole response file: what the ceremony published
    /// for this contribution and what the next challenge carried.
    pub response_hash: [u8; HASH_SIZE],
}

/// Import a response of a `2^power` ceremony as a phase 1 accumulator for
/// a domain of `n` (a power of two, at most `2^power`). Reads only what it
/// keeps and seeks over the rest; hashes the whole file.
pub fn import_response<R: Read + Seek>(mut r: R, power: u32, n: usize) -> CeremonyResult<Imported> {
    let bad = |what: String| CeremonyError::Invalid(what);
    if !(1..=28).contains(&power) {
        return Err(bad(format!("power {power} out of range")));
    }
    let full = 1usize << power;
    if n < 2 || !n.is_power_of_two() || n > full {
        return Err(bad(format!(
            "domain {n} is not a power of two between 2 and 2^{power}"
        )));
    }
    let len = r.seek(SeekFrom::End(0))?;
    if len != response_len(power) {
        return Err(bad(format!(
            "file is {len} bytes, a 2^{power} response is {} bytes",
            response_len(power)
        )));
    }
    r.seek(SeekFrom::Start(0))?;
    let mut challenge_hash = [0u8; HASH_SIZE];
    r.read_exact(&mut challenge_hash)?;
    let tau_g1 = read_g1(&mut r, 2 * n - 1)?;
    r.seek(SeekFrom::Current(
        ((2 * full - 1) - (2 * n - 1)) as i64 * G1_COMPRESSED as i64,
    ))?;
    let tau_g2 = read_g2(&mut r, n)?;
    r.seek(SeekFrom::Current((full - n) as i64 * G2_COMPRESSED as i64))?;
    let alpha_tau_g1 = read_g1(&mut r, n)?;
    r.seek(SeekFrom::Current((full - n) as i64 * G1_COMPRESSED as i64))?;
    let beta_tau_g1 = read_g1(&mut r, n)?;
    r.seek(SeekFrom::Current((full - n) as i64 * G1_COMPRESSED as i64))?;
    let beta_g2 = read_g2(&mut r, 1)?[0];
    if !valid_g1(&tau_g1)
        || !valid_g2(&tau_g2)
        || !valid_g1(&alpha_tau_g1)
        || !valid_g1(&beta_tau_g1)
        || !valid_g2(&[beta_g2])
    {
        return Err(bad("a point is not in the prime-order subgroup".into()));
    }
    // hash the whole file
    r.seek(SeekFrom::Start(0))?;
    let mut hasher = Blake2b512::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let got = r.read(&mut buf)?;
        if got == 0 {
            break;
        }
        hasher.update(&buf[..got]);
    }
    let response_hash: [u8; HASH_SIZE] = hasher.finalize().into();
    let phase1 = Phase1 {
        n,
        // the accumulator's provenance in our chain is the response itself
        prev_digest: crate::transcript::digest(&response_hash),
        key: None,
        tau_g1,
        tau_g2,
        alpha_tau_g1,
        beta_tau_g1,
        beta_g2,
    };
    Ok(Imported {
        phase1,
        challenge_hash,
        response_hash,
    })
}

/// Write a phase 1 accumulator of exactly `2^power` powers as a response
/// file, with `challenge_hash` in front and `public_key` (1152 bytes, not
/// interpreted here) at the end. For tests and for feeding other tools.
pub fn write_response<W: Write>(
    p: &Phase1,
    power: u32,
    challenge_hash: &[u8; HASH_SIZE],
    public_key: &[u8],
    mut w: W,
) -> CeremonyResult<()> {
    if p.n != 1usize << power {
        return Err(CeremonyError::Invalid(format!(
            "accumulator has {} powers, not 2^{power}",
            p.n
        )));
    }
    if public_key.len() != PUBLIC_KEY_SIZE {
        return Err(CeremonyError::Invalid("public key size".into()));
    }
    w.write_all(challenge_hash)?;
    for q in &p.tau_g1 {
        q.serialize_compressed(&mut w)?;
    }
    for q in &p.tau_g2 {
        q.serialize_compressed(&mut w)?;
    }
    for q in &p.alpha_tau_g1 {
        q.serialize_compressed(&mut w)?;
    }
    for q in &p.beta_tau_g1 {
        q.serialize_compressed(&mut w)?;
    }
    p.beta_g2.serialize_compressed(&mut w)?;
    w.write_all(public_key)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript::digest;
    use ark_ec::AffineRepr;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::io::Cursor;

    /// The Zcash encoding, as the `powersoftau` files use it.
    #[test]
    fn point_encoding_is_the_zcash_one() {
        let mut g1 = Vec::new();
        G1Affine::generator().serialize_compressed(&mut g1).unwrap();
        assert_eq!(
            hex::encode(&g1),
            "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
        );
        let mut g2 = Vec::new();
        G2Affine::generator().serialize_compressed(&mut g2).unwrap();
        assert_eq!(
            hex::encode(&g2),
            "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
        );
        let mut inf = Vec::new();
        G1Affine::identity().serialize_compressed(&mut inf).unwrap();
        assert_eq!(&hex::encode(&inf)[..4], "c000");
    }

    #[test]
    fn a_response_round_trips_and_a_larger_one_is_cut_down() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let p0 = Phase1::new(16).unwrap();
        let p = p0.contribute(digest(&p0.to_bytes().unwrap()), &mut rng);
        let mut file = Vec::new();
        let key = vec![7u8; PUBLIC_KEY_SIZE];
        write_response(&p, 4, &[9u8; HASH_SIZE], &key, &mut file).unwrap();
        assert_eq!(file.len() as u64, response_len(4));
        // the whole thing
        let imp = import_response(Cursor::new(&file), 4, 16).unwrap();
        assert_eq!(imp.challenge_hash, [9u8; HASH_SIZE]);
        assert_eq!(imp.phase1.tau_g1, p.tau_g1);
        assert_eq!(imp.phase1.tau_g2, p.tau_g2);
        assert_eq!(imp.phase1.alpha_tau_g1, p.alpha_tau_g1);
        assert_eq!(imp.phase1.beta_tau_g1, p.beta_tau_g1);
        assert_eq!(imp.phase1.beta_g2, p.beta_g2);
        assert!(imp.phase1.key.is_none());
        assert_eq!(imp.phase1.prev_digest, digest(&imp.response_hash));
        let expected: [u8; 64] = Blake2b512::digest(&file).into();
        assert_eq!(imp.response_hash, expected);
        imp.phase1.verify_shape(&mut rng).unwrap();
        // a smaller domain takes the prefixes
        let small = import_response(Cursor::new(&file), 4, 4).unwrap().phase1;
        assert_eq!(small.n, 4);
        assert_eq!(small.tau_g1, p.tau_g1[..7]);
        assert_eq!(small.tau_g2, p.tau_g2[..4]);
        assert_eq!(small.alpha_tau_g1, p.alpha_tau_g1[..4]);
        assert_eq!(small.beta_tau_g1, p.beta_tau_g1[..4]);
        small.verify_shape(&mut rng).unwrap();
        // and can be contributed to as any accumulator
        let d = digest(&small.to_bytes().unwrap());
        let next = small.contribute(d, &mut rng);
        Phase1::verify_transition(&small, d, &next, &mut rng).unwrap();
        // our own file round trip
        assert_eq!(Phase1::read(&small.to_bytes().unwrap()[..]).unwrap(), small);
    }

    #[test]
    fn bad_inputs_are_refused() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let p0 = Phase1::new(8).unwrap();
        let p = p0.contribute([0u8; 32], &mut rng);
        let key = vec![0u8; PUBLIC_KEY_SIZE];
        let mut file = Vec::new();
        write_response(&p, 3, &[0u8; HASH_SIZE], &key, &mut file).unwrap();
        let err = |r: CeremonyResult<Imported>| r.unwrap_err().to_string();
        assert!(err(import_response(Cursor::new(&file), 4, 8)).contains("bytes"));
        assert!(err(import_response(Cursor::new(&file), 3, 16)).contains("between 2 and"));
        assert!(err(import_response(Cursor::new(&file), 3, 3)).contains("power of two"));
        assert!(err(import_response(Cursor::new(&file), 0, 2)).contains("out of range"));
        assert!(err(import_response(Cursor::new(&file[..file.len() - 1]), 3, 8)).contains("bytes"));
        // a point outside the subgroup
        let mut rogue = file.clone();
        let mut x = ark_bls12_381::Fq::from(5u64);
        let q = loop {
            if let Some(q) = G1Affine::get_point_from_x_unchecked(x, true) {
                if !q.is_in_correct_subgroup_assuming_on_curve() {
                    break q;
                }
            }
            x += ark_bls12_381::Fq::from(1u64);
        };
        let mut enc = Vec::new();
        q.serialize_compressed(&mut enc).unwrap();
        rogue[HASH_SIZE + 2 * G1_COMPRESSED..HASH_SIZE + 3 * G1_COMPRESSED].copy_from_slice(&enc);
        assert!(err(import_response(Cursor::new(&rogue), 3, 8)).contains("subgroup"));
        // not a point at all
        let mut junk = file.clone();
        junk[HASH_SIZE + 1] ^= 0xff;
        junk[HASH_SIZE] = 0x80;
        assert!(import_response(Cursor::new(&junk), 3, 8).is_err());
        // a tampered power passes decoding but fails the shape check
        let mut swapped = file.clone();
        let a = HASH_SIZE + 3 * G1_COMPRESSED;
        let b = HASH_SIZE + 4 * G1_COMPRESSED;
        let tmp: Vec<u8> = swapped[a..b].to_vec();
        swapped.copy_within(b..b + G1_COMPRESSED, a);
        swapped[b..b + G1_COMPRESSED].copy_from_slice(&tmp);
        let imp = import_response(Cursor::new(&swapped), 3, 8).unwrap();
        assert!(imp.phase1.verify_shape(&mut rng).is_err());
        // writer checks
        assert!(write_response(&p, 4, &[0u8; HASH_SIZE], &key, Vec::new()).is_err());
        assert!(write_response(&p, 3, &[0u8; HASH_SIZE], &key[..10], Vec::new()).is_err());
    }
}
