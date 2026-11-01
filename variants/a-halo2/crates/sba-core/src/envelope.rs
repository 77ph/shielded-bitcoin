//! Transfer envelope of family A: canonical body serialisation, strict
//! parsing and `h_body` (paper §11, §13, §A.3, §A.5; PROFILE-A.md §7).
//! The body layout is the paper profile's; the version byte is `0x02`, the
//! field elements and points are Pasta's, the proof is a 4 416-byte Halo 2
//! proof, and `h_body` clears two bits.

use sha2::{Digest, Sha256};

use sba_primitives::encoding::{
    DecodeError, fp_from_bytes, fp_to_bytes, point_from_bytes, point_to_bytes,
};
use sba_primitives::{Affine, Fp};

use crate::note::{CT_NOTE_LEN, NoteCiphertext};
use crate::recovery::{CT_OUT_LEN, N_OUT};

pub const MAGIC: [u8; 3] = *b"btc";
/// Family A (PROFILE-A.md §7, §13).
pub const VERSION: u8 = 2;
pub const KIND_TRANSFER: u8 = 0x01;
pub const HEADER_LEN: usize = 6;
/// Inputs per transfer (profile §7).
pub const N_IN: usize = 2;
/// One Halo 2 proof of the transfer circuit at `k = 14` (PROFILE-A.md §1).
pub const PROOF_LEN: usize = 4416;
pub const BODY_LEN: usize =
    HEADER_LEN + 4 + 2 + N_IN * 32 + N_OUT * 32 + N_OUT * CT_NOTE_LEN + CT_OUT_LEN;
pub const ENVELOPE_LEN: usize = BODY_LEN + PROOF_LEN;

/// Prefix every candidate payload of this family must start with.
pub const CANDIDATE_PREFIX: [u8; 4] = [b'b', b't', b'c', VERSION];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("bad magic")]
    Magic,
    #[error("unsupported version {0}")]
    Version(u8),
    #[error("unsupported kind {0}")]
    Kind(u8),
    #[error("reserved header byte is not zero")]
    Reserved,
    #[error("bad length {got}, expected {expected}")]
    Length { got: usize, expected: usize },
    #[error("non-canonical CompactSize")]
    CompactSize,
    #[error("unsupported arity {0} in / {1} out")]
    Arity(u64, u64),
    #[error("field {0}: {1}")]
    Field(&'static str, DecodeError),
    #[error("re-serialisation differs from the published bytes")]
    NonCanonical,
}

/// The proof-excluded body (paper Table 3, fields 0–7).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TransferBody {
    pub h_anchor: u32,
    pub nullifiers: [Fp; N_IN],
    pub pk_eph: [Affine; N_OUT],
    pub ct_note: [NoteCiphertext; N_OUT],
    pub ct_out: [u8; CT_OUT_LEN],
}

/// Body plus proof bytes (opaque here; `sba-circuit` verifies them).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TransferEnvelope {
    pub body: TransferBody,
    pub proof: Vec<u8>,
}

fn push_compact_size(out: &mut Vec<u8>, v: u64) {
    match v {
        0..=0xfc => out.push(v as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(v as u16).to_le_bytes());
        }
        0x10000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(v as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&v.to_le_bytes());
        }
    }
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        if self.pos + n > self.b.len() {
            return Err(ParseError::Length {
                got: self.b.len(),
                expected: self.pos + n,
            });
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, ParseError> {
        Ok(self.take(1)?[0])
    }

    /// Canonical (minimal) Bitcoin CompactSize.
    fn compact_size(&mut self) -> Result<u64, ParseError> {
        let first = self.u8()?;
        Ok(match first {
            0..=0xfc => first as u64,
            0xfd => {
                let v = u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as u64;
                if v < 0xfd {
                    return Err(ParseError::CompactSize);
                }
                v
            }
            0xfe => {
                let v = u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as u64;
                if v <= 0xffff {
                    return Err(ParseError::CompactSize);
                }
                v
            }
            _ => {
                let v = u64::from_le_bytes(self.take(8)?.try_into().unwrap());
                if v <= 0xffff_ffff {
                    return Err(ParseError::CompactSize);
                }
                v
            }
        })
    }
}

fn header(out: &mut Vec<u8>, kind: u8) {
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(kind);
    out.push(0);
}

fn parse_header(r: &mut Reader<'_>, expected_kind: u8) -> Result<(), ParseError> {
    if r.take(3)? != MAGIC {
        return Err(ParseError::Magic);
    }
    let version = r.u8()?;
    if version != VERSION {
        return Err(ParseError::Version(version));
    }
    let kind = r.u8()?;
    if kind != expected_kind {
        return Err(ParseError::Kind(kind));
    }
    if r.u8()? != 0 {
        return Err(ParseError::Reserved);
    }
    Ok(())
}

impl TransferBody {
    /// `body_bytes(e)` (PROFILE-A.md §7).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BODY_LEN);
        header(&mut out, KIND_TRANSFER);
        out.extend_from_slice(&self.h_anchor.to_le_bytes());
        push_compact_size(&mut out, N_IN as u64);
        push_compact_size(&mut out, N_OUT as u64);
        for nf in &self.nullifiers {
            out.extend_from_slice(&fp_to_bytes(nf));
        }
        for p in &self.pk_eph {
            out.extend_from_slice(&point_to_bytes(p));
        }
        for c in &self.ct_note {
            out.extend_from_slice(&c.to_bytes());
        }
        out.extend_from_slice(&self.ct_out);
        debug_assert_eq!(out.len(), BODY_LEN);
        out
    }

    /// Strict parse of exactly one body (no trailing bytes).
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader { b: bytes, pos: 0 };
        let body = Self::parse_prefix(&mut r)?;
        if r.pos != bytes.len() {
            return Err(ParseError::Length {
                got: bytes.len(),
                expected: r.pos,
            });
        }
        Ok(body)
    }

    fn parse_prefix(r: &mut Reader<'_>) -> Result<Self, ParseError> {
        parse_header(r, KIND_TRANSFER)?;
        let h_anchor = u32::from_le_bytes(r.take(4)?.try_into().unwrap());
        let n_in = r.compact_size()?;
        let n_out = r.compact_size()?;
        if n_in != N_IN as u64 || n_out != N_OUT as u64 {
            return Err(ParseError::Arity(n_in, n_out));
        }
        let mut nullifiers = [Fp::zero(); N_IN];
        for nf in nullifiers.iter_mut() {
            *nf = fp_from_bytes(r.take(32)?).map_err(|e| ParseError::Field("nf", e))?;
        }
        let mut pk_eph = Vec::with_capacity(N_OUT);
        for _ in 0..N_OUT {
            pk_eph.push(point_from_bytes(r.take(32)?).map_err(|e| ParseError::Field("pk_eph", e))?);
        }
        let mut ct_note = Vec::with_capacity(N_OUT);
        for _ in 0..N_OUT {
            ct_note.push(
                NoteCiphertext::from_bytes(r.take(CT_NOTE_LEN)?)
                    .map_err(|e| ParseError::Field("ct_note", e))?,
            );
        }
        let mut ct_out = [0u8; CT_OUT_LEN];
        ct_out.copy_from_slice(r.take(CT_OUT_LEN)?);
        Ok(TransferBody {
            h_anchor,
            nullifiers,
            pk_eph: pk_eph.try_into().unwrap(),
            ct_note: ct_note.try_into().unwrap(),
            ct_out,
        })
    }

    /// `h_body = H_body(const_salt ‖ body_bytes)` (PROFILE-A.md §2.2, §7).
    pub fn h_body(&self, const_salt: &[u8; 32]) -> Fp {
        h_body(const_salt, &self.to_bytes())
    }
}

/// `SHA-256(const_salt ‖ body_bytes)` with bits 254 and 255 cleared, as `Fp`.
pub fn h_body(const_salt: &[u8; 32], body_bytes: &[u8]) -> Fp {
    let mut h = Sha256::new();
    h.update(const_salt);
    h.update(body_bytes);
    bytes_to_fp_254(&h.finalize().into())
}

/// Interpret 32 bytes as a `< 2^254` little-endian field element.
pub fn bytes_to_fp_254(bytes: &[u8; 32]) -> Fp {
    let mut b = *bytes;
    b[31] &= 0x3f;
    fp_from_bytes(&b).expect("< 2^254 < p is canonical")
}

impl TransferEnvelope {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.body.to_bytes();
        out.extend_from_slice(&self.proof);
        out
    }

    /// Strict parse: exact length and byte-for-byte re-serialisation.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() != ENVELOPE_LEN {
            if bytes.len() >= HEADER_LEN {
                let mut r = Reader {
                    b: &bytes[..HEADER_LEN],
                    pos: 0,
                };
                parse_header(&mut r, KIND_TRANSFER)?;
            }
            return Err(ParseError::Length {
                got: bytes.len(),
                expected: ENVELOPE_LEN,
            });
        }
        let body = TransferBody::parse(&bytes[..BODY_LEN])?;
        let env = TransferEnvelope {
            body,
            proof: bytes[BODY_LEN..].to_vec(),
        };
        if env.to_bytes() != bytes {
            return Err(ParseError::NonCanonical);
        }
        Ok(env)
    }
}

// ---------------------------------------------------------------------------
// Development boundary: mint envelope (kind 0x02), as `docs/BOUNDARY.md`
// for the paper profile.
// ---------------------------------------------------------------------------

pub const KIND_MINT: u8 = 0x02;
/// `header ‖ v (u64 LE) ‖ d (11) ‖ rseed (32) ‖ pk_d (32)`.
pub const MINT_LEN: usize = HEADER_LEN + 8 + crate::note::DIVERSIFIER_LEN + 32 + 32;

/// A plaintext mint: the carrier transaction pays `note.value` satoshis to
/// the deployment vault, and replay derives the note leaf exactly as for a
/// transfer output (`j = 0`) from the recomputed `(pk_eph, ct_note)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MintEnvelope {
    pub note: crate::note::NotePlaintext,
    pub pk_d: Affine,
}

impl MintEnvelope {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MINT_LEN);
        header(&mut out, KIND_MINT);
        out.extend_from_slice(&self.note.value.to_le_bytes());
        out.extend_from_slice(&self.note.d);
        out.extend_from_slice(&fp_to_bytes(&self.note.rseed));
        out.extend_from_slice(&point_to_bytes(&self.pk_d));
        debug_assert_eq!(out.len(), MINT_LEN);
        out
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() != MINT_LEN {
            return Err(ParseError::Length {
                got: bytes.len(),
                expected: MINT_LEN,
            });
        }
        let mut r = Reader { b: bytes, pos: 0 };
        parse_header(&mut r, KIND_MINT)?;
        let value = u64::from_le_bytes(r.take(8)?.try_into().unwrap());
        let mut d = [0u8; crate::note::DIVERSIFIER_LEN];
        d.copy_from_slice(r.take(crate::note::DIVERSIFIER_LEN)?);
        let rseed = fp_from_bytes(r.take(32)?).map_err(|e| ParseError::Field("rseed", e))?;
        let pk_d = point_from_bytes(r.take(32)?).map_err(|e| ParseError::Field("pk_d", e))?;
        let env = MintEnvelope {
            note: crate::note::NotePlaintext { value, d, rseed },
            pk_d,
        };
        if env.to_bytes() != bytes {
            return Err(ParseError::NonCanonical);
        }
        Ok(env)
    }

    pub fn h_body(&self, const_salt: &[u8; 32]) -> Fp {
        h_body(const_salt, &self.to_bytes())
    }

    /// `(pk_eph, ct_note)` for the minted note; `None` if `d` is invalid.
    pub fn derive(&self) -> Option<(Affine, NoteCiphertext)> {
        crate::note::encrypt_note(&self.note, &self.pk_d)
    }
}

/// Any envelope kind this family knows.
#[derive(Clone, PartialEq, Eq, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Envelope {
    Transfer(TransferEnvelope),
    Mint(MintEnvelope),
}

/// Dispatch on the kind byte (index 4) after the magic and version.
pub fn parse_envelope(bytes: &[u8]) -> Result<Envelope, ParseError> {
    if bytes.len() < HEADER_LEN {
        return Err(ParseError::Length {
            got: bytes.len(),
            expected: HEADER_LEN,
        });
    }
    if bytes[..3] != MAGIC {
        return Err(ParseError::Magic);
    }
    if bytes[3] != VERSION {
        return Err(ParseError::Version(bytes[3]));
    }
    match bytes[4] {
        KIND_TRANSFER => Ok(Envelope::Transfer(TransferEnvelope::parse(bytes)?)),
        KIND_MINT => Ok(Envelope::Mint(MintEnvelope::parse(bytes)?)),
        k => Err(ParseError::Kind(k)),
    }
}

/// Does a payload look like a family-A envelope (magic + version)?
pub fn is_candidate(payload: &[u8]) -> bool {
    payload.starts_with(&CANDIDATE_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{Seed, WalletKeys};
    use ff::Field;
    use group::{Curve, Group};
    use rand::{RngCore, SeedableRng, rngs::StdRng};
    use sba_primitives::{Point, Scalar};

    pub(crate) fn random_body(rng: &mut StdRng) -> TransferBody {
        let mut ct_out = [0u8; CT_OUT_LEN];
        rng.fill_bytes(&mut ct_out);
        let p = |rng: &mut StdRng| (Point::generator() * Scalar::random(&mut *rng)).to_affine();
        let c = |rng: &mut StdRng| NoteCiphertext {
            c0: Fp::random(&mut *rng),
            c1: Fp::random(&mut *rng),
            tag: Fp::random(&mut *rng),
        };
        TransferBody {
            h_anchor: rng.next_u32(),
            nullifiers: [Fp::random(&mut *rng), Fp::random(&mut *rng)],
            pk_eph: [p(rng), p(rng)],
            ct_note: [c(rng), c(rng)],
            ct_out,
        }
    }

    #[test]
    fn sizes_match_the_profile() {
        assert_eq!(BODY_LEN, 508);
        assert_eq!(ENVELOPE_LEN, 4924);
        assert_eq!(CANDIDATE_PREFIX, *b"btc\x02");
    }

    #[test]
    fn round_trip_and_rejections() {
        let mut rng = StdRng::seed_from_u64(1);
        let body = random_body(&mut rng);
        let mut proof = vec![0u8; PROOF_LEN];
        rng.fill_bytes(&mut proof);
        let env = TransferEnvelope { body, proof };
        let good = env.to_bytes();
        assert_eq!(good.len(), ENVELOPE_LEN);
        assert!(is_candidate(&good));
        assert_eq!(TransferEnvelope::parse(&good).unwrap(), env);
        assert!(matches!(
            parse_envelope(&good).unwrap(),
            Envelope::Transfer(_)
        ));

        let mut b = good.clone();
        b[0] = b'x';
        assert_eq!(TransferEnvelope::parse(&b), Err(ParseError::Magic));
        let mut b = good.clone();
        b[3] = 1; // the paper profile's version is not ours
        assert_eq!(TransferEnvelope::parse(&b), Err(ParseError::Version(1)));
        assert_eq!(parse_envelope(&b), Err(ParseError::Version(1)));
        let mut b = good.clone();
        b[4] = 9;
        assert_eq!(TransferEnvelope::parse(&b), Err(ParseError::Kind(9)));
        let mut b = good.clone();
        b[5] = 1;
        assert_eq!(TransferEnvelope::parse(&b), Err(ParseError::Reserved));
        let mut b = good.clone();
        b[10] = 3;
        assert_eq!(TransferEnvelope::parse(&b), Err(ParseError::Arity(3, 2)));
        let mut b = good.clone();
        b.push(0);
        assert!(matches!(
            TransferEnvelope::parse(&b),
            Err(ParseError::Length { .. })
        ));
        assert!(matches!(
            TransferEnvelope::parse(&good[..100]),
            Err(ParseError::Length { .. })
        ));
        let mut b = good.clone();
        b[12..44].copy_from_slice(&[0xffu8; 32]);
        assert_eq!(
            TransferEnvelope::parse(&b),
            Err(ParseError::Field("nf", DecodeError::NonCanonical))
        );
        let mut b = good.clone();
        b.splice(10..11, [0xfd, 0x02, 0x00]);
        assert!(TransferEnvelope::parse(&b).is_err());
        assert_eq!(
            TransferBody::parse(&b[..BODY_LEN + 2]),
            Err(ParseError::CompactSize)
        );
    }

    #[test]
    fn h_body_is_254_bits_and_salted() {
        let mut rng = StdRng::seed_from_u64(3);
        let body = random_body(&mut rng);
        let a = body.h_body(&[0u8; 32]);
        let b = body.h_body(&[1u8; 32]);
        assert_ne!(a, b);
        assert!(fp_to_bytes(&a)[31] <= 0x3f);
    }

    #[test]
    fn mint_round_trip_and_dispatch() {
        let mut rng = StdRng::seed_from_u64(9);
        let k = WalletKeys::from_seed(&Seed([1u8; 32]));
        let (_, a) = k.ivk.find_address(0);
        let m = MintEnvelope {
            note: crate::note::NotePlaintext {
                value: 12345,
                d: a.d,
                rseed: Fp::random(&mut rng),
            },
            pk_d: a.pk_d,
        };
        let bytes = m.to_bytes();
        assert_eq!(bytes.len(), MINT_LEN);
        assert_eq!(MintEnvelope::parse(&bytes).unwrap(), m);
        assert!(matches!(parse_envelope(&bytes).unwrap(), Envelope::Mint(_)));
        assert!(m.derive().is_some());
        assert_ne!(m.h_body(&[0u8; 32]), m.h_body(&[1u8; 32]));
        let mut b = bytes.clone();
        b[4] = 7;
        assert_eq!(parse_envelope(&b), Err(ParseError::Kind(7)));
        assert!(matches!(
            parse_envelope(&b[..3]),
            Err(ParseError::Length { .. })
        ));
    }
}
