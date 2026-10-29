//! Transfer envelope: canonical body serialisation, strict parsing and
//! `h_body` (paper §11, §13, §A.3, §A.5; profile §7).

use sha2::{Digest, Sha256};

use sb_primitives::encoding::{
    DecodeError, fr_from_bytes, fr_to_bytes, point_from_bytes, point_to_bytes,
};
use sb_primitives::{Fr, JubjubAffine};

use crate::note::{CT_NOTE_LEN, NoteCiphertext};
use crate::recovery::{CT_OUT_LEN, N_OUT};

pub const MAGIC: [u8; 3] = *b"btc";
pub const VERSION: u8 = 1;
pub const KIND_TRANSFER: u8 = 0x01;
/// Swap extension envelope (`docs/SWAP.md` §4).
pub const KIND_SWAP: u8 = 0x03;
pub const HEADER_LEN: usize = 6;
/// Inputs per transfer (profile §7).
pub const N_IN: usize = 2;
pub const PROOF_LEN: usize = 192;
pub const BODY_LEN: usize =
    HEADER_LEN + 4 + 2 + N_IN * 32 + N_OUT * 32 + N_OUT * CT_NOTE_LEN + CT_OUT_LEN;
pub const ENVELOPE_LEN: usize = BODY_LEN + PROOF_LEN;
/// Swap body: the base body plus one `h_aux` per output.
pub const SWAP_BODY_LEN: usize = BODY_LEN + N_OUT * 32;
pub const SWAP_ENVELOPE_LEN: usize = SWAP_BODY_LEN + PROOF_LEN;

/// Prefix every candidate payload must start with.
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
    pub nullifiers: [Fr; N_IN],
    pub pk_eph: [JubjubAffine; N_OUT],
    pub ct_note: [NoteCiphertext; N_OUT],
    pub ct_out: [u8; CT_OUT_LEN],
}

/// Body plus proof bytes (the proof is opaque here; `sb-circuit` decodes it).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TransferEnvelope {
    pub body: TransferBody,
    pub proof: [u8; PROOF_LEN],
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

impl TransferBody {
    /// `body_bytes(e)` (profile §7.1).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes_with_kind(KIND_TRANSFER)
    }

    /// The header with `kind` followed by the base fields.
    fn to_bytes_with_kind(&self, kind: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(BODY_LEN);
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(kind);
        out.push(0);
        out.extend_from_slice(&self.h_anchor.to_le_bytes());
        push_compact_size(&mut out, N_IN as u64);
        push_compact_size(&mut out, N_OUT as u64);
        for nf in &self.nullifiers {
            out.extend_from_slice(&fr_to_bytes(nf));
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
        Self::parse_prefix_kind(r, KIND_TRANSFER)
    }

    fn parse_prefix_kind(r: &mut Reader<'_>, expected_kind: u8) -> Result<Self, ParseError> {
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
        let h_anchor = u32::from_le_bytes(r.take(4)?.try_into().unwrap());
        let n_in = r.compact_size()?;
        let n_out = r.compact_size()?;
        if n_in != N_IN as u64 || n_out != N_OUT as u64 {
            return Err(ParseError::Arity(n_in, n_out));
        }
        let mut nullifiers = [Fr::from(0u64); N_IN];
        for nf in nullifiers.iter_mut() {
            *nf = fr_from_bytes(r.take(32)?).map_err(|e| ParseError::Field("nf", e))?;
        }
        let mut pk_eph = [JubjubAffine::default(); N_OUT];
        for p in pk_eph.iter_mut() {
            *p = point_from_bytes(r.take(32)?).map_err(|e| ParseError::Field("pk_eph", e))?;
        }
        let zero_ct = NoteCiphertext {
            c0: Fr::from(0u64),
            c1: Fr::from(0u64),
            tag: Fr::from(0u64),
        };
        let mut ct_note = [zero_ct; N_OUT];
        for c in ct_note.iter_mut() {
            *c = NoteCiphertext::from_bytes(r.take(CT_NOTE_LEN)?)
                .map_err(|e| ParseError::Field("ct_note", e))?;
        }
        let mut ct_out = [0u8; CT_OUT_LEN];
        ct_out.copy_from_slice(r.take(CT_OUT_LEN)?);
        Ok(TransferBody {
            h_anchor,
            nullifiers,
            pk_eph,
            ct_note,
            ct_out,
        })
    }

    /// `h_body = H_body(const_salt ‖ body_bytes)` (profile §2.2, §7.2).
    pub fn h_body(&self, const_salt: &[u8; 32]) -> Fr {
        h_body(const_salt, &self.to_bytes())
    }
}

/// `SHA-256(const_salt ‖ body_bytes)` with bits 253..255 cleared, as `Fr`.
pub fn h_body(const_salt: &[u8; 32], body_bytes: &[u8]) -> Fr {
    let mut h = Sha256::new();
    h.update(const_salt);
    h.update(body_bytes);
    bytes_to_fr_253(&h.finalize().into())
}

/// Interpret 32 bytes as a `< 2^253` little-endian field element.
pub fn bytes_to_fr_253(bytes: &[u8; 32]) -> Fr {
    let mut b = *bytes;
    b[31] &= 0x1f;
    fr_from_bytes(&b).expect("< 2^253 is canonical")
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
            // Distinguish header problems first so rejections are informative.
            if bytes.len() >= HEADER_LEN {
                let mut r = Reader {
                    b: &bytes[..HEADER_LEN],
                    pos: 0,
                };
                let _ = TransferBody::parse_prefix(&mut r).map_err(|e| match e {
                    ParseError::Length { .. } => ParseError::Length {
                        got: bytes.len(),
                        expected: ENVELOPE_LEN,
                    },
                    other => other,
                })?;
            }
            return Err(ParseError::Length {
                got: bytes.len(),
                expected: ENVELOPE_LEN,
            });
        }
        let body = TransferBody::parse(&bytes[..BODY_LEN])?;
        let mut proof = [0u8; PROOF_LEN];
        proof.copy_from_slice(&bytes[BODY_LEN..]);
        let env = TransferEnvelope { body, proof };
        if env.to_bytes() != bytes {
            return Err(ParseError::NonCanonical);
        }
        Ok(env)
    }
}

// ---------------------------------------------------------------------------
// Swap extension (docs/SWAP.md §4): the base body plus the per-output
// h_aux slots, under kind 0x03.
// ---------------------------------------------------------------------------

/// The body of a swap envelope.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SwapBody {
    pub base: TransferBody,
    /// The `h_aux` slot of each output; `0` for a plain output.
    pub h_aux: [Fr; N_OUT],
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SwapEnvelope {
    pub body: SwapBody,
    pub proof: [u8; PROOF_LEN],
}

impl SwapBody {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.base.to_bytes_with_kind(KIND_SWAP);
        for h in &self.h_aux {
            out.extend_from_slice(&fr_to_bytes(h));
        }
        debug_assert_eq!(out.len(), SWAP_BODY_LEN);
        out
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader { b: bytes, pos: 0 };
        let base = TransferBody::parse_prefix_kind(&mut r, KIND_SWAP)?;
        let mut h_aux = [Fr::from(0u64); N_OUT];
        for h in h_aux.iter_mut() {
            *h = fr_from_bytes(r.take(32)?).map_err(|e| ParseError::Field("h_aux", e))?;
        }
        if r.pos != bytes.len() {
            return Err(ParseError::Length {
                got: bytes.len(),
                expected: r.pos,
            });
        }
        Ok(SwapBody { base, h_aux })
    }

    /// `h_body` over the whole swap body (`docs/SWAP.md` §4).
    pub fn h_body(&self, const_salt: &[u8; 32]) -> Fr {
        h_body(const_salt, &self.to_bytes())
    }
}

impl SwapEnvelope {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.body.to_bytes();
        out.extend_from_slice(&self.proof);
        out
    }

    /// Strict parse: exact length and byte-for-byte re-serialisation.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() != SWAP_ENVELOPE_LEN {
            if bytes.len() >= HEADER_LEN {
                let mut r = Reader {
                    b: &bytes[..HEADER_LEN],
                    pos: 0,
                };
                let _ =
                    TransferBody::parse_prefix_kind(&mut r, KIND_SWAP).map_err(|e| match e {
                        ParseError::Length { .. } => ParseError::Length {
                            got: bytes.len(),
                            expected: SWAP_ENVELOPE_LEN,
                        },
                        other => other,
                    })?;
            }
            return Err(ParseError::Length {
                got: bytes.len(),
                expected: SWAP_ENVELOPE_LEN,
            });
        }
        let body = SwapBody::parse(&bytes[..SWAP_BODY_LEN])?;
        let mut proof = [0u8; PROOF_LEN];
        proof.copy_from_slice(&bytes[SWAP_BODY_LEN..]);
        let env = SwapEnvelope { body, proof };
        if env.to_bytes() != bytes {
            return Err(ParseError::NonCanonical);
        }
        Ok(env)
    }
}

/// Does a payload look like a Shielded Bitcoin envelope (magic + version)?
pub fn is_candidate(payload: &[u8]) -> bool {
    payload.len() >= CANDIDATE_PREFIX.len() && payload[..CANDIDATE_PREFIX.len()] == CANDIDATE_PREFIX
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{CurveGroup, PrimeGroup};
    use ark_ff::UniformRand;
    use ark_std::rand::{RngCore, SeedableRng, rngs::StdRng};
    use sb_primitives::{Jubjub, JubjubScalar};

    pub(crate) fn random_body(rng: &mut StdRng) -> TransferBody {
        let mut ct_out = [0u8; CT_OUT_LEN];
        rng.fill_bytes(&mut ct_out);
        let p = |rng: &mut StdRng| (Jubjub::generator() * JubjubScalar::rand(rng)).into_affine();
        let c = |rng: &mut StdRng| NoteCiphertext {
            c0: Fr::rand(rng),
            c1: Fr::rand(rng),
            tag: Fr::rand(rng),
        };
        TransferBody {
            h_anchor: rng.next_u32(),
            nullifiers: [Fr::rand(rng), Fr::rand(rng)],
            pk_eph: [p(rng), p(rng)],
            ct_note: [c(rng), c(rng)],
            ct_out,
        }
    }

    #[test]
    fn sizes_match_the_profile() {
        assert_eq!(BODY_LEN, 508);
        assert_eq!(ENVELOPE_LEN, 700);
    }

    #[test]
    fn round_trip() {
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..20 {
            let body = random_body(&mut rng);
            let mut proof = [0u8; PROOF_LEN];
            rng.fill_bytes(&mut proof);
            let env = TransferEnvelope { body, proof };
            let bytes = env.to_bytes();
            assert_eq!(bytes.len(), ENVELOPE_LEN);
            assert!(is_candidate(&bytes));
            assert_eq!(TransferEnvelope::parse(&bytes).unwrap(), env);
        }
    }

    #[test]
    fn rejections() {
        let mut rng = StdRng::seed_from_u64(2);
        let env = TransferEnvelope {
            body: random_body(&mut rng),
            proof: [1u8; PROOF_LEN],
        };
        let good = env.to_bytes();

        let mut b = good.clone();
        b[0] = b'x';
        assert_eq!(TransferEnvelope::parse(&b), Err(ParseError::Magic));
        let mut b = good.clone();
        b[3] = 2;
        assert_eq!(TransferEnvelope::parse(&b), Err(ParseError::Version(2)));
        let mut b = good.clone();
        b[4] = 9;
        assert_eq!(TransferEnvelope::parse(&b), Err(ParseError::Kind(9)));
        let mut b = good.clone();
        b[5] = 1;
        assert_eq!(TransferEnvelope::parse(&b), Err(ParseError::Reserved));
        let mut b = good.clone();
        b[10] = 3;
        assert_eq!(TransferEnvelope::parse(&b), Err(ParseError::Arity(3, 2)));
        // trailing byte
        let mut b = good.clone();
        b.push(0);
        assert!(matches!(
            TransferEnvelope::parse(&b),
            Err(ParseError::Length { .. })
        ));
        // truncated
        assert!(matches!(
            TransferEnvelope::parse(&good[..100]),
            Err(ParseError::Length { .. })
        ));
        // non-canonical nullifier (>= q)
        let mut b = good.clone();
        b[12..44].copy_from_slice(&[0xffu8; 32]);
        assert_eq!(
            TransferEnvelope::parse(&b),
            Err(ParseError::Field("nf", DecodeError::NonCanonicalField))
        );
        // non-canonical CompactSize for the count: 0xfd 0x02 0x00 (shifts layout, still must fail)
        let mut b = good.clone();
        b.splice(10..11, [0xfd, 0x02, 0x00]);
        assert!(TransferEnvelope::parse(&b).is_err());
        assert_eq!(
            TransferBody::parse(&b[..BODY_LEN + 2]),
            Err(ParseError::CompactSize)
        );
    }

    #[test]
    fn h_body_is_253_bits_and_salted() {
        let mut rng = StdRng::seed_from_u64(3);
        let body = random_body(&mut rng);
        let a = body.h_body(&[0u8; 32]);
        let b = body.h_body(&[1u8; 32]);
        assert_ne!(a, b);
        assert!(fr_to_bytes(&a)[31] <= 0x1f);
    }
}

// ---------------------------------------------------------------------------
// Development boundary: mint envelope (kind 0x02). NOT part of the paper's
// transfer layer (§22.3): a deployment extension that lets value enter a
// test deployment through a custodial vault. See docs/BOUNDARY.md.
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
    pub pk_d: JubjubAffine,
}

impl MintEnvelope {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MINT_LEN);
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(KIND_MINT);
        out.push(0);
        out.extend_from_slice(&self.note.value.to_le_bytes());
        out.extend_from_slice(&self.note.d);
        out.extend_from_slice(&fr_to_bytes(&self.note.rseed));
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
        if r.take(3)? != MAGIC {
            return Err(ParseError::Magic);
        }
        let version = r.u8()?;
        if version != VERSION {
            return Err(ParseError::Version(version));
        }
        let kind = r.u8()?;
        if kind != KIND_MINT {
            return Err(ParseError::Kind(kind));
        }
        if r.u8()? != 0 {
            return Err(ParseError::Reserved);
        }
        let value = u64::from_le_bytes(r.take(8)?.try_into().unwrap());
        let mut d = [0u8; crate::note::DIVERSIFIER_LEN];
        d.copy_from_slice(r.take(crate::note::DIVERSIFIER_LEN)?);
        let rseed = fr_from_bytes(r.take(32)?).map_err(|e| ParseError::Field("rseed", e))?;
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

    pub fn h_body(&self, const_salt: &[u8; 32]) -> Fr {
        h_body(const_salt, &self.to_bytes())
    }

    /// `(pk_eph, ct_note)` for the minted note; `None` if `d` is invalid.
    pub fn derive(&self) -> Option<(JubjubAffine, NoteCiphertext)> {
        crate::note::encrypt_note(&self.note, &self.pk_d)
    }
}

/// Any envelope kind this implementation knows.
#[derive(Clone, PartialEq, Eq, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Envelope {
    Transfer(TransferEnvelope),
    Mint(MintEnvelope),
    Swap(SwapEnvelope),
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
        KIND_SWAP => Ok(Envelope::Swap(SwapEnvelope::parse(bytes)?)),
        k => Err(ParseError::Kind(k)),
    }
}

#[cfg(test)]
mod mint_tests {
    use super::*;
    use crate::keys::{Seed, WalletKeys};
    use ark_ff::UniformRand;
    use ark_std::rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn mint_round_trip_and_dispatch() {
        let mut rng = StdRng::seed_from_u64(9);
        let k = WalletKeys::from_seed(&Seed([1u8; 32]));
        let (_, a) = k.ivk.find_address(0);
        let m = MintEnvelope {
            note: crate::note::NotePlaintext {
                value: 12345,
                d: a.d,
                rseed: Fr::rand(&mut rng),
            },
            pk_d: a.pk_d,
        };
        let bytes = m.to_bytes();
        assert_eq!(bytes.len(), MINT_LEN);
        assert_eq!(MintEnvelope::parse(&bytes).unwrap(), m);
        assert_eq!(parse_envelope(&bytes).unwrap(), Envelope::Mint(m.clone()));
        assert!(m.derive().is_some());
        let mut bad = bytes.clone();
        bad[4] = 0x07;
        assert_eq!(parse_envelope(&bad), Err(ParseError::Kind(7)));
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use crate::keys::{Seed, WalletKeys};
    use ark_ff::UniformRand;
    use ark_std::rand::{SeedableRng, rngs::StdRng};

    fn round_trip_compact(v: u64) -> u64 {
        let mut out = Vec::new();
        push_compact_size(&mut out, v);
        let mut r = Reader { b: &out, pos: 0 };
        let back = r.compact_size().unwrap();
        assert_eq!(r.pos, out.len());
        back
    }

    #[test]
    fn compact_size_all_widths_round_trip() {
        for v in [
            0u64,
            0xfc,
            0xfd,
            0xffff,
            0x1_0000,
            0xffff_ffff,
            0x1_0000_0000,
            u64::MAX,
        ] {
            assert_eq!(round_trip_compact(v), v);
        }
        // non-minimal encodings of every width are rejected
        for bad in [
            vec![0xfdu8, 0x02, 0x00],
            vec![0xfeu8, 0x02, 0x00, 0x00, 0x00],
            vec![0xffu8, 0x02, 0, 0, 0, 0, 0, 0, 0],
        ] {
            let mut r = Reader { b: &bad, pos: 0 };
            assert_eq!(r.compact_size(), Err(ParseError::CompactSize));
        }
        // truncated
        let mut r = Reader {
            b: &[0xfdu8, 0x01],
            pos: 0,
        };
        assert!(matches!(r.compact_size(), Err(ParseError::Length { .. })));
    }

    #[test]
    fn body_parse_rejects_trailing_bytes_and_header_errors_on_short_input() {
        let mut rng = StdRng::seed_from_u64(5);
        let body = tests::random_body(&mut rng);
        let mut b = body.to_bytes();
        b.push(0);
        assert!(matches!(
            TransferBody::parse(&b),
            Err(ParseError::Length { .. })
        ));
        // a short envelope with a bad magic reports the magic, not the length
        let mut short = body.to_bytes();
        short[0] = b'x';
        assert_eq!(
            TransferEnvelope::parse(&short[..100]),
            Err(ParseError::Magic)
        );
        // a short envelope with a good header reports the envelope length
        assert_eq!(
            TransferEnvelope::parse(&body.to_bytes()[..100]),
            Err(ParseError::Length {
                got: 100,
                expected: ENVELOPE_LEN
            })
        );
        assert!(matches!(
            TransferEnvelope::parse(&[1, 2, 3]),
            Err(ParseError::Length { .. })
        ));
    }

    #[test]
    fn mint_parse_rejections_and_envelope_dispatch() {
        let mut rng = StdRng::seed_from_u64(6);
        let k = WalletKeys::from_seed(&Seed([1u8; 32]));
        let (_, a) = k.ivk.find_address(0);
        let m = MintEnvelope {
            note: crate::note::NotePlaintext {
                value: 7,
                d: a.d,
                rseed: Fr::rand(&mut rng),
            },
            pk_d: a.pk_d,
        };
        let good = m.to_bytes();
        assert!(matches!(
            MintEnvelope::parse(&good[..10]),
            Err(ParseError::Length { .. })
        ));
        let mut b = good.clone();
        b[0] = b'x';
        assert_eq!(MintEnvelope::parse(&b), Err(ParseError::Magic));
        let mut b = good.clone();
        b[3] = 9;
        assert_eq!(MintEnvelope::parse(&b), Err(ParseError::Version(9)));
        let mut b = good.clone();
        b[4] = KIND_TRANSFER;
        assert_eq!(
            MintEnvelope::parse(&b),
            Err(ParseError::Kind(KIND_TRANSFER))
        );
        let mut b = good.clone();
        b[5] = 1;
        assert_eq!(MintEnvelope::parse(&b), Err(ParseError::Reserved));
        let mut b = good.clone();
        b[HEADER_LEN + 8 + 11..HEADER_LEN + 8 + 11 + 32].copy_from_slice(&[0xffu8; 32]);
        assert!(matches!(
            MintEnvelope::parse(&b),
            Err(ParseError::Field("rseed", _))
        ));
        let mut b = good.clone();
        b[MINT_LEN - 32..].copy_from_slice(&[0xffu8; 32]);
        assert!(matches!(
            MintEnvelope::parse(&b),
            Err(ParseError::Field("pk_d", _))
        ));
        assert_eq!(m.h_body(&[0u8; 32]), h_body(&[0u8; 32], &good));

        // parse_envelope: short, magic, version
        assert!(matches!(
            parse_envelope(&[1u8; 3]),
            Err(ParseError::Length { .. })
        ));
        let mut b = good.clone();
        b[1] = b'x';
        assert_eq!(parse_envelope(&b), Err(ParseError::Magic));
        let mut b = good.clone();
        b[3] = 2;
        assert_eq!(parse_envelope(&b), Err(ParseError::Version(2)));
        assert!(!is_candidate(b"bt"));
    }
}

#[cfg(test)]
mod swap_tests {
    use super::*;
    use ark_std::rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn swap_round_trip_dispatch_and_rejections() {
        let mut rng = StdRng::seed_from_u64(3);
        let base = tests::random_body(&mut rng);
        let body = SwapBody {
            base: base.clone(),
            h_aux: [Fr::from(0u64), Fr::from(12345u64)],
        };
        let env = SwapEnvelope {
            body: body.clone(),
            proof: [7u8; PROOF_LEN],
        };
        let bytes = env.to_bytes();
        assert_eq!(bytes.len(), SWAP_ENVELOPE_LEN);
        assert_eq!(bytes[4], KIND_SWAP);
        assert_eq!(SwapEnvelope::parse(&bytes).unwrap(), env);
        assert_eq!(SwapBody::parse(&body.to_bytes()).unwrap(), body);
        assert!(matches!(parse_envelope(&bytes).unwrap(), Envelope::Swap(e) if e == env));
        // h_body covers the aux section
        let mut other = body.clone();
        other.h_aux[0] = Fr::from(1u64);
        assert_ne!(other.h_body(&[1u8; 32]), body.h_body(&[1u8; 32]));
        assert_ne!(body.h_body(&[1u8; 32]), base.h_body(&[1u8; 32]));
        // the base parser refuses the kind, the swap parser refuses the base kind
        assert_eq!(
            TransferEnvelope::parse(&bytes).unwrap_err(),
            ParseError::Kind(KIND_SWAP)
        );
        let base_env = TransferEnvelope {
            body: base,
            proof: [7u8; PROOF_LEN],
        };
        assert_eq!(
            SwapEnvelope::parse(&base_env.to_bytes()).unwrap_err(),
            ParseError::Kind(KIND_TRANSFER)
        );
        // lengths and canonicality
        assert!(matches!(
            SwapEnvelope::parse(&bytes[..bytes.len() - 1]).unwrap_err(),
            ParseError::Length { .. }
        ));
        assert!(matches!(
            SwapBody::parse(&body.to_bytes()[..SWAP_BODY_LEN - 1]).unwrap_err(),
            ParseError::Length { .. }
        ));
        let mut long = body.to_bytes();
        long.push(0);
        assert!(matches!(
            SwapBody::parse(&long).unwrap_err(),
            ParseError::Length { .. }
        ));
        let mut non_canonical = bytes.clone();
        // h_aux_0 with a value ≥ q is not a field element
        non_canonical[BODY_LEN..BODY_LEN + 32].copy_from_slice(&[0xff; 32]);
        assert!(matches!(
            SwapEnvelope::parse(&non_canonical).unwrap_err(),
            ParseError::Field("h_aux", _)
        ));
        assert!(matches!(
            SwapEnvelope::parse(&bytes[..5]).unwrap_err(),
            ParseError::Length { .. }
        ));
        let mut bad_magic = bytes.clone();
        bad_magic[0] = b'x';
        assert_eq!(
            SwapEnvelope::parse(&bad_magic).unwrap_err(),
            ParseError::Magic
        );
    }
}
