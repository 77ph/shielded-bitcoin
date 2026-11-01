//! Key hierarchy (paper §6, Table 1; PROFILE-A.md §3).
//!
//! ```text
//! seed ─HKDF("master")─▶ sk_master ─HKDF("spend")─▶ sk_spend (Fp)
//!                                  └HKDF("out")───▶ vk_out  (32 bytes)
//! sk_spend ─PH_A(T_SKNF)─▶ sk_nf          (Fp, in circuit)
//! sk_spend ─PH_A(T_VKIN)─▶ vk_in          (Fp, in circuit)
//! vk_in    ─PH_A(T_VIEW)─▶ sk_view        (Fp used as a Pallas scalar, in circuit)
//! vk_in    ─HKDF("diversifier"‖i)─▶ d_i   (11 bytes)
//! ```

use group::Curve;
use group::prime::PrimeCurveAffine;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use sba_primitives::diversify::{DIVERSIFIER_LEN, diversify_hash};
use sba_primitives::encoding::fp_to_bytes;
use sba_primitives::poseidon::hash;
use sba_primitives::scalar::{fp_from_wide_bytes, scalar_from_fp};
use sba_primitives::tags::{t_sknf, t_view, t_vkin};
use sba_primitives::{Affine, Fp, Scalar};

use crate::address::PaymentAddress;

/// 32 uniformly random bytes (profile §A.2).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Seed(pub [u8; 32]);

impl Seed {
    pub fn random<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> Self {
        let mut s = [0u8; 32];
        rng.fill_bytes(&mut s);
        Seed(s)
    }
}

fn hkdf(ikm: &[u8], info: &[u8], out: &mut [u8]) {
    Hkdf::<Sha256>::new(None, ikm)
        .expand(info, out)
        .expect("output length is valid for HKDF-SHA256");
}

/// Incoming viewing capability: detects and decrypts received notes, derives
/// addresses. Read-only (paper §7, "IncomingView").
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IncomingViewingKey {
    pub vk_in: Fp,
    /// `PH_A(T_VIEW, vk_in)` as a Pallas scalar (PROFILE-A.md §3).
    pub sk_view: Scalar,
}

impl IncomingViewingKey {
    pub fn from_vk_in(vk_in: Fp) -> Self {
        let sk_view = scalar_from_fp(&hash(t_view(), &[vk_in]));
        IncomingViewingKey { vk_in, sk_view }
    }

    /// `d_i` for receive-path index `i` (may be invalid; see [`Self::address_at`]).
    pub fn diversifier(&self, index: u64) -> [u8; DIVERSIFIER_LEN] {
        let mut info = Vec::with_capacity(19 + 8);
        info.extend_from_slice(b"sb-a/v1/diversifier");
        info.extend_from_slice(&index.to_le_bytes());
        let mut d = [0u8; DIVERSIFIER_LEN];
        hkdf(&fp_to_bytes(&self.vk_in), &info, &mut d);
        d
    }

    /// `pk_d = [sk_view] G_d` for an explicit diversifier, if `d` is valid.
    pub fn address_for(&self, d: [u8; DIVERSIFIER_LEN]) -> Option<PaymentAddress> {
        let g_d = diversify_hash(&d)?;
        let pk_d = (g_d.to_curve() * self.sk_view).to_affine();
        Some(PaymentAddress { d, pk_d })
    }

    /// The address at receive-path index `i`, if `d_i` is valid.
    pub fn address_at(&self, index: u64) -> Option<PaymentAddress> {
        self.address_for(self.diversifier(index))
    }

    /// The first valid address at or after `start`, with its index.
    pub fn find_address(&self, start: u64) -> (u64, PaymentAddress) {
        let mut i = start;
        loop {
            if let Some(a) = self.address_at(i) {
                return (i, a);
            }
            i += 1;
        }
    }

    /// Does `addr` belong to this key? (`d` must map to `pk_d` under `sk_view`.)
    pub fn owns(&self, addr: &PaymentAddress) -> bool {
        self.address_for(addr.d).as_ref() == Some(addr)
    }
}

/// Outgoing viewing capability: recovers sent notes from `ct_out` (paper §7,
/// "OutgoingView").
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct OutgoingViewingKey(pub [u8; 32]);

/// Every wallet capability derived from a seed.
#[derive(Clone)]
pub struct WalletKeys {
    pub sk_master: [u8; 32],
    /// The circuit witness, an `Fp` element.
    pub sk_spend: Fp,
    pub sk_nf: Fp,
    pub ivk: IncomingViewingKey,
    pub ovk: OutgoingViewingKey,
}

impl Drop for WalletKeys {
    fn drop(&mut self) {
        self.sk_master.zeroize();
    }
}

/// `sk_nf = PH_A(T_SKNF, sk_spend)`.
pub fn derive_sk_nf(sk_spend: &Fp) -> Fp {
    hash(t_sknf(), &[*sk_spend])
}

/// `vk_in = PH_A(T_VKIN, sk_spend)`.
pub fn derive_vk_in(sk_spend: &Fp) -> Fp {
    hash(t_vkin(), &[*sk_spend])
}

impl WalletKeys {
    pub fn from_seed(seed: &Seed) -> Self {
        let mut sk_master = [0u8; 32];
        hkdf(&seed.0, b"sb-a/v1/master", &mut sk_master);
        let mut wide = [0u8; 64];
        hkdf(&sk_master, b"sb-a/v1/spend", &mut wide);
        let sk_spend = fp_from_wide_bytes(&wide);
        wide.zeroize();
        let mut vk_out = [0u8; 32];
        hkdf(&sk_master, b"sb-a/v1/out", &mut vk_out);
        let sk_nf = derive_sk_nf(&sk_spend);
        let ivk = IncomingViewingKey::from_vk_in(derive_vk_in(&sk_spend));
        WalletKeys {
            sk_master,
            sk_spend,
            sk_nf,
            ivk,
            ovk: OutgoingViewingKey(vk_out),
        }
    }

    /// `pk_d` for a diversifier under this wallet's `sk_view` (the circuit's
    /// "ownership rule", paper §9).
    pub fn pk_d(&self, d: [u8; DIVERSIFIER_LEN]) -> Option<Affine> {
        self.ivk.address_for(d).map(|a| a.pk_d)
    }

    /// Secret of the `index`-th fee-vault authorization key
    /// (`docs/FEE-VAULT.md` §2): `HKDF(sk_master, "sb-a/v1/feeauth" ‖ LE64(index))`.
    pub fn fee_auth_secret(&self, index: u64) -> [u8; 32] {
        let mut info = Vec::with_capacity(15 + 8);
        info.extend_from_slice(b"sb-a/v1/feeauth");
        info.extend_from_slice(&index.to_le_bytes());
        let mut out = [0u8; 32];
        hkdf(&self.sk_master, &info, &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn derivation_is_deterministic_and_keys_differ() {
        let seed = Seed([7u8; 32]);
        let a = WalletKeys::from_seed(&seed);
        let b = WalletKeys::from_seed(&seed);
        assert_eq!(a.sk_spend, b.sk_spend);
        assert_eq!(a.ivk, b.ivk);
        assert_eq!(a.ovk.0, b.ovk.0);
        let c = WalletKeys::from_seed(&Seed([8u8; 32]));
        assert_ne!(a.sk_spend, c.sk_spend);
        assert_ne!(a.ivk.vk_in, c.ivk.vk_in);
        assert_ne!(a.sk_nf, c.sk_nf);
        assert_ne!(a.fee_auth_secret(0), a.fee_auth_secret(1));
        let mut rng = StdRng::seed_from_u64(1);
        assert_ne!(Seed::random(&mut rng).0, Seed::random(&mut rng).0);
    }

    #[test]
    fn addresses_are_owned_and_distinct() {
        let k = WalletKeys::from_seed(&Seed([1u8; 32]));
        let (i0, a0) = k.ivk.find_address(0);
        let (i1, a1) = k.ivk.find_address(i0 + 1);
        assert!(i1 > i0);
        assert_ne!(a0, a1);
        assert!(k.ivk.owns(&a0));
        assert!(k.ivk.owns(&a1));
        let other = WalletKeys::from_seed(&Seed([2u8; 32]));
        assert!(!other.ivk.owns(&a0));
        let ivk2 = IncomingViewingKey::from_vk_in(k.ivk.vk_in);
        assert_eq!(ivk2.address_at(i0), Some(a0));
        assert_eq!(k.pk_d(a0.d), Some(a0.pk_d));
    }
}
