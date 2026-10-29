//! The fee vault's authorization-key commitment (`docs/FEE-VAULT.md` §2):
//! a deposit note's `rseed` commits to the BIP 340 x-only key that may
//! draw against the deposit. Only the commitment lives here; the key
//! itself, the signatures and the vault are deployment-layer code.

use sb_primitives::Fr;
use sb_primitives::poseidon::hash;
use sb_primitives::tags::t_feeauth;

use crate::lock::hash_halves;

/// `C(P) = PH(T_FEEAUTH, LE_int(P[0..16]), LE_int(P[16..32]))`.
pub fn key_commitment(key: &[u8; 32]) -> Fr {
    let (lo, hi) = hash_halves(key);
    hash(t_feeauth(), &[lo, hi])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{Seed, WalletKeys};

    #[test]
    fn commitment_is_injective_in_both_halves_and_keys_are_per_index() {
        let p = [7u8; 32];
        let mut lo = p;
        lo[0] ^= 1;
        let mut hi = p;
        hi[31] ^= 1;
        assert_ne!(key_commitment(&p), key_commitment(&lo));
        assert_ne!(key_commitment(&p), key_commitment(&hi));
        assert_eq!(key_commitment(&p), key_commitment(&[7u8; 32]));
        let k = WalletKeys::from_seed(&Seed([3u8; 32]));
        assert_ne!(k.fee_auth_secret(0), k.fee_auth_secret(1));
        assert_eq!(k.fee_auth_secret(5), k.fee_auth_secret(5));
        assert_ne!(
            k.fee_auth_secret(0),
            WalletKeys::from_seed(&Seed([4u8; 32])).fee_auth_secret(0)
        );
    }
}
