//! Fee-vault authorizations for this profile: `sb_common::feeauth` over the
//! profile's key derivation (`WalletKeys::fee_auth_secret`) and field
//! encoding (`h_body` as the 32-byte LE canonical `Fr`).

use anyhow::Result;
use sb_core::keys::WalletKeys;
use sb_primitives::Fr;
use sb_primitives::encoding::fr_to_bytes;

pub use sb_common::feeauth::{AuthKey, reclaim_message, verify};

/// The draw message (`docs/FEE-VAULT.md` §3) over this profile's `h_body`.
pub fn draw_message(deployment: &str, h_body: &Fr, max_fee: u64, memo: Option<&[u8]>) -> [u8; 32] {
    sb_common::feeauth::draw_message(deployment, &fr_to_bytes(h_body), max_fee, memo)
}

/// The client's authorization key at a derivation index (§2).
pub fn derive(keys: &WalletKeys, index: u64) -> Result<AuthKey> {
    AuthKey::from_secret(&keys.fee_auth_secret(index), index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_core::keys::Seed;

    #[test]
    fn keys_sign_and_verify_and_messages_differ() {
        let k = WalletKeys::from_seed(&Seed([5u8; 32]));
        let a = derive(&k, 0).unwrap();
        let b = derive(&k, 1).unwrap();
        assert_ne!(a.public(), b.public());
        let hb = Fr::from(77u64);
        let m = draw_message("e2e", &hb, 1000, None);
        assert_ne!(m, draw_message("e2e", &Fr::from(78u64), 1000, None));
        assert_ne!(m, draw_message("e2e", &hb, 1001, None));
        assert_ne!(m, draw_message("e2e", &hb, 1000, Some(b"x")));
        let sig = a.sign(&m);
        verify(&a.public(), &m, &sig).unwrap();
        assert!(verify(&b.public(), &m, &sig).is_err());
    }
}
