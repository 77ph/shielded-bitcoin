//! Domain-separation tags (`PROFILE-A.md` §2.1): `tag = LE_int(ASCII)` as
//! an `Fp` element; labels are at most 31 bytes so no reduction occurs.

use ff::PrimeField;

use crate::Fp;

/// Build a tag from its ASCII label.
pub fn tag(label: &[u8]) -> Fp {
    assert!(label.len() <= 31, "tag must fit in one field element");
    let mut bytes = [0u8; 32];
    bytes[..label.len()].copy_from_slice(label);
    Fp::from_repr(bytes).expect("31 bytes are below the modulus")
}

macro_rules! tags {
    ($($name:ident = $label:literal;)*) => {
        $(
            #[doc = concat!("`", $label, "`")]
            pub fn $name() -> Fp { tag($label.as_bytes()) }
        )*
        /// Every (name, label) pair, for test vectors.
        pub const ALL: &[(&str, &str)] = &[$((stringify!($name), $label)),*];
    };
}

tags! {
    t_node = "sb-a/v1/node";
    t_leaf = "sb-a/v1/leaf";
    t_nf = "sb-a/v1/nf";
    t_rho = "sb-a/v1/rho";
    t_eph = "sb-a/v1/eph";
    t_sknf = "sb-a/v1/sknf";
    t_vkin = "sb-a/v1/vkin";
    t_view = "sb-a/v1/view";
    t_div = "sb-a/v1/div";
    t_kdf = "sb-a/v1/kdf";
    t_stream = "sb-a/v1/stream";
    t_mac = "sb-a/v1/mac";
    t_aux = "sb-a/v1/aux";
    t_nflock = "sb-a/v1/nflock";
    t_feeauth = "sb-a/v1/feeauth";
    t_imt = "sb-a/v1/imt";
    t_state = "sb-a/v1/state";
    t_batch = "sb-a/v1/batch";
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn tags_are_distinct_and_differ_from_the_paper_profile() {
        let set: HashSet<_> = ALL
            .iter()
            .map(|(_, l)| tag(l.as_bytes()).to_repr())
            .collect();
        assert_eq!(set.len(), ALL.len());
        assert_ne!(tag(b"sb-a/v1/node").to_repr(), tag(b"sb/v1/node").to_repr());
    }
}
