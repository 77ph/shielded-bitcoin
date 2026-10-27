//! Domain-separation tags (profile §2.1). `tag = LE_bytes_mod_q(ASCII)`.

use ark_ff::PrimeField;

use crate::Fr;

/// Build a tag from its ASCII label.
pub fn tag(label: &[u8]) -> Fr {
    debug_assert!(
        label.len() <= 31,
        "a tag must fit in one field element without reduction"
    );
    Fr::from_le_bytes_mod_order(label)
}

macro_rules! tags {
    ($($name:ident = $label:literal;)*) => {
        $(
            #[doc = concat!("`", $label, "`")]
            pub fn $name() -> Fr { tag($label.as_bytes()) }
        )*
        /// Every (name, label) pair, for test vectors.
        pub const ALL: &[(&str, &str)] = &[$((stringify!($name), $label)),*];
    };
}

tags! {
    t_node = "sb/v1/node";
    t_leaf = "sb/v1/leaf";
    t_nf = "sb/v1/nf";
    t_rho = "sb/v1/rho";
    t_eph = "sb/v1/eph";
    t_sknf = "sb/v1/sknf";
    t_vkin = "sb/v1/vkin";
    t_view = "sb/v1/view";
    t_div = "sb/v1/div";
    t_kdf = "sb/v1/kdf";
    t_stream = "sb/v1/stream";
    t_mac = "sb/v1/mac";
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn tags_are_distinct() {
        let set: HashSet<_> = ALL.iter().map(|(_, l)| tag(l.as_bytes())).collect();
        assert_eq!(set.len(), ALL.len());
    }
}
