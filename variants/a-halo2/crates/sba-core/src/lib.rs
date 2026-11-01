//! Variant A core (`docs/PROFILE-A.md` §3–§7): keys, addresses, notes,
//! encryption, leaves, nullifiers, the envelope codec and the note tree,
//! over the Pasta field and the Pallas curve. The design is the paper's
//! (`sb-core`), the field, curve, hash mode and wire version are the
//! family's; the two never share a value.

pub mod address;
pub mod envelope;
pub mod event;
pub mod keys;
pub mod note;
pub mod recovery;
pub mod tree;

pub use sba_primitives::{Affine, Fp, Point, Scalar};

/// Version of docs/PROFILE-A.md this code implements; a deployment profile
/// names it and is refused on mismatch (PROFILE-A.md §13).
pub const PROFILE_VERSION: &str = "a-0.1";
/// The family name a deployment profile carries (`VARIANT-A.md` §6.2).
pub const FAMILY: &str = "a-halo2";

/// `(x, y)` of an affine point (never the identity in this protocol).
pub fn xy(p: &Affine) -> (Fp, Fp) {
    use pasta_curves::arithmetic::CurveAffine;
    let c = p
        .coordinates()
        .expect("protocol points are never the identity");
    (*c.x(), *c.y())
}
