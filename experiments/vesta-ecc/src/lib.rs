//! `halo2_gadgets`' elliptic-curve chip (v0.5.0, MIT OR Apache-2.0, Zcash
//! Foundation and Electric Coin Company) ported from Pallas points in a
//! circuit over `Fp` to **Vesta** points in a circuit over `Fq`: the chip a
//! verifier of the family's Vesta-committed proofs needs
//! (`docs/REPLAY-PROOF-A.md` §3.3). The port is textual — `pallas` → `vesta`
//! throughout — plus the two constants of the variable-base multiplication's
//! overflow check, which depend on the scalar field (`ecc/chip/constants.rs`:
//! `T_Q` is now `p − 2^254`, `T_P` is `q − 2^254`). The Sinsemilla
//! dependency of the lookup range check is reduced to its constant `K`.

pub mod ecc;
pub mod sinsemilla;
pub mod utilities;
