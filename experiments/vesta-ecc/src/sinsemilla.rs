//! The one thing the lookup range check takes from the Sinsemilla module of
//! `halo2_gadgets`: the lookup table's bit width.
pub mod primitives {
    /// Number of bits of each table entry.
    pub const K: usize = 10;
}
