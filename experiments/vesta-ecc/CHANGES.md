# Changes against upstream

This crate is a port of the elliptic-curve chip of `halo2_gadgets` 0.5.0
(crates.io; https://github.com/zcash/halo2), Copyright (c) 2020-2022 The
Electric Coin Company and (c) 2022 The Halo 2 developers, offered by its
authors under either the MIT license (`LICENSE-MIT`) or the Apache
License, Version 2.0 (`LICENSE-APACHE`), and redistributed here under the
Apache License, Version 2.0 (`NOTICE`). The changes are Copyright (c) 2026
PostCryptum Research (https://postcryptum.io/), under the Apache License,
Version 2.0.

Every source file here derives from an upstream file of the same path
under `halo2_gadgets/src/` and was changed (Apache License §4(b): this
is the notice): the chip over Pallas points in a circuit over `Fp` was
ported, textually, to Vesta points in a circuit over `Fq` (`pallas` →
`vesta` throughout); the two constants of the variable-base
multiplication's overflow check that depend on the scalar field were
recomputed (`src/ecc/chip/constants.rs`: `T_Q` = p − 2^254, `T_P` =
q − 2^254); the Sinsemilla dependency of the lookup range check was
reduced to its constant `K` (`src/sinsemilla.rs`); the crate carries no
Sinsemilla gadget. Files: `src/lib.rs`, `src/ecc.rs`, `src/ecc/chip.rs`,
`src/ecc/chip/{add,add_incomplete,constants,mul,mul_fixed,witness_point}.rs`,
`src/ecc/chip/mul/{complete,incomplete,overflow}.rs`,
`src/ecc/chip/mul_fixed/{base_field_elem,full_width,short}.rs`,
`src/sinsemilla.rs`, `src/utilities.rs`,
`src/utilities/{decompose_running_sum,lookup_range_check}.rs`.

`src/ecc/chip/mul_fixed/short.rs` also contains the test helper
`format_value`, copied from `halo2_proofs::dev::util` (the same upstream
project and licenses).
