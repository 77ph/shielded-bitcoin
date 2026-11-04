#!/usr/bin/env python3
"""Variant A: cross-check the Poseidon constants pinned in
variants/a-halo2/crates/sba-primitives/src/poseidon_params.rs (the gadget
crate's `P128Pow5T3` instance over the Pallas base field) against the same
independent port of the reference Grain-LFSR generator that
poseidon_params_check.py uses for the paper profile, with the parameters of
docs/PROFILE-A.md §2.1: n = 255, t = 3, R_F = 8, R_P = 56 over
p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001.

The gadget crate states that its constants come from
`generate_parameters_grain.sage 1 0 255 3 8 56 <p>` (daira/pasta-hadeshash);
this script re-derives them without Sage and without the Rust toolchain:

* 80-bit LFSR state = field(2) | sbox(4) | n(12) | t(12) | R_F(10) | R_P(10) | 1^30,
  feedback s[62]^s[51]^s[38]^s[23]^s[13]^s[0], first 160 bits discarded,
  self-shrinking output (take pairs, keep the second bit when the first is 1);
* round constants: n-bit big-endian integers by rejection sampling (< p);
* MDS: Cauchy M[i][j] = 1/(x_i + y_j) with x_0..x_{t-1}, y_0..y_{t-1} the next
  2t samples reduced mod p (no rejection; the generator requires the 2t
  values to be distinct and the gadget crate's `secure_mds()` index is 0,
  so the first distinct sample is the one used).

Prints two booleans; both must be True for PROFILE-A.md §2.1 to hold.
"""
import re, sys, pathlib


def derive(p, n=255, t=3, RF=8, RP=56):
    """Round constants and MDS of the instance over the prime p."""
    bits = []
    def add(v, w): bits.extend(int(b) for b in format(v, f'0{w}b'))
    add(1, 2); add(0, 4); add(n, 12); add(t, 12); add(RF, 10); add(RP, 10); add((1 << 30) - 1, 30)
    state = bits
    def lfsr_bit():
        nonlocal state
        new = state[62] ^ state[51] ^ state[38] ^ state[23] ^ state[13] ^ state[0]
        state = state[1:] + [new]
        return new
    for _ in range(160):
        lfsr_bit()
    def rand_bit():
        while True:
            b1, b2 = lfsr_bit(), lfsr_bit()
            if b1:
                return b2
    def sample_int():
        return int(''.join(str(rand_bit()) for _ in range(n)), 2)
    def elem_reject():
        while True:
            v = sample_int()
            if v < p:
                return v
    ark = [elem_reject() for _ in range((RF + RP) * t)]
    while True:
        vals = [sample_int() % p for _ in range(2 * t)]
        if len(set(vals)) == 2 * t:
            break
    xs, ys = vals[:t], vals[t:]
    mds = [[pow((xs[i] + ys[j]) % p, -1, p) for j in range(t)] for i in range(t)]
    return ark, [mds[i][j] for i in range(t) for j in range(t)]

P_FP = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001  # Pallas base field, the circuit
P_FQ = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001  # Vesta base field, the transcript (PROFILE-A.md §1.1)

here = pathlib.Path(__file__).resolve().parent.parent
src = (here / 'variants/a-halo2/crates/sba-primitives/src/poseidon_params.rs').read_text()

def pinned(name):
    block = src.split('pub const ' + name, 1)[1].split('= [', 1)[1].split('];', 1)[0]
    return [int.from_bytes(bytes.fromhex(h), 'little') for h in re.findall(r'"([0-9a-f]{64})"', block)]

ok = True
for label, p, rc_name, mds_name in [
    ("Fp", P_FP, "ROUND_CONSTANTS_HEX", "MDS_HEX"),
    ("Fq", P_FQ, "ROUND_CONSTANTS_FQ_HEX", "MDS_FQ_HEX"),
]:
    ark, mds = derive(p)
    rc_ok = pinned(rc_name) == ark
    mds_ok = pinned(mds_name) == mds
    print(f"variant A {label} round constants match the reference generator:", rc_ok)
    print(f"variant A {label} MDS matches the reference generator:", mds_ok)
    ok = ok and rc_ok and mds_ok
sys.exit(0 if ok else 1)
