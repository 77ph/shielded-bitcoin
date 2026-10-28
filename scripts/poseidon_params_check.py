#!/usr/bin/env python3
"""Cross-check the pinned Poseidon constants (crates/sb-primitives/src/poseidon/params_hex.rs)
against an independent port of the reference Grain-LFSR generator
(generate_params_poseidon.sage from the Poseidon reference implementation):

* 80-bit LFSR state = field(2) | sbox(4) | n(12) | t(12) | R_F(10) | R_P(10) | 1^30,
  feedback s[62]^s[51]^s[38]^s[23]^s[13]^s[0], first 160 bits discarded,
  self-shrinking output (take pairs, keep the second bit when the first is 1);
* round constants: n-bit big-endian integers by rejection sampling (< p);
* MDS: Cauchy M[i][j] = 1/(x_i + y_j) with x_0..x_{t-1}, y_0..y_{t-1} the next
  2t samples reduced mod p (no rejection), as in the reference generate_matrix.

Prints two booleans; both must be True for the profile's §2.1 claim to hold.
"""
import re, sys, pathlib

p = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
n, t, RF, RP = 255, 3, 8, 57

bits = []
def add(v, w): bits.extend(int(b) for b in format(v, f'0{w}b'))
add(1, 2); add(0, 4); add(n, 12); add(t, 12); add(RF, 10); add(RP, 10); add((1 << 30) - 1, 30)
state = bits

def lfsr_bit():
    global state
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
xs = [sample_int() % p for _ in range(t)]
ys = [sample_int() % p for _ in range(t)]
mds = [[pow((xs[i] + ys[j]) % p, -1, p) for j in range(t)] for i in range(t)]

here = pathlib.Path(__file__).resolve().parent.parent
src = (here / 'crates/sb-primitives/src/poseidon/params_hex.rs').read_text()
pinned = [int.from_bytes(bytes.fromhex(h), 'little') for h in re.findall(r'"([0-9a-f]{64})"', src)]
rc_ok = pinned[:(RF + RP) * t] == ark
mds_ok = pinned[(RF + RP) * t:(RF + RP) * t + t * t] == [mds[i][j] for i in range(t) for j in range(t)]
print("round constants match the reference generator:", rc_ok)
print("MDS matches the reference generator:", mds_ok)
sys.exit(0 if rc_ok and mds_ok else 1)
