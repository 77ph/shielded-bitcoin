# Parameter ceremony

The transfer circuit is proven with Groth16, whose keys come from a trusted
setup: whoever knows the setup's secrets can forge proofs, which here
means minting shielded value from nothing. Development deployments use a
deterministic setup from a published seed and say so everywhere. A
deployment meant to hold value needs keys that **nobody** knows the secrets
of, which a multi-party ceremony gives: each participant applies a fresh
secret and destroys it, and the keys are safe as long as at least one
participant of each phase did.

`sb ceremony` (crate `sb-ceremony`) implements the protocol of Bowe,
Gabizon and Miers, "Scalable Multi-party Computation for zk-SNARK
Parameters in the Random Beacon Model" (BGM17), the one the Zcash Sapling
parameters were made with. Everything is files: participants pass them
along in any order the coordinator chooses, and anyone can verify the whole
chain afterwards from the published files alone.

## Phase 1: powers of tau

The accumulator holds `[τ^i]₁` for `i < 2n − 1`, `[τ^i]₂`, `[ατ^i]₁` and
`[βτ^i]₁` for `i < n`, and `[β]₂`, where `n` is the circuit's evaluation
domain (`2^17` for the transfer circuit; `phase1-new` sizes it, or
`--power` picks a larger one that serves any smaller circuit). It starts at
`τ = α = β = 1`.

```sh
sb ceremony phase1-new --out p1-0.bin
sb ceremony phase1-contribute --in p1-0.bin --out p1-1.bin --entropy "anything you like"
sb ceremony phase1-verify --before p1-0.bin --after p1-1.bin
```

A contribution multiplies every element by the participant's `τ'`, `α'`,
`β'` (drawn from the OS random generator mixed with the typed entropy, and
never written anywhere) and attaches three proofs of knowledge, each bound
to the SHA-256 digest of the file it was made from. Verification checks the
proofs, that the same secrets reached every component (`G1` and `G2`, the
`α` and `β` vectors), and that the result is a consistent sequence of
powers, with batched pairing checks over random linear combinations. The
digest a contributor publishes is the digest of their output file, so a
coordinator cannot silently replace a contribution.

## Key derivation

```sh
sb ceremony phase2-new --phase1 p1-N.bin --out p2-0.bin
```

derives the transfer circuit's Groth16 key from the final accumulator with
`γ = δ = 1`: the R1CS matrices and the Lagrange basis in the exponent (an
inverse FFT over the curve points `[τ^j]`) give exactly what arkworks'
generator computes in the field, which the tests check against it with
the same secrets, element by element. The derived key is deterministic, so
every verifier recomputes it instead of trusting the file.

## Phase 2: delta

```sh
sb ceremony phase2-contribute --in p2-0.bin --out p2-1.bin
sb ceremony phase2-beacon --in p2-K.bin --out p2-final.bin --beacon <hex>
sb ceremony phase2-verify --phase1 p1-N.bin --final p2-final.bin
sb ceremony export --final p2-final.bin --pk transfer.pk --vk transfer.vk
```

Each participant multiplies `[δ]₁`, `[δ]₂` by a fresh `δ'` and the `H` and
`L` queries by its inverse, with a proof of knowledge bound to the
transcript so far (the initial key's digest and every earlier
contribution). The **beacon** is the last contribution: its `δ'` is derived
from a public value nobody could predict while the participants were
working, agreed on in advance, for example the hash of a Bitcoin block at
a chosen height. That makes the final key independent of the order and
choices of the participants and lets anyone recompute the last step.
Verification recomputes the initial key, checks that the circuit part is
untouched, walks the contributions, and checks `H` and `L` against the
final `δ` with one batched pairing each. `export` refuses a key without
contributions.

`sb profile-new … --ceremony-vk transfer.vk --ceremony-pk transfer.pk` pins
the verifying key's hash in a deployment profile with `"setup": {"kind":
"ceremony", …}`; indexers need only the verifying key, wallets the proving
key too.

## What it does and does not give

* Secure keys if at least one participant per phase destroyed their
  secret and the beacon was unpredictable. The participants' honesty is
  the only assumption; the coordinator is not trusted (every file is
  verifiable and every contribution has a published digest).
* The verifier of a contribution does not learn the secrets; the proofs
  of knowledge hold in the generic group model, as in BGM17.
* The implementation is from scratch over arkworks. Transcript hashing is
  SHA-256 and hashing to `G2` samples a point from a ChaCha20 stream seeded
  by SHA-256, instead of the BLAKE2b of the Sapling tools, so the files
  are **not** interchangeable with Sapling or Filecoin transcripts;
  reusing one of those public phase 1 transcripts would need a format
  adapter, which does not exist yet. A real ceremony for this circuit
  therefore runs its own phase 1.
* The tooling has not been reviewed by anyone outside this project. Before
  a ceremony whose keys will hold value, it should be.
* Files are read with full point validation (subgroup checks), which takes
  a while for a `2^17` domain; that is deliberate.
