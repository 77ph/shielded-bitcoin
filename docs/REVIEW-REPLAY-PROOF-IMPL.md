# Review — succinct replay-proof implementation (paper §22.2, `docs/REPLAY-PROOF.md`, slices 1–3)

**Verdict: PASS, firsthand, no soundness findings in the code.** The batch
circuit `T` enforces replay's `Step` for every accepted statement, the
client verifies before it applies and undoes a whole block on any
mismatch, and batched Groth16 verification is sound. One **trust-honesty
finding** (F-3-1) asks the document — not the code — to name the one
place the proof client trusts the indexer for *value creation* (mints).
Two low notes.

**Ref:** slice 1 `2fd70b5` (indexed Merkle tree), slice 2 `c26dbaf`
(circuit `T`), slice 3 `9cc80a8` (protocol, mint, batched verification,
e2e, signet). Read firsthand: `sb-core/src/imt.rs`, `sb-core/src/batch.rs`,
`sb-circuit/src/batch.rs`, `sb-circuit/src/groth16.rs::verify_batch`,
`sb-indexer/src/proof.rs`, `sb-indexer/src/state.rs`, `sb-indexer/src/replay.rs`
(step 5), and the slice tests. The signet run in `RUNS.md` corroborates;
I reasoned from the code and did not re-run it.

## Slice 1 — the indexed Merkle tree (nullifier set)

Non-membership is `low < x < next` with **strict** bounds both ways
(`x == low` and `x == next` are members and are rejected by the same
witness); the sentinel `(0, 0)` with `next = 0` proves every non-zero
value absent in the empty tree; zero is the sentinel, never insertable
and never provably-absent. Insertion rewrites the low leaf and appends
`(x, old_next)` in one step; `Insertion::roots()` recomputes
before→mid→after from one `low_before`/`old_next` and rejects a tampered
value or position. `Duplicate`/`Zero`/`Full` are errors; the root commits
the insertion order. **F-1-1 (fixed):** the replay used `.expect` on
`insert` that did not account for `Full`; step 5 now refuses a carrier
when the tree would overflow (`size + 2 > 2^DEPTH`), so the insert is
total.

## Slice 2 — the batch circuit `T` (the soundness core)

`T` proves `digest(S_prev) → digest(S_next)` over `n` slots for a `D` that
binds every statement. Verified firsthand:
- **State digest commits the frontier**: `PH(T_STATE, root, size, nf_root,
  nf_size, h_root, height, applied)` — appends prove against the committed
  **size**, not just the root, so a wrong frontier cannot be slipped in.
- **The empty-slot discipline is enforced both ways**: an inactive slot is
  all zeros; an active slot cannot carry a zero nullifier (the strict
  `low < 0` is unsatisfiable), so a real statement cannot be hidden as a
  skip and a skip cannot be a real statement.
- **Nullifiers are threaded sequentially** through `cur_nf_root`/
  `cur_nf_size`, which start at the previous state's values — so a
  double-spend is caught **both within a batch** (the second insert's
  non-membership fails) **and across the whole history** (the set is
  persistent). Leaves thread the same way, computed from the statement so
  `D` binds them.
- **Anchor**: membership at `h_anchor − activation (+1)` against the
  *previous* root history (anchors are buried by `K_min`), with the window
  and `K_min` range checks.
- **Fragments**: an `applied` counter and a `final` bit append the block's
  root to the history exactly once, at the right position, when the block
  completes.

The native `SlotStatement::to_elements` and the circuit's element indexing
agree field-for-field, and `StateOpening::digest` equals the circuit's
opening digest, so the digest the client computes natively is the one the
proof proves. The circuit test is a real mutation suite: five distinct
tamperings (double-spend, foreign anchor, anchor below `K_min`, leaf at
the wrong position, block closed without a root append) each leave the
constraints unsatisfied, alongside the positive and fragment cases.

**Soundness statement (the honest conjunction).** `T` proves the
transition *for the given statements, valid or not* — it does **not**
verify the transfer proofs. A client's state is therefore sound only
under the **conjunction**: `T` soundness ∧ the Poseidon hash's
collision-resistance ∧ the §4.3 transfer/swap proof verification ∧ the
§3 enumeration trust. None follows from another.

## Slice 3 — the protocol (mint, batched verification, the client)

**Mint circuit delta — sound.** `kind ∈ {0,1}` is enforced; `active_tx =
active ∧ ¬mint` gates every anchor check and both nullifier inserts; the
first output leaf is appended on `active` (so a mint cannot skip its one
leaf) and the second on `active_tx`; `kind` is the 18th committed element,
so it enters `D` and the all-zero-skip (a `kind = 1` mint cannot be hidden
as a skip). A pre-activation anchor opens to the constant empty root, and
the root-tree indexing is shifted by one consistently for the empty root
at leaf 0.

**Batched Groth16 verification — sound.** `verify_batch` forms, per proof,
`e(rA,B)·e(−rL,γ)·e(−rC,δ)` with `L = γ_abc[0] + Σ xᵢ γ_abc[i]`, plus one
`e(−(Σr)α, β)`; for valid proofs each collapses to `e(rα,β)` and the whole
product is `1`. The scalars `r` are drawn from the **client's** rng, so an
indexer cannot craft proofs that cancel; the public-input count is
checked against the key.

**Client verifies before it applies.** `apply_fragments` first checks, for
every fragment, that it starts from the expected state, that the batch
proof verifies, that the claimed opening hashes to `s_next`, that the
declared `kind` matches the statement, and that the statements hash to
`D`; then it batch-verifies the transfer proofs under the transfer key and
the swaps under the swap key; **only then** does it apply the leaves.
`sync` recomputes the opening after the block and **undoes the entire
block** (nullifiers, leaves, roots, checkpoint) if it does not equal the
claimed digest. The light client keeps `nf_root`/`nf_size` and a per-block
history; a rollback restores them from the history snapshot and truncates
the note and root trees.

## F-3-1 — name the mint-backing trust (document, not code)

A mint **creates value** (it appends a note leaf with no nullifiers), and
the proof client verifies **no proof** for it: `("mint", true)` collects
nothing. A transfer or swap the indexer *adds* is caught by §4.3 (its
proof must verify, and a valid transfer conserves value); a **mint cannot
be caught this way**, because mints carry no proof the client checks. Its
backing is a Bitcoin-layer fact (a payment to the vault) that a light
client, holding only headers, **cannot verify** — a full replayer sees it
in the block, a proof client does not. So an indexer serving a proof
client is trusted not to inject an unbacked mint; this is the **one
inflation-capable trust point**, and it is sharper than the generic
"enumeration trust" of §3, where added transfers are still value-neutral.

This is **inherent to a light client, not a code defect** — there is no
proof to add here. The finding is that the document must **say so
explicitly**: §3/§4.6 should state that the proof client trusts the
indexer for **mint validity / backing** (value creation), name it as the
inflation surface, and point to the full replayer as the party that
verifies it against the block. For an academic write-up of §22 the trust
base must be stated at this precision; a reader must not take "the state
is proven" to mean mints are backed. (This is the backing-forcing
question applied to the client: every value-creating path must name the
invariant that ties it to a real source, and here that invariant is not
enforced on the client's side.)

## Low notes

- **Light reorg-rollback is logic-only.** The rollback path (restore
  `nf_root`/`nf_size` from the history, truncate the trees) is correct by
  reading, but is not exercised end-to-end (the e2e covers forward sync and
  the two rejection cases, not a reorg). Add an e2e reorg test before a
  client is relied on. Low.
- **Setup regeneration for the verifying key.** The client regenerates the
  (insecure) setup to obtain the verifying key; a ceremony supplies the
  key file in production. Already named as a known gap; it is the same
  trusted-setup condition as the transfer circuit's.

*Auditor: security-audit (77ph), firsthand. For the owner's personal
public `shielded-bitcoin`; audit against the paper's design and general
security.*
