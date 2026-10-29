# Witness-carrier review

A firsthand code review of the witness-carried publication profile
(`docs/WITNESS-CARRIER.md`, crates `sb-indexer`/`sb-cli`), graded against
the paper's witness-carried envelopes (§22.1, §A.4) and against the one
property a publication carrier must have: every implementation reads the
*same* envelope from the *same* transaction.

**Reviewed at:** `37d2d3c` (the profile) and `8a32313` (the annex fix and
the relay caveat). The witness carrier is a separate, non-interoperable
deployment profile selected by a `carrier` field; it does not change the
base OP_RETURN profile, the envelope format, the statement, or replay.

**Verdict:** sound. The envelope is committed in a taproot leaf and revealed
by a script-path spend, so it cannot be altered after the commit and the
internal key cannot sign; extraction is deterministic and consensus-exact,
including across a BIP 341 annex. The one issue of the first pass (an annex
could hide the script from the reader) is fixed and re-verified. The
standardness of witness data is a network property, measured and stated as
such, not claimed as a guarantee.

This is a code-and-soundness review by the project's security reviewer, not
a formal audit. The profile moves no value by itself — it only locates the
envelope bytes — but it is the input to replay, so an indexer disagreement
about *which* bytes are the envelope would be a consensus split; that is the
risk this review is centred on.

---

## What was verified, firsthand

**The envelope is committed, not merely carried.** The commitment
(`sb-cli`'s `witness.rs`) is a single-leaf taproot output whose internal key
is BIP 341's "nothing up my sleeve" NUMS point
(`50929b74c1a04954…ce803ac0`), tweaked by the one leaf — the envelope
tapscript. Two consequences, both checked: the output key has no known
discrete log, so the **key path is unspendable** and the only spend is the
script path that reveals the committed leaf; and the control block lets
consensus (and the test) verify the revealed script *is* that leaf, so no
other envelope can be revealed against the same output. The envelope is
therefore fixed at commit time and `h_body` binds the same bytes the proof
already commits to — the binding equals the OP_RETURN profile's.

**Extraction is deterministic and consensus-exact.** `tapscript_payload`
parses the revealed script with `instructions_minimal` — Bitcoin's minimal
push rules, not a raw-byte scan — so every indexer reads the pushes as
consensus does. The envelope form is `<32-byte key> OP_CHECKSIG OP_FALSE
OP_IF <chunks> OP_ENDIF`, and the chunking is forced canonical: every chunk
but the last is exactly 520 bytes, no empty push, nothing after `OP_ENDIF`;
one envelope therefore has exactly one valid tapscript, and a script that
breaks the form is either "not a candidate" or, if its raw bytes carry the
magic, a rejected probe. The carrier rule is "exactly one input reveals an
envelope, else reject"; a commit transaction is never a candidate (its
inputs reveal nothing).

**The script is located correctly past a BIP 341 annex.** A taproot
script-path witness is `…, script, control block`, or `…, script, control
block, annex` when the last element begins with `0x50`. `tapscript_of` takes
the second-to-last element, or the third-to-last when an annex is present,
and returns nothing for a witness too short for either — so a reveal that
carries an annex is read, not silently ignored. This matters for two
reasons the profile now states: a validly spent commit must not be dropped
by the reader, and every implementation must agree on the same inputs (an
annex handled by one reader and not another would split them). The
publisher never adds an annex; the rule handles one anyway. Verified in
both directions: an annex reveal yields the same envelope, and a two-element
witness whose last item looks like an annex yields no script.

**The base profile is untouched.** The carrier is a `CarrierMode` enum field
on the deployment (default OP_RETURN); the two extractors are fully
separate, and a deployment of one mode does not read the other's carriers —
checked by a replay test running two deployments over one chain, each seeing
only its own, and an end-to-end test of a base-profile deployment over a
witness chain accepting nothing. The envelope, the statement and replay are
the base profile's unchanged; only the transport differs.

**The weight is measured, not asserted.** On a local signet under Bitcoin
Core's default policy the witness carrier's reveals are smaller in virtual
bytes than the OP_RETURN equivalents (`docs/RUNS.md`, §6), as expected since
witness data is one weight unit per byte.

## Finding

**F-1 — an annex could hide the script from the reader (FIXED, `8a32313`).**
The first pass took the second-to-last witness element unconditionally,
which is the control block, not the script, when a BIP 341 annex is present;
such a reveal was read as "not a candidate" and its envelope ignored. No
third party can add an annex to a signed reveal (the annex is covered by the
signature) and the publisher adds none, so correct operation never produced
this — but a reveal that validly spends a commit and is then ignored is a
stranded commit, and a future reader that handled the annex would disagree
with one that did not. The fix reads the script past an annex per BIP 341
and states the rule in `docs/WITNESS-CARRIER.md` §4. Re-verified.

## Caveats (stable)

* **Witness-data relay is a network property, not a guarantee.** The
  inscription form (`OP_FALSE OP_IF` data in a tapscript) relays and mines
  under Core's default policy today; operators and miners can and some do
  filter such data, so relay is a property of the network a deployment
  publishes to, to be measured there. `docs/WITNESS-CARRIER.md` §6 states
  this; it is a deployment assumption, not a consensus guarantee.
* **Dynamics are shown on a local signet.** Core validates the scripts,
  which is the point, but mainnet relay and fee behaviour are not exercised
  there.
* **Two profiles do not interoperate, by design.** A witness-carrier
  deployment and an OP_RETURN deployment read different transactions; mixing
  them, or changing a deployment's `carrier` after it has published, would
  make earlier envelopes unreadable. This is a deployment-time choice, not a
  runtime one.

---

*Reviewed 2026-10-29 against `37d2d3c` / `8a32313`. Commitment, NUMS key-path
unspendability, deterministic consensus-exact extraction (including the
annex), base-profile non-regression and the measured weights checked
firsthand; F-1 verified fixed; the relay caveat is a network property, not a
guarantee.*
