# The post-quantum thread: a study before any code (draft v0.1)

Status: a study, 30 October 2026. No code changes. It answers three
questions the owner asked after §22 was closed, and it fixes what "the
post-quantum part" of this project would mean. Conventions as in
`REMAINING.md`: **[cited]** with the source, **[measured]** on this
stack, **[computed]** with the arithmetic shown, **[estimate]** with
the assumption. Sources in §7.

The three questions:

1. Does this project need variant **A**, a change of proof system to
   something proven in production such as Zcash's Halo 2, and what does
   that solve and not solve?
2. If the proof system changes anyway, should it go straight to a
   post-quantum one (variant **B**), with no change to Bitcoin?
3. Should the project aim at a post-quantum Bitcoin that has Zcash's
   properties from the start (variant **C**)?

## 1. What "post-quantum" means for this stack

A quantum adversary with a cryptographically relevant quantum computer
(CRQC) runs Shor's algorithm against discrete logarithms and Grover's
against hashes. Against this profile (`PROFILE.md`) that means, surface
by surface:

| Surface | In this profile | A CRQC can | Post-quantum today? |
|---|---|---|---|
| Soundness of the transfer, swap and batch proofs | Groth16 over BLS12-381 (pairings, q-type assumptions) | forge proofs: inflation, theft from the pool | no |
| Zero knowledge of those proofs | Groth16, perfect zero knowledge | nothing: a published proof reveals no witness, to any adversary | **yes** |
| Note encryption `ct_note`, `ct_out` (§5.2, §7.3) | ECDH on Jubjub, Poseidon/ChaCha20-Poly1305 symmetric part | recover every shared secret from the published `pk_eph` and decrypt the whole history, retroactively | no |
| Spend authority and addresses (`ak`, `pk_d`, diversified addresses, §3) | discrete logarithm on Jubjub | derive spending keys from published or shared public keys | no |
| Note commitments, nullifiers, `h_body`, the trees | Poseidon over `Fr`, SHA-256 | Grover: 255-bit → ≈ 128-bit preimage work, no structural break | yes (with the usual halving) |
| The Bitcoin boundary: funding keys, HTLC, fee-vault draw key, a future PIPE | secp256k1 ECDSA / BIP 340 | what it can do to any Bitcoin output | no, and not ours to fix |

Two facts follow and drive everything below.

**The proof system is not where privacy dies.** Groth16's zero
knowledge is information-theoretic; the Ethereum post-quantum privacy
analysis states the same for shielded protocols in general: "ZK itself
is quantum-safe; the vulnerability lies in" the encrypted notes and the
elliptic-curve key exchange, and "any privacy-relevant ciphertext
posted today is harvestable by default and will remain exposed for the
lifetime of the ledger" [cited: ethresear.ch, "Post-Quantum Threats to
Ethereum Privacy"]. Zcash's own 2026 roadmap says of its current
protocol that "signatures, proof verification, and note encryption
still depend on pre-quantum primitives" and makes the removal of
in-band secret distribution (Project Tachyon) its answer to
harvest-now-decrypt-later [cited: ZODL roadmap, Consensus, 8 May 2026,
as reported]. For this profile the published `pk_eph` and `ct_note` of
every transfer are exactly such ciphertexts.

**Replacing the proof system buys inflation resistance, not privacy.**
A post-quantum proof system closes the first row. The third and fourth
rows are closed only by post-quantum key agreement in the envelope and
post-quantum ownership in the key hierarchy, and they must be closed
*before* a CRQC exists, because the chain is the archive.

So the levels are:

* **A: transparent.** No trusted setup; not post-quantum. Halo 2 over
  the Pasta cycle with the inner-product argument, as in Zcash Orchard
  and in the owner's `kupermind/confidant` (which reuses "the Zcash
  Orchard Action circuit unchanged", `orchard` 0.15.5 [cited: its
  README]).
* **B: post-quantum soundness.** A hash-based (FRI, STIR, WHIR) or
  lattice-based proof system; no trusted setup either.
* **C: post-quantum privacy.** B plus post-quantum note encryption and
  ownership. Independently of A/B/C, the Bitcoin boundary becomes
  post-quantum only if Bitcoin does (§5).

## 2. The proof-system landscape, with numbers

### 2.1 Proof sizes [cited]

| System | Assumption | Setup | Proof size | Source |
|---|---|---|---|---|
| Groth16 (this profile) | pairings, GGM | circuit-specific | 192 B | `PROFILE.md` §7.1 |
| Polymath / Pari | pairings, AGMOS / AGM+ROM | circuit-specific | 176 / 160 B | `REMAINING.md` §1 |
| Halo 2 + IPA (Orchard) | discrete log on Pasta | none | 4 992 B for 1 action, 7 264 B for 2 (2 272 B per action) | zebra-chain `orchard::shielded_data::expected_proof_size`; halo2 book, "Orchard transaction format" |
| Plonky2 (FRI, Goldilocks) | hash (conjectured PQ) | none | "about 43 kilobytes", "down to 45kb with only 20 seconds of proving time" | Polygon, "Introducing Plonky2" |
| RISC Zero succinct receipt (FRI) | hash | none | "approximately 200kB", wrapped in Groth16 for on-chain use | RISC Zero docs, "Recursion" |
| STARKs in general | hash | none | "typically few hundred kilobytes" | Zcash forum, STARK-as-TZE thread |
| FRI / STIR / WHIR as proximity arguments, 128-bit, degree 2²⁴, rate ½ | hash | none | 306 / 160 / 157 KiB | WHIR paper §6 (ePrint 2024/1586) |
| WHIR, 128-bit, degrees 2¹⁸–2³⁰ | hash | none | 120–187 KiB at rate ½; 56–87 KiB at rate 1/16 | ePrint 2024/1586 §1.1 |
| STIR, 128-bit | hash | none | 94 KiB (d = 2²⁴, ρ = ½) to 189 KiB (d = 2²⁸); 107–128 KiB at ρ = ¼ | ePrint 2024/390 §1, Table 3 |
| LaBRADOR (Module-SIS) | lattice (PQ) | none | 47–58 KB for 2¹⁰–2²⁰ R1CS constraints | ePrint 2022/1341 §1 |

Reading the table. The proximity-argument rows are lower bounds for a
hash-based SNARK of that size, not full proofs (a SNARK commits to
several polynomials and adds its own openings); the full-system rows
(Plonky2, RISC Zero) are what shipping provers produce, at their own
security levels (Plonky2's figure is at its default ≈ 100-bit
conjectured security; the STIR/WHIR figures are at 128 bits). LaBRADOR
is the compact post-quantum alternative, but its verifier is not
succinct in the SNARK sense (the paper's own comparison is on proof
size, and verification work is linear in the statement), which rules
it out where a light client or a replay proof must verify many of them
cheaply. The direction of travel is down (FRI → STIR → WHIR halves the
argument), but nothing published puts a 128-bit hash-based proof of a
relation of this profile's size below several tens of kilobytes.

The transfer relation of this profile is 84 362 R1CS constraints
[measured, `README.md`], degree 2¹⁷ after padding; the swap circuit
174 803; the batch circuit ≈ 217 000 per slot [measured,
`REPLAY-PROOF.md` §6].

### 2.2 What each class costs on the carrier [computed]

The measured carriers of this profile: OP_RETURN 825 vB and witness
447 vB for the 700-byte envelope (`WITNESS-CARRIER.md` §6), so the
non-envelope part is 125 vB (OP_RETURN) and 272 vB (witness, at
0.25 vB per envelope byte). The envelope is 508 bytes of body plus the
proof.

| Proof | Envelope | OP_RETURN carrier | Witness carrier | Share of a 1 MvB block | Transfers per block (witness) |
|---|---|---|---|---|---|
| 192 B (Groth16, today) | 700 B | 825 vB | 447 vB | 0.045 % | ≈ 2 200 |
| 4 992 B (Halo 2, 1 action) | 5 500 B | 5 625 vB | 1 647 vB | 0.16 % | ≈ 600 |
| 7 264 B (Halo 2, 2 actions) | 7 772 B | 7 897 vB | 2 215 vB | 0.22 % | ≈ 450 |
| 45 KB (Plonky2 class) | 45.5 KB | 45 633 vB | 11 649 vB | 1.2 % | ≈ 85 |
| 58 KB (LaBRADOR class) | 58.5 KB | 58 633 vB | 14 899 vB | 1.5 % | ≈ 67 |
| 150 KB (STIR/WHIR class, 128-bit) | 150.5 KB | not relayable (above the 100 000-byte OP_RETURN default of current Bitcoin Core) | 37 899 vB | 3.8 % | ≈ 26 |
| 200 KB (RISC Zero class) | 200.5 KB | not relayable | 50 399 vB | 5.0 % | ≈ 19 |

At 1 sat/vB the witness-carried fee is the vB figure in satoshi; at
20 sat/vB, twenty times that. Today's transfer at 20 sat/vB costs
8 940 sat; a 45-KB proof costs 232 980 sat, a 150-KB proof 757 980 sat.
The witness carrier stays standard up to the 400 000-WU transaction
limit, so every row fits one transaction; the OP_RETURN carrier is
out of the question above 100 KB.

## 3. Question 1: variant A, Halo 2 as in Zcash and confidant

**What A solves.**

* The ceremony. `CEREMONY.md`, the BGM17 code, the drills, the
  "insecure setup from a published seed" caveat on every deployment
  profile and the operational condition "a ceremony with independent
  participants before any value deployment" all disappear. For a
  project whose owner has ruled out a real ceremony, this is the one
  concrete gain.
* A production-proven circuit toolkit (Orchard's gadgets: Sinsemilla,
  Poseidon, the Merkle path, ECC) and shared ground with confidant.
* Recursion. The Pasta cycle is built for accumulation, and §2.3(d) of
  `REMAINING.md` already prices it: Nova's ≈ 10 000-constraint verifier
  circuit, split accumulation's 52 000-constraint recursion threshold
  on Pasta [cited there]. The lineage obstacle R1 of `REMAINING.md` §2
  becomes an engineering problem on A, at packages of kilobytes per
  output (`REMAINING.md` §2.4).

**What A does not solve.**

* Nothing post-quantum: the inner-product argument's soundness is a
  discrete-logarithm assumption, and the note encryption and keys stay
  as they are (§1). Zcash, which runs A, lists its proof verification
  among the pre-quantum components it has to replace [cited: §1].
* The footprint: 192 → 4 992–7 264 bytes per transfer, 3.7–5× the
  witness carrier, 6.8–9.6× the OP_RETURN carrier (§2.2).
* The migration is total. Pasta's fields are not BLS12-381's scalar
  field: every Poseidon value (commitments, nullifiers, `h_body`'s
  embedding, the three trees), the embedded curve of the key hierarchy
  (Jubjub → Pallas), addresses, test vectors, the swap and batch
  circuits, the envelope codec. This is a new, non-interoperable
  profile, the same size of work as B's migration, and done twice if B
  follows.
* A does not lead to B. Halo 2's accumulation is specific to the
  discrete-logarithm commitment; a hash-based successor keeps nothing
  of it but the PLONKish front end.

**Answer.** This project does not need A on its own path. A is the
right choice for a project whose goal is "ship a shielded pool now with
no ceremony and a battle-tested circuit", which is confidant's goal,
not this one's. For the post-quantum thread A is a detour that costs a
full profile migration and would have to be repeated; the one thing it
offers that B needs, recursion, hash-based systems also have (Plonky2,
Plonky3, RISC Zero and Stwo all recurse natively, since a hash-based
verifier is arithmetic over the same field). If the owner wants A for
the ceremony-free property or for a common stack with confidant, it
should be an explicit, separate decision with that justification, not
a step of the post-quantum thread.

## 4. Question 2: straight to B, no change to Bitcoin

**Yes, if the proof system changes at all, B is the only change worth
making**, for the reason in §3: the migration cost is the same and A
does not compound into B.

**What B buys and does not buy.** It closes row 1 of §1 (no forgery, no
inflation by a CRQC), removes the ceremony like A, keeps zero knowledge
(the FRI-based systems have zero-knowledge variants; this must be
checked per implementation, several ship without it by default), and
keeps recursion. It does not touch rows 3 and 4: privacy stays
pre-quantum until C. Its soundness is conjectural in the quantum random
oracle model like every hash-based system's, which is the accepted
state of the art.

**What B costs.** The footprint, and only the footprint. From §2.2: the
smallest shipping hash-based proofs put a transfer at ≈ 11 600 vB on
the witness carrier, 26 × today's, ≈ 85 transfers per Bitcoin block;
128-bit STIR/WHIR-class proofs at ≈ 38 000 vB, 85 × today's, 26 per
block. The OP_RETURN carrier is gone above 100 KB. There is no
engineering around this: the proof is published in every envelope by
the paper's design (replay from Bitcoin alone), and off-chain proofs
would reintroduce exactly the availability trust that `REPLAY-PROOF.md`
§3 refuses.

**What is not known and must be measured.** The table in §2.1 is other
people's circuits. The number that decides B is the proof size and
proving time of *this* transfer relation (84 362 R1CS constraints, with
Poseidon and the Jubjub arithmetic) in a concrete hash-based system at
128 bits with zero knowledge, on this laptop. Candidates with a Rust
implementation: Plonky3 (AIR over BabyBear/Goldilocks with Poseidon2),
Stwo (Circle STARK over M31), and an arkworks-adjacent R1CS route
(Spartan-style with a WHIR commitment; WHIR's authors "plan to upstream
into arkworks" [cited: ePrint 2024/1586 §1.1]). The relation would have
to be re-expressed (R1CS → AIR for the first two), and the in-circuit
Jubjub arithmetic, native over BLS12-381's scalar field today, becomes
non-native over a 31- or 64-bit field, which is where the constraint
count will move. A decision gate the owner can set now, from §2.2: for
example "≤ 50 KB per transfer and ≤ 30 × today's fee on the witness
carrier", which the Plonky2 class meets and the 128-bit STIR/WHIR class
does not.

**Answer.** B is the post-quantum thread's core and should be chosen
over A. It is feasible on Bitcoin as it is, on the witness carrier
only, at a fee 26–85 × today's, and it is worth doing only together
with the analysis of C, because B alone leaves every note readable by
the adversary it is meant to resist.

### 4.1 What C adds, as analysis

* Note encryption: ML-KEM-768 (FIPS 203) has 1 184-byte encapsulation
  keys and 1 088-byte ciphertexts, "33x larger than compressed ECDH
  points" [cited: ethresear.ch]. Per output: +1 088 bytes in the
  envelope, replacing the 32-byte `pk_eph`; per address: a 1 184-byte
  encapsulation key where today's address is 43 bytes. Two outputs add
  ≈ 2.1 KB to every envelope, small against B's proof but a change of
  the address format and of §5.2's committing encryption: the KEM
  encapsulation cannot be proven in-circuit at a sane cost, so the
  profile would prove only the symmetric part (as Orchard proves
  nothing about its ciphertexts) and lose the in-circuit
  ciphertext-consistency property of §12.1 of the paper, or keep it
  for a symmetric key the recipient derives by other means.
* Ownership: a hash-based key hierarchy (spend key = preimage,
  `ak = PH(ask)`), which this circuit does cheaply (one Poseidon), but
  diversified addresses as designed depend on an elliptic-curve
  `DiversifyHash`; a post-quantum address is a (KEM key, hash key)
  pair with no diversifier, so address unlinkability must be bought
  by fresh keys, as Tachyon buys it by out-of-band delivery.
* The boundary stays Bitcoin's (§5).

## 5. Question 3: aiming at a post-quantum Bitcoin

### 5.1 The taxonomy, as of 30 October 2026 [cited]

**(i) Soft forks to Bitcoin itself.**

* **BIP-360, Pay-to-Merkle-Root (P2MR).** Draft, merged into the BIPs
  repository on 11 February 2026; SegWit version 2 (`bc1z…`), Taproot
  without the key path. It protects against "long exposure attacks"
  only and says itself that "protection against … short exposure
  attacks … may require the introduction of post-quantum signatures in
  Bitcoin. We … intend to offer a separate proposal"; "we are currently
  researching options for the potential proposal of post-quantum
  signature algorithms". A Bitcoin Core pull request (#35107, April
  2026) wires validation, policy and wallet support; no activation
  mechanism has been agreed. [cited: bip-0360.mediawiki, Core PR
  #35107, news reports]
* **BIP-361, Post Quantum Migration and Legacy Signature Sunset.**
  Draft, informational, "Requires: TBD Post Quantum Signature BIP";
  Phase A forbids sending to quantum-vulnerable addresses, Phase B
  encumbers ECDSA/Schnorr spends "by a well-publicized flag-day five
  years after activation". [cited: bip-0361.mediawiki]
* **OP_CAT (BIP-347) with Lamport/WOTS.** Hash-based one-time
  signatures in tapscript; BIP-360's own related-work section notes
  they "are one-time signatures … a significant security downgrade" for
  everyday use, and that a Taproot commitment with a key path would
  not be quantum resistant anyway. [cited: bip-0360.mediawiki, BIP-347]
* Signature sizes that any of these would put in witnesses: ML-DSA-44
  2 420 B, ML-DSA-65 3 309 B, ML-DSA-87 4 627 B, SLH-DSA-SHA2-128s
  7 856 B [FIPS 204, FIPS 205], against 64 B for BIP 340.

**(ii) No-fork demonstrations on Bitcoin mainnet.**

* **StarkWare / "Quantum Safe Bitcoin" (Avihu Levy).** A spend
  confirmed in block 964 199 on 26 August 2026 by "signature grinding":
  "brute-forcing millions of candidates until one has a shape that does
  not expose the public key material"; ≈ 3 100 GPU-hours, ≈ $320 of
  compute later recomputed to $67, and non-standard: "it had to be
  handed straight to a miner willing to accept it". [cited: The Block,
  Cointelegraph, Forklog]
* **QuFi Network.** An external verification layer: "separates
  verification from settlement, using a decentralized network of nodes
  to validate transactions with post-quantum cryptography before they
  are settled"; uBTC on Bitcoin Testnet4, ML-DSA-65, SLH-DSA, ML-KEM-1024;
  "without requiring changes to existing blockchain settlement
  networks". The quantum resistance lives in the node network's
  policy, not in Bitcoin's rules. [cited: Cointelegraph, 4 Sept 2026]

**(iii) Separate chains derived from Bitcoin Core.**

* **Bitcoin Quantum (BTQ Technologies, bitcoinquantum.com).** A Core-
  derived fork (`btq-ag/btq-core`, MIT, releases v0.3.0-testnet … v0.5.0-
  testnet, 20 August 2026) with ML-DSA in place of ECDSA, BIP-360 P2MR
  addresses (`tbtq1z…`) implemented in March 2026 with wallet RPC
  support, a public permissionless testnet since 12 January 2026 (> 50
  miners, > 200 000 blocks by March), "Phase 03 (Mainnet): Upcoming".
  Block parameters differ by source and date: 64 MiB blocks in the
  January announcement, "8 MB" and "1 min" on the site in August. No
  bridge to Bitcoin and no privacy feature is described. [cited:
  bitcoinquantum.com, The Quantum Insider, Cointelegraph, GitHub]
* **qBTC (qb.tc).** "The world's first quantum-safe sidechain for
  Bitcoin", ML-DSA-87 for every transaction, `bqs1` addresses, a
  "failsafe bridge" whose mechanism is not described, Jameson Lopp as
  advisor, chief architect Christian Papathanasiou (also a BIP-361
  author); a public testnet since 2025; the site renders only in a
  browser, so its whitepaper could not be read by this study. [cited:
  news.bitcoin.com, search summaries]
* Smaller forks exist (e.g. `beartec-jpg/QuantBTC`); none claims a
  shielded layer.

**(iv) Not Bitcoin, but the reference for "Zcash properties".** Zcash
itself: quantum-recoverable wallets announced for June 2026, "full
transition to post-quantum cryptography over the next 12 to 18 months",
Tachyon removing in-band note delivery. [cited: §1]

### 5.2 What "a post-quantum Bitcoin with Zcash's properties" means here

Nothing in (i)–(iii) has a shielded layer; the Zcash-like properties
would be *this* metaprotocol, running on such a chain. What that needs:

* **The carrier**: unchanged. OP_RETURN and witness carriers are
  Bitcoin transactions; a Core-derived chain relays them under its own
  policy (to be checked per chain: BTQ's `datacarrier` and witness
  limits are not documented in its README).
* **Funding the carriers**: ML-DSA keys instead of the profile's
  P2WPKH funding wallet. This stack already has the mode that
  sidesteps it: `--no-broadcast` plus the node wallet's
  `fundrawtransaction` / `signrawtransactionwithwallet` (`BOUNDARY.md`
  model 2, run on signet in `RUNS.md`); the chain's own wallet signs
  with whatever it has.
* **The boundary**: the HTLC of `SWAP.md` is a hash-lock plus a
  signature, so it is whatever signature the chain has; the fee vault
  signs draws with a key of the profile's choosing (`FEE-VAULT.md` §3,
  BIP 340 today, replaceable); a PIPE over ML-DSA keys is a question
  for the PIPE authors.
* **The shielded layer itself**: B and C, exactly as on Bitcoin.
  Bigger blocks change only the economics: on an 8-MB or 64-MiB chain
  a 45-KB envelope is 0.07–0.6 % of a block, not 1.2 %.

So "aiming at a post-quantum Bitcoin" is not a design choice of this
project; it is a choice of venue, and the layer's own post-quantum
work (B, C) is identical on every venue. What the venue decides is
whether B's footprint is affordable (cheap block space) and whether the
boundary is post-quantum (the chain's signatures).

### 5.3 Answer

Not as a target: no post-quantum Bitcoin exists to target. BIP-360 is a
draft without post-quantum signatures and without an activation plan;
BIP-361 waits on a signature BIP that does not exist; the mainnet
demonstration is non-standard and costs GPU-hours per spend; the
external layers move the trust into a node network. The forks are
testnets of companies with a mainnet "upcoming".

As a venue for a drill, yes, and cheaply: the metaprotocol as it is
today should run on Bitcoin Quantum's testnet through the node-funded
publishing mode, with P2MR funding addresses, without changing a line
of the shielded layer. The result is a run record (`RUNS.md`) showing
that the layer survives the chain's post-quantum migration by
construction, because it never touched secp256k1 except at the
boundary, and the chain's relay policy for carriers, measured. That is
the only form of question 3 that produces evidence now; the "Zcash
properties" part of it is B and C, whose numbers come from question 2.

## 6. Recommendation of the study

1. **A: no**, unless the owner wants the ceremony-free property or a
   common stack with confidant for their own sake; then as a separate,
   so-justified decision, not as a post-quantum step.
2. **B: the core of the thread, measured before chosen.** One
   experiment in the spirit of `experiments/`: the transfer relation in
   one or two hash-based systems with zero knowledge at 128 bits, proof
   size and proving time on this laptop, and the carrier arithmetic of
   §2.2 applied to the result; a decision gate on footprint set by the
   owner beforehand.
3. **C: analysed in the same document**, with the envelope and address
   sizes of §4.1 made exact for this profile and the
   ciphertext-consistency question settled, because B without C is a
   proof system no adversary needs to break.
4. **The venue: a drill on Bitcoin Quantum's testnet** with the current
   code, no shielded-layer changes, recorded in `RUNS.md`; nothing more
   until a post-quantum output type exists on Bitcoin's own signet.
5. **Not now**: anything that waits on BIP-360/361 activation, on a PQ
   signature BIP, or on PIPEs over post-quantum keys.

## 7. Sources

* This repository: `PROFILE.md`, `WITNESS-CARRIER.md` §6,
  `REPLAY-PROOF.md`, `REMAINING.md`, `BOUNDARY.md`, `RUNS.md`.
* ethresear.ch, *Post-Quantum Threats to Ethereum Privacy* (thread
  24450).
* Zcash: ZODL roadmap presented at Consensus, 8 May 2026 (CoinDesk,
  Decrypt, Blockhead reports); Project Tachyon (zeroknowledge.fm
  episode 388 and the Zcash community forum).
* `kupermind/confidant` README (Orchard Action circuit reused
  unchanged).
* Orchard proof size: zebra-chain, `orchard::shielded_data::
  expected_proof_size`; the halo2 book, "Orchard transaction format".
* Polygon, *Introducing Plonky2* (proof size); RISC Zero developer
  docs, *Recursion* (succinct receipt ≈ 200 kB); Zcash community forum,
  *STARK verification as a Transparent Zcash Extension*.
* ePrint 2024/390 (STIR), 2024/1586 (WHIR), 2022/1341 (LaBRADOR); read
  through the web-archive mirror of eprint.iacr.org.
* arXiv 2512.10020, *A Comparative Analysis of zk-SNARKs and
  zk-STARKs* (a toy benchmark: 384 B vs 68 564 B; cited only as one
  more measured ratio).
* `bitcoin/bips`: bip-0360.mediawiki (Draft, v0.12.1), bip-0361.mediawiki
  (Draft), bip-0347.mediawiki; Bitcoin Core PR #35107.
* Bitcoin Quantum: bitcoinquantum.com (page dated 20 August 2026),
  `btq-ag/btq-core` releases, The Quantum Insider (12 January and 20
  March 2026), Cointelegraph.
* qBTC: news.bitcoin.com (May 2025), qb.tc (not machine-readable).
* QuFi Network: Cointelegraph, 4 September 2026.
* StarkWare / QSB: The Block, 26 August 2026; Cointelegraph; Forklog
  (cost recomputed to $67).
* NIST FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA) for key,
  ciphertext and signature sizes.

## 8. Changelog

* **v0.1** (30 October 2026) — the study: the six surfaces, the
  proof-system table and carrier arithmetic, the three questions
  answered, the taxonomy of post-quantum Bitcoin efforts.
