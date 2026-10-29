# Review — publication privacy & wallet-policy implementation (paper §22.3, `docs/PUBLICATION.md`)

**Verdict: PASS, firsthand, no findings.** The network layer and the
wallet-policy changes match PUBLICATION.md v0.2, and the three properties
the design leans on hold against the code: every outbound connection goes
through the proxy or fails, the proxy is set before any connection can be
memoised un-proxied, and a delayed carrier is re-validated against the
window before it is broadcast.

**Ref:** net-layer implementation at `33bf2af` (reviewed against current
`main`; the later docs commit is an address scrub that does not touch the
code). Read firsthand: `crates/sb-indexer/src/net.rs` (whole), every
caller of `net::agent()` / `net::connect_tcp`, `main.rs` (the `set_proxy`
call site and the publish path), `Ctx::hold_before_publishing`, and
`sb-wallet/src/builder.rs` (the change-placement swap). The signet run in
`RUNS.md` corroborates; I reasoned from the code firsthand and did **not**
re-run it.

## 1. Egress completeness — nothing goes out directly (swept, not trusted)

I did not take the "one chokepoint" claim on faith; I swept every
outbound-network primitive in `crates/` (production code). The result:
- **All HTTP** is built through `net::agent()` — Esplora, the Bitcoin
  Core RPC, the light/verified-sync client, the funding UTXO query, and
  the relayer/fee-vault client. No bare `ureq::get`/`post`, no second
  `AgentBuilder`, no other HTTP library anywhere outside `net.rs`.
- **The only raw TCP** (Electrum) goes through `net::connect_tcp`.
- Every `TcpListener` is an **inbound** server (the vault, the relayer,
  the local serve path), not egress.

`connect_tcp` sends the **target host by name** to the proxy (RFC 1928
CONNECT, address type = domain), so there is no local DNS lookup of the
target, and when a proxy is set there is **no fallback to a direct
connection** — a connection that cannot be made through the proxy fails.
The agent is built once with the proxy. So with a proxy set, the only
connection the design claims to protect cannot escape it.

**One residual, correctly documented in v0.2:** reaching the proxy itself
resolves the proxy's own host if it was given as a name (the one local
lookup). Given as an address — which Tor and an SSH dynamic forward both
are — even that is gone. This matches what §2.1 now says.

## 2. The proxy is set before any connection (the memoisation trap)

The HTTP agent is a process-wide value built on first use: whatever proxy
setting is in effect at that first call is frozen for the process. So the
load-bearing fact is **ordering** — if any connection were made before
the proxy is set, the un-proxied agent would be frozen in and every later
request would leak out directly, silently.

The code closes this: `set_proxy` is the **first statement of `main`**,
before any indexer, chain source, sync or publish path runs. The first
agent build therefore happens after the proxy is set, and freezes in the
**proxied** agent. There is no eager/lazy static that could build it
earlier. The "first setting wins" rule on the proxy value then means no
later code path can quietly switch the process back to direct.

## 3. Delayed publication re-validates the window before broadcast

`hold_before_publishing` holds the carrier for a uniform time in the
`--delay lo-hi` range, then — in this order — re-fetches the chain tip,
re-checks that the envelope's anchor is still inside the acceptance
window `W` at the new tip, and **bails ("rebuild the transfer") if it is
not**; only on success does control return to the caller to broadcast
(the hold is invoked with `?`, so a stale-anchor bail prevents the
broadcast). An envelope with no anchor (a mint) correctly skips the
window check. So a delay that would outlive the anchor's window is
refused rather than published into a rejection.

## 4. Change placement — random, and consistent through the proof

The builder places the two outputs in a uniformly random order (one rng
bit, which for two outputs is the whole permutation space). The swap is
applied to the output witnesses **and** their addresses together, **after**
the outputs are built but **before** encryption, before the statement,
and before the proof — so the ciphertexts, the proven statement, and the
returned notes/addresses are all in the same final order. A seeded
`rseed` (the fee-vault deposit tag) stays attached to its output and
merely moves position, and the wallet recovers its notes by
trial-decryption, not by position, so nothing downstream depends on the
order. Soundness is intact.

## 5. Notes

- **Out-of-scope observation resolved.** My fee-vault review flagged a
  `swap_replay` test that passed only because the release build compiles
  out a `debug_assert` (a check that is green because it is absent). It no
  longer asks the prover for an infeasible witness; the rejection is now
  exercised via a statement mismatch that runs in debug, and
  infeasibility-as-a-chain-property stays in the circuit tests. The shape
  is right; I did not read the new test firsthand.
- **Method honesty.** I reasoned from the code firsthand. The signet run
  in `RUNS.md` corroborates (publication through an SSH dynamic forward
  with a delay, so the egress address the network sees is the server's,
  not the laptop's — no values recorded, per the run records). I did not
  re-run it (testnet dev-scaffold — right-sized).
- PUBLICATION.md is still a v0.2 draft and will iterate; this review
  covers the network-layer code and the wallet-policy changes as they
  stand at the reviewed ref.

*Auditor: security-audit (77ph), firsthand. For the owner's personal
public `shielded-bitcoin`; audit against the paper's design and general
security.*
