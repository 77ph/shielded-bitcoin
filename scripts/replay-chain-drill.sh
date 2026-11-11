#!/usr/bin/env bash
# The accumulated replay proof's chain (docs/REPLAY-PROOF-A.md §3.8) on a
# node you can mine on (the private signet of scripts/localsignet.sh): a
# family-A deployment is made, a mint and two transfers are published and
# mined, then `sb a replay-prove` proves every block from the activation
# as steps of one chain and `sb a replay-decide` accepts them as a client
# would. Three phases, because the prover is heavy (about 15 GB, k = 18
# twice) and runs where heavy jobs run, while the wallet steps and the
# mining run beside the node:
#
#   scripts/replay-chain-drill.sh events WORKDIR CHAIN "MINE_CMD" "FUND_CMD" "CLI_CMD"
#   scripts/replay-chain-drill.sh prove  WORKDIR CHAIN [BLOCKS]
#   scripts/replay-chain-drill.sh decide WORKDIR CHAIN
#
#   WORKDIR   directory for the profile, the wallets' data dir (a/), the
#             prover's and client's data dir (b/) and LOG.md (created);
#             prove and decide read the profile events wrote
#   CHAIN     the --chain spec for a full source (rpc-cookie:<url>:<cookie-path>)
#   MINE_CMD  mines N blocks: run as `$MINE_CMD N`
#   FUND_CMD  pays BTC to an address and mines a block: `$FUND_CMD ADDRESS 0.01`
#   CLI_CMD   bitcoin-cli against the node (validateaddress, getblockcount)
#   BLOCKS    steps to prove this run (default 50; the prover stops at the tip)
#
# Set SB to the binary (default: target/release/sb). PROOFS/SLOTS/EMPTY/KQ/KP
# are the fragment and circuit sizes (defaults 2/4/8/18/18; the phases must agree).
# Written 10 November 2026; its first run is recorded in docs/RUNS.md when made.
set -euo pipefail
PHASE=${1:?events|prove|decide}; WORK=${2:?workdir}; CHAIN=${3:?chain spec}
SB=${SB:-target/release/sb}
PROOFS=${PROOFS:-2}; SLOTS=${SLOTS:-4}; EMPTY=${EMPTY:-8}; KQ=${KQ:-18}; KP=${KP:-18}
mkdir -p "$WORK/a" "$WORK/b"
LOG="$WORK/LOG.md"; PROFILE="$WORK/profile.json"
log() { echo "$*" | tee -a "$LOG"; }
[ -f "$WORK/pass" ] || echo "drill passphrase" > "$WORK/pass"
a() { "$SB" --profile "$PROFILE" --data-dir "$WORK/a" --chain "$CHAIN" --passphrase-file "$WORK/pass" "$@" 2>&1 | tee -a "$LOG"; }
b() { "$SB" --profile "$PROFILE" --data-dir "$WORK/b" --chain "$CHAIN" --passphrase-file "$WORK/pass" "$@" 2>&1 | tee -a "$LOG"; }
field() { grep "^$2" <<<"$1" | head -1 | awk '{print $NF}'; }
sizes=(--proofs "$PROOFS" --slots "$SLOTS" --empty "$EMPTY" --k-q "$KQ" --k-p "$KP")

case "$PHASE" in
  events)
    MINE=${4:?mine command}; FUND=${5:?fund command}; CLI=${6:?bitcoin-cli command}
    mine() { log "\$ mine $1"; $MINE "$1" 2>&1 | tail -1 | tee -a "$LOG"; }
    script_of() { $CLI validateaddress "$1" | python3 -c 'import json,sys; print(json.load(sys.stdin)["scriptPubKey"])'; }
    H=$($CLI getblockcount); ACT=$((H + 1))
    log "# Replay-chain drill, $(date -u +%Y-%m-%dT%H:%MZ): events"
    log "node at $H; activation $ACT; sizes ${sizes[*]}"
    # the operator wallet first: its funding script is the development vault
    a profile-new --family a-halo2 --name replay-drill --network signet --activation "$ACT" --carrier witness >/dev/null
    op=$(a wallet-new --name operator)
    op_funding=$(field "$op" "funding address:"); op_shielded=$(field "$op" "shielded address:")
    a profile-new --family a-halo2 --name replay-drill --network signet --activation "$ACT" --carrier witness \
      --vault-script "$(script_of "$op_funding")" --operator-address "$op_shielded" >/dev/null
    alice=$(a wallet-new --name alice); alice_funding=$(field "$alice" "funding address:")
    bob=$(a wallet-new --name bob); bob_shielded=$(field "$bob" "shielded address:")
    log "\$ fund alice 0.01"; $FUND "$alice_funding" 0.01 2>&1 | tail -1 | tee -a "$LOG"
    a sync >/dev/null
    log "## mint 5000 to alice"; a mint --name alice --amount 5000 | grep -E "envelope|height|txid" || true
    mine 3
    a sync | grep -E "accepted|replayed" || true
    log "## alice pays bob 2000"; a send --name alice --to "$bob_shielded" --amount 2000 | grep -E "envelope|vB|height|txid" || true
    mine 3
    a sync | grep -E "accepted|replayed" || true
    log "## alice pays the operator 1000"; a send --name alice --to "$op_shielded" --amount 1000 | grep -E "envelope|vB|height|txid" || true
    mine 3
    a sync | grep -E "accepted|replayed" || true
    a status | grep -E "height|events|accepted|rejected" || true
    TIP=$($CLI getblockcount)
    log "events done: blocks $ACT..$TIP, $((TIP - ACT + 1)) steps to prove"
    ;;
  prove)
    BLOCKS=${4:-50}
    log "# Replay-chain drill, $(date -u +%Y-%m-%dT%H:%MZ): prove up to $BLOCKS blocks (${sizes[*]})"
    t0=$(date +%s)
    b replay-prove --blocks "$BLOCKS" "${sizes[@]}"
    log "prove phase: $(( $(date +%s) - t0 )) s wall"
    ;;
  decide)
    log "# Replay-chain drill, $(date -u +%Y-%m-%dT%H:%MZ): decide (${sizes[*]})"
    t0=$(date +%s)
    b replay-decide "${sizes[@]}"
    log "decide phase: $(( $(date +%s) - t0 )) s wall"
    ;;
  *) echo "phase: events|prove|decide" >&2; exit 2 ;;
esac
