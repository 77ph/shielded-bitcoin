#!/usr/bin/env bash
# A swap drill on a node you can mine on (the private signet of
# scripts/localsignet.sh): both roles of docs/SWAP.md §9 on one machine,
# in separate data directories, through the same `sb` commands a real
# user and a real liquidity provider would run. Two swaps: one completed
# (X claims the HTLC, Y claims the note with the revealed preimage) and
# one that nobody claims, refunded on both sides after the heights.
#
#   scripts/swap-drill.sh WORKDIR PROFILE CHAIN "MINE_CMD" "FUND_CMD"
#
#   WORKDIR   directory for the two data directories and LOG.md (created)
#   PROFILE   a deployment profile with a `swap` section and a dev vault
#   CHAIN     the --chain spec for a full source (RPC or Esplora)
#   MINE_CMD  a command that mines N blocks: it is run as `$MINE_CMD N`
#   FUND_CMD  a command that pays BTC to an address and mines a block:
#             run as `$FUND_CMD ADDRESS 0.001`
#
# The profile is created by the caller (`sb profile-new … --swap-insecure
# --vault-script <any script>`): the drill only mints, so the vault can be
# any address, for example alice's own funding address. Set SB to the
# binary (default: target/release/sb).
set -euo pipefail

WORK=${1:?workdir}; PROFILE=${2:?profile}; CHAIN=${3:?chain spec}
MINE=${4:?mine command}; FUND=${5:?fund command}
SB=${SB:-target/release/sb}
mkdir -p "$WORK/x" "$WORK/y"
LOG="$WORK/LOG.md"
log() { echo "$*" | tee -a "$LOG"; }
x() { "$SB" --profile "$PROFILE" --data-dir "$WORK/x" --chain "$CHAIN" --passphrase-file "$WORK/pass" "$@" 2>&1 | tee -a "$LOG"; }
y() { "$SB" --profile "$PROFILE" --data-dir "$WORK/y" --chain "$CHAIN" --passphrase-file "$WORK/pass" "$@" 2>&1 | tee -a "$LOG"; }
field() { grep "^$2" <<<"$1" | head -1 | awk '{print $NF}'; }
tip() { x status | grep -o "replayed to Some([0-9]*)" | grep -o "[0-9]*"; }
mine() { log "\$ mine $1"; $MINE "$1" 2>&1 | tail -1 | tee -a "$LOG"; }
[ -f "$WORK/pass" ] || echo "drill passphrase" > "$WORK/pass"


log "# Swap drill, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log ""
log "Profile $PROFILE, chain $CHAIN."
log ""
log "## Wallets and coins"
x wallet-new --name alice >/dev/null 2>&1 || true
y wallet-new --name lp >/dev/null 2>&1 || true
A=$(x address --name alice); ALICE_SH=$(field "$A" "shielded address:"); ALICE_FUND=$(field "$A" "funding address:")
L=$(y address --name lp); LP_FUND=$(field "$L" "funding address:")
log "alice shielded $ALICE_SH"
log "\$ fund alice and lp"
$FUND "$ALICE_FUND" 0.001 2>&1 | tail -1 | tee -a "$LOG"
$FUND "$LP_FUND" 0.001 2>&1 | tail -1 | tee -a "$LOG"
x sync >/dev/null
x mint --name alice --amount 20000 --fee-rate 1
mine 3
x sync >/dev/null; y sync >/dev/null
x scan --name alice | grep balance

run_swap() {
  # $1 = tag, $2 = v_sh, $3 = v_btc, $4 = t_htlc offset, $5 = t_refund offset, $6 = complete|refund
  local tag=$1 vsh=$2 vbtc=$3 dh=$4 dr=$5 ending=$6
  local T; T=$(tip)
  local th=$((T + dh)) tr=$((T + dr))
  log ""; log "## Swap $tag: $vsh sat shielded for $vbtc sat, t_htlc $th, t_refund $tr, ending: $ending"
  x swap offer --name alice --v-sh "$vsh" --v-btc "$vbtc" --t-refund "$tr" --t-htlc "$th" --out "$WORK/offer-$tag.json"
  local H; H=$(python3 -c "import json;print(json.load(open('$WORK/offer-$tag.json'))['hash'])")
  y swap accept --name lp --in "$WORK/offer-$tag.json" --out "$WORK/accept-$tag.json"
  x swap lock --name alice --in "$WORK/accept-$tag.json" --fee-rate 1
  mine 1
  x sync >/dev/null; y sync >/dev/null
  y swap check --name lp --hash "$H"
  local F; F=$(y htlc fund --name lp --hash "$H" --fee-rate 1)
  local OUTPOINT; OUTPOINT=$(grep "^HTLC funded" <<<"$F" | sed 's/.* at \([^ ]*\) .*/\1/')
  mine 1
  if [ "$ending" = complete ]; then
    x htlc claim --name alice --hash "$H" --outpoint "$OUTPOINT" --fee-rate 1
    mine 1
    y sync >/dev/null
    y swap claim --name lp --hash "$H" --fee-rate 1
    mine 1
    x sync >/dev/null; y sync >/dev/null
    y scan --name lp | grep balance
    log "\$ alice refund must be impossible now"
    x swap refund --name alice --hash "$H" || true
  else
    log "\$ nobody claims; wait for t_htlc then refund the HTLC"
    while [ "$(tip)" -lt "$th" ]; do mine 1; x sync >/dev/null; done
    y htlc refund --name lp --hash "$H" --fee-rate 1
    mine 1
    log "\$ wait for the note's refund height"
    while [ "$(tip)" -lt $((tr + 3)) ]; do mine 1; x sync >/dev/null; done
    x swap refund --name alice --hash "$H" --fee-rate 1
    mine 1
    x sync >/dev/null
    x scan --name alice | grep balance
  fi
  x swap list --name alice; y swap list --name lp
}

run_swap one 7000 50000 12 24 complete
run_swap two 5000 40000 6 18 refund
log ""
log "Done $(date -u +%Y-%m-%dT%H:%M:%SZ)."
