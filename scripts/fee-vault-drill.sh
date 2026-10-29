#!/usr/bin/env bash
# A fee-vault drill on a node you can mine on (the private signet of
# scripts/localsignet.sh): the vault operator and a client of
# docs/FEE-VAULT.md on one machine, in separate data directories, through
# the same `sb` commands they would run. A deposit, a transfer and a
# withdraw drawn from the credit, the refusals of the rule, the backing
# guard, a top-up and a reclaim; the fees charged are recorded.
#
#   scripts/fee-vault-drill.sh WORKDIR PROFILE CHAIN "MINE_CMD" "FUND_CMD"
#
#   WORKDIR   directory for the two data directories and LOG.md (created)
#   PROFILE   a deployment profile with a dev boundary (for the withdraw)
#   CHAIN     the --chain spec for a full source (RPC or Esplora)
#   MINE_CMD  a command that mines N blocks: it is run as `$MINE_CMD N`
#   FUND_CMD  a command that pays BTC to an address and mines a block:
#             run as `$FUND_CMD ADDRESS 0.001`
#
# Set SB to the binary (default: target/release/sb).
set -euo pipefail

WORK=${1:?workdir}; PROFILE=${2:?profile}; CHAIN=${3:?chain spec}
MINE=${4:?mine command}; FUND=${5:?fund command}
SB=${SB:-target/release/sb}
mkdir -p "$WORK/c" "$WORK/v"
LOG="$WORK/LOG.md"
log() { echo "$*" | tee -a "$LOG"; }
c() { "$SB" --profile "$PROFILE" --data-dir "$WORK/c" --chain "$CHAIN" --passphrase-file "$WORK/pass" "$@" 2>&1 | tee -a "$LOG"; }
v() { "$SB" --profile "$PROFILE" --data-dir "$WORK/v" --chain "$CHAIN" --passphrase-file "$WORK/pass" "$@" 2>&1 | tee -a "$LOG"; }
# like c/v but a failure is the expected outcome
cfail() { set +e; "$SB" --profile "$PROFILE" --data-dir "$WORK/c" --chain "$CHAIN" --passphrase-file "$WORK/pass" "$@" 2>&1 | tee -a "$LOG"; local rc=${PIPESTATUS[0]}; set -e; [ "$rc" -ne 0 ] || { log "EXPECTED A REFUSAL"; exit 1; }; }
vfail() { set +e; "$SB" --profile "$PROFILE" --data-dir "$WORK/v" --chain "$CHAIN" --passphrase-file "$WORK/pass" "$@" 2>&1 | tee -a "$LOG"; local rc=${PIPESTATUS[0]}; set -e; [ "$rc" -ne 0 ] || { log "EXPECTED A REFUSAL"; exit 1; }; }
field() { grep "^$2" <<<"$1" | head -1 | awk '{print $NF}'; }
mine() { log "\$ mine $1"; $MINE "$1" 2>&1 | tail -1 | tee -a "$LOG"; }
[ -f "$WORK/pass" ] || echo "drill passphrase" > "$WORK/pass"

VAULT_PID=""
stop_vault() { if [ -n "$VAULT_PID" ]; then kill "$VAULT_PID" 2>/dev/null || true; wait "$VAULT_PID" 2>/dev/null || true; VAULT_PID=""; fi; }
start_vault() {
  "$SB" --profile "$PROFILE" --data-dir "$WORK/v" --chain "$CHAIN" --passphrase-file "$WORK/pass" \
    fee-vault serve --name vault --listen 127.0.0.1:0 --fee-rate 1 --margin 10 --sync-interval 2 --max-checks-per-minute 1000 \
    > "$WORK/vault.out" 2>> "$WORK/vault.log" &
  VAULT_PID=$!
  for _ in $(seq 1 600); do
    URL=$(grep -o 'http://[^ ]*' "$WORK/vault.out" 2>/dev/null | head -1 || true)
    [ -n "$URL" ] && break
    sleep 0.5
  done
  [ -n "$URL" ] || { log "vault did not start"; cat "$WORK/vault.log"; exit 1; }
  log "vault at $URL"
}
trap stop_vault EXIT

log "# Fee-vault drill, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log ""
log "Profile $PROFILE, chain $CHAIN."
log ""
log "## Wallets and coins"
c wallet-new --name alice >/dev/null 2>&1 || true
c wallet-new --name bob >/dev/null 2>&1 || true
v wallet-new --name vault >/dev/null 2>&1 || true
A=$(c address --name alice); ALICE_FUND=$(field "$A" "funding address:")
B=$(c address --name bob); BOB_SH=$(field "$B" "shielded address:"); BOB_FUND=$(field "$B" "funding address:")
V=$(v address --name vault); VAULT_FUND=$(field "$V" "funding address:")
log "\$ fund alice (client fees for the mint and the deposit) and the vault's pool"
$FUND "$ALICE_FUND" 0.001 2>&1 | tail -1 | tee -a "$LOG"
$FUND "$VAULT_FUND" 0.001 2>&1 | tail -1 | tee -a "$LOG"
c sync >/dev/null
c mint --name alice --amount 20000 --fee-rate 1
mine 3
c sync >/dev/null; v sync >/dev/null
c scan --name alice | grep balance

log ""; log "## The vault"
start_vault
log "\$ GET /info"
curl -s "$URL/info" | tee -a "$LOG"; log ""

log ""; log "## Deposit"
log "\$ no credit yet: the client refuses before asking"
cfail send --name alice --to "$BOB_SH" --amount 1000 --fee-rate 1 --fee-vault "$URL"
c unlock --name alice >/dev/null
c fee-vault deposit --name alice --vault "$URL" --amount 2500 --fee-rate 1
mine 1
c fee-vault accounts --name alice
mine 2
c sync >/dev/null
c fee-vault accounts --name alice

log ""; log "## Draws"
log "\$ a ceiling below the fee is refused, nothing charged"
cfail send --name alice --to "$BOB_SH" --amount 1000 --fee-rate 1 --fee-vault "$URL" --max-fee 1
c unlock --name alice >/dev/null
log "\$ a transfer to bob, paid from the credit"
c send --name alice --to "$BOB_SH" --amount 1000 --fee-rate 1 --fee-vault "$URL"
mine 3
c sync >/dev/null
c scan --name bob | grep balance
log "\$ a withdraw of 2000 sat to bob's Bitcoin address, paid from the credit"
c withdraw --name alice --amount 2000 --to "$BOB_FUND" --fee-rate 1 --fee-vault "$URL"
log "\$ the vault restarts with that draw still in the mempool (I3)"
stop_vault
start_vault
sleep 3
c fee-vault accounts --name alice --vault "$URL"
mine 3
c sync >/dev/null
log "\$ credit below one fee: the vault refuses, nothing charged"
NB=$(c send --name alice --to "$BOB_SH" --amount 500 --fee-rate 1 --no-broadcast)
LABEL=$(grep -o 'outbox/[^ ]*\.json' <<<"$NB" | head -1 | sed 's#outbox/##; s#\.json##')
cfail publish "$LABEL" --name alice --fee-vault "$URL" --max-fee 5000
c unlock --name alice >/dev/null
log "\$ a remainder below the reclaim fee cannot be reclaimed on its own"
cfail fee-vault reclaim --name alice --vault "$URL"

log ""; log "## The operator's backing guard (I2)"
stop_vault
v fee-vault status --name vault
log "\$ spending below the outstanding credit is refused"
vfail send --name vault --to "$BOB_SH" --amount 2400 --no-broadcast
v unlock --name vault >/dev/null
log "\$ within the bound it is not"
v send --name vault --to "$BOB_SH" --amount 100 --no-broadcast
v unlock --name vault >/dev/null

log ""; log "## Top-up and reclaim"
start_vault
c fee-vault deposit --name alice --vault "$URL" --amount 2000 --fee-rate 1 --index 0
mine 3
c sync >/dev/null
c fee-vault accounts --name alice --vault "$URL"
c fee-vault reclaim --name alice --vault "$URL"
mine 3
c sync >/dev/null
c scan --name alice | grep balance
c fee-vault accounts --name alice --vault "$URL"
stop_vault
v sync >/dev/null
v fee-vault status --name vault
log ""
log "## Ledger"
cat "$WORK/v/fee-vault-vault.json" | tee -a "$LOG"
log ""
log "Done, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
