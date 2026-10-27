#!/usr/bin/env bash
# Stand up a private signet you can mine yourself (OP_TRUE challenge) for
# end-to-end runs of `sb`, and mine blocks on it.
#
#   scripts/localsignet.sh up [HEIGHT]     # start the node (own datadir/port) and mine to HEIGHT (default 130)
#   scripts/localsignet.sh mine [N]        # mine N more blocks (default 1)
#   scripts/localsignet.sh fund ADDR [BTC] # pay ADDR from the miner wallet (default 1 BTC) and mine a block
#   scripts/localsignet.sh cli ...         # bitcoin-cli against the node
#
# Needs bitcoind/bitcoin-cli/bitcoin-util on PATH and a Bitcoin Core source
# checkout for contrib/signet/miner (CORE=...). The grind is niced and pinned
# (GRIND_CPUS) because `bitcoin-util grind` otherwise takes every core.
set -euo pipefail

D=${D:-$HOME/shielded-bitcoin/btc-localsignet}
PORT=${PORT:-10815}
CORE=${CORE:-$HOME/bitcoin}
GRIND_CPUS=${GRIND_CPUS:-4-7}
GRIND="nice -n 19 taskset -c $GRIND_CPUS bitcoin-util grind"
CLI="bitcoin-cli -datadir=$D -signet -rpcport=$PORT -rpccookiefile=$D/signet/.cookie"
MINER="python3 $CORE/contrib/signet/miner"

cmd=${1:-up}; shift || true
case "$cmd" in
  up)
    HEIGHT=${1:-130}
    mkdir -p "$D"
    cat > "$D/bitcoin.conf" <<CONF
signet=1
signetchallenge=51
fallbackfee=0.0002
daemon=1
server=1
txindex=1
listen=0
[signet]
rpcport=$PORT
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
CONF
    if ! $CLI getblockcount >/dev/null 2>&1; then
      bitcoind -datadir="$D" -conf="$D/bitcoin.conf"
      for _ in $(seq 1 30); do $CLI getblockcount >/dev/null 2>&1 && break; sleep 1; done
    fi
    $CLI createwallet miner >/dev/null 2>&1 || $CLI loadwallet miner >/dev/null 2>&1 || true
    A=$($CLI -rpcwallet=miner getnewaddress)
    HAVE=$($CLI getblockcount)
    if [ "$HAVE" = 0 ]; then
      # Backdate the schedule so the whole chain can be mined without waiting.
      START=$(( $(date +%s) - (HEIGHT + 50) * 600 ))
      $MINER --cli="$CLI" --quiet generate --address="$A" --grind-cmd="$GRIND" --min-nbits --set-block-time="$START"
    fi
    MINE=$(( HEIGHT - $($CLI getblockcount) ))
    [ "$MINE" -gt 0 ] && $MINER --cli="$CLI" --quiet generate --address="$A" --grind-cmd="$GRIND" --min-nbits --max-blocks="$MINE"
    $CLI -rpcwallet=miner rescanblockchain 0 >/dev/null 2>&1 || true
    echo "height $($CLI getblockcount), miner balance $($CLI -rpcwallet=miner getbalance)"
    ;;
  mine)
    N=${1:-1}
    A=$($CLI -rpcwallet=miner getnewaddress)
    $MINER --cli="$CLI" --quiet generate --address="$A" --grind-cmd="$GRIND" --min-nbits --max-blocks="$N"
    echo "height $($CLI getblockcount)"
    ;;
  fund)
    ADDR=$1; AMT=${2:-1}
    $CLI -rpcwallet=miner sendtoaddress "$ADDR" "$AMT"
    "$0" mine 1
    ;;
  cli)
    $CLI "$@"
    ;;
  *)
    echo "usage: $0 up [HEIGHT] | mine [N] | fund ADDR [BTC] | cli ..." >&2; exit 2;;
esac
