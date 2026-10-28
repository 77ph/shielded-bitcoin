#!/usr/bin/env bash
# A parameter-ceremony drill: every phase of `sb ceremony` for N
# participants, each transition verified before the next participant sees
# the file, a public beacon, export, and a log of every digest. One person
# can play all the roles (the owner's drills), or each role can be run on
# its own machine by passing files around: the commands are the same.
#
#   scripts/ceremony.sh WORKDIR BEACON ENTROPY1 [ENTROPY2 ...]
#
#   WORKDIR   directory for the files and the log (created)
#   BEACON    64-hex beacon value (a Bitcoin block hash agreed by height
#             before the contributions started), or `mainnet:<height>` /
#             `signet:<height>` to fetch that block's hash from mempool.space
#             after the last contribution. Pick a height that is still in
#             the future when the drill starts; for a real ceremony confirm
#             the hash against your own node, not one web API
#   ENTROPY*  one string per participant, mixed into that participant's
#             secrets; the number of strings is the number of participants
#
# Set SB to the `sb` binary (default: target/release/sb).
set -euo pipefail

WORK=${1:?workdir}; BEACON=${2:?beacon}; shift 2
[ $# -ge 1 ] || { echo "at least one participant's entropy is needed" >&2; exit 2; }
SB=${SB:-target/release/sb}
mkdir -p "$WORK"
LOG="$WORK/LOG.md"
log() { echo "$*" | tee -a "$LOG"; }
run() { log '```'; log "\$ $*"; "$@" 2>&1 | tee -a "$LOG"; log '```'; }

log "# Ceremony drill, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log ""
log "Participants: $#. Beacon: $BEACON."
log ""
log "## Phase 1"
run "$SB" ceremony phase1-new --out "$WORK/p1-0.bin"
i=0
for entropy in "$@"; do
  prev=$i; i=$((i + 1))
  log ""; log "### Participant $i"
  run "$SB" ceremony phase1-contribute --in "$WORK/p1-$prev.bin" --out "$WORK/p1-$i.bin" --entropy "$entropy"
  run "$SB" ceremony phase1-verify --before "$WORK/p1-$prev.bin" --after "$WORK/p1-$i.bin"
done
N=$i
log ""; log "## Key derivation"
run "$SB" ceremony phase2-new --phase1 "$WORK/p1-$N.bin" --out "$WORK/p2-0.bin"
log ""; log "## Phase 2"
i=0
for entropy in "$@"; do
  prev=$i; i=$((i + 1))
  log ""; log "### Participant $i"
  run "$SB" ceremony phase2-contribute --in "$WORK/p2-$prev.bin" --out "$WORK/p2-$i.bin" --entropy "$entropy"
  # quick check against the published initial key before the next turn;
  # the full recompute comes at the end
  run "$SB" ceremony phase2-verify --initial "$WORK/p2-0.bin" --final "$WORK/p2-$i.bin"
done
case "$BEACON" in
  mainnet:*|signet:*)
    net=${BEACON%%:*}; height=${BEACON#*:}
    api="https://mempool.space/api"; [ "$net" = signet ] && api="https://mempool.space/signet/api"
    log ""; log "Waiting for $net block $height…"
    until hash=$(curl -sf "$api/block-height/$height") && [ ${#hash} = 64 ]; do sleep 30; done
    BEACON=$hash
    log "Beacon: $net block $height = $BEACON";;
esac
[ ${#BEACON} = 64 ] || { echo "beacon must be 64 hex characters" >&2; exit 2; }
log ""; log "## Beacon"
run "$SB" ceremony phase2-beacon --in "$WORK/p2-$N.bin" --out "$WORK/p2-final.bin" --beacon "$BEACON"
log ""; log "## Verification of the whole phase 2 against phase 1"
run "$SB" ceremony phase2-verify --phase1 "$WORK/p1-$N.bin" --final "$WORK/p2-final.bin"
log ""; log "## Export"
run "$SB" ceremony export --final "$WORK/p2-final.bin" --pk "$WORK/transfer.pk" --vk "$WORK/transfer.vk"
log ""
log "Files: $(ls "$WORK" | tr '\n' ' ')"
log "Done $(date -u +%Y-%m-%dT%H:%M:%SZ). Keys: $WORK/transfer.pk, $WORK/transfer.vk; profile with"
log "  sb --profile <dir>/profile.json profile-new … --ceremony-vk transfer.vk --ceremony-pk transfer.pk"
