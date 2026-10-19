#!/bin/sh
# tpm-dos.sh - DoS availability test, GUEST side. One script, whole sweep.
# Runs INSIDE the QEMU guest (the attester device).
#
# For each load level it: starts N contending TPM workers, runs the CA in
# bench mode for one measured round (enroll + REQ attests -> ca_load<N>.csv),
# then stops the workers. Pair it with tpm-dos-sweep-verifier.sh on the PC,
# started FIRST, with the SAME levels and request count; the two stay in
# lockstep because the verifier waits for the CA to connect at each level.
#
# usage: ./tpm-dos.sh [requests] [verifier-ip] [port]
#   requests : attests per level (default 20; must match the verifier --count)
#   LEVELS   : edit below (default "0 1 2 4 8 16 32")
#   LOAD     : pcrread (default, light read) | quote (heavy signing)
#              quote auto-creates its key on first use - no separate prep step.
#   results  : $DIR/results/ca_load<N>.csv  (= ~/optee/dos/results on the PC)

DIR=$(cd "$(dirname "$0")" && pwd)
CA=${CA:-./ra-ca-tpm}      # ra-ca-tpm is the CA binary
OUT=${OUT:-$DIR/results}
LEVELS=${LEVELS:-"0 2 4 8 16 32"}

TCTI=${TCTI:-device:/dev/tpmrm0}
AK_CTX=${AK_CTX:-/tmp/tpm-dos-ak.ctx}
LOAD=${LOAD:-Null}

# /dev/tpmrm0 is the default for the RPi4's TPM
# /dev/tpmrm1 is the default for the RPi4's fTPM
DEVICE=${DEVICE:-/dev/tpmrm0}

REQ=${1:-10}
IP=${2:-127.0.0.1}
PORT=${3:-5000}

# ---- pick the load command from LOAD (TOOL/ARGS still override) -----------
if [ "$LOAD" = "quote" ]; then
    TOOL=${TOOL:-tpm2_quote}
    ARGS=${ARGS:--c $AK_CTX -l sha256:0 -q abcd}
else
    TOOL=${TOOL:-tpm2_pcrread}
    ARGS=${ARGS:-sha256:0}
fi

if ! command -v "$CA" >/dev/null 2>&1; then
    echo "CA '$CA' not found (set CA=/path/to/binary)"; exit 1
fi
if ! command -v "$TOOL" >/dev/null 2>&1; then
    echo "$TOOL not found (is tpm2-tools installed?)"; exit 1
fi

# ---- one-time key setup for the quote load (only if needed) ---------------
prep_quote() {
    [ -f "$AK_CTX" ] && return 0
    echo "creating ECC key for the quote load -> $AK_CTX"
    tpm2_createprimary -T "$TCTI" -C e -g sha256 -G ecc \
        -c /tmp/tpm-dos-prim.ctx >/dev/null 2>&1 || return 1
    tpm2_create -T "$TCTI" -C /tmp/tpm-dos-prim.ctx -g sha256 -G ecc \
        -u /tmp/tpm-dos-ak.pub -r /tmp/tpm-dos-ak.priv >/dev/null 2>&1 || return 1
    tpm2_load -T "$TCTI" -C /tmp/tpm-dos-prim.ctx \
        -u /tmp/tpm-dos-ak.pub -r /tmp/tpm-dos-ak.priv \
        -c "$AK_CTX" >/dev/null 2>&1 || return 1
}
# Only prep the quote key if the sweep actually uses load (some level > 0).
if [ "$LOAD" = "quote" ]; then
    _has_load=0
    for _lv in $LEVELS; do
        [ "$_lv" -gt 0 ] 2>/dev/null && _has_load=1
    done
    if [ "$_has_load" = 1 ]; then
        prep_quote || { echo "quote key setup failed (tpm2-tools missing?)"; exit 1; }
    fi
fi

# ---- load workers ---------------------------------------------------------
# kill_tool NAME - kill every process whose ps line mentions NAME. Pure shell,
# no pkill (BusyBox ps/sh has no pkill). This is what actually stops the
# workers: killing the subshell PIDs alone can leave the spawned tpm2 tool (or
# a respawn) running, so we scan ps by name. Run twice to catch a race where a
# loop respawns the tool just as we kill it.
kill_tool() {
    _name=$1
    _i=0
    while [ "$_i" -lt 2 ]; do
        ps | grep "$_name" | grep -v grep | while read _pid _rest; do
            kill -9 "$_pid" 2>/dev/null
        done
        _i=$((_i + 1))
    done
}

# Safety: clear any stray workers left over from a previous run (e.g. a run
# that was Ctrl-C'd mid-level). Otherwise they keep hammering the TPM and every
# level below runs at a higher load than its label says, poisoning the sweep.
kill_tool tpm2_quote
kill_tool tpm2_pcrread

LOAD_PIDS=""
start_load() {
    n=$1
    w=1
    while [ "$w" -le "$n" ]; do
        ( while true; do "$TOOL" -T "$TCTI" $ARGS >/dev/null 2>&1; done ) &
        LOAD_PIDS="$LOAD_PIDS $!"
        w=$((w + 1))
    done
}
stop_load() {
    [ -n "$LOAD_PIDS" ] && kill $LOAD_PIDS 2>/dev/null
    kill_tool "$TOOL"                     # the reliable stop: kill by name
    LOAD_PIDS=""
}
# Always clean up the load on exit/interrupt, whatever happens.
trap 'stop_load; exit' INT TERM
trap 'stop_load' EXIT

# ---- the sweep ------------------------------------------------------------
mkdir -p "$OUT"
echo "DoS sweep: levels [$LEVELS], $REQ attests each, load=$LOAD"

for LEVEL in $LEVELS; do
    echo "============================================================"
    echo "LEVEL $LEVEL  ($REQ attests, load=$LOAD)"
    echo "============================================================"

    if [ "$LEVEL" -gt 0 ] 2>/dev/null; then
        echo "  starting $LEVEL worker(s): $TOOL $ARGS"
        start_load "$LEVEL"
        sleep 1                           # let workers spin up before measuring
    else
        echo "  level 0: baseline, NO contending load (load=$LOAD ignored here)"
    fi

    CSV="$OUT/ca_load$LEVEL.csv"
    rm -f "$CSV"
    # CA logs one bench row per quote INCLUDING the enroll, so count REQ+1:
    # enroll (seq 0) + REQ attests. The CA exits itself after that many.
    # > /dev/null: console printing is slow in QEMU.
    BENCH_OUT="$CSV" BENCH_REQUESTS=$((REQ)) "$CA" "$IP" "$PORT" "$DEVICE" >/dev/null
    echo "  done -> $CSV"

    stop_load
    sleep 2                               # let the TPM settle before next level
done

echo "sweep done. Results in $OUT/ca_load*.csv"