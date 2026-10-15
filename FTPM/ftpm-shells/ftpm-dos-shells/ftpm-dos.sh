#!/bin/sh
# ftpm-dos.sh - run ONE load level of the DoS availability test.
# Starts N contending TPM workers, runs the CA (bench) for that level,
# then stops the workers. Runs INSIDE the QEMU guest (attester device).
#
# usage: ./ftpm-dos.sh [level] [requests] [verifier-ip] [port]
#   level     : number of contending workers AND the output label (default 0)
#   requests  : attestations to measure this level (default 20)
#   defaults  : 10.0.2.2, port 5000
#
#   level 0 = no load (healthy baseline); CA writes ca_load0.csv
#   level N = N workers; CA writes ca_loadN.csv  -> ~/optee/dos/results
#
# Pair on the verifier with: --count <requests> --load-level <level>
#   --verdict-csv ~/optee/dos/results/verifier_load<level>.csv

DIR=$(cd "$(dirname "$0")" && pwd)
LEVEL=${1:-0}
REQ=${2:-20}
IP=${3:-10.0.2.2}
PORT=${4:-5000}
LOAD_TOOL=${TOOL:-tpm2_pcrread}   # must match ftpm-dos-load.sh's tool

cleanup() {
    # Stop the load: kill the loader AND its worker loops by name, not just
    # the tpm2 tool (the while-loops would respawn it otherwise), then the
    # tool itself as a backstop. -9 so nothing lingers on the TPM.
    [ -n "$LOAD_PID" ] && kill "$LOAD_PID" 2>/dev/null
    pkill -9 -f ftpm-dos-load 2>/dev/null
    pkill -9 -f "$LOAD_TOOL" 2>/dev/null
    wait 2>/dev/null
}
trap cleanup EXIT INT TERM

# Start the contending load for this level (skip entirely at level 0).
LOAD_PID=""
if [ "$LEVEL" -gt 0 ] 2>/dev/null; then
    echo "starting load: $LEVEL worker(s)"
    "$DIR/ftpm-dos-load.sh" "$LEVEL" &
    LOAD_PID=$!
    sleep 1            # let the workers spin up before measuring
else
    echo "level 0: no contending load (baseline)"
fi

# Run the CA for this level. dos.sh sets BENCH_OUT=ca_load<level>.csv and
# BENCH_REQUESTS=<requests>; the CA exits itself after that many attests.
"$DIR/ftpm-dos-benchmark.sh" "$LEVEL" "$REQ" "$IP" "$PORT"
STATUS=$?

# cleanup() runs here via the EXIT trap, stopping the load.
exit "$STATUS"