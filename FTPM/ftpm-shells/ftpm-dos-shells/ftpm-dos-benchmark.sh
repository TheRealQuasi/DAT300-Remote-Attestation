#!/bin/sh
# ftpm-dos-benchmark.sh - run the CA (bench mode) for ONE DoS load level.
# This is the file ftpm-dos.sh invokes. Runs INSIDE the QEMU guest.
#
# Writes ca_load<N>.csv (one per load level) so ftpm-dos-analyzer.py can pair
# it with the verifier's verifier_load<N>.csv.
#
# usage: ./ftpm-dos-benchmark.sh [level] [requests] [verifier-ip] [port]
#   defaults: level 0, 20 requests, 10.0.2.2, port 5000
#   result:   /mnt/host/dos/results/ca_load<level>.csv = ~/optee/dos/results
#
# THE COUNT: the CA logs one bench row per quote, and the enroll is a quote
# too. The verifier does 1 enroll + <requests> attests, so the CA must count
# <requests>+1 quotes to cover the enroll plus every attest. It then exits by
# itself after that many (bench_done) - exactly like benchmark.sh. (The
# exit-on-disconnect patch in the CA is a harmless backup.)
#
# Pair on the verifier with: --count <requests> --load-level <level>
#   --verdict-csv ~/optee/dos/results/verifier_load<level>.csv

DIR=$(cd "$(dirname "$0")" && pwd)
LEVEL=${1:-0}
REQ=${2:-20}
IP=${3:-10.0.2.2}
PORT=${4:-5000}
CA=${CA:-optee_example_ra_ftpm}   # optee_examples installs the CA into /usr/bin
OUT=${OUT:-$DIR/results}

if ! command -v "$CA" >/dev/null 2>&1; then
    echo "CA '$CA' not found (set CA=/path/to/binary)"
    exit 1
fi

mkdir -p "$OUT"
CSV="$OUT/ca_load$LEVEL.csv"
rm -f "$CSV"                   # clear a stale file for this level

echo "DoS run: load level $LEVEL, $REQ attests (+1 enroll) -> $CSV"

# > /dev/null: discard the CA's normal output (console printing is slow in QEMU)
# REQ+1 = one enroll round + REQ measured attests. The enroll ends up at
# seq 0; drop it with the analyzer's --warmup 1.
BENCH_OUT="$CSV" BENCH_REQUESTS=$((REQ + 1)) "$CA" "$IP" "$PORT" > /dev/null

echo "done -> $CSV"
echo "On your PC: python3 FTPM/ftpm-analyzers/ftpm-dos-analyzer.py --warmup 1"