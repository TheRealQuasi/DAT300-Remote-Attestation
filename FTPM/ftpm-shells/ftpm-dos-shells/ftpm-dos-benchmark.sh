#!/bin/sh
# dos.sh - run the CA for DoS availability testing. Runs INSIDE the QEMU guest.
#
# Same idea as benchmark.sh, but the output files are named ca_load<N>.csv
# (one per load level) so ftpm-dos-analyzer.py can pair them with the
# verifier's verifier_load<N>.csv files.
#
# This script only starts the CA in bench mode. The CONTENDING LOAD (the N
# processes that keep the fTPM busy) is started separately on the device,
# before you run this; here N is just a LABEL for the output filename.
#
# In QEMU (once per boot):
#   mkdir -p /mnt/host && mount -t 9p -o trans=virtio host /mnt/host
#   cd /mnt/host/dos && ./dos.sh
#
# usage: ./dos.sh [load-level] [requests] [verifier-ip] [port]
#   defaults: level 0 (no load / dry run), 20 requests, 10.0.2.2, port 5000
#   result:   /mnt/host/dos/results/ca_load<level>.csv
#             = ~/optee/dos/results on the PC
#
# The CA exits by itself after <requests> attestations (BENCH_REQUESTS).
# Start the verifier on the PC with a matching --count and
# --verdict-csv ~/optee/dos/results/verifier_load<level>.csv

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

echo "DoS run: load level $LEVEL, $REQ requests -> $CSV"
if [ "$LEVEL" = "0" ]; then
    echo "  (level 0 = no contending load; this is the healthy baseline)"
else
    echo "  NOTE: make sure the $LEVEL contending TPM loop(s) are running"
    echo "        on this device BEFORE the verifier starts sending."
fi

# > /dev/null: discard the CA's normal output (console printing is slow in QEMU)
BENCH_OUT="$CSV" BENCH_REQUESTS="$REQ" "$CA" "$IP" "$PORT" > /dev/null

echo "done -> $CSV"
echo "On your PC: python3 FTPM/ftpm-analyzers/ftpm-dos-analyzer.py --warmup 1"