#!/bin/sh
# benchmark.sh - run the fTPM benchmark several times. Runs INSIDE the QEMU guest.
#
# In QEMU (once per boot):
#   mkdir -p /mnt/host && mount -t 9p -o trans=virtio host /mnt/host
#   cd /mnt/host/benchmark && ./benchmark.sh
#
# usage: ./benchmark.sh [runs] [requests-per-run] [verifier-ip] [port]
#   defaults: 10 runs, 100 requests, 10.0.2.2 (= the host PC seen from QEMU), port 5000
#   results:  /mnt/host/benchmark/results/run1.csv ...  = ~/optee/benchmark/results on the PC
#
# Each run starts the CA in bench mode; it exits by itself after
# <requests-per-run> attestations. The verifier must keep sending attest
# commands and accept the CA reconnecting between runs.

DIR=$(cd "$(dirname "$0")" && pwd)
RUNS=${1:-2}
REQ=${2:-5}
IP=${3:-10.0.2.2}
PORT=${4:-5000}
CA=${CA:-optee_example_ra_ftpm}   # optee_examples installs the CA into /usr/bin
OUT=${OUT:-$DIR/results}

if ! command -v "$CA" >/dev/null 2>&1; then
	echo "CA '$CA' not found (set CA=/path/to/binary)"
	exit 1
fi

mkdir -p "$OUT"
rm -f "$OUT"/run*.csv          # <-- clear stale runs from previous benchmarks
for i in $(seq 1 "$RUNS"); do
	echo "run $i/$RUNS ($REQ requests) -> $OUT/run$i.csv"
	# > /dev/null: discard the CA's normal output (console printing is slow in QEMU)
	BENCH_OUT="$OUT/run$i.csv" BENCH_REQUESTS="$REQ" "$CA" "$IP" "$PORT" > /dev/null
	sleep 2
done

echo "done -> $OUT"
echo "On your PC: python3 FTPM/ftpm-analyzers/ftpm-benchmark-analyzer.py"