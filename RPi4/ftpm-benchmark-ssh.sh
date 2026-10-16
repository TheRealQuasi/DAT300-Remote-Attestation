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
CA=${CA:-./ra-ca-ftpm}   # optee_examples installs the CA into /usr/bin
OUT=${OUT:-$DIR/results}

# /dev/tpmrm0 is the default for the RPi4's TPM
# /dev/tpmrm1 is the default for the RPi4's fTPM
DEVICE=${DEVICE:-/dev/tpmrm1}

RUNS=${1:-10}
REQ=${2:-20}
IP=${3:-127.0.0.1}
PORT=${4:-5000}


if ! command -v "$CA" >/dev/null 2>&1; then
	echo "CA '$CA' not found (set CA=/path/to/binary)"
	exit 1
fi

mkdir -p "$OUT"
rm -f "$OUT"/run*.csv          # <-- clear stale runs from previous benchmarks
for i in $(seq 1 "$RUNS"); do
	echo "run $i/$RUNS ($REQ requests) -> $OUT/run$i.csv"
	# > /dev/null: discard the CA's normal output (console printing is slow in QEMU)
	BENCH_OUT="$OUT/run$i.csv" BENCH_REQUESTS="$REQ" "$CA" "$IP" "$PORT" "$DEVICE" > /dev/null
	sleep 1
done

echo "done -> $OUT"