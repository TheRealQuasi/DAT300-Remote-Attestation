#!/bin/sh
# ftpm-benchmark-ssh.sh - run a benchmark on the device. It exits by itself after
# <RUNS> runs, each with <REQ> requests. Each run produces a CSV file with the results.
#
# Used on RPi4
#
# Pair with verifier: "Verifiers/shells/benchmark-verifier.sh"
#
# usage: ./ftpm-benchmark-ssh.sh <runs> <requests-per-run>

# ------------------------- Change these parameters to change the benchmark -------------------------

RUNS=${1:-10}
REQ=${2:-120}

# ------------------------- Don't change these parameters unless you know what you're doing -------------------------

DIR=$(cd "$(dirname "$0")" && pwd)
CA=${CA:-./ra-ca-ftpm}
OUT=${OUT:-$DIR/results}

# /dev/tpmrm0 is the default for the RPi4's TPM
# /dev/tpmrm1 is the default for the RPi4's fTPM
DEVICE=${DEVICE:-/dev/tpmrm1}
if [ "$DEVICE" = "/dev/tpmrm0" ]; then
    DEVICE_NAME=${DEVICE_NAME:-tpm}
else
    DEVICE_NAME=${DEVICE_NAME:-fTPM}
fi

IP=${IP:-127.0.0.1}
PORT=${PORT:-5000}

# ------------------------- Run the benchmark ------------------------------------------------------------

if ! command -v "$CA" >/dev/null 2>&1; then
	echo "CA '$CA' not found (set CA=/path/to/binary)"
	exit 1
fi

mkdir -p "$OUT"
rm -f "$OUT"/run*.csv          # <-- clear stale runs from previous benchmarks
for i in $(seq 1 "$RUNS"); do
	echo "$DEVICE_NAME: run $i/$RUNS ($REQ requests) -> $OUT/run$i.csv"
	# > /dev/null: discard the CA's normal output
	BENCH_OUT="$OUT/run$i.csv" BENCH_REQUESTS="$REQ" "$CA" "$IP" "$PORT" "$DEVICE" > /dev/null
	sleep 1
done

echo "done -> $OUT"

# ------------------------- End of script ------------------------------------------------------------
