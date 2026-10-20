#!/bin/sh
# idle-runner-ssh.sh - run a idle benchmark on the device. It exits after 
# <RUNS> runs, each with <REQ> requests. Each run produces a CSV file with the results.
#
# Used on RPi4
#
# Pair with verifier: "Verifiers/shells/idle-verifier.sh"
#
# usage: ./idle-runner-ssh.sh <runs> <requests> <wait-window>

# ------------------------- Change these parameters to change the benchmark -------------------------

RUNS=${1:-10}
REQ=${2:-100}
WINDOW=${3:-0.1}

# ------------------------- Don't change these parameters unless you know what you're doing -------------------------

DIR=$(cd "$(dirname "$0")" && pwd)
CA=${CA:-./idle-ca}
OUT=${OUT:-$DIR/results/}

# ------------------------- Run the idle benchmark ------------------------------------------------------------

mkdir -p "$OUT"
rm -f "$OUT"/idle_run*.csv          # <-- clear stale runs from previous benchmarks
echo "Running the idle CA ($REQ requests, $WINDOW s wait between each)."
i=0
while [ $i -lt $RUNS ]; do
    echo "NO ATTENSTATION: run $i/$RUNS ($REQ requests) -> $OUT"
    BENCH_OUT=$OUT/idle_run$i.csv BENCH_REQUESTS=$REQ $CA $WINDOW
    i=$((i + 1))
done

done -> $OUT

# ------------------------- End of script ------------------------------------------------------------
