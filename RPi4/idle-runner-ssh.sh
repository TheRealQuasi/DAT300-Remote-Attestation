#!/bin/sh

CA=${CA:-./idle-ca}
DIR=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-$DIR/results/}

# Change these parameters to adjust the benchmark:
RUNS=${1:-10}
REQ=${2:-100}
WINDOW=${3:-0.1}

echo "Running the idle CA ($REQ requests, $WINDOW s wait between each)."
i=0
while [ $i -lt $RUNS ]; do
    echo "run $i/$RUNS ($REQ requests) -> $OUT"
    BENCH_OUT=$OUT/idle_run$i.csv BENCH_REQUESTS=$REQ $CA $WINDOW
    i=$((i + 1))
done
# BENCH_OUT=$OUT BENCH_REQUESTS=$REQ $CA $WINDOW