#!/bin/sh
# ftpm-benchmark-verifier.sh - PC side launcher for NORMAL benchmarking.
# Starts the verifier in benchmark mode (attests nonstop, no verdict log) and
# waits for the CA to connect. The CA, started in the guest with
# BENCH_OUT/BENCH_REQUESTS, drives the run length and exits itself.
#
# usage: ./ftpm-benchmark-verifier.sh
#   PROTECTED : file the attester must hash (default /root/protected.txt)
#   VERIFIER  : path to verifier.py (default FTPM/ra-ftpm/verifier.py)
#   extra args after -- are passed straight to verifier.py

ANALYZER=${ANALYZER:-FTPM/ftpm-analyzers/ftpm-benchmark-analyzer.py}
VERIFIER=${VERIFIER:-FTPM/ra-ftpm/verifier.py}
PROTECTED=${PROTECTED:-/root/protected.txt}
TIMEOUT=${TIMEOUT:-120}

RUNS=${1:-3}
REQ=${2:-5}

echo "benchmark verifier: waiting for the attester (Ctrl-C to stop)"
python3 "$VERIFIER" --file "$PROTECTED" --benchmark \
    --requests "$REQ" --runs "$RUNS" --timeout "$TIMEOUT" "$@"

echo "Analyzing results..."
python3 "$ANALYZER"
echo "done -> FTPM/results"