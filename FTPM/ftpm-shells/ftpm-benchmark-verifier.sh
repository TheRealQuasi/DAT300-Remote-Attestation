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

VERIFIER=${VERIFIER:-FTPM/ra-ftpm/verifier.py}

echo "benchmark verifier: waiting for the attester (Ctrl-C to stop)"
exec python3 "$VERIFIER" --benchmark "$@"