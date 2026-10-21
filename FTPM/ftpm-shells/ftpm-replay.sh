#!/bin/sh
# ftpm-replay.sh - normal world for the replay test.
# Starts the CA normally (not in enrollment or benchmark mode) so the PC-side
# verifier can perform a trusted attestation followed by a replay attempt.
#
# usage: ./ftpm-replay.sh [verifier-ip] [port]
# defaults: 10.0.2.2 (= the host PC as seen from QEMU), port 5000

set -eu

CA=${CA:-optee_example_ra_ftpm}
IP=${1:-10.0.2.2}
PORT=${2:-5000}

if ! command -v "$CA" >/dev/null 2>&1; then
    echo "CA '$CA' not found (set CA=/path/to/optee_example_ra_ftpm)" >&2
    exit 1
fi

# Make sure this run is a normal attestation session, not an accidentally
# inherited enrollment or benchmark run.
unset ENROLL BENCH_OUT BENCH_REQUESTS

echo "starting CA for replay test; connecting to verifier at $IP:$PORT"
exec "$CA" "$IP" "$PORT"
