#!/bin/sh
# ftpm-replay-verifier.sh - PC side of the replay test.
# Runs one automatic replay test and then exits.
# Start this first; it waits for the guest attester to connect.
#
# usage: ./ftpm-replay-verifier.sh
# overrides:
#   VERIFIER  path to verifier.py (default FTPM/ra-ftpm/verifier.py)
#   PROTECTED file path sent to the attester (default /root/protected.txt)
#   PORT      verifier listen port (default 5000)
#   TIMEOUT   timeout per attestation response in seconds (default 120)

set -eu

VERIFIER=${VERIFIER:-FTPM/ra-ftpm/verifier.py}
PROTECTED=${PROTECTED:-/root/protected.txt}
PORT=${PORT:-5000}
TIMEOUT=${TIMEOUT:-120}

if [ ! -f "$VERIFIER" ]; then
    echo "verifier.py not found: $VERIFIER (set VERIFIER=/path/to/verifier.py)" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 not found" >&2
    exit 1
fi

echo "replay verifier: waiting for the attester on port $PORT"
echo "the device must already be enrolled; this script does not enroll it"
exec python3 "$VERIFIER" --file "$PROTECTED" --port "$PORT" \
    --test-replay --timeout "$TIMEOUT"
