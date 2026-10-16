#!/bin/sh
# ftpm-enroll-verifier.sh - enroll the device ONCE. Run this after each QEMU boot,
# before any benchmark or DoS run. Sends exactly one request (which enrolls),
# then exits.
#
# usage: ./ftpm-enroll-verifier.sh

VERIFIER=${VERIFIER:-FTPM/ra-ftpm/verifier.py}
PROTECTED=${PROTECTED:-/root/protected.txt}

echo "enrolling the device (one round, waiting for the attester)..."
exec python3 "$VERIFIER" --file "$PROTECTED" --enroll --timeout 120
