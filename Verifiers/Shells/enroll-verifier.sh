#!/bin/sh
# enroll-verifier.sh - enroll the device ONCE. Run this after each boot,
# before any benchmark or DoS run. Sends exactly one request (which enrolls),
# then exits.
#
# usage: ./enroll-verifier.sh

DEVICE_NAME=${DEVICE_NAME:-ftpm}
if [ "$DEVICE_NAME" = "tpm" ]; then
    VERIFIER=${VERIFIER:-$HOME/shared/DAT300-Remote-Attestation/TPM/ra-tpm/verifier.py}
else
    VERIFIER=${VERIFIER:-$HOME/shared/DAT300-Remote-Attestation/FTPM/ra-ftpm/verifier.py}
fi

echo "enrolling the device (one round, waiting for the attester)..."
exec python3 "$VERIFIER" --enroll --timeout 120