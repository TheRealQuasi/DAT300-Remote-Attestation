#!/bin/sh
# enroll-verifier.sh - enroll the device ONCE. Run this after each boot,
# before any other run. Sends exactly one request (which enrolls),
# then exits.
#
# Used on own machine (PC)
#
# Pair with attester: "RPi4/ftpm-enroll-ssh.sh" or "RPi4/tpm-enroll-ssh.sh"
#
# usage: DEVICE=<device-name> ./enroll-verifier.sh

# ------------------------- Don't change these parameters unless you know what you're doing -------------------------

DEVICE_NAME=${DEVICE_NAME:-ftpm}
LABEL=${LABEL:-$DEVICE_NAME}

if [ "$DEVICE_NAME" = "tpm" ]; then
    VERIFIER=${VERIFIER:-$HOME/shared/DAT300-Remote-Attestation/TPM/ra-tpm/verifier.py}
else
    VERIFIER=${VERIFIER:-$HOME/shared/DAT300-Remote-Attestation/FTPM/ra-ftpm/verifier.py}
fi

# ------------------------- Run the enrollment ------------------------------------------------------------

echo "enrolling the $LABEL (one round, waiting for the attester)..."
exec python3 "$VERIFIER" --enroll --timeout 120

# ------------------------- End of script ------------------------------------------------------------