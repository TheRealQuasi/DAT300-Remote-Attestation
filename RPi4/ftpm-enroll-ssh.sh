#!/bin/sh
# ftpm-enroll-ssh.sh - enroll the device ONCE. Run this after each reboot,
# before any other run. Sends exactly one request (which enrolls),
# then exits.
#
# Used on RPi4
#  
# Pair with verifier: "Verifiers/shells/enroll-verifier.sh"
#
# usage: ./ftpm-enroll.sh

# ------------------------- Don't change these parameters unless you know what you're doing -------------------------
ENROLL=${ENROLL:-True}
CA=${CA:-./ra-ca-ftpm}
IP=${IP:-127.0.0.1}
PORT=${PORT:-5000}

# /dev/tpmrm0 is the default for the RPi4's TPM
# /dev/tpmrm1 is the default for the RPi4's fTPM
DEVICE_NAME=${3:-ftpm}
DEVICE=${3:-/dev/tpmrm1}

# ------------------------- Run the enrollment ------------------------------------------------------------

echo "enrolling the $DEVICE_NAME device (one round, waiting for the attester)..."
ENROLL=$ENROLL "$CA" "$IP" "$PORT" "$DEVICE" > /dev/null
echo "enroll done!"

# ------------------------- End of script ------------------------------------------------------------
