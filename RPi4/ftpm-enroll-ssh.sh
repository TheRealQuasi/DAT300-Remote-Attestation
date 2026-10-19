#!/bin/sh
# ftpm-enroll.sh - enroll the device ONCE. Run this after each QEMU boot,
# before any benchmark or DoS run. Sends exactly one request (which enrolls),
# then exits.
#
# usage: ./ftpm-enroll.sh

ENROLL=${ENROLL:-True}
CA=${CA:-./ra-ca-ftpm}   # optee_examples installs the CA into /usr/bin

IP=${1:-127.0.0.1}
PORT=${2:-5000}

# /dev/tpmrm0 is the default for the RPi4's TPM
# /dev/tpmrm1 is the default for the RPi4's fTPM
DEVICE_NAME=${3:-ftpm}
DEVICE=${3:-/dev/tpmrm1}

echo "enrolling the $DEVICE_NAME device (one round, waiting for the attester)..."
ENROLL=$ENROLL "$CA" "$IP" "$PORT" "$DEVICE" > /dev/null
echo "enroll done!"