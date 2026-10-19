#!/bin/sh
# ftpm-enroll.sh - enroll the device ONCE. Run this after each QEMU boot,
# before any benchmark or DoS run. Sends exactly one request (which enrolls),
# then exits.
#
# usage: ./ftpm-enroll.sh

CA=${CA:-optee_example_ra_ftpm}   # optee_examples installs the CA into /usr/bin
ENROLL=${ENROLL:-True}

IP=${1:-10.0.2.2}
PORT=${2:-5000}

echo "enrolling the device (one round, waiting for the attester)..."
ENROLL=$ENROLL "$CA" "$IP" "$PORT" > /dev/null
echo "enroll done!"