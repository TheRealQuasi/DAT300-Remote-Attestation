#!/bin/sh
# ftpm-dos-load.sh - contending fTPM load generator. Runs ON the attester
# device (inside the QEMU guest), NOT on the verifier.
#
# Starts N background workers, each calling a stock tpm2-tools command in a
# tight loop against /dev/tpmrm0 - the same resource-manager queue the CA's
# attestation uses. N concurrent workers = "load level N". This is ordinary
# TPM usage simply competing for the serialized command queue; there is no
# network flood involved.
#
# usage: ./ftpm-dos-load.sh [N]
#   N: number of concurrent workers (default 1)
#
# Stop it with Ctrl-C (interactive), or from elsewhere:
#   pkill -f tpm2_pcrread
#
# NOTE: no 'set -e' / 'pipefail' on purpose - a worker must shrug off an
# occasional "TPM busy" error and keep going, not abort the whole load.

CONC=${1:-1}
TOOL=${TOOL:-tpm2_pcrread}
TCTI=${TCTI:-device:/dev/tpmrm0}
ARGS=${ARGS:-sha256:0}

if ! command -v "$TOOL" >/dev/null 2>&1; then
    echo "$TOOL not found on this device (is tpm2-tools installed?)"
    exit 1
fi

# One worker: run the command, discard output, immediately repeat, forever.
worker() {
    while true; do
        "$TOOL" -T "$TCTI" $ARGS >/dev/null 2>&1
    done
}

# Stop all workers when this script is interrupted or killed.
cleanup() {
    echo
    echo "stopping $CONC worker(s)..."
    kill $PIDS 2>/dev/null
    wait 2>/dev/null
    exit 0
}
trap cleanup INT TERM

echo "starting $CONC contending TPM worker(s): $TOOL -T $TCTI $ARGS"
PIDS=""
w=1
while [ "$w" -le "$CONC" ]; do
    worker &
    PIDS="$PIDS $!"
    w=$((w + 1))
done

echo "running. Ctrl-C to stop (or: pkill -f $TOOL)"
wait