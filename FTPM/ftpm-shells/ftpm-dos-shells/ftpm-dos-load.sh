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
# Which TPM command the workers hammer is chosen by LOAD:
#   LOAD=pcrread  (default) light, read-only  -> tpm2_pcrread sha256:0
#   LOAD=quote               heavy, signing   -> tpm2_quote -c <ak.ctx> ...
#                            run ftpm-dos-prep-quote.sh ONCE first to make the key
# You can still override TOOL / ARGS directly to use any other command.
#
# Stop it with Ctrl-C (interactive), or from elsewhere:
#   pkill -f tpm2_pcrread   (or tpm2_quote)
#
# NOTE: no 'set -e' / 'pipefail' on purpose - a worker must shrug off an
# occasional "TPM busy" error and keep going, not abort the whole load.

CONC=${1:-1}
TCTI=${TCTI:-device:/dev/tpmrm0}
LOAD=${LOAD:-pcrread}
AK_CTX=${AK_CTX:-/tmp/ak.ctx}       # key made by ftpm-dos-prep-quote.sh

# Pick the tool + args from LOAD, unless TOOL/ARGS are set explicitly.
if [ "$LOAD" = "quote" ]; then
    TOOL=${TOOL:-tpm2_quote}
    ARGS=${ARGS:--c $AK_CTX -l sha256:0 -q abcd}
    if [ ! -f "$AK_CTX" ]; then
        echo "quote load needs $AK_CTX - run ftpm-dos-prep.sh first"
        exit 1
    fi
else
    TOOL=${TOOL:-tpm2_pcrread}
    ARGS=${ARGS:-sha256:0}
fi

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
    # Kill the worker loop subshells, then the tool they spawn.
    kill $PIDS 2>/dev/null
    pkill -9 -P $$ 2>/dev/null       # any children of this script
    pkill -9 -f "$TOOL" 2>/dev/null  # the in-flight tool, as a backstop
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