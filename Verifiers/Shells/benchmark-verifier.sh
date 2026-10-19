#!/bin/sh
# ftpm-benchmark-verifier.sh - PC side launcher for NORMAL benchmarking.
# Runs the verifier in benchmark mode (attests nonstop, no verdict log), waits
# for it to finish (Ctrl-C when the guest/Pi runs are done), then collects and
# analyses the results.
#
# usage: ./ftpm-benchmark-verifier.sh
#   env toggles (default false):
#     USE_SSH=true    pull run*.csv from the Pi over scp before analysing
#   env paths:
#     RPI4            ssh host alias for the Pi (default rpi4-optee)
#     RPI4_PATH       local dir for the Pi's results
#     CSV_PATH        where run CSVs live for the analyzer

# ---- environment toggles (lowercase true/false) --------------------------
USE_SSH=${USE_SSH:-false}

RPI4=${RPI4:-rpi4-optee}
RPI4_PATH=${RPI4_PATH:-$HOME/shared/DAT300-Remote-Attestation/RPi4}
RESULTS_PATH=${RESULTS_PATH:-$RPI4_PATH/results}

# /dev/tpmrm0 is the default for the RPi4's TPM
# /dev/tpmrm1 is the default for the RPi4's fTPM
DEVICE_NAME=${DEVICE_NAME:-ftpm}
RESULTS_PATH="$RESULTS_PATH/$DEVICE_NAME"

CSV_PATH=${CSV_PATH:-$RESULTS_PATH/benchmark-data}

# ---- program defaults ----------------------------------------------------
if [ "$DEVICE_NAME" = "tpm" ]; then
    VERIFIER=${VERIFIER:-$HOME/shared/DAT300-Remote-Attestation/TPM/ra-tpm/verifier.py}
else
    VERIFIER=${VERIFIER:-$HOME/shared/DAT300-Remote-Attestation/FTPM/ra-ftpm/verifier.py}
fi
ANALYZER=${ANALYZER:-$HOME/shared/DAT300-Remote-Attestation/Verifiers/Analyzers/benchmark-analyzer.py}
PROTECTED=${PROTECTED:-/root/protected.txt}
TIMEOUT=${TIMEOUT:-120}

RUNS=${1:-10}     # runs (passed to the verifier)
REQ=${2:-20}       # requests per run (passed to the verifier)

# ---- run the verifier (benchmark mode, unlimited; Ctrl-C when done) -------
echo "benchmark verifier: waiting for the attester (Ctrl-C to stop)"
python3 "$VERIFIER" --file "$PROTECTED" --benchmark \
    --requests "$REQ" --runs "$RUNS" --timeout "$TIMEOUT" "$@"

# ---- collect + analyse ---------------------------------------------------
if [ "$USE_SSH" = "true" ]; then
    # Results are on the Pi: pull them over scp, then analyse those.
    mkdir -p "$RESULTS_PATH"
    mkdir -p "$CSV_PATH"
    scp "$RPI4":~/results/run*.csv "$CSV_PATH"/

    echo "Analyzing results..."
    python3 "$ANALYZER" "$CSV_PATH"/run*.csv \
        --out "$RESULTS_PATH"/$DEVICE_NAME-benchmark-summary.txt --plot "$RESULTS_PATH"/$DEVICE_NAME-benchmark-summary.png \
        --device "$DEVICE_NAME"
    echo "done -> $CSV_PATH"
else
    # Results are already local (default results dir): let the analyzer find them.
    echo "Analyzing results..."
    python3 "$ANALYZER"
    echo "done -> FTPM/results"
fi
