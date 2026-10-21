#!/bin/sh
# benchmark-verifier.sh - run the benchmark verifier. It exits by itself 
# after <RUNS> runs, each with <REQ> requests. Each run produces a CSV file with the results.
#
# Used on own machine (PC)
#
# Pair with attester: "RPi4/ftpm-benchmark-ssh.sh" or "RPi4/tpm-benchmark-ssh.sh"
#
# usage: DEVICE=<device-name> ./benchmark-verifier.sh <runs> <requests-per-run>

# ------------------------- Change these parameters to change the benchmark -------------------------

RUNS=${1:-10}
REQ=${2:-20}

# ------------------------- Don't change these parameters unless you know what you're doing -------------------------

USE_SSH=${USE_SSH:-true}

# /dev/tpmrm0 is the default for the RPi4's TPM
# /dev/tpmrm1 is the default for the RPi4's fTPM
DEVICE_NAME=${DEVICE_NAME:-ftpm}
LABEL=${LABEL:-$DEVICE_NAME}

RPI4=${RPI4:-rpi4-optee}
RPI4_PATH=${RPI4_PATH:-$HOME/shared/DAT300-Remote-Attestation/RPi4}
RESULTS_PATH=${RESULTS_PATH:-$RPI4_PATH/results}

RESULTS_PATH="$RESULTS_PATH/$LABEL"

CSV_PATH=${CSV_PATH:-$RESULTS_PATH/benchmark-data}

if [ "$DEVICE_NAME" = "tpm" ]; then
    VERIFIER=${VERIFIER:-$HOME/shared/DAT300-Remote-Attestation/TPM/ra-tpm/verifier.py}
else
    VERIFIER=${VERIFIER:-$HOME/shared/DAT300-Remote-Attestation/FTPM/ra-ftpm/verifier.py}
fi
ANALYZER=${ANALYZER:-$HOME/shared/DAT300-Remote-Attestation/Verifiers/analyzers/benchmark-analyzer.py}
PROTECTED=${PROTECTED:-/root/protected.txt}
TIMEOUT=${TIMEOUT:-120}

# ------------------------- Run the benchmark verifier -------------------------------

# Clean up any stale results from previous runs
mkdir -p "$RESULTS_PATH"
mkdir -p "$CSV_PATH"
rm -f "$CSV_PATH"/run*.csv          # <-- clear stale runs from previous benchmarks

# ---- run the verifier (benchmark mode, unlimited; Ctrl-C when done) -------
if [ "$DEVICE_NAME" = "tpm" ]; then
    echo "benchmark verifier: waiting for the $LABEL attester (Ctrl-C to stop)"
    python3 "$VERIFIER" --benchmark \
    --requests "$REQ" --runs "$RUNS" --timeout "$TIMEOUT" "$@"
else
    echo "benchmark verifier: waiting for the $LABEL attester (Ctrl-C to stop)"
    python3 "$VERIFIER" --file "$PROTECTED" --benchmark \
        --requests "$REQ" --runs "$RUNS" --timeout "$TIMEOUT" "$@"
fi

# ---- collect + analyse ---------------------------------------------------
if [ "$USE_SSH" = "true" ]; then
    # Results are on the Pi: pull them over scp, then analyse those.
    scp "$RPI4":~/results/run*.csv "$CSV_PATH"/

    echo "Analyzing results..."
    python3 "$ANALYZER" "$CSV_PATH"/run*.csv \
        --out "$RESULTS_PATH"/$LABEL-benchmark-summary.txt --plot "$RESULTS_PATH"/$LABEL-benchmark-summary.png \
        --device "$LABEL"
    echo "done -> $CSV_PATH"
else
    # Results are already local (default results dir): let the analyzer find them.
    echo "Analyzing results..."
    python3 "$ANALYZER"
    echo "done -> FTPM/results"
fi

# ------------------------- End of script ------------------------------------------------------------
