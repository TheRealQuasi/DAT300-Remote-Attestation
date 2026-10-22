#!/bin/sh
# idle-verifier.sh - run the idle verifier (not actually a verifier). Run this after
# idle-runner-ssh.sh has finished. It collects the results and produces a summary.
#
# Used on own machine (PC)
#
# Pair with attester: "RPi4/idle-runner-ssh.sh"
#
# usage: DEVICE=<device-name> ./idle-verifier.sh

# ------------------------- Don't change these parameters unless you know what you're doing -------------------------

USE_SSH=${USE_SSH:-true}

DEVICE_NAME=${DEVICE_NAME:-idle}

RPI4=${RPI4:-rpi4-optee}
RPI4_PATH=${RPI4_PATH:-$HOME/shared/DAT300-Remote-Attestation/RPi4}
RESULTS_PATH=${RESULTS_PATH:-$RPI4_PATH/results}

RESULTS_PATH="$RESULTS_PATH/$DEVICE_NAME"

CSV_PATH=${CSV_PATH:-$RESULTS_PATH/$DEVICE_NAME-data}

ANALYZER=${ANALYZER:-$HOME/shared/DAT300-Remote-Attestation/Verifiers/analyzers/benchmark-analyzer.py}

# ------------------------- Run the idle verifier ------------------------------------------------------------

# Clean up any stale results from previous runs
mkdir -p "$RESULTS_PATH"
mkdir -p "$CSV_PATH"
rm -f "$CSV_PATH"/$DEVICE_NAME*.csv         # <-- clear stale runs from previous benchmarks

# ---- collect + analyse ---------------------------------------------------
if [ "$USE_SSH" = "true" ]; then
    # Results are on the Pi: pull them over scp, then analyse those.
    scp "$RPI4":~/results/$DEVICE_NAME*.csv "$CSV_PATH"/

    echo "Analyzing results..."
    python3 "$ANALYZER" "$CSV_PATH"/$DEVICE_NAME*.csv \
        --out "$RESULTS_PATH"/$DEVICE_NAME-benchmark-summary.txt --plot "$RESULTS_PATH"/$DEVICE_NAME-benchmark-summary.png \
        --device "$DEVICE_NAME" --warmup 20
    echo "done -> $CSV_PATH"
else
    # Results are already local (default results dir): let the analyzer find them.
    echo "Analyzing results..."
    python3 "$ANALYZER"
    echo "done -> FTPM/results"
fi

# ------------------------- End of script --------------------------------