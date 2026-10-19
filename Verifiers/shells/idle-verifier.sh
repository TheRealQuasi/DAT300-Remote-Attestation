#!/bin/sh


# ---- environment toggles (lowercase true/false) --------------------------
USE_SSH=${USE_SSH:-false}

RPI4=${RPI4:-rpi4-optee}
RPI4_PATH=${RPI4_PATH:-$HOME/shared/DAT300-Remote-Attestation/RPi4}
RESULTS_PATH=${RESULTS_PATH:-$RPI4_PATH/results}

DEVICE_NAME=${DEVICE_NAME:-idle}
RESULTS_PATH="$RESULTS_PATH/$DEVICE_NAME"

CSV_PATH=${CSV_PATH:-$RESULTS_PATH/$DEVICE_NAME-data}

# ---- program defaults ----------------------------------------------------
ANALYZER=${ANALYZER:-$HOME/shared/DAT300-Remote-Attestation/Verifiers/analyzers/benchmark-analyzer.py}

# ---- collect + analyse ---------------------------------------------------
if [ "$USE_SSH" = "true" ]; then
    # Results are on the Pi: pull them over scp, then analyse those.
    mkdir -p "$RESULTS_PATH"
    mkdir -p "$CSV_PATH"
    scp "$RPI4":~/results/$DEVICE_NAME*.csv "$CSV_PATH"/

    echo "Analyzing results..."
    python3 "$ANALYZER" "$CSV_PATH"/$DEVICE_NAME*.csv \
        --out "$RESULTS_PATH"/$DEVICE_NAME-benchmark-summary.txt --plot "$RESULTS_PATH"/$DEVICE_NAME-benchmark-summary.png \
        --device "$DEVICE_NAME"
    echo "done -> $CSV_PATH"
else
    # Results are already local (default results dir): let the analyzer find them.
    echo "Analyzing results..."
    python3 "$ANALYZER"
    echo "done -> $RESULTS_PATH"
fi
