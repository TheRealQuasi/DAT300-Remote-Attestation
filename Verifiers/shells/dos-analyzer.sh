#!/bin/bash
# dos-analyzer.sh - run the DoS analyzer. Run this after
# the DoS benchmark has finished. It collects the results and produces a summary.
# NOTE: If the results are not already local (default results dir), 
# set GET_RESULTS=true to pull them over scp from the RPi4.
#
# Used on own machine (PC)
#
# usage: LABEL=<label> ./dos-analyzer.sh


# ------------------------- Change these parameters to change the benchmark -------------------------

LABEL=${LABEL:-ftpm}
GET_RESULTS=${GET_RESULTS:-false}

# ------------------------- Don't change these parameters unless you know what you're doing -------------------------

USE_SSH=${USE_SSH:-true}

RPI4=${RPI4:-rpi4-optee}
RPI4_PATH=${RPI4_PATH:-$HOME/shared/DAT300-Remote-Attestation/RPi4}
RESULTS_PATH=${RESULTS_PATH:-$RPI4_PATH/results}

RESULTS_PATH="$RESULTS_PATH/$LABEL"

CSV_PATH=${CSV_PATH:-$RESULTS_PATH/dos-data}

ANALYZER=${ANALYZER:-$HOME/shared/DAT300-Remote-Attestation/Verifiers/analyzers/dos-analyzer.py}

# ------------------------- Run the DoS analyzer -------------------------------

# Make sure the results directories exist
mkdir -p "$RESULTS_PATH"
mkdir -p "$CSV_PATH"

if [ "$USE_SSH" = "true" ]; then
    if [ "$GET_RESULTS" = "true" ]; then
        rm -f "$CSV_PATH"/ca_load*.csv         # <-- clear stale runs from previous DoS sweeps

        # Results are on the Pi: pull them over scp, then analyse those.
        scp "$RPI4":~/results/ca_load*.csv "$CSV_PATH"
    fi

    echo "Analyzing results..."
    python3 "$ANALYZER" "$CSV_PATH"/*.csv \
        --out "$RESULTS_PATH"/$LABEL-dos-summary.txt --plot "$RESULTS_PATH"/$LABEL-dos-summary.png \
        --device "$LABEL" --warmup 20
    echo "done -> $CSV_PATH"
else
    # Results are already local (default results dir): let the analyzer find them.
    echo "Analyzing results..."
    python3 "$ANALYZER"
    echo "done -> FTPM/results"
fi

# ------------------------- End of script --------------------------------
