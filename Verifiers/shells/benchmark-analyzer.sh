#!/bin/bash
# benchmark-analyzer.sh - run the benchmark analyzer. Run this after
# the attention benchmark has finished. It collects the results and produces a summary.
# NOTE: If the results are not already local (default results dir), 
# set GET_RESULTS=true to pull them over scp from the RPi4.
#
# Used on own machine (PC)
# 
# usage: LABEL=<label> ./benchmark-analyzer.sh

# ------------------------- Change these parameters to change the benchmark -------------------------

LABEL=${LABEL:-ftpm}
GET_RESULTS=${GET_RESULTS:-false}

# ------------------------- Don't change these parameters unless you know what you're doing -------------------------

USE_SSH=${USE_SSH:-true}

RPI4=${RPI4:-rpi4-optee}
RPI4_PATH=${RPI4_PATH:-$HOME/shared/DAT300-Remote-Attestation/RPi4}
RESULTS_PATH=${RESULTS_PATH:-$RPI4_PATH/results}

RESULTS_PATH="$RESULTS_PATH/$LABEL"

CSV_PATH=${CSV_PATH:-$RESULTS_PATH/benchmark-data}

ANALYZER=${ANALYZER:-$HOME/shared/DAT300-Remote-Attestation/Verifiers/analyzers/benchmark-analyzer.py}

# ------------------------- Run the benchmark analyzer -------------------------------

# Make sure the results directories exist
mkdir -p "$RESULTS_PATH"
mkdir -p "$CSV_PATH"

if [ "$USE_SSH" = "true" ]; then
    if [ "$GET_RESULTS" = "true" ]; then
        rm -f "$CSV_PATH"/run*.csv         # <-- clear stale runs from previous benchmarks

        # Results are on the Pi: pull them over scp, then analyse those.
        scp "$RPI4":~/results/run*.csv "$CSV_PATH"/
    fi

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

# ------------------------- End of script --------------------------------
