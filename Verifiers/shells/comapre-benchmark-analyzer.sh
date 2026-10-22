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

LABEL=${LABEL:-compare}
GET_RESULTS=${GET_RESULTS:-false}

# ------------------------- Don't change these parameters unless you know what you're doing -------------------------

USE_SSH=${USE_SSH:-true}

RPI4=${RPI4:-rpi4-optee}
RPI4_PATH=${RPI4_PATH:-$HOME/shared/DAT300-Remote-Attestation/RPi4}
RESULTS_PATH=${RESULTS_PATH:-$RPI4_PATH/results}

RESULTS_PATH="$RESULTS_PATH/$LABEL"

IDLE_CSV_PATH=${IDLE_CSV_PATH:-$RESULTS_PATH/idle}
FTPM_CSV_PATH=${FTPM_CSV_PATH:-$RESULTS_PATH/ftpm}
TPM_CSV_PATH=${TPM_CSV_PATH:-$RESULTS_PATH/tpm}
TPM_FILE_CSV_PATH=${TPM_FILE_CSV_PATH:-$RESULTS_PATH/tpm-file}

ANALYZER=${ANALYZER:-$HOME/shared/DAT300-Remote-Attestation/Verifiers/analyzers/compare-benchmark-analyzer.py}

# ------------------------- Run the benchmark analyzer -------------------------------

# Make sure the results directories exist
mkdir -p "$RESULTS_PATH"
mkdir -p "$IDLE_CSV_PATH"
mkdir -p "$FTPM_CSV_PATH"
mkdir -p "$TPM_CSV_PATH"
mkdir -p "$TPM_FILE_CSV_PATH"

if [ "$USE_SSH" = "true" ]; then
    if [ "$GET_RESULTS" = "true" ]; then
        rm -f "$IDLE_CSV_PATH"/run*.csv         # <-- clear stale runs from previous benchmarks
        rm -f "$FTPM_CSV_PATH"/run*.csv
        rm -f "$TPM_CSV_PATH"/run*.csv
        rm -f "$TPM_FILE_CSV_PATH"/run*.csv

        # Results are on the Pi: pull them over scp, then analyse those.
        scp "$RPI4":~/results/idle/run*.csv "$IDLE_CSV_PATH"/
        scp "$RPI4":~/results/ftpm/run*.csv "$FTPM_CSV_PATH"/
        scp "$RPI4":~/results/tpm/run*.csv "$TPM_CSV_PATH"/
        scp "$RPI4":~/results/tpm-file/run*.csv "$TPM_FILE_CSV_PATH"/
    fi

    echo "Analyzing results..."
    python3 "$ANALYZER" \
    --idle     $IDLE_CSV_PATH \
    --ftpm     $FTPM_CSV_PATH \
    --tpm      $TPM_CSV_PATH \
    --tpm-file $TPM_FILE_CSV_PATH \
    --out  $RESULTS_PATH/$LABEL-summary.txt \
    --plot $RESULTS_PATH/$LABEL-summary.png
else
    # Results are already local (default results dir): let the analyzer find them.
    echo "Analyzing results..."
    python3 "$ANALYZER" \
fi

