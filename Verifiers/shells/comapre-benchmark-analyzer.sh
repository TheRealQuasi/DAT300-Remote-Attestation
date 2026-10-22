#!/bin/bash
# compare-benchmark-analyzer.sh - run the compare benchmark analyzer. Run this after
# the attention benchmarks has finished. It collects the results and produces a compare summary.
# NOTE: The results need to already be local (default results dir).
#
# Used on own machine (PC)
# 
# usage: LABEL=<label> ./compare-benchmark-analyzer.sh

# ------------------------- Change these parameters to change the benchmark -------------------------

LABEL=${LABEL:-compare}

# ------------------------- Don't change these parameters unless you know what you're doing -------------------------

USE_SSH=${USE_SSH:-true}

RPI4=${RPI4:-rpi4-optee}
RPI4_PATH=${RPI4_PATH:-$HOME/shared/DAT300-Remote-Attestation/RPi4}
RESULTS_PATH=${RESULTS_PATH:-$RPI4_PATH/results}

IDLE_CSV_PATH=${IDLE_CSV_PATH:-$RESULTS_PATH/idle/idle-data}
FTPM_CSV_PATH=${FTPM_CSV_PATH:-$RESULTS_PATH/ftpm/benchmark-data}
TPM_CSV_PATH=${TPM_CSV_PATH:-$RESULTS_PATH/tpm/benchmark-data}
TPM_FILE_CSV_PATH=${TPM_FILE_CSV_PATH:-$RESULTS_PATH/tpm-file/benchmark-data}

RESULTS_PATH="$RESULTS_PATH/$LABEL"

ANALYZER=${ANALYZER:-$HOME/shared/DAT300-Remote-Attestation/Verifiers/analyzers/compare-benchmark-analyzer.py}

# ------------------------- Run the benchmark analyzer -------------------------------

# Make sure the results directories exist
mkdir -p "$RESULTS_PATH"
mkdir -p "$IDLE_CSV_PATH"
mkdir -p "$FTPM_CSV_PATH"
mkdir -p "$TPM_CSV_PATH"
mkdir -p "$TPM_FILE_CSV_PATH"

if [ "$USE_SSH" = "true" ]; then
    echo "Analyzing results..."
    python3 "$ANALYZER" \
    --idle     $IDLE_CSV_PATH \
    --ftpm     $FTPM_CSV_PATH \
    --tpm      $TPM_CSV_PATH \
    --tpm-file $TPM_FILE_CSV_PATH \
    --out  $RESULTS_PATH/compare-benchmark-summary.txt \
    --plot $RESULTS_PATH/compare-benchmark-summary.png
else
    # Results are already local (default results dir): let the analyzer find them.
    echo "Analyzing results..."
    python3 "$ANALYZER"
fi
