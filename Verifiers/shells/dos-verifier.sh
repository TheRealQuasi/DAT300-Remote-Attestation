#!/bin/sh
# dos-verifier.sh - run the DoS verifier, sweeping through load levels. It exits by itself after 
# <LEVELS> levels, each with <REQ> requests. Each level produces a CSV file with the results.
#
# Used on own machine (PC)
#
# Pair with attester: "Verifiers/shells/ftpm-dos-ssh.sh" or "Verifiers/shells/tpm-dos-ssh.sh"
#
# usage: DEVICE=<device-name> LEVELS="<load-levels>" ./dos-verifier.sh <requests>

# ------------------------- Change these parameters to change the benchmark -------------------------

LEVELS=${LEVELS:-"0 2 4 8 16 32"}
REQ=${1:-10}
TIMEOUT=${TIMEOUT:-20}

# ------------------------- Don't change these parameters unless you know what you're doing -------------------------

RUNS=${RUNS:-1}
USE_SSH=${USE_SSH:-true}

# /dev/tpmrm0 is the default for the RPi4's TPM
# /dev/tpmrm1 is the default for the RPi4's fTPM
DEVICE_NAME=${DEVICE_NAME:-ftpm}
LABEL=${LABEL:-$DEVICE_NAME}

RPI4=${RPI4:-rpi4-optee}
RPI4_PATH=${RPI4_PATH:-$HOME/shared/DAT300-Remote-Attestation/RPi4}
RESULTS_PATH=${RESULTS_PATH:-$RPI4_PATH/results}

RESULTS_PATH="$RESULTS_PATH/$LABEL"

CSV_PATH=${CSV_PATH:-$RESULTS_PATH/dos-data}

if [ "$DEVICE_NAME" = "tpm" ]; then
    VERIFIER=${VERIFIER:-$HOME/shared/DAT300-Remote-Attestation/TPM/ra-tpm/verifier.py}
else
    VERIFIER=${VERIFIER:-$HOME/shared/DAT300-Remote-Attestation/FTPM/ra-ftpm/verifier.py}
fi
ANALYZER=${ANALYZER:-$HOME/shared/DAT300-Remote-Attestation/Verifiers/analyzers/dos-analyzer.py}
PROTECTED=${PROTECTED:-/root/protected.txt}

# ------------------------- Run the DoS verifier  -----------------------------------------------

# Clean up any stale results from previous runs
mkdir -p "$RESULTS_PATH"
mkdir -p "$CSV_PATH"
rm -f "$CSV_PATH"/ca_load*.csv         # <-- clear stale runs from previous DoS sweeps
rm -f "$CSV_PATH"/verifier_load*.csv   # <-- clear stale runs from previous DoS sweeps

# --- run the verifier (DoS mode, unlimited; Ctrl-C when done) -------

# The sweep - one verifier round per level.
for LEVEL in $LEVELS; do
    echo "============================================================"
    echo "$LABEL: LEVEL $LEVEL  (waiting for the attester to connect...)"
    echo "============================================================"
    # DoS policy: --dos logs verdicts and implies auto-send. --no-auto-enroll
    # because enrollment is done ONCE up front, so only attests flow here
    # (count = REQ, no enroll row). Short timeout so a starved request = denied.
    if [ "$DEVICE_NAME" = "tpm" ]; then
        python3 "$VERIFIER" --dos --dos-csv "$CSV_PATH"/verifier_load$LEVEL.csv \
            --requests "$REQ" --runs "$RUNS" --timeout "$TIMEOUT" --load-level "$LEVEL"
    else
        python3 "$VERIFIER" --file "$PROTECTED" --dos --dos-csv "$CSV_PATH"/verifier_load$LEVEL.csv \
            --requests "$REQ" --runs "$RUNS" --timeout "$TIMEOUT" --load-level "$LEVEL"
    fi
done

# ---- collect + analyse ---------------------------------------------------
if [ "$USE_SSH" = "true" ]; then
    # Results are on the Pi: pull them over scp, then analyse those.
    scp "$RPI4":~/results/ca_load*.csv "$CSV_PATH"

    echo "Analyzing results..."
    python3 "$ANALYZER" "$CSV_PATH"/*.csv \
        --out "$RESULTS_PATH"/$LABEL-dos-summary.txt --plot "$RESULTS_PATH"/$LABEL-dos-summary.png \
        --device "$LABEL"
    echo "done -> $CSV_PATH"
else
    # Results are already local (default results dir): let the analyzer find them.
    echo "Analyzing results..."
    python3 "$ANALYZER"
    echo "done -> FTPM/results"
fi

# ------------------------- End of script ------------------------------------------------------------
