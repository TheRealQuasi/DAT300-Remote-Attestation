#!/bin/sh
# ftpm-dos-sweep-verifier.sh - PC side of the DoS sweep. Runs on the PC.
#
# Steps through the SAME load levels as the guest's ftpm-dos-sweep.sh, running
# one verifier round per level. Each round:
#   - waits for the CA to connect (so it stays in lockstep with the guest),
#   - sends 1 enroll + <requests> attests,
#   - writes ~/optee/dos/results/verifier_load<level>.csv,
#   - exits when done, and the loop moves to the next level.
#
# Start THIS first, then start ftpm-dos-sweep.sh in the guest. Levels and
# request count must match the guest's.
#
# usage: ./ftpm-dos-sweep-verifier.sh [requests]
#   requests : attests per level (default 20; passed as the verifier --count)
#   levels    : edit LEVELS below (default 0 1 2 4 8 16 32)

# ---- environment toggles (lowercase true/false) --------------------------
USE_SSH=${USE_SSH:-false}

RPI4=${RPI4:-rpi4-optee}
RPI4_PATH=${RPI4_PATH:-$HOME/shared/DAT300-Remote-Attestation/RPi4}
RESULTS_PATH=${RESULTS_PATH:-$RPI4_PATH/results}

# /dev/tpmrm0 is the default for the RPi4's TPM
# /dev/tpmrm1 is the default for the RPi4's fTPM
DEVICE_NAME=${DEVICE_NAME:-ftpm}
RESULTS_PATH="$RESULTS_PATH/$DEVICE_NAME"

CSV_PATH=${CSV_PATH:-$RESULTS_PATH/dos-data}

# ---- program defaults ----------------------------------------------------
if [ "$DEVICE_NAME" = "tpm" ]; then
    VERIFIER=${VERIFIER:-$HOME/shared/DAT300-Remote-Attestation/TPM/ra-tpm/verifier.py}
else
    VERIFIER=${VERIFIER:-$HOME/shared/DAT300-Remote-Attestation/FTPM/ra-ftpm/verifier.py}
fi
ANALYZER=${ANALYZER:-$HOME/shared/DAT300-Remote-Attestation/Verifiers/analyzers/dos-analyzer.py}
PROTECTED=${PROTECTED:-/root/protected.txt}


TIMEOUT=${TIMEOUT:-20}
LEVELS=${LEVELS:-"0 2 4 8 16 32"}   # load levels to sweep through

RUNS=${1:-1}
REQ=${2:-10}

# The sweep - one verifier round per level.
for LEVEL in $LEVELS; do
    echo "============================================================"
    echo "LEVEL $LEVEL  (waiting for the attester to connect...)"
    echo "============================================================"
    # DoS policy: --dos logs verdicts and implies auto-send. --no-auto-enroll
    # because enrollment is done ONCE up front, so only attests flow here
    # (count = REQ, no enroll row). Short timeout so a starved request = denied.
    if [ "$DEVICE_NAME" = "tpm" ]; then
        python3 "$VERIFIER" --dos --dos-csv "$CSV_PATH"/verifier_load{$LEVEL}.csv \
            --requests "$REQ" --runs "$RUNS" --timeout "$TIMEOUT" --load-level "$LEVEL"
    else
        python3 "$VERIFIER" --file "$PROTECTED" --dos --dos-csv "$CSV_PATH"/verifier_load{$LEVEL}.csv \
            --requests "$REQ" --runs "$RUNS" --timeout "$TIMEOUT" --load-level "$LEVEL"
    fi
done

# ---- collect + analyse ---------------------------------------------------
if [ "$USE_SSH" = "true" ]; then
    # Results are on the Pi: pull them over scp, then analyse those.
    mkdir -p "$RESULTS_PATH"
    mkdir -p "$CSV_PATH"
    scp "$RPI4":~/results/ca_load*.csv "$CSV_PATH"

    echo "Analyzing results..."
    python3 "$ANALYZER" "$CSV_PATH"/*.csv \
        --out "$RESULTS_PATH"/$DEVICE_NAME-dos-summary.txt --plot "$RESULTS_PATH"/$DEVICE_NAME-dos-summary.png \
        --device "$DEVICE_NAME"
    echo "done -> $CSV_PATH"
else
    # Results are already local (default results dir): let the analyzer find them.
    echo "Analyzing results..."
    python3 "$ANALYZER"
    echo "done -> FTPM/results"
fi