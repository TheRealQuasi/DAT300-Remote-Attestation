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
USE_RPI4=${USE_RPI4:-false}
RPI4=${RPI4:-rpi4-optee}
RPI4_PATH=${RPI4_PATH:-$HOME/shared/DAT300-Remote-Attestation/RPi4}
CSV_PATH=${CSV_PATH:-$RPI4_PATH/results}

# ---- program defaults ----------------------------------------------------
ANALYZER=${ANALYZER:-FTPM/ftpm-analyzers/ftpm-benchmark-analyzer.py}
VERIFIER=${VERIFIER:-FTPM/ra-ftpm/verifier.py}
PROTECTED=${PROTECTED:-/root/protected.txt}
TIMEOUT=${TIMEOUT:-120}

RUNS=${RUNS:-10}     # runs (passed to the verifier)
REQ=${REQ:-20}       # requests per run (passed to the verifier)

# ---- run the verifier (benchmark mode, unlimited; Ctrl-C when done) -------
echo "benchmark verifier: waiting for the attester (Ctrl-C to stop)"
python3 "$VERIFIER" --file "$PROTECTED" --benchmark \
    --requests "$REQ" --runs "$RUNS" --timeout "$TIMEOUT" "$@"

# ---- collect + analyse ---------------------------------------------------
if [ "$USE_SSH" = "true" ]; then
    # Results are on the Pi: pull them over scp, then analyse those.
    mkdir -p "$CSV_PATH"
    mkdir -p "$CSV_PATH"/data
    scp "$RPI4":~/results/* "$CSV_PATH"/data/

    echo "Analyzing results..."
    python3 "$ANALYZER" "$CSV_PATH"/data/run*.csv --out "$CSV_PATH"/benchmark-summary.txt --plot "$CSV_PATH"/benchmark-summary.png
    echo "done -> $CSV_PATH"
elif [ "$USE_RPI4" = "true" ]; then
    # TBA: For when actually using TCP.
    echo "TBA: Collecting results from RPi4 over TCP (not yet implemented)"
else
    # Results are already local (default results dir): let the analyzer find them.
    echo "Analyzing results..."
    python3 "$ANALYZER"
    echo "done -> FTPM/results"
fi
