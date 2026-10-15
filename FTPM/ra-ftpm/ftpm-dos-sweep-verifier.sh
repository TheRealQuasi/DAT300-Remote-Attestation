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

REQ=${1:-20}
LEVELS="0"

# Path to verifier.py and the protected file - adjust if yours differ.
VERIFIER=${VERIFIER:-FTPM/ra-ftpm/verifier.py}
PROTECTED=${PROTECTED:-/root/protected.txt}

for LEVEL in $LEVELS; do
    echo "============================================================"
    echo "LEVEL $LEVEL  (waiting for the attester to connect...)"
    echo "============================================================"
    python3 "$VERIFIER" --file "$PROTECTED" --dos \
        --count "$REQ" --load-level "$LEVEL"
done

echo "sweep done. Analyse: python3 FTPM/ftpm-analyzers/ftpm-dos-analyzer.py"s