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

ANALYZER=${ANALYZER:-FTPM/ftpm-analyzers/ftpm-dos-analyzer.py}
VERIFIER=${VERIFIER:-FTPM/ra-ftpm/verifier.py}
PROTECTED=${PROTECTED:-/root/protected.txt}
TIMEOUT=${TIMEOUT:-5}
LEVELS=${LEVELS:-"0 2 4"}

RUNS=${1:-1}
REQ=${2:-5}

# The sweep - one verifier round per level.
for LEVEL in $LEVELS; do
    echo "============================================================"
    echo "LEVEL $LEVEL  (waiting for the attester to connect...)"
    echo "============================================================"
    # DoS policy: --dos logs verdicts and implies auto-send. --no-auto-enroll
    # because enrollment is done ONCE up front, so only attests flow here
    # (count = REQ, no enroll row). Short timeout so a starved request = denied.
    python3 "$VERIFIER" --file "$PROTECTED" --dos\
        --requests "$REQ" --runs "$RUNS" --timeout "$TIMEOUT" --load-level "$LEVEL"
done

echo "Analyzing results..."
python3 "$ANALYZER"
echo "done -> "FTPM/results"