#!/bin/sh
# ftpm-dos-sweep.sh - GUEST side of the DoS sweep. Runs INSIDE the QEMU guest.
#
# Steps through a list of load levels. For each level it runs ftpm-dos.sh,
# which starts that level's contending TPM workers, runs the CA for one
# measured round (writing ca_load<level>.csv), then stops the workers.
#
# Pair it with ftpm-dos-sweep-verifier.sh on the PC, started FIRST, with the
# SAME levels and request count. The two stay in lockstep because the verifier
# waits for the CA to connect at each level.
#
# usage: ./ftpm-dos-sweep.sh [requests] [verifier-ip] [port]
#   requests : attests per level (default 20; must match the verifier's --count)
#   levels    : edit LEVELS below (default 0 1 2 4 8 16 32)

DIR=$(cd "$(dirname "$0")" && pwd)
REQ=${1:-20}
IP=${2:-10.0.2.2}
PORT=${3:-5000}
LEVELS="0 1 2 4 8 16 32"

for LEVEL in $LEVELS; do
    echo "============================================================"
    echo "LEVEL $LEVEL  ($REQ attests)"
    echo "============================================================"
    "$DIR/ftpm-dos.sh" "$LEVEL" "$REQ" "$IP" "$PORT"
    sleep 2        # let the TPM settle and the verifier re-arm before next level
done

echo "sweep done. Results in $DIR/results/ca_load*.csv"