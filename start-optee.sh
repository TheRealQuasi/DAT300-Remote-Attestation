#!/bin/bash
# start-optee.sh - run from ~/optee/build/
set -e
cd "$(dirname "$0")"

FLAGS="CFG_ATTESTATION_PTA=y CFG_ATTESTATION_PTA_KEY_SIZE=2048 QEMU_VIRTFS_AUTOMOUNT=y"

tmux kill-session -t optee 2>/dev/null || true
tmux new-session -d -s optee './soc_term.py 54320'                       # Linux console
tmux set -g mouse on
tmux split-window -h -t optee './soc_term.py 54321'                      # OP-TEE console
tmux split-window -v -t optee "(sleep 2 && echo c) | make $FLAGS run-only" # QEMU
tmux select-layout -t optee tiled
tmux attach -t optee
