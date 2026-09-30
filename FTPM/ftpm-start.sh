#!/bin/bash
# start-optee.sh - run from ~/optee/build/
set -e
cd "$(dirname "$0")"

FLAGS="MEASURED_BOOT_FTPM=y BR2_PACKAGE_TPM2_TSS=y QEMU_VIRTFS_ENABLE=y"

tmux kill-session -t optee 2>/dev/null || true
tmux new-session -d -s optee './soc_term.py 54320'                       # Linux console
tmux split-window -h -t optee './soc_term.py 54321'                      # OP-TEE console
tmux split-window -v -t optee "(sleep 3 && echo c) | make $FLAGS run-only" # QEMU
tmux select-layout -t optee tiled
tmux attach -t optee
