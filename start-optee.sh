#!/bin/bash
# start-optee.sh - boot QEMU + both UART consoles in one tmux session,
# with the flags this project's features actually need already applied.
#
# Place this in ~/optee/build/ and run it from there.
#
# What it does:
#   - Skips the manual "type 'c' in the QEMU monitor" step
#   - Spawns both soc_term.py consoles automatically (no xterm/X11 needed,
#     works headless over SSH/WSL)
#   - Passes CFG_ATTESTATION_PTA / QEMU_VIRTFS_ENABLE so ra_demo's
#     `pubkey`/`attest` commands and the /mnt/host share both work
#     without you having to remember the flags every single boot
#
# Usage:
#   ./start-optee.sh
#   Ctrl-b then arrow keys (or Ctrl-b o) to move between the 3 panes
#   Ctrl-b d to detach without killing the session
#   tmux attach -t optee    to come back later

set -e
cd "$(dirname "$0")"

SESSION=optee

# These three flags must travel together on every run - dropping any one
# silently disables that feature on the next boot (see README's
# Troubleshooting section for what happens if you forget one).
RUN_FLAGS="CFG_ATTESTATION_PTA=y CFG_ATTESTATION_PTA_KEY_SIZE=2048 QEMU_VIRTFS_ENABLE=y"

tmux kill-session -t "$SESSION" 2>/dev/null || true

# Pane 0: Normal World console
tmux new-session -d -s "$SESSION" -n main './soc_term.py 54320'

# Pane 1: Secure World console
tmux split-window -h -t "$SESSION" './soc_term.py 54321'

# Pane 2: QEMU itself. The `sleep` gives QEMU a moment to initialize
# before we send 'c' into its monitor stdin, skipping the manual
# keypress. If this pane's command seems to die immediately (tmux says
# "server exited unexpectedly"), bump the sleep value up - it usually
# means QEMU needed slightly longer to start on this machine.
tmux split-window -v -t "$SESSION" "(sleep 3 && echo c) | make $RUN_FLAGS run-only"

tmux select-layout -t "$SESSION" tiled
tmux attach -t "$SESSION"
