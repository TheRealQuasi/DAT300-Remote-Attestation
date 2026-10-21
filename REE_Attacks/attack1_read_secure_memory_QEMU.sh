#!/bin/sh
# RQ3 1.1.1 (read secure memory from REE)
# =============================================================================
# GOAL
#   As root in the REE, try to read OP-TEE's secure DRAM carveout via /dev/mem.
#   Confirmed region for qemu_armv8a (from the OP-TEE boot-time mmap dump):
#       TZDRAM (secure)      : 0x0e100000 - 0x0effffff
#       TEE_RAM_RX (core)    : 0x0e100000
#       SEC_RAM / TA RAM     : 0x0e1b7000   <- fTPM + its keys live here
#       Control (non-secure) : 0x40200000   <- System RAM (kernel image),
#                                               SHOULD be readable with real data.
#
# =============================================================================
#
# From normal world, mount localhost first so it can access the script, unless you decide to move it manually.
# mount -t 9p -o trans=virtio host /mnt/host
# 
# Run (logged in as root) inside normal world:  
# Usage: sh /mnt/host/optee_examples/ra-ftpm/attacks/attack1_read_secure_memory.sh

set -u

# The output will be printed to terminal, but a copy will be saved to /tmp/, or your mount point if you decided to mount localhost
OUT=/tmp/attack1_result.txt
if [ -d /mnt/host ] && touch /mnt/host/.w 2>/dev/null; then
	rm -f /mnt/host/.w; OUT=/mnt/host/attack1_result.txt
fi

# The memory regions of OP-TEE are not explicitly stated when checking /proc/iomem. The build logs must be reviewed to confirm.
#
# TEE core + TA RAM, confirmed after reviewing optee_os/core/arch/arm/plat-vexpress/conf.mk and inspecting run-time build logs.
SECURE="0x0e100000 0x0e1b7000 0x0e200000"   
#
# Non-secure system RAM. This was initially not readable either. 
# CONFIG_STRICT_DEVMEM had to be disabled first through configuration file: </optee/build/kconfigs/qemu.conf>
CONTROL="0x40200000"                         # non-secure System RAM (kernel image)

# Read one 32-bit word using busybox 'devmem'
# Prints the value, or "BLOCKED" if the read failed (fault / policy).
rd_word() {
	if command -v devmem >/dev/null 2>&1; then
		devmem "$1" 32 2>/dev/null || echo BLOCKED
	else
		echo "no-devmem"
	fi
}

# Read a 4 KiB page via /dev/mem with dd; classify the result.
rd_page() {
	addr=$1
	dec=$(printf '%d' "$addr")
	page=$((dec / 4096))
	tmp=$(mktemp 2>/dev/null || echo /tmp/pg.$$)
	if dd if=/dev/mem bs=4096 skip="$page" count=1 of="$tmp" 2>/dev/null; then
		got=$(wc -c < "$tmp")
		if [ "$got" -eq 0 ]; then
			echo "READ-FAILED (0 bytes - blocked/fault)"
		else
			nz=$(tr -d '\000' < "$tmp" | wc -c | tr -d ' ')
			if [ "$nz" -eq 0 ]; then
				echo "ALL-ZERO ($got bytes, no data leaked)"
			else
				echo "NON-ZERO"
				echo "    first bytes:"
				xxd "$tmp" 2>/dev/null | head -4 | sed 's/^/    /'
			fi
		fi
	else
		echo "DD-FAILED (open/read denied)"
	fi
	rm -f "$tmp"
}

{
	echo "================================================================"
	echo " RQ3 1.1.1 - Attack 1: read secure memory from REE via /dev/mem"
	echo " date: $(date -u 2>/dev/null) UTC"
	echo " host: $(uname -a)"
	echo "================================================================"
	id
	echo
	echo

	echo "---- CONTROL: non-secure memory (expected to succeed) ----------"
	for a in $CONTROL; do
		echo "  $a  word=$(rd_word "$a")  page=$(rd_page "$a")"
	done
	echo

	echo "---- TARGET: OP-TEE secure regions (expected to fail) ----"
	for a in $SECURE; do
		echo "  $a  word=$(rd_word "$a")  page=$(rd_page "$a")"
	done
	echo

} 2>&1 | tee "$OUT"

echo; echo "Saved to: $OUT"
