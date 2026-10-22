#!/bin/sh

set -u
export TPM2TOOLS_TCTI="device:/dev/tpmrm0"

OUT=/tmp/attack4_pcrreset_result.txt
if [ -d /mnt/host ] && touch /mnt/host/.w 2>/dev/null; then
	rm -f /mnt/host/.w; OUT=/mnt/host/attack4_pcrreset_result.txt
fi
WORK=$(mktemp -d 2>/dev/null || echo /tmp/a4.$$); mkdir -p "$WORK"; cd "$WORK"

# PCRs we try to reset and what we expect.
#   0-7  : platform/firmware measurements  -> reset MUST fail
#   10   : IMA / OS measurement log        -> reset MUST fail
#   16   : debug PCR                        -> reset SHOULD succeed
RESETTABLE="16"              # expected to succeed
NONRESETTABLE="0 1 2 3 4 5 6 7 10"  # expected to fail

unexpected=no

# read_pcr <index> : print the current value, or "unavailable"
# tpm2_pcrread prints "  <idx> : 0x<value>" (index and colon are separate
# fields); some builds attach the colon as "<idx>:". Handle both.
read_pcr() {
	tpm2_pcrread "sha256:$1" 2>/dev/null | awk -v i="$1" '
		$1 == i && $2 == ":" { print $3; found=1; exit }
		$1 == i":"           { print $2; found=1; exit }
		END { if (!found) print "unavailable" }'
}

# try_reset <index> <expected: pass|fail>
try_reset() {
	idx=$1; expect=$2
	before=$(read_pcr "$idx")
	echo "\$ tpm2_pcrreset $idx"
	if tpm2_pcrreset "$idx" 2>&1; then
		rc=0; echo "  -> reset returned success"
	else
		rc=1; echo "  -> reset returned failure"
	fi
	after=$(read_pcr "$idx")
	echo "     before: $before"
	echo "     after : $after"

	if [ "$expect" = pass ]; then
		if [ "$rc" -eq 0 ]; then
			echo "     OK: resettable PCR $idx reset as expected."
		else
			echo "     !!! UNEXPECTED: PCR $idx was expected to reset but did not."
			unexpected=yes
		fi
	else
		if [ "$rc" -ne 0 ]; then
			echo "     OK: PCR $idx refused reset as expected."
		else
			echo "     !!! UNEXPECTED: PCR $idx accepted a reset - it should be locked."
			unexpected=yes
		fi
	fi
	echo
}

{
	echo "================================================================"
	echo " RQ3 Attack 4 - Reset the PCRs"
	echo " date: $(date -u 2>/dev/null) UTC"
	echo " tcti: $TPM2TOOLS_TCTI"
	echo "================================================================"
	id; echo

	echo "---- Reset attempts: PCRs that MUST stay locked ----------------"
	echo " (platform/firmware 0-7 and measurement log 10 are not"
	echo "  resettable from this locality; tpm2_pcrreset should fail)"
	echo
	for i in $NONRESETTABLE; do
		try_reset "$i" fail
	done

	echo "---- Reset attempt: debug PCR that may be reset ----------------"
	echo " (PCR 16 is a debug register resettable from locality 0)"
	echo
	for i in $RESETTABLE; do
		try_reset "$i" pass
	done

	echo "---- Results ----------------------------------------------"
	if [ "$unexpected" = no ]; then
		echo "  PASS: PCRs behaved as expected. 0-7 and 10 refused reset"
		echo "        (DRTM/SRTM reset-locality protection intact), and the"
		echo "        debug PCR 16 reset cleanly."
	else
		echo "  FAIL: at least one PCR did not behave as expected - a locked"
		echo "        PCR was resettable, or a resettable PCR would not reset."
		echo "        Inspect the per-PCR output above."
	fi
	echo "================================================================"
} 2>&1 | tee "$OUT"

cd /; rm -rf "$WORK"
echo; echo "Saved to: $OUT"
