#!/bin/sh

set -u
export TPM2TOOLS_TCTI="device:/dev/tpmrm0"

OUT=/tmp/attack3_export_result.txt
if [ -d /mnt/host ] && touch /mnt/host/.w 2>/dev/null; then
	rm -f /mnt/host/.w; OUT=/mnt/host/attack3_export_result.txt
fi
WORK=$(mktemp -d 2>/dev/null || echo /tmp/a3.$$); mkdir -p "$WORK"; cd "$WORK"

exported=no
try() {
	echo "\$ $*"
	if "$@" 2>&1; then
		echo "  -> command successful"
		return 0
	else
		echo "  -> command failed (expected for an export attempt)"
		return 1
	fi
}

{
	echo "================================================================"
	echo " RQ3 Attack 3 Export the AK"
	echo " date: $(date -u 2>/dev/null) UTC"
	echo " tcti: $TPM2TOOLS_TCTI"
	echo "================================================================"
	id; echo

	echo "---- Recreate the AK in the same way CA does -------------------"
	# Restricted signing primary, ECC P-256, fixedtpm|fixedparent, NULL
	# symmetric (':null') - matches host/main.c. Deterministic => same AK.
	try tpm2_createprimary -C e -G ecc256:ecdsa-sha256:null -g sha256 \
		-a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign" \
		-c ak.ctx
	echo

	echo "---- Export attempt A: plain-auth duplication -------------"
	# A new parent to wrap into, then try to duplicate the AK under it.
	tpm2_createprimary -C o -g sha256 -G ecc -c parent.ctx >/dev/null 2>&1
	if try tpm2_duplicate -C parent.ctx -c ak.ctx -G null -p "" \
		-r dup.priv -s dup.seed; then exported=yes; fi
	echo

	echo "---- Export attempt B: policy session 			 --------"
	tpm2_startauthsession -S s.ctx >/dev/null 2>&1
	tpm2_policycommandcode -S s.ctx TPM2_CC_Duplicate >/dev/null 2>&1
	if try tpm2_duplicate -C parent.ctx -c ak.ctx -G null -p "session:s.ctx" \
		-r dup2.priv -s dup2.seed; then exported=yes; fi
	tpm2_flushcontext s.ctx >/dev/null 2>&1
	echo

	echo "---- Did any private-key material come out? ---------------"
	for f in dup.priv dup2.priv; do
		if [ -s "$f" ]; then
			echo "  !!! $f exists and is non-empty -> possibly exported!"
			exported=yes
		else
			echo "  $f : not produced (good)"
		fi
	done
	echo

	echo "---- Results ----------------------------------------------"
	if [ "$exported" = no ]; then
		echo "  PASS: the AK private key could not be exported. Duplication"
		echo "        fails (fixedtpm/fixedparent + empty authPolicy = no"
		echo "        ADMIN-role auth), and no other command exports it."
	else
		echo "  FAIL: an export step produced private-key material - inspect"
		echo "        the exported files."
	fi
	echo "================================================================"
} 2>&1 | tee "$OUT"

cd /; rm -rf "$WORK"
echo; echo "Saved to: $OUT"
