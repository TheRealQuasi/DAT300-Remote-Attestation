#!/bin/sh
# attack2_storage_host.sh
# =============================================================================
#
# Usage: Make a local copy of /var/lib/tee (QEMU) or /data/tee/ (RaspberryPi):
# ./attack2_storage_host.sh <path_to_files> <result_output_path>
#
# PASS (key protected): objects are high-entropy (~8 bits/byte) and
#   incompressible, contain no DER/ASN.1 key structure, no loadable private
#   key, no PEM armor, and short printable runs -> ciphertext, not keys.
# FAIL: any object yields a private key / PEM armor / low-entropy key blob.
#
# =============================================================================

set -u

STORE=${1:-}
if [ -z "$STORE" ] || [ ! -d "$STORE" ]; then
	echo "Usage: $0 <dir-with-copied-store>" >&2
	echo "  (a local copy of /var/lib/tee or /data/tee)" >&2
	exit 1
fi
OUT=${2:-./attack2_host_result.txt}

HAVE_OPENSSL=no; command -v openssl >/dev/null 2>&1 && HAVE_OPENSSL=yes
HAVE_GZIP=no;    command -v gzip    >/dev/null 2>&1 && HAVE_GZIP=yes

# --- metrics ---------------------------------------------------------------
# Content region = bytes 0..last-non-zero (excludes trailing zero padding).

nonzero_count() { tr -d '\000' < "$1" 2>/dev/null | wc -c | tr -d ' '; }

content_extent() {
	od -An -tu1 -v "$1" 2>/dev/null | tr ' ' '\n' | grep -v '^$' | \
		awk '{ if ($1 != 0) last = NR } END { print last + 0 }'
}

distinct_bytes() {
	od -An -tu1 -v "$1" 2>/dev/null | tr ' ' '\n' | grep -v '^$' | \
		awk '{ c[$1]=1 } END { n=0; for (b in c) n++; print n+0 }'
}

longest_printable() {
	od -An -tu1 -v "$1" 2>/dev/null | tr ' ' '\n' | grep -v '^$' | \
		awk '{ if ($1>=32 && $1<=126) { r++; if (r>m) m=r } else r=0 }
		     END { print m+0 }'
}

# Shannon entropy (bits/byte) over the NON-ZERO bytes only: 
# the blocks of zero bytes are stripped first, so the measure
# reflects the actual data and is not dragged down by padding. Needs awk with
# log() - fine on a host. 8.000 = maximally random.

entropy_nonzero() {
	tr -d '\000' < "$1" 2>/dev/null | od -An -tu1 -v | tr ' ' '\n' | \
		grep -v '^$' | awk '
			{ c[$1]++; n++ }
			END {
				if (n == 0) { printf "0.000\n"; exit }
				H = 0
				for (b in c) { p = c[b]/n; H -= p*log(p)/log(2) }
				printf "%.3f\n", H
			}'
}

comp_nonzero() {
	[ "$HAVE_GZIP" = yes ] || { echo -1; return; }
	tr -d '\000' < "$1" 2>/dev/null | gzip -c 2>/dev/null | wc -c | tr -d ' '
}

der_sniff() {
	od -An -tu1 -v -N5 "$1" 2>/dev/null | tr -s ' ' | sed 's/^ *//' | \
		awk -v EXT="$2" '{
			b0=$1; b1=$2; d=-1
			if (b0==48) {
				if (b1<128)       d=b1+2
				else if (b1==129) d=$3+3
				else if (b1==130) d=$3*256+$4+4
			}
			if (d>0 && d>=EXT-4 && d<=EXT+4) print "yes"; else print "no"
		}'
}

{
	echo "================================================================"
	echo " RQ3 1.1.1 - Attack 2: can key be found in data at rest?"
	echo " date : $(date -u 2>/dev/null) UTC"
	echo "================================================================"
	echo
	echo " PASS = incompressible, ~8 bits/byte entropy, no DER key, no PEM,"
	echo "        no loadable key -> ciphertext. FAIL = any key recovered."
	echo

	echo "---- Per-object metrics -----------------------------------"
	echo "  NZERO=non-zero bytes  DISTIN=distinct values(/256)"
	echo "  ENTROPY=Shannon bits/byte over content (8.0=random)"
	echo "  MAXRUN=longest printable run  COMP=gzip size of content  DER?=key struct"
	echo
	printf "  %-10s %7s %6s %8s %6s %7s %5s\n" OBJECT NZERO DISTIN ENTROPY MAXRUN COMP DER?
	flag=0
	N=0; SUM_NZ=0; SUM_DIST=0; MAXRUN_ALL=0; RUN_MIN=999999
	DIST_MIN=999; DIST_MAX=0
	N_RATIO=0; SUM_RATIO=0; RATIO_MIN=999999; RATIO_MAX=0
	ENT_N=0; ENT_SUM=0; ENT_MIN=9999; ENT_MAX=0   # entropy*1000 (integer math)
	DER_YES=0
	for f in "$STORE"/* ; do
		[ -f "$f" ] || continue
		NZ=$(nonzero_count "$f");       NZ=${NZ:-0}
		EXT=$(content_extent "$f");     EXT=${EXT:-0}
		DIST=$(distinct_bytes "$f");    DIST=${DIST:-0}
		ENT=$(entropy_nonzero "$f");     ENT=${ENT:-0.000}
		RUN=$(longest_printable "$f");  RUN=${RUN:-0}
		COMP=$(comp_nonzero "$f");      COMP=${COMP:-'-1'}
		DER=$(der_sniff "$f" "$EXT");   DER=${DER:-no}
		if [ "$HAVE_OPENSSL" = yes ] && \
		   openssl asn1parse -inform der -in "$f" >/dev/null 2>&1; then
			DER=yes
		fi

		[ "$DER" = yes ] && flag=1
		[ "$RUN" -ge 24 ] 2>/dev/null && flag=1
		if [ "$COMP" -ge 0 ] 2>/dev/null && [ "$NZ" -ge 64 ] 2>/dev/null; then
			[ $((COMP * 10)) -lt $((NZ * 7)) ] && flag=1
		fi

		# aggregates
		N=$((N + 1)); SUM_NZ=$((SUM_NZ + NZ)); SUM_DIST=$((SUM_DIST + DIST))
		[ "$RUN" -gt "$MAXRUN_ALL" ] 2>/dev/null && MAXRUN_ALL=$RUN
		[ "$RUN" -lt "$RUN_MIN" ] 2>/dev/null && RUN_MIN=$RUN
		[ "$DIST" -lt "$DIST_MIN" ] 2>/dev/null && DIST_MIN=$DIST
		[ "$DIST" -gt "$DIST_MAX" ] 2>/dev/null && DIST_MAX=$DIST
		EI=$(awk -v e="$ENT" 'BEGIN{printf "%d", e*1000 + 0.5}')  # 7.991 -> 7991
		ENT_N=$((ENT_N + 1)); ENT_SUM=$((ENT_SUM + EI))
		[ "$EI" -lt "$ENT_MIN" ] && ENT_MIN=$EI
		[ "$EI" -gt "$ENT_MAX" ] && ENT_MAX=$EI
		if [ "$COMP" -ge 0 ] 2>/dev/null && [ "$NZ" -gt 0 ] 2>/dev/null; then
			R=$((COMP * 100 / NZ)); N_RATIO=$((N_RATIO + 1)); SUM_RATIO=$((SUM_RATIO + R))
			[ "$R" -lt "$RATIO_MIN" ] && RATIO_MIN=$R
			[ "$R" -gt "$RATIO_MAX" ] && RATIO_MAX=$R
		fi
		[ "$DER" = yes ] && DER_YES=$((DER_YES + 1))

		printf "  %-10s %7s %6s %8s %6s %7s %5s\n" \
			"$(basename "$f")" "$NZ" "$DIST" "$ENT" "$RUN" "$COMP" "$DER"
	done
	echo

	echo "---- Direct key-extraction attempts -----"
	if [ "$HAVE_OPENSSL" = yes ]; then
		found=no
		for f in "$STORE"/* ; do
			[ -f "$f" ] || continue
			if openssl pkey -inform der -in "$f" -noout 2>/dev/null \
			   || openssl ec  -inform der -in "$f" -noout 2>/dev/null \
			   || openssl rsa -inform der -in "$f" -noout 2>/dev/null; then
				echo "  !!! $f loaded as a PRIVATE KEY -> FAIL"
				flag=1; found=yes
			fi
		done
		[ "$found" = no ] && echo "  (no object loaded as a private key)"
	else
		echo "  openssl CLI not found; relying on [2] DER? sniff."
	fi
	echo
	echo "PEM armor anywhere in the store?"
	if grep -rlaF -- "-----BEGIN" "$STORE" 2>/dev/null; then
		echo "  !!! PEM armor found -> inspect -> possible FAIL"; flag=1
	else
		echo "  (none - no PEM key material found)"
	fi
	echo

	echo "---- Summary -----------------"
	if [ "$N" -gt 0 ]; then
		echo "  objects analysed            : $N"
		echo "  mean non-zero bytes (NZERO) : $((SUM_NZ / N))"
		echo "  distinct byte values DISTIN : min $DIST_MIN  max $DIST_MAX  mean $((SUM_DIST / N))  (256=random)"
		if [ "$ENT_N" -gt 0 ]; then
			printf "  Shannon entropy (bits/byte) : min %d.%03d  max %d.%03d  mean %d.%03d  (8.0=random)\n" \
				$((ENT_MIN/1000)) $((ENT_MIN%1000)) \
				$((ENT_MAX/1000)) $((ENT_MAX%1000)) \
				$((ENT_SUM/ENT_N/1000)) $(((ENT_SUM/ENT_N)%1000))
		fi
		echo "  longest printable run MAXRUN: min $RUN_MIN  max $MAXRUN_ALL  (small=>no plaintext)"
		[ "$N_RATIO" -gt 0 ] && echo "  compressed/content ratio    : min ${RATIO_MIN}%  max ${RATIO_MAX}%  mean $((SUM_RATIO / N_RATIO))%  (>=100%=>incompressible)"
		echo "  objects with DER key struct : $DER_YES / $N"
	else
		echo "  (no objects to summarise)"
	fi
	echo

	echo "---- Verdict ----------------------------------------------"
	if [ "$flag" -eq 0 ]; then
		echo "  PASS: no DER key, no loadable key, no PEM, short runs,"
		echo "        high entropy + incompressible => encrypted ciphertext."
	else
		echo "  REVIEW: an object was flagged above - open it before"
		echo "          declaring a FAIL."
	fi
	echo "================================================================"
} 2>&1 | tee "$OUT"

echo
echo "Saved to: $OUT"
