#!/bin/sh
# ftpm-dos-prep-quote.sh - one-time key setup for the tpm2_quote load.
# Runs INSIDE the QEMU guest. Creates an ECC attestation key context that the
# quote workers reuse, so each worker forces a real ECDSA signature in the fTPM
# (the same signing path the CA's attestation uses). Run once per boot before
# a quote-based sweep; safe to re-run (it just rebuilds the context files).
#
# Output: $CTX_DIR/ak.ctx  (default /tmp/ftpm-dos-ak.ctx dir -> /tmp)
#
# usage: ./ftpm-dos-prep-quote.sh

TCTI=${TCTI:-device:/dev/tpmrm0}
CTX_DIR=${CTX_DIR:-/tmp}
AK_CTX="$CTX_DIR/ak.ctx"

for t in tpm2_createprimary tpm2_create tpm2_load; do
    if ! command -v "$t" >/dev/null 2>&1; then
        echo "$t not found (is tpm2-tools installed?)"
        exit 1
    fi
done

echo "creating ECC attestation key context -> $AK_CTX"
tpm2_createprimary -T "$TCTI" -C e -g sha256 -G ecc \
    -c "$CTX_DIR/ftpm-dos-prim.ctx" >/dev/null || exit 1
tpm2_create -T "$TCTI" -C "$CTX_DIR/ftpm-dos-prim.ctx" -g sha256 -G ecc \
    -u "$CTX_DIR/ftpm-dos-ak.pub" -r "$CTX_DIR/ftpm-dos-ak.priv" >/dev/null || exit 1
tpm2_load -T "$TCTI" -C "$CTX_DIR/ftpm-dos-prim.ctx" \
    -u "$CTX_DIR/ftpm-dos-ak.pub" -r "$CTX_DIR/ftpm-dos-ak.priv" \
    -c "$AK_CTX" >/dev/null || exit 1

echo "done. quote workers will use -c $AK_CTX"