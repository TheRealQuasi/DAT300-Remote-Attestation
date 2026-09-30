#!/bin/bash
# build.sh - builds BOTH ra-pta and ra-ftpm. Run from ~/optee/build/
set -e
cd "$(dirname "$0")"

# Buildroot can't handle spaces in PATH (WSL adds Windows folders like "Program Files")
export PATH=$(echo "$PATH" | tr ':' '\n' | grep -v '[[:space:]]' | paste -sd:)

FLAGS="CFG_ATTESTATION_PTA=y CFG_ATTESTATION_PTA_KEY_SIZE=2048 \
MEASURED_BOOT_FTPM=y BR2_PACKAGE_TPM2_TSS=y QEMU_VIRTFS_ENABLE=y"

# Let optee_examples use the tpm2-tss library (only added once)
MK=br-ext/package/optee_examples_ext/optee_examples_ext.mk
grep -q tpm2-tss $MK || sed -i '/^OPTEE_EXAMPLES_EXT_DEPENDENCIES/ s/$/ tpm2-tss/' $MK

# Always rebuild the examples so both demos are up to date
make optee_examples_ext-dirclean || true

make -j"$(nproc)" $FLAGS
