#!/bin/bash
# build.sh - run from ~/optee/build/
set -e
cd "$(dirname "$0")"

FLAGS="MEASURED_BOOT_FTPM=y BR2_PACKAGE_TPM2_TSS=y QEMU_VIRTFS_ENABLE=y"

# Let optee_examples use the tpm2-tss library (only added once)
MK=br-ext/package/optee_examples_ext/optee_examples_ext.mk
grep -q tpm2-tss $MK || sed -i '/^OPTEE_EXAMPLES_EXT_DEPENDENCIES/ s/$/ tpm2-tss/' $MK

# Always rebuild the examples so ra_demo is never stale
make optee_examples_ext-dirclean || true

make -j"$(nproc)" $FLAGS
