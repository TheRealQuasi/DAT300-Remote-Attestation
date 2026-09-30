#!/bin/bash
# build.sh - full OP-TEE rebuild with every flag ra_demo needs.
#
# Run this from ~/optee/build/ (or wherever your OP-TEE build directory
# is) AFTER copying ra_demo/ into optee_examples/.
#
# Usage:
#   ./build.sh          # normal build
#   ./build.sh clean     # force a clean rebuild of the examples package
#                         # (use this if ra_demo doesn't show up after a
#                         # normal build - see README Troubleshooting)

set -e
cd "$(dirname "$0")"

BUILD_FLAGS="CFG_ATTESTATION_PTA=y CFG_ATTESTATION_PTA_KEY_SIZE=2048 QEMU_VIRTFS_ENABLE=y"

if [ "$1" = "clean" ]; then
	echo ">>> Forcing a clean rebuild of optee_examples_ext (stale cache workaround)"
	make optee_examples_ext-dirclean
fi

echo ">>> Building with: $BUILD_FLAGS"
make -j"$(nproc)" $BUILD_FLAGS

echo ""
echo ">>> Done. Verify with:"
echo "    grep -i 'ra_demo\|optee_example_ra_demo' build.log 2>/dev/null || true"
echo "    (or just boot with ./start-optee.sh and run: which optee_example_ra_demo)"
