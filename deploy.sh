#!/bin/bash
# deploy.sh - copy this repo's files into the OP-TEE tree.
# Run from anywhere:  ./deploy.sh        (OP-TEE in another place: OPTEE=/path ./deploy.sh)
set -e

REPO="$(cd "$(dirname "$0")" && pwd)"
OPTEE="${OPTEE:-$HOME/optee}"

if [ ! -d "$OPTEE/build" ] || [ ! -d "$OPTEE/optee_examples" ]; then
	echo "OP-TEE tree not found at $OPTEE (set OPTEE=/path/to/optee)"
	exit 1
fi

# build and start scripts -> ~/optee/build
cp "$REPO/build.sh" "$REPO/start-optee.sh" "$OPTEE/build/"
chmod +x "$OPTEE/build/build.sh" "$OPTEE/build/start-optee.sh"
echo "build.sh, start-optee.sh  		-> $OPTEE/build/"

# DEPLOY PTA
# PTA (built as an optee_example) -> ~/optee/optee_examples/ra-pta
# the old copy is removed first so deleted/renamed files don't linger
rm -rf "$OPTEE/optee_examples/ra-pta"
cp -r "$REPO/PTA/ra-pta" "$OPTEE/optee_examples/"
echo "PTA/ra-pta               		-> $OPTEE/optee_examples/ra-pta/"

# DEPLOY FTPM
# CA (built as an optee_example) -> ~/optee/optee_examples/ra-ftpm
# the old copy is removed first so deleted/renamed files don't linger
rm -rf "$OPTEE/optee_examples/ra-ftpm"
cp -r "$REPO/FTPM/ra-ftpm" "$OPTEE/optee_examples/"
echo "FTPM/ra-ftpm              		-> $OPTEE/optee_examples/ra-ftpm/"

# benchmark script -> ~/optee/benchmark  (= /mnt/host/benchmark inside QEMU)
mkdir -p "$OPTEE/benchmark"
cp "$REPO/FTPM/ftpm-shells/ftpm-benchmark.sh" "$OPTEE/benchmark/"
chmod +x "$OPTEE/benchmark/ftpm-benchmark.sh"
echo "FTPM/ftpm-shells/ftpm-benchmark.sh  	-> $OPTEE/benchmark/"

# DoS script -> ~/optee/dos  (= /mnt/host/dos inside QEMU)
mkdir -p "$OPTEE/dos"
cp "$REPO/FTPM/ftpm-shells/ftpm-dos-shells/ftpm-dos.sh" "$OPTEE/dos/"
cp "$REPO/FTPM/ftpm-shells/ftpm-dos-shells/ftpm-dos-benchmark.sh" "$OPTEE/dos/"
chmod +x "$OPTEE/dos/ftpm-dos.sh"
chmod +x "$OPTEE/dos/ftpm-dos-benchmark.sh"
echo "FTPM/ftpm-shells/ftpm-dos-shells/ftpm-dos.sh  	-> $OPTEE/dos/"
echo "FTPM/ftpm-shells/ftpm-dos-shells/ftpm-dos-benchmark.sh  	-> $OPTEE/dos/"

# DEPLOY TPM
# cp -r "$REPO/TPM/..." "$OPTEE/..."


# TO PRINT THE FILES IN THE OPTEE TREE:
# echo
# ls -R "$OPTEE/optee_examples/ra-ftpm"