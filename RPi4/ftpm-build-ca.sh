CA=~/shared/DAT300-Remote-Attestation/FTPM/ra-ftpm/host/main.c
SYS=~/pi4-sysroot

OUT_DIR=~/shared/DAT300-Remote-Attestation/RPi4/CA
FILE=ra-ca-ftpm
FILE_PATH="$OUT_DIR/$FILE"

mkdir -p "$OUT_DIR"
rm -f "$FILE_PATH"

~/optee/toolchains/aarch64/bin/aarch64-linux-gnu-gcc \
    --sysroot="$SYS" -O2 \
    -I"$SYS/usr/include" \
    -I"$SYS/usr/include/aarch64-linux-gnu" \
    -B"$SYS/usr/lib/aarch64-linux-gnu" \
    -L"$SYS/usr/lib/aarch64-linux-gnu" -L"$SYS/lib/aarch64-linux-gnu" \
    -Wl,-rpath-link,"$SYS/usr/lib/aarch64-linux-gnu" \
    -Wl,-rpath-link,"$SYS/lib/aarch64-linux-gnu" \
    -ltss2-esys -ltss2-mu -ltss2-rc -ltss2-tctildr \
    -o "$FILE_PATH" "$CA" 
echo "Done building CA $FILE_PATH"
