#!/bin/sh
#
# tee_storage_test.sh - watch how OP-TEE REE FS secure storage changes on disk
# and whether OP-TEE notices when /data/tee is rolled back to an older copy.
#
# Steps:
#   1. Snapshot /data/tee (file list + checksums) and back it up to ./backup
#   2. Run the secure storage example
#   3. Compare /data/tee against the snapshot (appeared / removed / changed)
#   4. If nothing changed, run the example again and compare again
#   5. If anything changed, restore /data/tee from ./backup
#   6. Run the example again and check whether it reported an error
#
# Settings can be overridden from the environment, e.g.:
#   EXAMPLE=optee_example_secure_storage TEE_DIR=/data/tee ./tee_storage_test.sh

set -u

TEE_DIR="${TEE_DIR:-/data/tee}"
BACKUP="${BACKUP:-./backup}"
EXAMPLE="${EXAMPLE:-optee_example_secure_storage}"
WORK="$(mktemp -d /tmp/teetest.XXXXXX)" || exit 1
trap 'rm -rf "$WORK"' EXIT

# Pick a checksum tool (BusyBox normally has both)
if command -v sha256sum >/dev/null 2>&1; then
    HASH=sha256sum
else
    HASH=md5sum
fi

line() { echo "------------------------------------------------------------"; }

# snapshot <outfile>: "checksum  ./filename" for every file, sorted by name
snapshot() {
    ( cd "$TEE_DIR" && find . -type f -exec $HASH {} \; ) | sort -k2 > "$1"
}

# show_files: list the directory with sizes and timestamps
show_files() {
    ls -la "$TEE_DIR"
}

# compare <old> <new>: print APPEARED / REMOVED / CHANGED lines, return 1 if any
compare() {
    awk '
        NR == FNR { old[$2] = $1; next }
        {
            seen[$2] = 1
            if (!($2 in old))        { print "  APPEARED: " $2; n++ }
            else if (old[$2] != $1)  { print "  CHANGED:  " $2; n++ }
        }
        END {
            for (f in old) if (!(f in seen)) { print "  REMOVED:  " f; n++ }
            if (n == 0) print "  (no differences)"
            exit (n > 0)
        }
    ' "$1" "$2"
}

# run_example <label>: run the example, show its output, save exit status
run_example() {
    echo ">>> Running $EXAMPLE ($1)"
    "$EXAMPLE" > "$WORK/out_$1.txt" 2>&1
    rc=$?
    sed 's/^/    /' "$WORK/out_$1.txt"
    echo ">>> Exit status: $rc"
    echo "$rc" > "$WORK/rc_$1"
}

# ---------------------------------------------------------------- checks
if [ ! -d "$TEE_DIR" ]; then
    echo "ERROR: $TEE_DIR does not exist." >&2
    exit 1
fi
if ! command -v "$EXAMPLE" >/dev/null 2>&1; then
    echo "ERROR: '$EXAMPLE' not found in PATH." >&2
    exit 1
fi
if [ -e "$BACKUP" ]; then
    echo "ERROR: $BACKUP already exists. Move it away first so it isn't overwritten." >&2
    exit 1
fi

# ---------------------------------------------------------------- step 1
line; echo "STEP 1: Initial contents of $TEE_DIR"; line
show_files
snapshot "$WORK/snap0"
cp -a "$TEE_DIR" "$BACKUP" || { echo "ERROR: backup failed." >&2; exit 1; }
echo "Backed up to $BACKUP"

# ---------------------------------------------------------------- step 2-3
line; echo "STEP 2: First run"; line
run_example run1
snapshot "$WORK/snap1"
echo
echo "Changes compared to the backup:"
compare "$WORK/snap0" "$WORK/snap1"
changed=$?

# ---------------------------------------------------------------- step 4
if [ "$changed" -eq 0 ]; then
    line; echo "STEP 3: Nothing changed, running a second time"; line
    run_example run2
    snapshot "$WORK/snap2"
    echo
    echo "Changes compared to the backup:"
    compare "$WORK/snap0" "$WORK/snap2"
    changed=$?
fi

echo
show_files

# ---------------------------------------------------------------- step 5
if [ "$changed" -eq 0 ]; then
    line; echo "No files changed after two runs; nothing to roll back."; line
    exit 0
fi

line; echo "STEP 4: Files changed, restoring $TEE_DIR from $BACKUP"; line
rm -rf "$TEE_DIR"
cp -a "$BACKUP" "$TEE_DIR" || { echo "ERROR: restore failed." >&2; exit 1; }
snapshot "$WORK/snap_restored"
echo "Restored contents compared to the backup:"
compare "$WORK/snap0" "$WORK/snap_restored"

# ---------------------------------------------------------------- step 6
line; echo "STEP 5: Running again on the rolled-back storage"; line
run_example after_restore
rc=$(cat "$WORK/rc_after_restore")

echo
line
if [ "$rc" -ne 0 ] || grep -qi "0xf0100001\|corrupt" "$WORK/out_after_restore.txt"; then
    echo "RESULT: The example reported an error after the rollback."
    echo "        OP-TEE (or the example) noticed something was wrong."
else
    echo "RESULT: The example ran without errors after the rollback."
    echo "        OP-TEE did not detect that the storage was replaced with an older copy."
fi
line
echo "The backup is still in $BACKUP."
