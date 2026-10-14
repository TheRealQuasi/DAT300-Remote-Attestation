# optee-ra-demo

A minimal OP-TEE remote-attestation demo built around OP-TEE's built-in
Attestation Pseudo-TA. Generates and signs a live measurement of a
Trusted Application's own code, using a key that never leaves secure
world, and verifies the result offline.

- **First time / never set up OP-TEE before?** Start at
  [`SETUP_AND_VERIFICATION.md`](SETUP_AND_VERIFICATION.md) — it covers
  prerequisites through to a working `RA RESULT: PASS`.
- **Already have OP-TEE + QEMU running, just want this demo?** See
  "Quick start" below.
- **Want to understand how the code works, not just run it?** See
  [`CODE_EXPLAINED.md`](CODE_EXPLAINED.md).

## Repo contents

```text
PTA/
├── ra-pta/
│   ├── CMakeLists.txt
│   ├── verifier.py                 # host-side challenge + evidence verifier
│   ├── host/main.c                 # normal-world client application
│   ├── ta/ra_demo_ta.c             # TA forwarding the nonce to Attestation PTA
│   └── tests/test_verifier_replay.py
├── pta-build.sh
├── pta-start.sh
├── PTA_SETUP_AND_VERIFICATION.md
└── PTA_CODE_EXPLAINED.md
```

## Quick start — with verifier-issued, one-use challenges

Assumes you already have `~/optee` set up. See
[`PTA_SETUP_AND_VERIFICATION.md`](PTA_SETUP_AND_VERIFICATION.md) for the
full build and boot instructions.

```bash
# 1. From the root of the uploaded RA/ repository:
cp -r PTA/ra-pta ~/optee/optee_examples/ra-pta
cp PTA/pta-build.sh ~/optee/build/pta-build.sh
cp PTA/pta-start.sh ~/optee/build/start-optee.sh
chmod +x ~/optee/build/pta-build.sh ~/optee/build/start-optee.sh
# 2. Build and boot:
cd ~/optee/build && ./pta-build.sh && ./start-optee.sh
# Log in to the QEMU guest as root.

# 2. Inside the QEMU guest:
mkdir -p /mnt/host
mount -t 9p -o trans=virtio host /mnt/host
optee_example_ra_pta pubkey /mnt/host
```

On the **trusted host**, issue a fresh challenge. Keep this verifier database
on the host's local filesystem, never in `/mnt/host` or any guest-writable
share:

```bash
VERIFIER=~/optee/optee_examples/ra-pta/verifier.py  # adjust if installed elsewhere
CHALLENGE=$(python3 "$VERIFIER" --issue-challenge)
printf 'Copy this challenge into the QEMU guest: %s\n' "$CHALLENGE"
```

Copy the printed 64-character token into the QEMU guest:

```sh
optee_example_ra_pta attest 'PASTE_CHALLENGE_HERE' /mnt/host
```

Back on the host, verify using the **same** challenge variable from the issuing
shell (do not reconstruct it from the guest-written `nonce.bin`):

```bash
cd ~/optee
python3 "$VERIFIER" --challenge "$CHALLENGE" \
    --exp pubkey_exp.bin --mod pubkey_mod.bin --evidence evidence.bin
```

A successful response prints `RA RESULT: PASS`. That challenge is now consumed;
running the verifier again with the same challenge and evidence must fail. A
new challenge is required for each attestation. The database defaults to
`~/.local/state/optee-ra-pta/challenges.sqlite3`; override it with
`--challenge-db /trusted/local/path/challenges.sqlite3` if needed.

### Run the regression tests (no QEMU required)

From the repository root:

```bash
python3 -m pip install cryptography
python3 PTA/ra-pta/tests/test_verifier_replay.py
```

These tests use a temporary synthetic RSA key to exercise the verifier's
protocol logic. They test fresh-response acceptance, exact replay rejection,
stale-evidence rejection against a new challenge, and evidence-tampering
rejection. Follow the QEMU procedure above as well to validate evidence from
the real OP-TEE Attestation PTA.

## The one thing to remember

Every build touching this project needs all three of these flags, or
something silently breaks on the next boot:

```
CFG_ATTESTATION_PTA=y CFG_ATTESTATION_PTA_KEY_SIZE=2048 QEMU_VIRTFS_ENABLE=y
```

The `pta-build.sh` and `start-optee.sh` wrappers apply these flags; use them
instead of raw `make` commands.
