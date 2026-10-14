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

```
.
├── README.md                    (this file)
├── SETUP_AND_VERIFICATION.md    Full setup + how to run + verify + troubleshoot
├── CODE_EXPLAINED.md            File-by-file explanation of how it works
├── start-optee.sh               Boots QEMU + both consoles, one command
├── build.sh                     Rebuilds with all required flags, one command
└── ra_demo/                     The actual example - copy this into optee_examples/
    ├── CMakeLists.txt           Registers the CA with the build (see CODE_EXPLAINED)
    ├── verifier.py              Offline verifier, runs on the host
    ├── host/
    │   └── main.c               CA (client app)
    └── ta/
        ├── Makefile
        ├── sub.mk
        ├── ra_demo_ta.c         TA (trusted app)
        └── include/
            ├── ra_demo_ta.h     Shared UUID/command constants
            └── user_ta_header_defines.h
```

## Quick start

Assumes you already have `~/optee` set up and built at least once (see
`SETUP_AND_VERIFICATION.md` §2 if not).

```bash
# 1. Clone this repo
git clone <this-repo-url> optee-ra-demo
cd optee-ra-demo

# 2. Install into your OP-TEE tree
cp -r ra_demo ~/optee/optee_examples/
cp start-optee.sh build.sh ~/optee/build/
chmod +x ~/optee/build/start-optee.sh ~/optee/build/build.sh

# 3. Build (bakes in all 3 required flags - see below for why they matter)
cd ~/optee/build
./build.sh

# 4. Boot
./start-optee.sh
# log in as: root  (blank password)

# 5. Inside the guest:
mkdir -p /mnt/host
mount -t 9p -o trans=virtio host /mnt/host
optee_example_ra_demo pubkey
optee_example_ra_demo attest "test-$(date +%s)"

# 6. Back on the host, in a different terminal:
cd ~/optee
pip install cryptography --break-system-packages
python3 optee_examples/ra_demo/verifier.py \
    --exp pubkey_exp.bin --mod pubkey_mod.bin \
    --evidence evidence.bin --nonce nonce.bin
# expect: RA RESULT: PASS
```

Full explanation of every step, plus a troubleshooting table covering
every failure mode we actually hit while building this, is in
[`SETUP_AND_VERIFICATION.md`](SETUP_AND_VERIFICATION.md).

## The one thing to remember

Every `make` command touching this project needs all three of these
flags, every time, or something silently breaks on the next boot:

```
CFG_ATTESTATION_PTA=y CFG_ATTESTATION_PTA_KEY_SIZE=2048 QEMU_VIRTFS_ENABLE=y
```

`build.sh` and `start-optee.sh` already bake these in — use them instead
of raw `make` commands and you won't need to think about this.
