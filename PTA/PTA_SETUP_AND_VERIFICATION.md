# ra_demo — Setup & Verification Guide

This document walks through everything needed to get this OP-TEE remote
attestation demo running from a clean environment: what it does, how to
build it, how to run it, and how to verify the result. It assumes you
already have a working OP-TEE + QEMU (Armv7-A, `qemu-system-arm`) build
environment. If not, see the "Prerequisites" section first.

For an explanation of *how the code works* rather than *how to run it*,
see [`CODE_EXPLAINED.md`](CODE_EXPLAINED.md).

---

## 1. What this demo actually does

It implements a simplified remote-attestation (RA) workflow using
OP-TEE's **built-in Attestation Pseudo-TA** (`core/pta/attestation.c`,
part of `optee_os` itself — nothing here is a from-scratch crypto
implementation).

```
 Verifier (you, on the host)              Attester (QEMU guest)
 ┌─────────────────┐                      ┌───────────────────────────┐
 │                  │  (0) fetch pubkey    │  Normal World              │
 │                  │◄─────────────────────┤  optee_example_ra_pta CA  │
 │  verifier.py     │                      │                            │
 │ verifier issues  │  (1) attest <token> │  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  │
 │ one-use challenge│◄─────────────────────┤  Secure World              │
 │ checks signature│                      │  ra_demo TA  ──► calls ──► │
 │ + digest + state │                      │  Attestation PTA (built    │
 │                  │                      │  into optee_os)            │
 └─────────────────┘                      └───────────────────────────┘
```

Two commands, both run inside the QEMU guest:

- **`optee_example_ra_pta pubkey`** — fetches the Attestation PTA's
  public RSA key directly (no TA mediation needed for this call).
  Saved as your trust anchor.
- **`optee_example_ra_pta attest <challenge-token>`** — asks our custom
  `ra_demo` TA to request signed evidence from the PTA for *itself*: a SHA-256
  measurement of the TA's own code+rodata, signed together with the verifier's
  64-character challenge token. The PTA's private key never leaves secure world.

Then, on your **host** machine (not the guest):

- **`verifier.py`** — checks the signature against the public key, and
  optionally checks the digest against a known-good value you supply.

This is deliberately simplified from a full RA protocol: there's no
Relying Party and no Provisioner/certificate chain. See "Known
simplifications" at the end of this document.

---

## 2. Prerequisites

You need a working OP-TEE build environment already. If starting
completely from scratch:

```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y \
    adb acpica-tools autoconf automake bc bison build-essential ccache \
    cpio cscope curl device-tree-compiler e2tools expect fastboot flex \
    ftp-upload gdisk git libgnutls28-dev libattr1-dev libcap-ng-dev \
    libfdt-dev libftdi-dev libglib2.0-dev libgmp3-dev libhidapi-dev \
    libmpc-dev libncurses5-dev libpixman-1-dev libslirp-dev libssl-dev \
    libtool libusb-1.0-0-dev make mtools netcat ninja-build \
    python3-cryptography python3-pip python3-pyelftools python3-serial \
    python3-tomli python-is-python3 rsync swig unzip uuid-dev wget \
    xdg-utils xsltproc xterm xz-utils zlib1g-dev uuid-runtime tmux

curl https://storage.googleapis.com/git-repo-downloads/repo > /tmp/repo && \
    chmod a+x /tmp/repo && sudo mv /tmp/repo /usr/local/bin/repo

mkdir ~/optee && cd ~/optee
repo init -u https://github.com/OP-TEE/manifest.git
repo sync -j10
cd build
make -j3 toolchains
```

(`uuid-runtime` and `tmux` are added to the standard OP-TEE prerequisite
list specifically for this demo — the former for generating your own TA
UUID if you fork this, the latter for `start-optee.sh`.)

---

## 3. Installing this package

From the root of the uploaded `RA/` repository:

```bash
cp -r PTA/ra-pta ~/optee/optee_examples/ra-pta
cp PTA/pta-build.sh ~/optee/build/pta-build.sh
cp PTA/pta-start.sh ~/optee/build/start-optee.sh
chmod +x ~/optee/build/pta-build.sh ~/optee/build/start-optee.sh
```

The examples build auto-discovers subdirectories with a `CMakeLists.txt`.
This project's CMake target installs the client as
`/usr/bin/optee_example_ra_pta`; the TA is built from `ra-pta/ta/Makefile`.

**If you want a different TA UUID**, update the UUID in
`PTA/ra-pta/ta/include/ra_demo_ta.h` and the `BINARY` value in
`PTA/ra-pta/ta/Makefile` so they match.

---

## 4. Building

This is the single most important thing to get right: **three build
flags must always travel together**, on every build. Missing any one of
them doesn't cause an error — it just silently disables that feature on
the next boot, which is exactly the kind of bug that costs hours to
track down (ask us how we know).

```
CFG_ATTESTATION_PTA=y CFG_ATTESTATION_PTA_KEY_SIZE=2048 QEMU_VIRTFS_ENABLE=y
```

- `CFG_ATTESTATION_PTA=y` — compiles OP-TEE's built-in Attestation PTA
  into `tee.elf`. Without this, both `pubkey` and `attest` fail with
  `0xffff0008` (item not found) — OP-TEE core doesn't even recognize the
  PTA's UUID and falls through to a fruitless search for a `.ta` file
  that doesn't exist.
- `CFG_ATTESTATION_PTA_KEY_SIZE=2048` — sets the PTA's RSA key size.
- `QEMU_VIRTFS_ENABLE=y` — rebuilds QEMU itself with 9p/virtfs support
  and adds the `-fsdev`/`-device virtio-9p-device` flags needed for
  `/mnt/host` to actually work. Without this, mounting fails with
  `9pnet_virtio: no channels available for device host`.

The copied `pta-build.sh` applies the required flags automatically:

```bash
cd ~/optee/build
./pta-build.sh
```

If `optee_example_ra_pta` doesn't show up after a build, the most
likely cause is a **stale Buildroot package cache**. Force a clean rebuild
of the examples package:

```bash
./pta-build.sh clean
```

A full build takes a while — this is normal, don't interrupt it.

---

## 5. Booting

```bash
cd ~/optee/build
./start-optee.sh
```

This opens a `tmux` session with three panes:

1. **Normal World console** — where you'll log in and run commands
2. **Secure World console** — trace output from OP-TEE core and TAs
   (useful for debugging, not something you type into)
3. **QEMU monitor** — QEMU's own control console; the script
   auto-continues past this, you shouldn't need to touch it

**tmux basics**, if you're not familiar:
- `Ctrl-b` then arrow keys, or `Ctrl-b o` — move between panes
- `Ctrl-b z` — zoom the current pane fullscreen (toggle) — useful to
  focus on just the Normal World console
- `Ctrl-b d` — detach (session keeps running in the background)
- `tmux attach -t optee` — reattach later

Once the Normal World pane shows `buildroot login:`, log in:

```
buildroot login: root
Password:            <-- leave blank, just press Enter
```

---

## 6. Running the attestation flow

All of this happens **inside the guest** (the Normal World console pane,
at the `#` prompt after logging in as root).

### 6.1 Mount the host share

```sh
mkdir -p /mnt/host
mount -t 9p -o trans=virtio host /mnt/host
```

Confirm it worked:

```sh
ls /mnt/host
```

You should see your actual `~/optee` project directory contents
(`build`, `optee_examples`, `out-br`, etc.) — **not** just a single
`README` file. If you only see a lone `README`, the mount silently
failed (this happens if `QEMU_VIRTFS_ENABLE=y` wasn't part of the build
— go back to step 4).

> **Note on paths:** `/mnt/host` maps to the *parent* of your `build/`
> directory — i.e. `~/optee`, not `~/optee/build`. Files written to
> `/mnt/host/whatever.bin` will land at `~/optee/whatever.bin` on your
> host.

### 6.2 Confirm the CA is present

```sh
which optee_example_ra_pta
```

Should print `/usr/bin/optee_example_ra_pta`. If this is empty, the
build didn't include it — see the Troubleshooting section.

### 6.3 Fetch the public key (once)

```sh
optee_example_ra_pta pubkey
```

Expected output:

```
Public key retrieved:
  exponent: 3 bytes
  modulus:  256 bytes
  sig alg:  0x70414930 (should be TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256)
  wrote /mnt/host/pubkey_exp.bin (3 bytes)
  wrote /mnt/host/pubkey_mod.bin (256 bytes)
```

(3-byte exponent = `0x010001` / 65537, the standard RSA public exponent.
256-byte modulus = 2048-bit RSA, matching `CFG_ATTESTATION_PTA_KEY_SIZE`.)

### 6.4 Issue a challenge and request evidence

On the **trusted host**, issue a challenge before asking the guest to attest.
The challenge database is verifier state: keep it outside `/mnt/host` and any
guest-writable path.

```bash
VERIFIER=~/optee/optee_examples/ra-pta/verifier.py  # adjust to your install
CHALLENGE=$(python3 "$VERIFIER" --issue-challenge)
printf 'Challenge to copy into QEMU: %s\n' "$CHALLENGE"
```

Copy the 64-character challenge into the QEMU guest:

```sh
optee_example_ra_pta attest 'PASTE_CHALLENGE_HERE' /mnt/host
```

Expected output includes:

```
Evidence retrieved: 288 bytes (32-byte digest + signature)
  wrote /mnt/host/evidence.bin (288 bytes)
  wrote /mnt/host/nonce.bin (64 bytes)
```

The CA still writes `nonce.bin` for diagnostics/backwards inspection, but the
hardened verifier deliberately does **not** read or trust it.

---

## 7. Verifying, on the host

Back in the **same host shell** that issued the challenge, verify the evidence
against that exact challenge:

```bash
cd ~/optee   # or wherever /mnt/host mapped to (see note in 6.1)
python3 "$VERIFIER" --challenge "$CHALLENGE" \
    --exp pubkey_exp.bin --mod pubkey_mod.bin --evidence evidence.bin
```

The expected result is `RA RESULT: PASS`, with `Signature valid: YES`,
`Challenge consumed: YES`, and `Freshness check: PASS`. The verifier stores
only a hash of each issued challenge in its local SQLite database, expires
challenges after 300 seconds by default, and consumes each challenge after a
cryptographically valid response. Run `python3 "$VERIFIER" --help` for options.

**Important:** a signature proves authenticity, not freshness on its own. The
verifier now checks the signature over `SHA256(current_challenge || digest)`
and independently checks that the challenge was issued, has not expired, and
has not already been consumed. The challenge database must remain private to
the verifier; protecting challenge state and the transport are part of the
protocol's security boundary.

### 7.1 Reproduce and reject replay attacks

After one successful round, save the evidence on the host:

```bash
cp evidence.bin evidence-first.bin
```

**Exact replay:** run the verifier again with the already accepted challenge.
This must fail because the challenge has been consumed:

```bash
python3 "$VERIFIER" --challenge "$CHALLENGE" \
    --exp pubkey_exp.bin --mod pubkey_mod.bin --evidence evidence-first.bin
# Expected: "Challenge has already been consumed" and RA RESULT: FAIL
```

**Stale evidence against a new challenge:** issue a new challenge, but first
try verifying the saved response against it:

```bash
CHALLENGE2=$(python3 "$VERIFIER" --issue-challenge)
python3 "$VERIFIER" --challenge "$CHALLENGE2" \
    --exp pubkey_exp.bin --mod pubkey_mod.bin --evidence evidence-first.bin
# Expected: Signature valid: NO; RA RESULT: FAIL
```

The invalid stale response does not consume `CHALLENGE2`. Copy `CHALLENGE2`
into QEMU, request new evidence with `optee_example_ra_pta attest
'PASTE_CHALLENGE2_HERE' /mnt/host`, then verify that new evidence against
`CHALLENGE2`; it should pass and consume the challenge. In the commands above,
exit status 1 is expected for the two deliberately rejected replay attempts.

---

## 8. Testing tamper detection

This is the more interesting test: showing that the digest changes when
the TA's code changes, even though the signature itself stays valid
(because the PTA still faithfully signs whatever it's asked to sign —
tamper *detection* is the verifier's job, not the PTA's).

During a successful verification, copy the reported `TA digest (hex)` value
into a host-side file, one line only:

```bash
printf '%s\n' '<paste TA digest hex here>' > known_good_digest.txt
```

Now make a source change that changes the compiled TA binary (a comment-only
edit usually will not change the measurement), then rebuild and reboot QEMU:

```bash
nano ~/optee/optee_examples/ra-pta/ta/ra_demo_ta.c
# From ~/optee/build: ./pta-build.sh
# Reboot QEMU using ./start-optee.sh
```

Issue a new challenge on the host, copy it into the guest, request new evidence,
then verify **against the original digest**. Use the same host `CHALLENGE` for
all steps in this single round:

```bash
CHALLENGE=$(python3 "$VERIFIER" --issue-challenge)
printf 'Copy to QEMU: %s\n' "$CHALLENGE"
# In QEMU: optee_example_ra_pta attest 'PASTE_CHALLENGE_HERE' /mnt/host
# Back on the host:
python3 "$VERIFIER" --challenge "$CHALLENGE" \
    --exp pubkey_exp.bin --mod pubkey_mod.bin --evidence evidence.bin \
    --expected-digest "$(cat known_good_digest.txt)"
```

Expected result:

```
Signature valid:      YES
Digest matches known-good build: NO

RA RESULT: FAIL
```

This split is the important part: **signature validity** proves the
*report itself* is authentic (genuinely came from this TEE); the
**digest comparison** is what proves the *code* wasn't modified. Both
checks matter, and they're testing different things.

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `which optee_example_ra_pta` returns nothing | Build didn't include it, likely a stale package cache | `./pta-build.sh clean` then rebuild |
| `TEEC_OpenSession(attestation PTA) failed 0xffff0008` | `CFG_ATTESTATION_PTA` missing from the build that's currently running | Rebuild with all 3 flags together (§4), then **reboot QEMU** — the currently-running instance still has the old `tee.elf` |
| `mount: mounting host on /mnt/host failed: No such file or directory` / `9pnet_virtio: no channels available` | `QEMU_VIRTFS_ENABLE` wasn't part of the build, or wasn't part of the **run** command | Rebuild AND make sure `start-optee.sh`/`run-only` also gets the flag — it's needed at both build time (compiles 9p support into QEMU) and run time (adds the actual `-fsdev` flags to the launch command) |
| `ls /mnt/host` shows only a lone `README` | Mount silently failed, you're looking at a placeholder baked into the rootfs, not the real share | Re-check the mount command actually returned no error; re-verify `QEMU_VIRTFS_ENABLE=y` was really used |
| Build error: `pta_attestation.h: No such file or directory` in `host/main.c` | Someone tried to `#include <pta_attestation.h>` from the CA side | That header is TA-devkit-only; the CA-safe constants are already provided as `RA_DEMO_PTA_ATTESTATION_*` in `ta/include/ra_demo_ta.h` — use those instead |
| `tmux`: "server exited unexpectedly" right after `./start-optee.sh` | Usually a timing issue — QEMU took longer than the script's `sleep` to initialize before `c` was sent to the monitor | Edit `start-optee.sh`, increase `sleep 3` to `sleep 5` or more |
| Typed a command, nothing happens / weird prompt | You're in the wrong pane — QEMU monitor (`(qemu)`), guest shell (`#`), and host shell (`user@host:~$`) are three different consoles | Check the prompt style; `Ctrl-b` + arrows to switch tmux panes |
| `find ~/optee -name whatever` returns nothing when you're sure the file exists | You ran it inside the guest, not the host | `~` inside the guest is a completely separate, tiny filesystem — switch to your actual host shell |

---

## 10. Known simplifications vs. a full RA deployment

- **No networked Relying Party / no authenticated transport.** This demo
  manually copies verifier-issued challenges into QEMU instead of using a live
  protocol over an authenticated channel. The verifier does track outstanding,
  expiring, one-use challenges locally, but a production deployment still needs
  a carefully designed authenticated transport and protected verifier state.
- **No Provisioner, no certificate chain.** `verifier.py` trusts
  whatever `pubkey_*.bin` you hand it, with no endorsement chain back to
  a hardware root or manufacturer CA. Keep the public-key files in a trusted
  location and pin/validate the key out of band; if an attacker can replace
  both the key and evidence, signature verification alone can be bypassed.
  Fine for demonstrating the mechanism; not sufficient for a real
  "unforgeable hardware-rooted identity" claim.
- **QEMU's hardware root isn't real.** OP-TEE's Hardware Unique Key
  (HUK) on the `virt` QEMU platform is a hardcoded placeholder value in
  source, not a real fused secret — every QEMU instance has the same
  one. Any "device identity" claim built on this only demonstrates
  correct *protocol logic*, not genuine hardware-rooted uniqueness. Real
  hardware (e.g. i.MX, HiKey960, STM32MP1) is needed for that claim.
