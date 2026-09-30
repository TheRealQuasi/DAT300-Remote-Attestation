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
 │                  │◄─────────────────────┤  optee_example_ra_demo CA  │
 │  verifier.py     │                      │                            │
 │                  │  (1) attest <nonce>  │  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  │
 │                  │◄─────────────────────┤  Secure World              │
 │                  │                      │  ra_demo TA  ──► calls ──► │
 │  checks signature│                      │  Attestation PTA (built    │
 │  + digest         │                      │  into optee_os)            │
 └─────────────────┘                      └───────────────────────────┘
```

Two commands, both run inside the QEMU guest:

- **`optee_example_ra_demo pubkey`** — fetches the Attestation PTA's
  public RSA key directly (no TA mediation needed for this call).
  Saved as your trust anchor.
- **`optee_example_ra_demo attest <nonce>`** — asks our custom `ra_demo`
  TA to request signed evidence from the PTA for *itself*: a SHA-256
  measurement of the TA's own code+rodata, signed together with your
  nonce. The PTA's private key never leaves secure world.

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

From the root of this repo:

```bash
cp -r ra_demo ~/optee/optee_examples/
cp start-optee.sh build.sh ~/optee/build/
chmod +x ~/optee/build/start-optee.sh ~/optee/build/build.sh
```

That's it for installation — the build system auto-discovers any
subdirectory of `optee_examples/` that has its own `CMakeLists.txt`
(which `ra_demo/` does), and the TA gets picked up separately via a
build-system hook that scans for `*/ta/Makefile`.

**If you want a different TA UUID** (e.g. to avoid any chance of
collision with other custom TAs in your project), generate one and
update it in two places — see the comment at the top of
`ra_demo/ta/include/ra_demo_ta.h`.

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

We've provided `build.sh` so you never have to type these by hand:

```bash
cd ~/optee/build
./build.sh
```

If `ra_demo` doesn't show up after a build (check with
`which optee_example_ra_demo` after booting — see below), the most
likely cause is a **stale Buildroot package cache** from an earlier
build that predates adding `ra_demo`. Force a clean rebuild of just that
package:

```bash
./build.sh clean
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
which optee_example_ra_demo
```

Should print `/usr/bin/optee_example_ra_demo`. If this is empty, the
build didn't include it — see the Troubleshooting section.

### 6.3 Fetch the public key (once)

```sh
optee_example_ra_demo pubkey
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

### 6.4 Request attestation evidence

```sh
optee_example_ra_demo attest "test-$(date +%s)"
```

Expected output:

```
Evidence retrieved: 288 bytes (32-byte digest + signature)
  wrote /mnt/host/evidence.bin (288 bytes)
  wrote /mnt/host/nonce.bin (15 bytes)
```

(288 bytes = 32-byte SHA-256 digest + 256-byte RSA signature.)

You can run `attest` as many times as you like with different nonces —
each run overwrites `evidence.bin`/`nonce.bin` with a fresh pair.

---

## 7. Verifying, on the host

Switch to your **host** shell (not the guest) — a separate terminal, SSH
session, or another tmux window entirely (this is not one of the three
panes `start-optee.sh` created).

```bash
cd ~/optee   # or wherever /mnt/host mapped to (see note in 6.1)
pip install cryptography --break-system-packages   # first time only
python3 optee_examples/ra_demo/verifier.py \
    --exp pubkey_exp.bin --mod pubkey_mod.bin \
    --evidence evidence.bin --nonce nonce.bin
```

Expected output:

```
Nonce (raw):          b'test-1234567890'
TA digest (hex):      f0607a82c8040f13623eb94e96cd096425b44fb21eb992880a07b9328a1648f3
Signature length:     256 bytes
Signature valid:      YES
(no --expected-digest given - skipping code-integrity check, only signature authenticity was verified)

RA RESULT: PASS
```

**PASS means:** the signature is a genuine RSASSA-PSS-SHA256 signature,
produced by the Attestation PTA's private key (which never left secure
world), over exactly `SHA256(your nonce || the TA's own code digest)`.
Nobody forged this outside the TEE, and it's bound to your specific
nonce (so it can't be replayed against a different challenge).

---

## 8. Testing tamper detection

This is the more interesting test: showing that the digest changes when
the TA's code changes, even though the signature itself stays valid
(because the PTA still faithfully signs whatever it's asked to sign —
tamper *detection* is the verifier's job, not the PTA's).

```bash
# 1. Run the flow once as above, note the digest
python3 optee_examples/ra_demo/verifier.py \
    --exp pubkey_exp.bin --mod pubkey_mod.bin \
    --evidence evidence.bin --nonce nonce.bin | grep digest

# Save it
echo "<paste the digest hex here>" > known_good_digest.txt
```

Now modify the TA — anything, even a comment:

```bash
nano ~/optee/optee_examples/ra_demo/ta/ra_demo_ta.c
```

Rebuild, reboot, re-run `attest` with a fresh nonce (steps 4–6 above),
then verify **against the original digest**:

```bash
python3 optee_examples/ra_demo/verifier.py \
    --exp pubkey_exp.bin --mod pubkey_mod.bin \
    --evidence evidence.bin --nonce nonce.bin \
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
| `which optee_example_ra_demo` returns nothing | Build didn't include it, likely a stale package cache | `./build.sh clean` then rebuild |
| `TEEC_OpenSession(attestation PTA) failed 0xffff0008` | `CFG_ATTESTATION_PTA` missing from the build that's currently running | Rebuild with all 3 flags together (§4), then **reboot QEMU** — the currently-running instance still has the old `tee.elf` |
| `mount: mounting host on /mnt/host failed: No such file or directory` / `9pnet_virtio: no channels available` | `QEMU_VIRTFS_ENABLE` wasn't part of the build, or wasn't part of the **run** command | Rebuild AND make sure `start-optee.sh`/`run-only` also gets the flag — it's needed at both build time (compiles 9p support into QEMU) and run time (adds the actual `-fsdev` flags to the launch command) |
| `ls /mnt/host` shows only a lone `README` | Mount silently failed, you're looking at a placeholder baked into the rootfs, not the real share | Re-check the mount command actually returned no error; re-verify `QEMU_VIRTFS_ENABLE=y` was really used |
| Build error: `pta_attestation.h: No such file or directory` in `host/main.c` | Someone tried to `#include <pta_attestation.h>` from the CA side | That header is TA-devkit-only; the CA-safe constants are already provided as `RA_DEMO_PTA_ATTESTATION_*` in `ta/include/ra_demo_ta.h` — use those instead |
| `tmux`: "server exited unexpectedly" right after `./start-optee.sh` | Usually a timing issue — QEMU took longer than the script's `sleep` to initialize before `c` was sent to the monitor | Edit `start-optee.sh`, increase `sleep 3` to `sleep 5` or more |
| Typed a command, nothing happens / weird prompt | You're in the wrong pane — QEMU monitor (`(qemu)`), guest shell (`#`), and host shell (`user@host:~$`) are three different consoles | Check the prompt style; `Ctrl-b` + arrows to switch tmux panes |
| `find ~/optee -name whatever` returns nothing when you're sure the file exists | You ran it inside the guest, not the host | `~` inside the guest is a completely separate, tiny filesystem — switch to your actual host shell |

---

## 10. Known simplifications vs. a full RA deployment

- **No Relying Party, no live challenge/response.** The nonce is just a
  CLI argument you pick, not something a server generates and tracks for
  freshness/replay protection. A real deployment needs a nonce registry
  (used-once enforcement) on the verifier side.
- **No Provisioner, no certificate chain.** `verifier.py` trusts
  whatever `pubkey_*.bin` you hand it, with no endorsement chain back to
  a hardware root or manufacturer CA. Fine for demonstrating the
  mechanism; not sufficient for a real "unforgeable hardware-rooted
  identity" claim.
- **QEMU's hardware root isn't real.** OP-TEE's Hardware Unique Key
  (HUK) on the `virt` QEMU platform is a hardcoded placeholder value in
  source, not a real fused secret — every QEMU instance has the same
  one. Any "device identity" claim built on this only demonstrates
  correct *protocol logic*, not genuine hardware-rooted uniqueness. Real
  hardware (e.g. i.MX, HiKey960, STM32MP1) is needed for that claim.
