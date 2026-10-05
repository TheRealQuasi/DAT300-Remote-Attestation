# Remote Attestation with OP-TEE's fTPM

A minimal remote-attestation system that lets a trusted **verifier** confirm,
over the network, that a remote device booted the expected software and that a
set of chosen files are byte-for-byte unchanged since enrollment. The proof is
anchored in OP-TEE's firmware TPM (fTPM), so it holds even against a fully
compromised Linux userspace — including root.

- **`main.c`** — the Client Application (CA) that runs on the device being
  attested. It is a pure relay: it never decides what gets measured and never
  handles a secret.
- **`verifier.py`** — the verifier that runs on a trusted machine (e.g. Ubuntu).
  It chooses what to measure, issues challenges, and renders the verdict.

---

## How it works

The device proves its state by building a PCR (Platform Configuration Register)
value inside the fTPM and having the fTPM sign it with an attestation key that
never leaves the TPM.

### The two sets of PCRs

| PCRs | Filled by | Resettable from Linux? | Proves |
|------|-----------|------------------------|--------|
| 0–7  | The boot chain, before Linux starts | No (extend-only) | The device booted the expected firmware/bootloader/kernel |
| 16   | The CA, per attestation round | Yes (reset + extend) | The chosen files currently hash to known-good values |

The security property that makes this worth doing: **PCRs 0–7 cannot be reset
from Linux, only extended.** A compromised root can push bad values into them
(causing a `FAIL`), but can never forge them back to the enrolled values,
because what goes into them was decided before Linux ran.

### One attestation round

Each time the verifier issues an `attest` (or `enroll`) command:

1. **Challenge.** The verifier sends a fresh 32-byte nonce plus the list of
   files to measure.
2. **Measure.** The CA resets PCR 16 and rebuilds it from scratch inside the
   fTPM:
   ```
   PCR16 = 0
   PCR16 = SHA256(PCR16 || SHA256(nonce))
   PCR16 = SHA256(PCR16 || SHA256(file))   for each file, in list order
   ```
   The fTPM does the hashing; the CA only streams bytes in. A missing file is
   hashed as the literal text `MISSING <path>` so its absence is detectable
   rather than silently skipped.
3. **Quote.** The CA asks the fTPM to sign a *quote* over PCRs 0–7 + 16 together
   with the nonce, using the attestation key (AK).
4. **Report.** The CA sends back the AK public key, the quote, the signature,
   the raw PCR values, and each file's SHA-256 (in list order).
5. **Verify.** The verifier checks the whole chain (see below) and sends back a
   one-line verdict, which the CA prints.

### The attestation key (AK)

The AK is an ECC P-256 signing key created as an **fTPM primary key** under the
endorsement hierarchy. Being primary means the fTPM re-derives the *same* key
deterministically on every run — no key material is stored on disk. It is
marked `restricted`, so the fTPM will only ever use it to sign structures it
produced itself (like quotes), never arbitrary attacker-supplied data.

### What the verifier checks

For a verdict of `TRUSTED`, every one of these must hold:

1. **Signature** — the quote is validly signed by the enrolled AK.
2. **Freshness** — the nonce in the quote equals the one just sent (no replay).
3. **PCR integrity** — `SHA256(concatenated PCR values)` equals the PCR digest
   inside the signed quote (the reported PCRs really are the signed ones).
4. **File binding** — replaying the reported file hashes through the PCR-16
   formula, starting from *this round's* nonce, reproduces the signed PCR 16.
5. **Identity** — the AK matches the enrolled device.
6. **Boot state** — PCRs 0–7 match the enrolled values.
7. **File state** — every file's hash matches its enrolled value.

A failure at any step yields a specific `FAIL: ...` message instead.

---

## Wire protocol

Every message is length-prefixed: a 4-byte big-endian length followed by that
many bytes of payload.

```
verifier -> CA   'A' + nonce_len(1 byte) + nonce + file_list
                 (file_list = paths separated by '\n')

CA -> verifier   AK public key   (TPM2B_PUBLIC, marshalled)
                 quote           (TPMS_ATTEST)
                 signature       (TPMT_SIGNATURE, marshalled)
                 PCR values      (9 × 32 bytes: PCRs 0-7, then 16)
                 file hashes     (32 bytes each, in file-list order)

verifier -> CA   verdict text
```

The connection is persistent: the CA connects once and stays connected,
reconnecting automatically with a 3-second backoff if the link drops. The
verifier handles one attester at a time and returns to waiting on disconnect.

---

## Building and running

### Prerequisites

**On the device (CA):**
- OP-TEE with the fTPM trusted application running, exposing `/dev/tpmrm0`
- The TPM2 TSS libraries (ESAPI, MU, RC, TCTI loader)

  ```sh
  sudo apt install libtss2-dev
  ```

**On the verifier:**
- Python 3
  ```sh
  sudo apt install python3-cryptography
  ```

### Build the CA

The CA is packaged as an OP-TEE example, so it builds as part of the OP-TEE
tree. Copy it in alongside the build scripts:

```sh
# Copy the example into the OP-TEE examples tree
cp -r FTPM/ra-ftpm ~/optee/optee_examples/
ls -R ~/optee/optee_examples/ra-ftpm

# Copy the build/run helper scripts into the build dir
cp -r build.sh start-optee.sh ~/optee/build/
ls ~/optee/build
```

Then build and boot the emulated device from `~/optee/build/`:

```sh
cd ~/optee/build
./build.sh
./start-optee
```

This drops you into the OP-TEE QEMU environment. OP-TEE boots secure world
(with the fTPM trusted application) and normal world (Linux) side by side in
two tmux panes.

> **Switching tmux panes:** `Ctrl-b` then `Ctrl-o`.

Standalone (non-OP-TEE) build, if you ever want the CA against a host TPM:

```sh
gcc -o ra_ftpm_ca main.c -ltss2-esys -ltss2-mu -ltss2-rc -ltss2-tctildr
```

### Run

**1. Create something to protect** (in the normal-world Linux shell):

```sh
echo "Root access? Bold move." > /root/protected.txt
```

**2. Start the verifier** on your host machine:

```sh
python3 FTPM/ra-ftpm/verifier.py --file /root/protected.txt
```

**3. Start the attester** in normal world, pointing at the host. Under QEMU the
host is reachable at `10.0.2.2`:

```sh
optee_example_ra_ftpm 10.0.2.2 5000 &
```

**4. Enroll, then attest** from the verifier's prompt:

```
Command [enroll / attest / quit]: enroll
  -> ENROLLED (1 files)
Command [enroll / attest / quit]: attest
  -> TRUSTED
```

- **`enroll`** — captures the current state as known-good and writes it to
  `enrolled_device.json` (AK, boot PCRs 0–7, and each file's hash). Run this
  once, on a device you trust.
- **`attest`** — challenges the device and compares against the enrollment.
- **`quit`** — stops the verifier.

> The file list is fixed by the verifier's `--file` flags for the session, so
> use the **same files** for `enroll` and later `attest` rounds.

### Testing the integrity check

To see a tampered file get caught, change it in normal world after enrolling:

```sh
echo "root access? Bold move." > /root/protected.txt
```

Then run `attest` again from the verifier. The single-byte change flips the
file's hash, so PCR 16 no longer matches the enrolled value and the verdict
becomes:

```
  -> FAIL: /root/protected.txt has been modified (or is missing)
```

Restore the original contents and `attest` once more to go back to `TRUSTED`.

---

## Options

**Verifier (`verifier.py`):**

| Flag | Default | Meaning |
|------|---------|---------|
| `--port` | `5000` | TCP port to listen on |
| `--state` | `enrolled_device.json` | Where enrollment data is stored |
| `--file PATH` | (none) | A file the attester must hash; repeatable |

**CA (`ra_ftpm_ca`):**

```
ra_ftpm_ca <verifier-ip> <port>
```

Compile-time limits: up to `MAX_FILES` (32) files per round and a `MAX_CMD`
(4096-byte) command buffer.

---

## Trust model and limitations

**What this protects against**
- Tampering with any enrolled file (changed, replaced, or deleted) — detected
  via PCR 16.
- Booting modified firmware/bootloader/kernel — detected via PCRs 0–7, which
  Linux cannot forge.
- Replay of an old quote — prevented by the per-round nonce.
- Impersonation by another device — the AK is TPM-resident and identity-bound.

**What it does not cover**
- **Time-of-check / time-of-use.** A file is trusted as of the moment it was
  hashed; it can be modified immediately afterwards. Attestation is a snapshot,
  not continuous enforcement. Attest on a schedule if you need ongoing assurance.
- **The verifier is the root of trust.** It must run on a trusted host and keep
  `enrolled_device.json` safe. There is no transport encryption here; the
  security comes from the signed quote and nonce, not from the channel, but you
  should still run this over a trusted or tunnelled network.
- **Enrollment is trust-on-first-use.** Whatever state the device is in at
  `enroll` time becomes "known-good." Enroll only a device you have reason to
  trust.
- **PCRs 0–7 reflect the boot chain, not the full running kernel.** They prove
  what was measured at boot, not that nothing was patched in memory afterwards.

---

## File layout

```
main.c                 CA / attester source (C, runs on the device)
verifier.py            Verifier (Python, runs on the trusted host)
enrolled_device.json   Written by the verifier on 'enroll'
```
