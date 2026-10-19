# Remote Attestation on the Raspberry Pi 4 — fTPM and hardware TPM

A minimal remote-attestation system that lets a trusted **verifier** confirm,
over the network, that a remote Raspberry Pi 4 is in the state it was enrolled
in. The device proves this with a TPM-signed *quote*: a set of Platform
Configuration Registers (PCRs) signed by an attestation key that never leaves
the TPM. Because the quote is signed inside the TPM and bound to a fresh nonce,
the proof holds even against a fully compromised Linux userspace — including
root.

The system runs against **two independent attestation targets on the same Pi**,
and the verifier has a mode for each:

| Device | TPM | What is measured | PCR | Verification |
|--------|-----|------------------|-----|--------------|
| **`ftpm`** | OP-TEE firmware TPM (`/dev/tpmrm1`) | Verifier-chosen files, re-measured each round | 16 | Absolute: PCR 16 recomputed from zero |
| **`tpm`**  | LetsTrust hardware TPM (`/dev/tpmrm0`) | The kernel's IMA runtime log | 10 | Anchored: new IMA entries chained onto the enrolled PCR 10 |

- **`main.c`** — the Client Application (CA) that runs on the Pi. It is a pure
  relay: it never decides what gets measured and never handles a secret.
- **`verifier.py`** — runs on a trusted machine (your PC). It issues the
  challenge, renders the verdict, and records latency/verdict data for the
  benchmark and DoS experiments. One verifier binary, selected per device.

---

## How it works

### The two attestation models

The two devices answer the same question — "is this Pi unchanged since
enrollment?" — but build the evidence differently.

**fTPM (`/dev/tpmrm1`, PCR 16, verifier-chosen files).** PCR 16 is resettable
from Linux, so each round the CA resets it and rebuilds it from scratch:

```
PCR16 = 0
PCR16 = SHA256(PCR16 || SHA256(nonce))
PCR16 = SHA256(PCR16 || SHA256(file))   for each file, in list order
```

The verifier recomputes this value **from zero** using *this round's* nonce and
the reported file hashes. A missing file is hashed as the literal text
`MISSING <path>` so its absence is detectable rather than silently skipped.
This mode is stateless — it needs no stored PCR anchor.

**Hardware TPM (`/dev/tpmrm0`, PCR 10, IMA).** PCR 10 is the kernel's IMA log
register: it is append-only and the kernel extends it with every measured file
at runtime. The CA does not choose anything — it just returns the current IMA
log. Two facts about this board forced an *anchored* design:

- **PCR 10 does not start at zero.** It is extended before IMA's first log
  entry, so replaying the log from an all-zero start never reproduces the live
  value. (Confirmed empirically — see `ima_probe5.py`.)
- The per-entry extend is `PCR = SHA256(PCR || SHA256(template_data))`, over the
  `ima-ng` template data. A zero template hash (an IMA violation) extends a
  run of `0xff` bytes instead.

So instead of an absolute replay, the verifier stores the PCR 10 value and log
length **captured at enrollment**, and on each later round chains only the
*new* IMA entries onto that anchor, checking the result equals the freshly
signed PCR 10. This is immune to whatever value PCR 10 held before IMA started.

### The PCR sets, and a note on this board

| PCRs | Filled by | Resettable from Linux? | On this Pi |
|------|-----------|------------------------|------------|
| 0–7  | The boot chain, before Linux starts | No (extend-only) | **All zero** |
| 10   | IMA, at runtime | No (extend-only) | Non-zero; grows continuously |
| 16   | The CA, per round | Yes (reset + extend) | Rebuilt each round |

> **Platform finding worth citing.** The RPi4 boot path does **no measured boot
> into the TPM**, so PCRs 0–7 are all zeros and carry no boot-integrity
> evidence here. Integrity therefore rests on PCR 10 (IMA) + the AK signature +
> the per-round nonce, not on the boot-chain PCRs. The verifier still enrolls
> and checks PCRs 0–7 so the property is exercised, but on a platform with
> measured boot they would additionally prove the firmware/bootloader/kernel.

### The attestation key (AK)

The AK is an ECC P-256 signing key created as a **TPM primary key** under the
endorsement hierarchy. Being primary means the TPM re-derives the *same* key
deterministically on every run — no key material is stored on disk. It is
marked `restricted`, so the TPM will only ever use it to sign structures it
produced itself (like quotes), never arbitrary attacker-supplied data.

### What the verifier checks

For a verdict of `TRUSTED`, every one of these must hold:

1. **Signature** — the quote is validly signed by the enrolled AK.
2. **Freshness** — the nonce in the quote equals the one just sent (no replay).
3. **PCR integrity** — `SHA256(concatenated PCR values)` equals the PCR digest
   inside the signed quote (the reported PCRs really are the signed ones).
4. **State binding** —
   - *fTPM:* replaying the reported file hashes through the PCR-16 formula from
     this round's nonce reproduces the signed PCR 16.
   - *TPM:* chaining the new IMA entries onto the enrolled PCR-10 anchor
     reproduces the signed PCR 10, and every new entry's file is in the
     enrolled allowlist.
5. **Identity** — the AK matches the enrolled device.
6. **Boot state** — PCRs 0–7 match the enrolled values.

A failure at any step yields a specific `FAIL: ...` message instead.

---

## Wire protocol

Every message is length-prefixed: a 4-byte big-endian length followed by that
many bytes of payload. The CA sends five messages per round; the fifth differs
by device.

```
verifier -> CA   'A' + nonce_len(1 byte) + nonce [ + file_list for fTPM ]

CA -> verifier   AK public key   (TPM2B_PUBLIC, marshalled)
                 quote           (TPMS_ATTEST)
                 signature       (TPMT_SIGNATURE, marshalled)
                 PCR values      (9 × 32 bytes: PCRs 0-7, then 16 or 10)
                 evidence        fTPM: file hashes (32 bytes each, in order)
                                 TPM:  binary IMA runtime measurements log

verifier -> CA   verdict text
```

The connection is persistent: the CA connects once and stays connected,
reconnecting automatically with a backoff if the link drops. The verifier
handles one attester at a time and returns to waiting on disconnect.

---

## Platform and networking

The verifier needs Python 3 and `cryptography`, which live on your **PC**. The
CA is cross-compiled for aarch64 and runs on the **Pi** inside the Debian
chroot at `/opt/pi4-debian`, which supplies the TSS libraries the binary links
against (the Pi's base system lacks a matching runtime, which caused the
earlier `Bus error`).

The PC and Pi are not on the same subnet, so the CA reaches the verifier over
an **SSH reverse tunnel**. From the PC you SSH into the Pi with `-R`, which
makes the Pi's `127.0.0.1:5000` forward back to the verifier listening on the
PC. The CA then simply connects to `127.0.0.1:5000`.

Add the Pi to your `~/.ssh/config` as `rpi4-optee` once, then the tunnel is a
single command (shown in each chain below).

---

## Running

Each experiment is a **pair**: a verifier script on your PC and a runner script
on the Pi. Start the verifier first (it listens), then start the Pi runner
(it connects and drives the rounds, exiting by itself when done). `DEVICE_NAME`
selects `ftpm` or `tpm`.

### RPi4 setup (once)

```sh
./deploy-rpi4-ssh.sh
```

### fTPM

**Enroll** (run once after each reboot, before anything else):

```sh
# On the Pi (from your PC — opens the reverse tunnel and a Pi shell):
ssh -R 5000:localhost:5000 rpi4-optee          # add rpi4-optee to ~/.ssh/config
chroot /opt/pi4-debian /bin/bash && cd root/host

# On your PC:
DEVICE_NAME=ftpm ./Verifiers/shells/enroll-verifier.sh

# On the Pi:
./ftpm-enroll-ssh.sh
```

**Benchmark:**

```sh
# On your PC:
DEVICE_NAME=ftpm ./Verifiers/shells/benchmark-verifier.sh <runs> <requests-per-run>

# On the Pi:
./ftpm-benchmark-ssh.sh <runs> <requests-per-run>
```

**DoS sweep:**

```sh
# On your PC:
DEVICE_NAME=ftpm LEVELS="<load-levels>" ./Verifiers/shells/dos-verifier.sh <requests>

# On the Pi:
./ftpm-dos-ssh.sh <requests>
```

### Hardware TPM (IMA)

Same chain, `DEVICE_NAME=tpm` and the `tpm-*` runners:

**Enroll:**

```sh
# On the Pi (from your PC):
ssh -R 5000:localhost:5000 rpi4-optee
chroot /opt/pi4-debian /bin/bash && cd root/host

# On your PC:
DEVICE_NAME=tpm ./Verifiers/shells/enroll-verifier.sh

# On the Pi:
./tpm-enroll-ssh.sh
```

**Benchmark:**

```sh
# On your PC:
DEVICE_NAME=tpm ./Verifiers/shells/benchmark-verifier.sh <runs> <requests-per-run>

# On the Pi:
./tpm-benchmark-ssh.sh <runs> <requests-per-run>
```

**DoS sweep:**

```sh
# On your PC:
DEVICE_NAME=tpm LEVELS="<load-levels>" ./Verifiers/shells/dos-verifier.sh <requests>

# On the Pi:
./tpm-dos-ssh.sh <requests>
```

### Idle baseline

Measures the device's CPU utilisation `U` while **no** attestation is running,
using the same `bench.h` instrumentation so `U` is directly comparable to the
benchmark. Only `U` is meaningful here — `T_FTPM` is just the sampling window
and `T_CPU` is ~0.

```sh
# On the Pi (from your PC):
ssh -R 5000:localhost:5000 rpi4-optee
chroot /opt/pi4-debian /bin/bash && cd root/host

# On your PC:
DEVICE_NAME=idle ./Verifiers/shells/idle-verifier.sh

# On the Pi:
./idle-runner-ssh.sh <runs> <requests> <wait-window>
```

---

## The scripts

**On the Pi (`RPi4/`):**

| Script | Purpose |
|--------|---------|
| `ftpm-enroll-ssh.sh` / `tpm-enroll-ssh.sh` | Enroll the device **once** per boot. Sends exactly one (enrolling) request, then exits. |
| `ftpm-benchmark-ssh.sh` / `tpm-benchmark-ssh.sh` | Run the benchmark: `<runs>` runs of `<requests-per-run>` requests. Exits by itself; one CSV per run. |
| `ftpm-dos-ssh.sh` / `tpm-dos-ssh.sh` | Run the DoS sweep over load levels, `<requests>` each. Exits by itself; one CSV per level. |
| `idle-runner-ssh.sh` | Idle `U` baseline: `<runs> <requests> <wait-window>`. |

**On your PC (`Verifiers/shells/`):**

| Script | Purpose |
|--------|---------|
| `enroll-verifier.sh` | Verifier side of enroll. One request, then exits. |
| `benchmark-verifier.sh` | Verifier side of the benchmark. One CSV per run. |
| `dos-verifier.sh` | Verifier side of the DoS sweep (`LEVELS=...`). One CSV per level. |
| `idle-verifier.sh` | Not actually a verifier — collects the idle results and prints a summary. Run after `idle-runner-ssh.sh` finishes. |

Each verifier script takes the device via `DEVICE_NAME` and must be started
before its Pi counterpart.

---

## Benchmarking and analysis

The benchmark measures the resource overhead attestation adds on the Pi:
wall-clock TPM time (`T_FTPM`), CA-process CPU time (`T_CPU`), system CPU
utilisation (`U`), and peak memory (`RSS`). The CA writes one CSV per run; the
DoS verifier additionally records, per request, the CA-side latency joined to
the verifier's verdict (success / fail / timeout), so you can plot latency and
success rate against load level.

Analyse with:

```sh
python3 FTPM/ftpm-analyzers/ftpm-benchmark-analyzer.py
```

With no arguments it reads the run CSVs and writes a summary and plot. To
compare against a no-security baseline, pass those runs with `--baseline`:

```sh
python3 FTPM/ftpm-analyzers/ftpm-benchmark-analyzer.py sec/run*.csv --baseline base/run*.csv
```

The DoS results have their own analyzer:

```sh
python3 FTPM/ftpm-analyzers/ftpm-dos-analyzer.py
```

---

## Trust model and limitations

**What this protects against**
- Tampering with an enrolled file (changed, replaced, or deleted) — fTPM via
  PCR 16, hardware TPM via a new/altered IMA entry against the allowlist.
- Replay of an old quote — prevented by the per-round nonce.
- Impersonation by another device — the AK is TPM-resident and identity-bound.

**What it does not cover**
- **Boot integrity on this board.** PCRs 0–7 are all zero because the RPi4 does
  no measured boot into the TPM, so they prove nothing about the firmware or
  kernel here. On a platform with measured boot they would.
- **Time-of-check / time-of-use.** A measurement is trusted as of the moment it
  was taken; the state can change immediately afterwards. Attestation is a
  snapshot, not continuous enforcement — attest on a schedule for ongoing
  assurance. (IMA narrows this for files it measures, since any later access
  appends a new, checkable log entry.)
- **The verifier is the root of trust.** It must run on a trusted host and keep
  its enrollment state (`enrolled_device.json`) safe. There is no transport
  encryption in the protocol itself; security comes from the signed quote and
  nonce. Here the channel is still carried over SSH.
- **Enrollment is trust-on-first-use.** Whatever state the device is in at
  `enroll` time becomes "known-good." Enroll only a device you trust, on a
  clean boot.

---

## File layout

Not good but whatever:
```
deploy-rpi4-ssh.sh                                Stages CA + scripts onto the Pi
RPi4/main.c                                       CA / attester source (C, runs on the Pi, both TPMs)
RPi4/bench.h                                      Per-request benchmark hooks for the CA
RPi4/idle_bench.c                                 Idle CPU-utilisation baseline (reuses bench.h)
RPi4/ftpm-enroll-ssh.sh, ftpm-benchmark-ssh.sh, ftpm-dos-ssh.sh   fTPM runners (on the Pi)
RPi4/tpm-enroll-ssh.sh,  tpm-benchmark-ssh.sh,  tpm-dos-ssh.sh    hardware-TPM runners (on the Pi)
RPi4/idle-runner-ssh.sh                           Idle runner (on the Pi)
Verifiers/verifier.py                             Verifier (Python; --enroll / --benchmark / --dos)
Verifiers/shells/enroll-verifier.sh               Verifier side of enroll (on the PC)
Verifiers/shells/benchmark-verifier.sh            Verifier side of the benchmark (on the PC)
Verifiers/shells/dos-verifier.sh                  Verifier side of the DoS sweep (on the PC)
Verifiers/shells/idle-verifier.sh                 Collects + summarises the idle results (on the PC)
FTPM/ftpm-analyzers/ftpm-benchmark-analyzer.py    Summarises + plots the benchmark
FTPM/ftpm-analyzers/ftpm-dos-analyzer.py          Summarises + plots the DoS sweep
enrolled_device.json                              Written by the verifier on 'enroll'
```