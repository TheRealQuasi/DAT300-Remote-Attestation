# ra_demo — Code Walkthrough

This document explains *how* the code works, file by file. For build and
run instructions, see [`SETUP_AND_VERIFICATION.md`](SETUP_AND_VERIFICATION.md).

## Background: why this isn't a from-scratch crypto implementation

OP-TEE ships a built-in **Attestation Pseudo-TA** (a "PTA" — a
trusted-service that lives inside `optee_os` itself, compiled directly
into `tee.elf`, rather than a regular TA loaded from a `.ta` file). It
lives at `core/pta/attestation.c` in the `optee_os` source tree and
already implements exactly the primitive a remote-attestation scheme
needs: generate a keypair that never leaves secure world, and sign a
measurement of a TA's code together with a caller-supplied nonce.

This project's job is *not* to reimplement that — it's to build a thin
CA/TA pair that calls it correctly, plus an offline verifier to check
the result. That's why the amount of actual custom code here is small.

---

## File-by-file

### `ta/include/ra_demo_ta.h` — shared constants

Included by **both** the TA and the CA. Two separate concerns live here:

**1. Our own TA's identity and command interface:**

```c
#define TA_RA_DEMO_UUID \
	{ 0xbb9a73d7, 0x684b, 0x4785, \
		{ 0x9e, 0x39, 0x06, 0xbf, 0xaa, 0xb9, 0xa2, 0xef } }

#define TA_RA_CMD_GET_EVIDENCE 0
```

`TA_RA_DEMO_UUID` is our TA's identity — every OP-TEE TA is addressed by
UUID rather than by name. `TA_RA_CMD_GET_EVIDENCE` is the (single)
command our TA exposes to callers: "give me signed evidence for
yourself, bound to this nonce."

**2. A local mirror of two constants from optee_os's real
`pta_attestation.h`:**

```c
#define RA_DEMO_PTA_ATTESTATION_UUID \
	{ 0x39800861, 0x182a, 0x4720, \
		{ 0x9b, 0x67, 0x2b, 0xcd, 0x62, 0x2b, 0xc0, 0xb5 } }
#define RA_DEMO_PTA_ATTESTATION_GET_PUBKEY 0x0
```

This exists because of a build-environment quirk worth understanding:
`optee_os`'s real `pta_attestation.h` lives under the **TA dev-kit**
headers — headers that get exported for compiling *TAs* (secure-world
code), not for compiling *CAs* (normal-world code, which only links
against `libteec`). Our TA (`ra_demo_ta.c`) includes the real header
directly and it works fine, because the TA build has the full TA dev-kit
available. Our CA (`host/main.c`) cannot include it — `libteec` simply
doesn't export it — so the two constants the CA actually needs are
duplicated here under different names (`RA_DEMO_PTA_ATTESTATION_*`
rather than `PTA_ATTESTATION_*`) to avoid any macro collision with the
real header the TA side includes.

---

### `ta/ra_demo_ta.c` — the Trusted Application

This is the only piece of secure-world code we wrote ourselves. It's
short because almost all the actual cryptographic work happens inside
the Attestation PTA, not here.

**Entry points** (`TA_CreateEntryPoint`, `TA_DestroyEntryPoint`,
`TA_OpenSessionEntryPoint`, `TA_CloseSessionEntryPoint`) are the
standard OP-TEE TA lifecycle hooks. Ours do nothing beyond returning
success — this TA has no state and no per-session setup.

**The interesting part — `get_evidence()`:**

```c
res = TEE_OpenTASession(&pta_attestation_uuid, 0, 0, NULL,
			 &sess, &ret_origin);
```

This is a **TA-to-TA (well, TA-to-PTA) call** — our TA, running in
secure world, opens a session to a *different* trusted service (the
Attestation PTA), also in secure world. This is a capability regular
apps don't have: normal-world code can only talk to TAs/PTAs via
`libteec`; TAs can talk to *each other* directly via `TEE_OpenTASession`
/ `TEE_InvokeTACommand`.

This matters architecturally: the Attestation PTA's
`GET_TA_SHDR_DIGEST` command is documented to only accept a request from
**the TA it's being asked to measure**. That's why the CA can't shortcut
this and call the PTA directly for evidence (unlike `GET_PUBKEY`, which
has no such restriction) — the measurement has to be requested by the
TA about itself, from inside secure world, or the guarantee "this TA
asked to be measured" wouldn't mean anything.

```c
pta_params[0].memref.buffer = (void *)&own_uuid;
pta_params[0].memref.size = sizeof(own_uuid);

pta_params[1].memref.buffer = params[0].memref.buffer;  /* nonce */
pta_params[1].memref.size = params[0].memref.size;

pta_params[2].memref.buffer = params[1].memref.buffer;  /* output */
pta_params[2].memref.size = params[1].memref.size;

res = TEE_InvokeTACommand(sess, 0, PTA_ATTESTATION_GET_TA_SHDR_DIGEST,
			   pta_pt, pta_params, &ret_origin);
```

Three parameters get passed to the PTA:
1. **Our own UUID** — tells the PTA which TA's memory to measure (itself).
2. **The nonce** — forwarded straight through from whatever the CA sent us.
3. **An output buffer** — reused directly from the CA's own output
   buffer (`params[1]`), so the PTA writes its result straight into
   memory the CA already provided — no extra copying needed.

Internally (inside `optee_os`, not our code), the PTA:
- Computes SHA-256 over the TA's signed-header-covered memory (code +
  read-only data — i.e. immutable parts of the loaded binary)
- Computes `SHA256(nonce || that digest)`
- Signs *that* value with its own RSA private key (RSASSA-PSS-SHA256),
  a key that was generated inside the PTA and persisted via OP-TEE's
  Trusted Storage — meaning it never exists outside secure world in any
  form, encrypted-at-rest included
- Writes `digest || signature` into our output buffer

```c
params[1].memref.size = pta_params[2].memref.size;
```

The PTA tells us how much it actually wrote; we report that real size
back to the CA (OP-TEE's parameter marshaling requires this — the
caller needs to know the true output length, not just assume the buffer
was filled to capacity).

```c
TEE_CloseTASession(sess);
return res;
```

Clean up the inner session and propagate whatever result the PTA gave
us (success or a specific error code) straight back to the CA.

---

### `host/main.c` — the Client Application

Normal-world code, runs as an ordinary Linux process
(`optee_example_ra_demo`), talks to secure world via `libteec`
(`tee_client_api.h`).

**`cmd_pubkey()`** — opens a session **directly** to the Attestation
PTA's UUID (no TA in between, since `GET_PUBKEY` has no
caller-restriction) and invokes `RA_DEMO_PTA_ATTESTATION_GET_PUBKEY`.
Two output memrefs receive the RSA exponent and modulus; a `VALUE_OUTPUT`
param receives the signature algorithm ID as a sanity check. All three
get written to disk via `save_to_file()`.

**`cmd_attest()`** — opens a session to **our own TA's** UUID (not the
PTA's), sends the nonce as an input memref, and receives the
digest+signature blob as an output memref. This is the CA side of the
`TA_RA_CMD_GET_EVIDENCE` call described above.

Both functions follow the same standard `libteec` pattern:
`TEEC_InitializeContext` → `TEEC_OpenSession` → build a `TEEC_Operation`
with the right `paramTypes` → `TEEC_InvokeCommand` → `TEEC_CloseSession`
→ `TEEC_FinalizeContext`. If you've seen any other OP-TEE example's CA
code, this will look familiar — it's deliberately unremarkable, since
all the actual attestation logic lives in the TA and PTA, not here.

**Why files get written to `/mnt/host` by default:** that's the 9p/virtfs
mount point shared with the host filesystem (see the setup guide, §6.1),
so the verifier script can read them without any manual copying between
guest and host.

---

### `verifier.py` — the offline verifier

Runs on the **host**, entirely separate from OP-TEE/QEMU — plain Python
using the `cryptography` library.

**Loading the public key:**

```python
def load_pubkey(exp_path, mod_path):
    with open(exp_path, "rb") as f:
        e = int.from_bytes(f.read(), "big")
    with open(mod_path, "rb") as f:
        n = int.from_bytes(f.read(), "big")
    return rsa.RSAPublicNumbers(e, n).public_key(default_backend())
```

The exponent and modulus were written as raw big-endian bytes by the CA
(straight from the PTA's `GET_PUBKEY` output) — this just reconstructs
a standard RSA public key object from them.

**Splitting the evidence blob:**

```python
digest = evidence[:DIGEST_LEN]       # first 32 bytes
signature = evidence[DIGEST_LEN:]    # remaining 256 bytes (2048-bit RSA)
```

Matches exactly what the PTA wrote: digest first, signature after.

**The one non-obvious part — `Prehashed`:**

```python
message = hashlib.sha256(nonce + digest).digest()

pubkey.verify(
    signature,
    message,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=DIGEST_LEN),
    utils.Prehashed(hashes.SHA256()),
)
```

OP-TEE's `TEE_AsymmetricSignDigest` — which the PTA uses internally —
signs a value that's *already been hashed*, without hashing it again
(hence "SignDigest" rather than just "Sign"). We replicate that exact
computation on the verifier side: hash `nonce || digest` ourselves, then
tell the `cryptography` library "this value is already a hash, don't
hash it again before verifying" via `utils.Prehashed`. Omitting
`Prehashed` here is a subtle bug that would make every signature appear
invalid, since the library would otherwise hash the already-hashed
value a second time before checking it against the signature — the
computation the PTA actually signed and the computation being verified
would silently diverge.

**Two independent checks, reported separately:**

```python
sig_ok = <signature verified against the public key>
digest_ok = (digest == expected) if --expected-digest given else True
result = sig_ok and digest_ok
```

This separation matters for interpreting results correctly: `sig_ok`
tells you the report is authentic (really came from this TEE's PTA
key); `digest_ok` tells you the *code being reported on* matches what
you expected. A tampered TA still produces a validly-signed report
(the PTA doesn't know or care what "correct" code looks like) — it's
the digest comparison, done entirely on the verifier side against a
value you supply, that catches the tampering. See §8 of the setup guide
for a worked example of this exact scenario.

---

### Build system files

**`ta/sub.mk`** — tells `optee_os`'s TA build system what to compile:

```
global-incdirs-y += include
srcs-y += ra_demo_ta.c
```

**`ta/Makefile`** — the TA's own build entry point, following the
standard OP-TEE TA pattern. The one thing to keep in sync is:

```
BINARY = bb9a73d7-684b-4785-9e39-06bfaab9a2ef
```

This **must** be the same UUID (just in dashed-string form) as
`TA_RA_DEMO_UUID` in `ra_demo_ta.h` — it's literally the filename the
compiled `.ta` file gets, and it's how OP-TEE core looks up the TA at
runtime by UUID.

**`CMakeLists.txt`** (at the `ra_demo/` root, not inside `host/`) — this
is what makes the CA actually get built at all. `optee_examples`'s
top-level `CMakeLists.txt` auto-discovers example subdirectories by
globbing for anything containing its own `CMakeLists.txt`:

```cmake
file(GLOB dirs *)
foreach(dir ${dirs})
	if(EXISTS ${dir}/CMakeLists.txt)
		add_subdirectory(${dir})
	endif()
endforeach()
```

Without this file, a plain Makefile in `host/` is invisible to that
loop — CMake never looks at it, so the CA silently never gets built
even though the TA (built via a completely separate, non-CMake hook
that scans for `*/ta/Makefile`) builds fine. This mismatch — TA builds,
CA doesn't, no error anywhere — was the single most time-consuming bug
in developing this demo. `optee_example_ra_demo` as the project name
matches the naming convention every other example in this tree uses
(`optee_example_secure_storage`, `optee_example_sign_verify`, etc.).

---

## How this maps back to a "real" RA architecture

If you're comparing this against a textbook remote-attestation diagram
(Attester / Relying Party / Verifier / Provisioner roles):

| Role | In this demo |
|---|---|
| **Attester** | The whole QEMU guest — specifically, `ra_demo` TA + the Attestation PTA together |
| **Relying Party** | Cut out — the CA plays both "request attestation" and "relay evidence" itself |
| **Verifier** | `verifier.py`, run manually on the host |
| **Provisioner** | Cut out — `verifier.py` just trusts whatever pubkey file you hand it, with no endorsement/certificate chain back to a manufacturing-time root of trust |

See §10 of the setup guide for what this means for how far you can
legitimately push conclusions drawn from this demo.
