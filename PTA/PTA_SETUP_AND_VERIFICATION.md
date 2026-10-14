# PTA replay-protection demo: host/guest network workflow

This keeps the same interaction pattern as the original fTPM demo: start the verifier on the Ubuntu host, start one attester in QEMU, then type `enroll` and `attest` at the verifier prompt. No 9p shared folder or evidence-file copying is required.

## 1. Build and install

Build the example using the repository's OP-TEE build environment:

```sh
cd RA/PTA
./pta-build.sh
```

Install/copy the generated `optee_example_ra_pta` CA and TA as your normal OP-TEE setup requires, then boot QEMU.

## 2. Start verifier on the host

Install the Python dependency if needed:

```sh
python3 -m pip install cryptography
python3 RA/PTA/ra-pta/verifier.py --port 5000 --state enrolled_pta.json
```

The verifier listens on all host interfaces on TCP port 5000. The state file pins the PTA public key and TA digest observed at enrollment. Keep this file on the trusted verifier host.

## 3. Start attester in the QEMU guest

For QEMU user-mode networking, the guest normally reaches the host at `10.0.2.2`:

```sh
optee_example_ra_pta connect 10.0.2.2 5000
```

If your QEMU networking differs, use the host address reachable from the guest. Keep this process running; it holds the connection while you use the host prompt.

## 4. Enroll and test

At the host verifier prompt:

```text
Command [enroll / attest / quit]: enroll
  -> ENROLLED (PTA public key and TA digest pinned)
Command [enroll / attest / quit]: attest
  -> TRUSTED
```

Run `attest` repeatedly. Each request gets a new 256-bit random challenge, and the guest obtains fresh PTA evidence bound to that challenge. An old response cannot verify against a new challenge. A response to a challenge is handled once per request. `quit` exits the verifier.

## What is checked

- The evidence signature verifies under the PTA public key.
- The signature binds the challenge and TA digest together.
- `enroll` pins the public key and digest in host-side state.
- `attest` rejects a changed key or digest.

The state file is part of the verifier's trust boundary. Do not store it in a guest-writable location. This demo measures the TA signed-header digest provided by the OP-TEE Attestation PTA; it does not reproduce the fTPM demo's PCR or per-file measurement checks.

## Protocol note

The verifier sends a command byte (`E` for enrollment, `A` for attestation) and a 64-character hexadecimal challenge. The CA returns the public-key exponent, modulus, and evidence using length-prefixed binary fields. The public key is pinned during enrollment. The demo connection is intended for QEMU testing; it does not add TLS or authenticate the guest at the transport layer.
