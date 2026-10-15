# PTA replay-protection demo: host/guest network workflow

This keeps the same interaction pattern as the original fTPM demo: start the verifier on the Ubuntu host, start one attester in QEMU, then type commands at the verifier prompt. No 9p shared folder or evidence-file copying is required.

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
Command [enroll / attest / test-replay / test-freshness / quit]: attest
  -> TRUSTED
Command [enroll / attest / test-replay / test-freshness / quit]: test-replay
  -> PASS: prior response rejected under the new challenge (replay blocked)
  -> PASS: current response for the new challenge is trusted
Command [enroll / attest / test-replay / test-freshness / quit]: test-freshness
  -> PASS: each attestation used a distinct 256-bit challenge
  -> PASS: both responses verified against their own challenge
```

Run `attest` repeatedly. It is correct for separate live attestations to each return `TRUSTED`: each request receives a new 256-bit random challenge, and the guest obtains evidence bound to that challenge. Two `TRUSTED` results alone are not evidence of a replay vulnerability.

Extra test commands:

- `test-replay` obtains a valid response to one challenge, then a response to a second challenge, and checks the captured first response against the second challenge. The old response should fail signature verification. This simulates a replay at the verifier's check; it does not inject or replay raw packets over TCP.
- `test-freshness` performs two exchanges and checks that the challenges differ and each response verifies only for its corresponding challenge.
- `quit` exits the verifier.

For the fast, offline crypto regression test (does not require QEMU), run this from the project root on the host:

```sh
python3 RA/PTA/ra-pta/tests/test_verifier_replay.py
```

That test generates a synthetic RSA key. It validates the verifier's challenge-binding logic but does not validate the OP-TEE PTA or the live C client.

## What is checked

- The evidence signature verifies under the PTA public key.
- The signature binds the challenge and TA digest together.
- `enroll` pins the public key and digest in host-side state.
- `attest` rejects a changed key or digest.

The state file is part of the verifier's trust boundary. Do not store it in a guest-writable location. This demo measures the TA signed-header digest provided by the OP-TEE Attestation PTA; it does not reproduce the fTPM demo's PCR or per-file measurement checks.

## Protocol note

The verifier sends a command byte (`E` for enrollment, `A` for attestation) and a 64-character hexadecimal challenge. The CA returns the public-key exponent, modulus, and evidence using length-prefixed binary fields. The public key is pinned during enrollment. The demo connection is intended for QEMU testing; it does not add TLS or authenticate the guest at the transport layer.

## Troubleshooting a disconnect during `enroll`

Keep the `optee_example_ra_pta connect ...` process running in the **QEMU guest's normal-world console** while the verifier runs in the outer Ubuntu VM. Do not launch the attester from the outer VM shell. With QEMU user-mode networking, the guest usually connects to `10.0.2.2:5000`; the verifier's peer address is normally the QEMU guest address (often `10.0.2.15`), not `127.0.0.1`.

The C client must be rebuilt after updating `ra-pta/host/main.c`. The challenge request is exactly 65 bytes (one command byte plus 64 hexadecimal characters). If you still see `attester disconnected`, check the QEMU normal-world console for the client's final error line; `errx()` exits the client immediately if the PTA/TA request fails.
