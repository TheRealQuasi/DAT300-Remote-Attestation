#!/usr/bin/env python3
"""
verifier.py - minimal RA verifier for the OP-TEE Attestation PTA demo.

Plays the "Verifier" role from the RA architecture diagram (steps 0, 2, 5
in the full design), simplified for this demo:
  - Trust anchor setup (0) = pointing this script at pubkey_*.bin, fetched
    once via `optee_example_ra_demo pubkey`.
  - Nonce (2) = you choose the nonce string yourself when you run
    `optee_example_ra_demo attest <nonce>`; there's no live
    challenge/response round-trip here (the Relying Party role is cut
    out of this simplified demo).
  - RA Result (5) = printed at the end: PASS or FAIL.

Requires: pip install cryptography

Usage:
    python3 verifier.py \\
        --exp pubkey_exp.bin --mod pubkey_mod.bin \\
        --evidence evidence.bin --nonce nonce.bin \\
        [--expected-digest <hex string>]

Evidence layout (matches optee_os's pta_attestation.h):
    evidence[0:32]  = digest (SHA-256 of the TA's signed header, i.e.
                       shdr::hash - a measurement of the TA's code+rodata)
    evidence[32:]   = RSASSA-PSS-SHA256 signature over
                       SHA256(nonce || digest)
"""
import argparse
import hashlib
import sys

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.exit("Missing dependency. Run: pip install cryptography --break-system-packages")

DIGEST_LEN = 32  # SHA-256


def load_pubkey(exp_path, mod_path):
    with open(exp_path, "rb") as f:
        e = int.from_bytes(f.read(), "big")
    with open(mod_path, "rb") as f:
        n = int.from_bytes(f.read(), "big")
    return rsa.RSAPublicNumbers(e, n).public_key(default_backend())


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--exp", default="pubkey_exp.bin")
    ap.add_argument("--mod", default="pubkey_mod.bin")
    ap.add_argument("--evidence", default="evidence.bin")
    ap.add_argument("--nonce", default="nonce.bin")
    ap.add_argument("--expected-digest",
                     help="hex-encoded digest of a known-good TA build. "
                          "Without this, the script only proves the "
                          "signature is genuine, not that the code "
                          "measured is the version you expect - use this "
                          "for tamper-detection testing (see README).")
    args = ap.parse_args()

    pubkey = load_pubkey(args.exp, args.mod)

    with open(args.evidence, "rb") as f:
        evidence = f.read()
    with open(args.nonce, "rb") as f:
        nonce = f.read()

    if len(evidence) <= DIGEST_LEN:
        sys.exit(f"Evidence too short ({len(evidence)} bytes) - expected "
                  f"{DIGEST_LEN}-byte digest plus a signature")

    digest = evidence[:DIGEST_LEN]
    signature = evidence[DIGEST_LEN:]

    # Per pta_attestation.h: the signed message is SHA256(nonce || digest).
    # OP-TEE's TEE_AsymmetricSignDigest signs that value directly (it does
    # not hash again internally, hence "SignDigest") - so verification
    # must treat `message` as already-hashed (Prehashed), not let the
    # library hash it a second time.
    message = hashlib.sha256(nonce + digest).digest()

    try:
        pubkey.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=DIGEST_LEN,
            ),
            utils.Prehashed(hashes.SHA256()),
        )
        sig_ok = True
    except InvalidSignature:
        sig_ok = False

    print(f"Nonce (raw):          {nonce!r}")
    print(f"TA digest (hex):      {digest.hex()}")
    print(f"Signature length:     {len(signature)} bytes")
    print(f"Signature valid:      {'YES' if sig_ok else 'NO'}")

    digest_ok = True
    if args.expected_digest:
        expected = bytes.fromhex(args.expected_digest)
        digest_ok = (digest == expected)
        print(f"Digest matches known-good build: {'YES' if digest_ok else 'NO'}")
    else:
        print("(no --expected-digest given - skipping code-integrity check, "
              "only signature authenticity was verified)")

    result = sig_ok and digest_ok
    print(f"\nRA RESULT: {'PASS' if result else 'FAIL'}")
    sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()
