#!/usr/bin/env python3
"""Offline crypto tests for challenge freshness and replay rejection.

This uses a synthetic RSA key; it tests verifier logic only. It does not need
QEMU or the OP-TEE TA. Use the host verifier's `test-replay` command for a
live test with the QEMU attester.
"""
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from verifier import verify_response
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_numbers = key.public_key().public_numbers()
exp = public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")
mod = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")
digest = hashlib.sha256(b"test TA signed header").digest()


def evidence(challenge):
    message = hashlib.sha256(challenge.encode("ascii") + digest).digest()
    signature = key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        utils.Prehashed(hashes.SHA256()),
    )
    return digest + signature


c1 = "a1" * 32
c2 = "b2" * 32
response1 = evidence(c1)
response2 = evidence(c2)

assert c1 != c2
assert verify_response(c1, exp, mod, response1) is not None
print("PASS: fresh response accepted for its challenge")
assert verify_response(c2, exp, mod, response1) is None
print("PASS: exact old response rejected under a new challenge (replay test)")
assert verify_response(c2, exp, mod, response2) is not None
print("PASS: new response accepted for the new challenge (freshness test)")
assert verify_response(c1, exp, mod, response2) is None
print("PASS: response for the newer challenge cannot be reused for the older challenge")

tampered = response2[:-1] + bytes([response2[-1] ^ 1])
assert verify_response(c2, exp, mod, tampered) is None
print("PASS: tampered evidence rejected")
print("NOTE: synthetic RSA key only; run the host verifier + QEMU guest for live validation")
