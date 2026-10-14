#!/usr/bin/env python3
"""Cryptographic regression test for challenge-bound PTA evidence."""
import hashlib
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from verifier import verify_response
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub = key.public_key().public_numbers()
exp = pub.e.to_bytes((pub.e.bit_length()+7)//8, 'big')
mod = pub.n.to_bytes((pub.n.bit_length()+7)//8, 'big')
digest = hashlib.sha256(b'test TA signed header').digest()
def evidence(challenge):
    message = hashlib.sha256(challenge.encode('ascii') + digest).digest()
    sig = key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), utils.Prehashed(hashes.SHA256()))
    return digest + sig
c1 = 'a1' * 32
c2 = 'b2' * 32
assert verify_response(c1, exp, mod, evidence(c1)) is not None
print('PASS: fresh challenge-bound response verifies')
assert verify_response(c2, exp, mod, evidence(c1)) is None
print('PASS: replayed evidence rejected for a new challenge')
assert verify_response(c1, exp, mod, evidence(c1)[:-1] + bytes([evidence(c1)[-1] ^ 1])) is None
print('PASS: tampered evidence rejected')
