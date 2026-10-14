#!/usr/bin/env python3
"""Offline regression tests for the PTA verifier's freshness/replay checks.

These tests use a temporary software RSA key to test the verifier protocol logic.
They do not replace the QEMU end-to-end test with real OP-TEE-signed evidence.
Run from any directory: python3 PTA/ra-pta/tests/test_verifier_replay.py
"""
import hashlib
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes

VERIFIER = Path(__file__).resolve().parents[1] / "verifier.py"
DIGEST = hashlib.sha256(b"synthetic TA signed header for verifier regression test").digest()


def run(*args, expected=0):
    result = subprocess.run(
        [sys.executable, str(VERIFIER), *map(str, args)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if expected == 0 and result.returncode != 0:
        raise AssertionError(f"command failed ({result.returncode}): {result.args}\n"
                             f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
    if expected != 0 and result.returncode == 0:
        raise AssertionError(f"command unexpectedly passed: {result.args}\n{result.stdout}")
    return result


def issue(db):
    out = run("--issue-challenge", "--challenge-db", db).stdout.strip()
    if len(out) != 64 or any(c not in "0123456789abcdef" for c in out):
        raise AssertionError(f"unexpected challenge output: {out!r}")
    return out


def make_evidence(private_key, challenge, path):
    message = hashlib.sha256(challenge.encode("ascii") + DIGEST).digest()
    signature = private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        utils.Prehashed(hashes.SHA256()),
    )
    path.write_bytes(DIGEST + signature)


def verify(db, exp, mod, evidence, challenge, expected=0):
    return run("--exp", exp, "--mod", mod, "--evidence", evidence,
               "--challenge", challenge, "--challenge-db", db, expected=expected)


def main():
    with tempfile.TemporaryDirectory(prefix="optee-ra-test-") as tmp:
        root = Path(tmp)
        db = root / "challenges.sqlite3"
        exp_path, mod_path = root / "pubkey_exp.bin", root / "pubkey_mod.bin"
        evidence = root / "evidence.bin"
        tampered = root / "tampered.bin"

        # Same RSA-PSS parameters as the real PTA evidence verifier; synthetic key
        # keeps tests self-contained and never needs OP-TEE/QEMU to be running.
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = private_key.public_key().public_numbers()
        exp_path.write_bytes(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big"))
        mod_path.write_bytes(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big"))

        # 1. Current challenge + correctly signed evidence passes and is consumed.
        c1 = issue(db)
        make_evidence(private_key, c1, evidence)
        result = verify(db, exp_path, mod_path, evidence, c1)
        assert "RA RESULT: PASS" in result.stdout
        assert "Challenge consumed:   YES" in result.stdout

        # 2. Exact same response and challenge cannot be accepted a second time.
        replay = verify(db, exp_path, mod_path, evidence, c1, expected=1)
        assert "already been consumed" in replay.stdout
        assert "RA RESULT: FAIL" in replay.stdout

        # 3. Old evidence with a new, valid outstanding challenge fails signature
        # verification; this models a stale response replay against a fresh nonce.
        c2 = issue(db)
        stale = verify(db, exp_path, mod_path, evidence, c2, expected=1)
        assert "Signature valid:      NO" in stale.stdout
        assert "RA RESULT: FAIL" in stale.stdout

        # The invalid response must not consume c2: a proper response can still pass.
        make_evidence(private_key, c2, evidence)
        current = verify(db, exp_path, mod_path, evidence, c2)
        assert "RA RESULT: PASS" in current.stdout

        # 4. Evidence tampering fails, but a valid response can subsequently use c3.
        c3 = issue(db)
        make_evidence(private_key, c3, evidence)
        tampered.write_bytes(evidence.read_bytes()[:-1] + bytes([evidence.read_bytes()[-1] ^ 1]))
        bad = verify(db, exp_path, mod_path, tampered, c3, expected=1)
        assert "Signature valid:      NO" in bad.stdout
        make_evidence(private_key, c3, evidence)
        good = verify(db, exp_path, mod_path, evidence, c3)
        assert "RA RESULT: PASS" in good.stdout

        print("PASS: fresh response accepted")
        print("PASS: exact replay rejected after challenge consumption")
        print("PASS: stale evidence rejected against a new challenge")
        print("PASS: evidence tampering rejected")

        # 5. Expired challenges are rejected before signature verification.
        short = run("--issue-challenge", "--challenge-ttl", "1",
                    "--challenge-db", db).stdout.strip()
        time.sleep(2)
        expired = verify(db, exp_path, mod_path, evidence, short, expected=1)
        assert "Challenge has expired" in expired.stdout
        print("PASS: expired challenge rejected")
        print("NOTE: synthetic RSA key used; run the QEMU procedure for end-to-end OP-TEE validation")


if __name__ == "__main__":
    main()
