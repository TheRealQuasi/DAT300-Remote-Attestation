#!/usr/bin/env python3
"""Verifier for the OP-TEE Attestation PTA demo, with replay protection.

Issue a challenge on the verifier (normal-world host):
    CHALLENGE=$(python3 verifier.py --issue-challenge)

Pass that exact string to the attester in QEMU:
    optee_example_ra_pta attest "$CHALLENGE" /mnt/host

Then verify on the verifier host, keeping the challenge database local/private:
    python3 verifier.py --challenge "$CHALLENGE" --exp pubkey_exp.bin \
        --mod pubkey_mod.bin --evidence evidence.bin

The `nonce.bin` file emitted by the guest is intentionally NOT trusted or read.
The verifier checks its independently-issued outstanding challenge and consumes
it after a cryptographically valid response. Challenges expire after 300 seconds
by default. This is a demo protocol; production deployments need authenticated
transport, access-controlled persistent state, rate limiting, and key lifecycle
management appropriate to their threat model.
"""
import argparse
import hashlib
import os
import re
import secrets
import sqlite3
import sys
import time
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.exit("Missing dependency. Run: pip install cryptography")

DIGEST_LEN = 32
CHALLENGE_RE = re.compile(r"^[0-9a-f]{64}$")  # secrets.token_hex(32), ASCII nonce
DEFAULT_DB = "~/.local/state/optee-ra-pta/challenges.sqlite3"


def load_pubkey(exp_path, mod_path):
    with open(exp_path, "rb") as f:
        e_raw = f.read()
    with open(mod_path, "rb") as f:
        n_raw = f.read()
    if not e_raw or not n_raw:
        raise ValueError("Public-key exponent/modulus file is empty")
    e = int.from_bytes(e_raw, "big")
    n = int.from_bytes(n_raw, "big")
    return rsa.RSAPublicNumbers(e, n).public_key(default_backend())


def connect_db(db_arg):
    path = Path(db_arg).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # The challenge database must live on the verifier, not in the QEMU 9p share.
    conn = sqlite3.connect(str(path,))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS challenges (
            nonce_hash TEXT PRIMARY KEY,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            consumed_at INTEGER
        )
    """)
    conn.commit()
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return conn


def issue_challenge(db_arg, ttl_seconds):
    if ttl_seconds < 1:
        raise ValueError("--challenge-ttl must be at least 1 second")
    challenge = secrets.token_hex(32)
    now = int(time.time())
    nonce_hash = hashlib.sha256(challenge.encode("ascii")).hexdigest()
    conn = connect_db(db_arg)
    try:
        with conn:
            conn.execute(
                "INSERT INTO challenges(nonce_hash, created_at, expires_at, consumed_at) "
                "VALUES (?, ?, ?, NULL)",
                (nonce_hash, now, now + ttl_seconds),
            )
    finally:
        conn.close()
    # stdout contains only the challenge so shell command substitution is safe.
    print(challenge)


def check_challenge_is_pending(conn, challenge):
    nonce_hash = hashlib.sha256(challenge.encode("ascii")).hexdigest()
    row = conn.execute(
        "SELECT expires_at, consumed_at FROM challenges WHERE nonce_hash = ?",
        (nonce_hash,),
    ).fetchone()
    if row is None:
        return False, "Challenge was not issued by this verifier"
    expires_at, consumed_at = row
    if consumed_at is not None:
        return False, "Challenge has already been consumed (replay rejected)"
    if int(time.time()) > expires_at:
        return False, "Challenge has expired (stale response rejected)"
    return True, nonce_hash


def consume_challenge(conn, nonce_hash):
    """Atomically consume a challenge; concurrent duplicate verifies cannot both win."""
    now = int(time.time())
    with conn:
        cursor = conn.execute(
            "UPDATE challenges SET consumed_at = ? "
            "WHERE nonce_hash = ? AND consumed_at IS NULL AND expires_at >= ?",
            (now, nonce_hash, now),
        )
    return cursor.rowcount == 1


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--exp", default="pubkey_exp.bin", help="PTA RSA public exponent file")
    ap.add_argument("--mod", default="pubkey_mod.bin", help="PTA RSA public modulus file")
    ap.add_argument("--evidence", default="evidence.bin")
    ap.add_argument("--challenge", help="the current verifier-issued 64-character challenge")
    ap.add_argument("--challenge-db", default=DEFAULT_DB,
                    help="verifier-local challenge state (never put this in /mnt/host)")
    ap.add_argument("--issue-challenge", action="store_true",
                    help="issue a fresh challenge and print it, then exit")
    ap.add_argument("--challenge-ttl", type=int, default=300,
                    help="challenge lifetime in seconds for --issue-challenge (default: 300)")
    ap.add_argument("--expected-digest",
                    help="hex SHA-256 digest of a known-good TA build")
    args = ap.parse_args()

    try:
        if args.issue_challenge:
            if args.challenge:
                ap.error("--issue-challenge and --challenge cannot be combined")
            issue_challenge(args.challenge_db, args.challenge_ttl)
            return 0

        if not args.challenge:
            ap.error("--challenge is required; do not trust the guest-written nonce.bin")
        if not CHALLENGE_RE.fullmatch(args.challenge):
            ap.error("--challenge must be exactly 64 lowercase hexadecimal characters")

        conn = connect_db(args.challenge_db)
        try:
            pending, challenge_info = check_challenge_is_pending(conn, args.challenge)
            if not pending:
                print(f"Freshness check: NO ({challenge_info})")
                print("\nRA RESULT: FAIL")
                return 1
            nonce_hash = challenge_info

            pubkey = load_pubkey(args.exp, args.mod)
            with open(args.evidence, "rb") as f:
                evidence = f.read()
            if len(evidence) <= DIGEST_LEN:
                print(f"Evidence too short ({len(evidence)} bytes)")
                print("\nRA RESULT: FAIL")
                return 1

            digest = evidence[:DIGEST_LEN]
            signature = evidence[DIGEST_LEN:]
            # The PTA signs SHA256(nonce || digest). The nonce is the verifier's
            # pending challenge, NOT the independently replaceable nonce.bin file.
            message = hashlib.sha256(args.challenge.encode("ascii") + digest).digest()
            try:
                pubkey.verify(
                    signature,
                    message,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=DIGEST_LEN),
                    utils.Prehashed(hashes.SHA256()),
                )
                sig_ok = True
            except (InvalidSignature, ValueError):
                sig_ok = False

            # Consume after a valid signature even if the optional known-good
            # digest check fails: this valid challenge response must not be reusable.
            consumed = consume_challenge(conn, nonce_hash) if sig_ok else False
            freshness_ok = sig_ok and consumed

            print(f"Challenge:            {args.challenge}")
            print(f"TA digest (hex):      {digest.hex()}")
            print(f"Signature length:     {len(signature)} bytes")
            print(f"Signature valid:      {'YES' if sig_ok else 'NO'}")
            print(f"Challenge consumed:   {'YES' if consumed else 'NO'}")
            print(f"Freshness check:      {'PASS' if freshness_ok else 'FAIL'}")

            digest_ok = True
            if args.expected_digest:
                try:
                    expected = bytes.fromhex(args.expected_digest)
                except ValueError:
                    ap.error("--expected-digest must be valid hexadecimal")
                digest_ok = len(expected) == DIGEST_LEN and digest == expected
                print(f"Digest matches known-good build: {'YES' if digest_ok else 'NO'}")
            else:
                print("(no --expected-digest: TA measurement allow-list check skipped)")

            result = freshness_ok and digest_ok
            print(f"\nRA RESULT: {'PASS' if result else 'FAIL'}")
            return 0 if result else 1
        finally:
            conn.close()
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(f"Verifier error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
