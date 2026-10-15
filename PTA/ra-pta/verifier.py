#!/usr/bin/env python3
"""Interactive network verifier for the OP-TEE Attestation PTA demo.

Run on the trusted host:
    python3 verifier.py --port 5000 --state enrolled_pta.json

Keep the guest CA connected, then use the host prompt:
    enroll          pin the PTA public key and TA digest
    attest          perform one normal attestation
    test-replay     capture two responses and test old-evidence rejection
    test-freshness  verify two separate, fresh challenge/response exchanges
    quit            stop the verifier

Protocol: server sends one command byte (E/A) plus 64 ASCII hex challenge
bytes; client replies with u16 exponent length, u16 modulus length, u32
 evidence length, then exponent, modulus, evidence. Lengths are network byte order.
"""
import argparse
import hashlib
import json
import os
import secrets
import socket
import struct
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

DIGEST_LEN = 32


def recv_exact(sock, n):
    chunks = bytearray()
    while len(chunks) < n:
        part = sock.recv(n - len(chunks))
        if not part:
            raise ConnectionError("attester disconnected")
        chunks.extend(part)
    return bytes(chunks)


def recv_response(conn):
    elen, nlen, slen = struct.unpack("!HHI", recv_exact(conn, 8))
    if not (1 <= elen <= 8 and 128 <= nlen <= 1024 and DIGEST_LEN < slen <= 2048):
        raise ValueError("invalid response lengths")
    return recv_exact(conn, elen), recv_exact(conn, nlen), recv_exact(conn, slen)


def verify_response(challenge, exp_b, mod_b, evidence):
    """Return the signed key/digest details, or None for invalid evidence."""
    if len(evidence) <= DIGEST_LEN:
        raise ValueError("evidence too short")
    try:
        public_key = rsa.RSAPublicNumbers(
            int.from_bytes(exp_b, "big"), int.from_bytes(mod_b, "big")
        ).public_key()
    except (ValueError, TypeError):
        return None
    digest, signature = evidence[:DIGEST_LEN], evidence[DIGEST_LEN:]
    message = hashlib.sha256(challenge.encode("ascii") + digest).digest()
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=DIGEST_LEN),
            utils.Prehashed(hashes.SHA256()),
        )
    except InvalidSignature:
        return None
    return {"exp": exp_b.hex(), "mod": mod_b.hex(), "digest": digest.hex()}


def exchange(conn, command="A"):
    """Issue a new 256-bit challenge and receive that request's response."""
    challenge = secrets.token_hex(32)
    conn.sendall((b"E" if command == "E" else b"A") + challenge.encode("ascii"))
    exp_b, mod_b, evidence = recv_response(conn)
    result = verify_response(challenge, exp_b, mod_b, evidence)
    return challenge, (exp_b, mod_b, evidence), result


def pinned_state_error(result, known):
    if result is None:
        return "invalid signature or challenge binding"
    if result["exp"] != known["exp"] or result["mod"] != known["mod"]:
        return "PTA public key changed"
    if result["digest"] != known["digest"]:
        return "TA digest changed since enrollment"
    return None


def load_state(path):
    with open(path, encoding="utf-8") as state_file:
        return json.load(state_file)


def normal_attest(conn, state_path):
    if not os.path.exists(state_path):
        print("  -> FAIL: not enrolled yet (type enroll first)")
        return
    known = load_state(state_path)
    _challenge, _response, result = exchange(conn, "A")
    error = pinned_state_error(result, known)
    print(f"  -> FAIL: {error}" if error else "  -> TRUSTED")


def test_replay(conn, state_path):
    """Live challenge exchange plus local replay of prior evidence under a new challenge."""
    if not os.path.exists(state_path):
        print("  -> FAIL: not enrolled yet (type enroll first)")
        return
    known = load_state(state_path)

    challenge1, response1, result1 = exchange(conn, "A")
    error = pinned_state_error(result1, known)
    if error:
        print(f"  -> FAIL: baseline attestation failed: {error}")
        return

    challenge2, _response2, result2 = exchange(conn, "A")
    if challenge2 == challenge1:
        print("  -> FAIL: challenge generator repeated a challenge")
        return
    error = pinned_state_error(result2, known)
    if error:
        print(f"  -> FAIL: second fresh attestation failed: {error}")
        return

    # Simulate an attacker replaying the first captured response as the reply
    # to the second challenge. The verifier checks it against challenge2.
    replay_result = verify_response(challenge2, *response1)
    if replay_result is None:
        print("  -> PASS: prior response rejected under the new challenge (replay blocked)")
        print("  -> PASS: current response for the new challenge is trusted")
    else:
        print("  -> FAIL: prior response verified under a different challenge")


def test_freshness(conn, state_path):
    """Ensure two distinct unpredictable challenges both get valid bound responses."""
    if not os.path.exists(state_path):
        print("  -> FAIL: not enrolled yet (type enroll first)")
        return
    known = load_state(state_path)

    challenge1, _response1, result1 = exchange(conn, "A")
    error = pinned_state_error(result1, known)
    if error:
        print(f"  -> FAIL: first challenge/response failed: {error}")
        return

    challenge2, _response2, result2 = exchange(conn, "A")
    if challenge2 == challenge1:
        print("  -> FAIL: challenge generator repeated a challenge")
        return
    error = pinned_state_error(result2, known)
    if error:
        print(f"  -> FAIL: second challenge/response failed: {error}")
        return

    print("  -> PASS: each attestation used a distinct 256-bit challenge")
    print("  -> PASS: both responses verified against their own challenge")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--state", default="enrolled_pta.json")
    args = parser.parse_args()

    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", args.port))
        server.listen(1)
        print(f"Waiting for OP-TEE PTA attester on port {args.port}...")
        while True:
            conn, address = server.accept()
            print(f"Attester connected from {address[0]}")
            with conn:
                conn.settimeout(120)
                while True:
                    try:
                        command = input(
                            "Command [enroll / attest / test-replay / test-freshness / quit]: "
                        ).strip().lower()
                        if command == "quit":
                            return
                        if command in ("test-replay", "replay"):
                            test_replay(conn, args.state)
                            continue
                        if command in ("test-freshness", "freshness"):
                            test_freshness(conn, args.state)
                            continue
                        if command not in ("enroll", "attest"):
                            print("  -> Unknown command")
                            continue
                        if command == "attest":
                            normal_attest(conn, args.state)
                            continue

                        challenge, response, result = exchange(conn, "E")
                        del challenge, response
                        if result is None:
                            print("  -> FAIL: invalid enrollment signature/challenge binding")
                            continue
                        state = {**result, "enrolled_at": int(time.time())}
                        with open(args.state, "w", encoding="utf-8") as state_file:
                            json.dump(state, state_file, indent=2)
                            state_file.write("\n")
                        os.chmod(args.state, 0o600)
                        print("  -> ENROLLED (PTA public key and TA digest pinned)")
                    except (ConnectionError, OSError, ValueError, struct.error) as exc:
                        print(f"  -> connection/protocol error: {exc}")
                        break
    finally:
        server.close()


if __name__ == "__main__":
    main()
