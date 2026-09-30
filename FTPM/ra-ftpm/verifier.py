#!/usr/bin/env python3
"""
verifier.py - remote-attestation verifier for ra_ftpm_ca (runs on Ubuntu).

    python3 verifier.py --enroll    # first time: trust this device
    python3 verifier.py             # after that: check it

For each device that connects:
  1. send a fresh random nonce
  2. receive AK public key, quote and signature
  3. check: signature valid, nonce matches, AK and PCR digest
     match what was saved at enrollment

Needs: sudo apt install python3-cryptography
"""

import argparse
import json
import os
import secrets
import socket
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


# ------------------------------------------------ network: [length][data]
def send_msg(sock, data):
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("device closed the connection")
        buf += chunk
    return buf


def recv_msg(sock):
    length = struct.unpack(">I", recv_exact(sock, 4))[0]
    if length > 65536:
        raise ValueError("message too large")
    return recv_exact(sock, length)


# ----------------------------------------- reading TPM structures
class Reader:
    def __init__(self, data):
        self.d, self.o = data, 0

    def take(self, n):
        if self.o + n > len(self.d):
            raise ValueError("truncated TPM structure")
        v = self.d[self.o:self.o + n]
        self.o += n
        return v

    def u8(self):  return self.take(1)[0]
    def u16(self): return struct.unpack(">H", self.take(2))[0]
    def u32(self): return struct.unpack(">I", self.take(4))[0]
    def tpm2b(self): return self.take(self.u16())


def ak_to_key(blob):
    """AK public (TPM2B_PUBLIC, ECC P-256) -> key we can verify with."""
    r = Reader(blob)
    r.u16(); r.u16(); r.u16(); r.u32()   # size, type, nameAlg, attributes
    r.tpm2b()                            # authPolicy
    r.u16(); r.u16(); r.u16()            # symmetric, scheme, scheme hash
    r.u16(); r.u16()                     # curve, kdf
    x, y = r.tpm2b(), r.tpm2b()
    return ec.EllipticCurvePublicNumbers(
        int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
    ).public_key()


def read_quote(blob):
    """Quote (TPMS_ATTEST) -> (nonce, pcr_digest)."""
    r = Reader(blob)
    if r.u32() != 0xFF544347 or r.u16() != 0x8018:
        raise ValueError("not a TPM quote")
    r.tpm2b()                            # which key signed it
    nonce = r.tpm2b()                    # the nonce we sent
    r.take(17 + 8)                       # clock info, firmware version
    for _ in range(r.u32()):             # PCR selection
        r.u16()
        r.take(r.u8())
    return nonce, r.tpm2b()              # digest of the PCR values


def sig_to_der(blob):
    """Signature (TPMT_SIGNATURE, ECDSA) -> DER."""
    r = Reader(blob)
    r.u16(); r.u16()                     # algorithm, hash
    return encode_dss_signature(int.from_bytes(r.tpm2b(), "big"),
                                int.from_bytes(r.tpm2b(), "big"))


# ----------------------------------------------------------- checking
def check_device(conn, args):
    nonce = secrets.token_bytes(32)
    send_msg(conn, nonce)

    ak_blob = recv_msg(conn)
    quote = recv_msg(conn)
    sig = recv_msg(conn)

    # Is the quote really signed by this AK?
    try:
        ak_to_key(ak_blob).verify(sig_to_der(sig), quote,
                                  ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return "FAIL: bad signature"

    # Is it fresh?
    q_nonce, pcr_digest = read_quote(quote)
    if q_nonce != nonce:
        return "FAIL: wrong nonce (replayed quote?)"

    if args.enroll:
        with open(args.state, "w") as f:
            json.dump({"ak": ak_blob.hex(), "pcr_digest": pcr_digest.hex()}, f)
        return "ENROLLED"

    if not os.path.exists(args.state):
        return "FAIL: not enrolled yet (run with --enroll)"
    with open(args.state) as f:
        known = json.load(f)

    # Is it the device we know, running the software we expect?
    if known["ak"] != ak_blob.hex():
        return "FAIL: unknown device (AK differs)"
    if known["pcr_digest"] != pcr_digest.hex():
        return "FAIL: PCR values changed since enrollment"
    return "TRUSTED"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--state", default="enrolled_device.json")
    ap.add_argument("--enroll", action="store_true")
    args = ap.parse_args()

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(1)
    print(f"Verifier listening on port {args.port}"
          + (" (enroll mode)" if args.enroll else ""))

    while True:
        conn, addr = srv.accept()
        with conn:
            try:
                conn.settimeout(120)
                result = check_device(conn, args)
                send_msg(conn, result.encode())
            except Exception as e:
                result = f"ERROR: {e}"
            print(f"{addr[0]}: {result}")
        if args.enroll:
            break


if __name__ == "__main__":
    main()