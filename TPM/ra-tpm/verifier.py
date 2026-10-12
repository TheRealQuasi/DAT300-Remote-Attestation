#!/usr/bin/env python3
"""
verifier.py - remote-attestation verifier for ra_ftpm_ca (runs on Ubuntu).

    python3 verifier.py --file /root/protected.txt [--file ...]

The verifier decides which files the attester must hash. Every attest
command carries a fresh nonce + that file list. The fTPM then builds
PCR 16 from scratch:

    PCR16 = 0
    PCR16 = SHA256(PCR16 || SHA256(nonce))
    PCR16 = SHA256(PCR16 || SHA256(file))      for each file, in order

and signs PCRs 0-7 + 16 together with the nonce. The CA also sends the
hash of each file; the verifier only accepts them if replaying them
gives exactly the signed PCR 16. At enrollment those hashes are saved
as the known-good values; later rounds must match them.

Waits for the attester to connect. The attester stays connected; you
then type commands here:

    enroll   send a nonce, check the quote, and trust this device
             (saves its AK, boot PCRs 0-7 and each file's hash to
             enrolled_device.json)
    attest   send a fresh nonce, check the quote against the enrollment
    quit     stop the verifier

Needs: sudo apt install python3-cryptography
"""

import argparse
import hashlib
import json
import os
import secrets
import socket
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

CMD_ATTEST = b"A"
NUM_PCRS = 9          # PCRs 0-7 and 16, in that order


def expected_pcr16(nonce, ref_hashes):
    """The PCR 16 value the fTPM must produce if every file is unchanged."""
    pcr = bytes(32)
    pcr = hashlib.sha256(pcr + hashlib.sha256(nonce).digest()).digest()
    for h in ref_hashes:
        pcr = hashlib.sha256(pcr + h).digest()
    return pcr


# ------------------------------------------------ network: [length][data]
def send_msg(sock, data):
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("attester closed the connection")
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
def attest(conn, state_file, enroll, paths):
    """Send nonce + file list, check the answer."""
    nonce = secrets.token_bytes(32)
    send_msg(conn, CMD_ATTEST + bytes([len(nonce)]) + nonce
             + "\n".join(paths).encode())
    print(f"  sent nonce {nonce.hex()[:16]}... + {len(paths)} files")

    ak_blob = recv_msg(conn)
    quote = recv_msg(conn)
    sig = recv_msg(conn)
    pcr_blob = recv_msg(conn)
    if len(pcr_blob) != NUM_PCRS * 32:
        return "FAIL: wrong number of PCR values"
    pcrs = [pcr_blob[i * 32:(i + 1) * 32] for i in range(NUM_PCRS)]
    hash_blob = recv_msg(conn)
    if len(hash_blob) != len(paths) * 32:
        return "FAIL: wrong number of file hashes"
    hashes_now = [hash_blob[i * 32:(i + 1) * 32] for i in range(len(paths))]

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

    # Are the PCR values we were sent the ones the fTPM signed?
    if hashlib.sha256(b"".join(pcrs)).digest() != pcr_digest:
        return "FAIL: PCR values don't match the signed quote"

    # Are the file hashes the ones the fTPM extended, after OUR nonce?
    if pcrs[8] != expected_pcr16(nonce, hashes_now):
        return "FAIL: file hashes don't match the signed PCR 16"

    if enroll:
        with open(state_file, "w") as f:
            json.dump({"ak": ak_blob.hex(),
                       "boot_pcrs": [p.hex() for p in pcrs[:8]],
                       "files": {p: h.hex()
                                 for p, h in zip(paths, hashes_now)}},
                      f, indent=2)
        return f"ENROLLED ({len(paths)} files)"

    if not os.path.exists(state_file):
        return "FAIL: not enrolled yet (type 'enroll' first)"
    with open(state_file) as f:
        known = json.load(f)

    # Is it the device we know, running the software we expect?
    if known["ak"] != ak_blob.hex():
        return "FAIL: unknown device (AK differs)"
    if known["boot_pcrs"] != [p.hex() for p in pcrs[:8]]:
        return "FAIL: boot PCRs 0-7 changed since enrollment"

    # Every file must still have the hash it had at enrollment.
    for p, h in zip(paths, hashes_now):
        if known["files"].get(p) != h.hex():
            return f"FAIL: {p} has been modified (or is missing)"
    return "TRUSTED"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--state", default="enrolled_device.json")
    ap.add_argument("--file", action="append", default=[],
                    metavar="PATH",
                    help="file the attester must hash (repeatable)")
    args = ap.parse_args()
    files = args.file

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(1)

    while True:
        print(f"Waiting for the attester on port {args.port}...")
        conn, addr = srv.accept()
        print(f"Attester connected from {addr[0]}")
        conn.settimeout(120)   # max wait for an answer from the fTPM

        with conn:
            while True:
                cmd = input("Command [enroll / attest / quit]: ").strip()
                if cmd == "quit":
                    return
                if cmd not in ("enroll", "attest"):
                    continue
                try:
                    result = attest(conn, args.state, cmd == "enroll",
                                    files)
                    send_msg(conn, result.encode())
                    print(f"  -> {result}")
                except (ConnectionError, OSError) as e:
                    print(f"  -> connection lost: {e}")
                    break          # go back and wait for a reconnect
                except ValueError as e:
                    print(f"  -> ERROR: {e}")


if __name__ == "__main__":
    main()