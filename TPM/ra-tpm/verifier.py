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
import csv
import hashlib
import json
import os
import secrets
import socket
import struct
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

PORT = 5000
CMD_ATTEST = b"A"
NUM_PCRS = 9          # PCRs 0-7 then 10, in that order
PCR_IMA = 8           # index of PCR 10 in the list above (0..7 = 0..7, 8 = 10)

DOS_OUT_DIR = "~/optee/dos/results"
DEFAULT_STATE_FILE = "trusted/enrolled_device.json"


def replay_ima(log):
    """Parse the binary IMA log -> list of per-entry (extend_value, path, hash).

    Each record in /sys/kernel/security/ima/binary_runtime_measurements is:
        pcr          (4 bytes, little-endian)
        template_hash(20 bytes  - the SHA1 template digest field)
        name_len     (4 bytes, LE) + template_name
        data_len     (4 bytes, LE) + template_data

    The value extended into the SHA256 PCR bank is sha256(template_data)
    (confirmed on this hardware); a violation entry (all-zero template hash)
    is extended as all 0xFF. path/hash come from the ima-ng d-ng/n-ng fields.
    Raises ValueError on a malformed log.
    """
    entries, o = [], 0
    while o < len(log):
        _pcr, = struct.unpack_from("<I", log, o); o += 4
        sha1 = log[o:o + 20]; o += 20
        nlen, = struct.unpack_from("<I", log, o); o += 4
        tname = log[o:o + nlen]; o += nlen
        dlen, = struct.unpack_from("<I", log, o); o += 4
        data = log[o:o + dlen]; o += dlen
        if len(data) != dlen:
            raise ValueError("truncated IMA log")

        ext = b"\xff" * 32 if sha1 == bytes(20) else hashlib.sha256(data).digest()

        path, digest_hex = None, None
        if tname.rstrip(b"\0") in (b"ima-ng", b"ima-sig"):
            l, = struct.unpack_from("<I", data, 0)
            algo, _, digest = data[4:4 + l].partition(b"\0")
            p = 4 + l
            l2, = struct.unpack_from("<I", data, p)
            path = data[p + 4:p + 4 + l2].rstrip(b"\0").decode(errors="replace")
            if algo != b"sha256:":
                raise ValueError(f"unsupported IMA hash {algo!r}")
            digest_hex = digest.hex()
        entries.append((ext, path, digest_hex))
    return entries


def chain(base, entries):
    """Fold per-entry extend values into base, as the TPM does."""
    pcr = base
    for ext, _p, _h in entries:
        pcr = hashlib.sha256(pcr + ext).digest()
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
    if length > 16 * 1024 * 1024:            # IMA logs can be large
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

    # 1. Is the quote really signed by this AK?
    try:
        ak_to_key(ak_blob).verify(sig_to_der(sig), quote,
                                  ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return "FAIL: bad signature"

    # 2. Is it fresh (our nonce)?
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
        os.makedirs(os.path.dirname(state_file) or ".", exist_ok=True)
        with open(state_file, "w") as f:
            json.dump({"ak": ak_blob.hex(),
                       "boot_pcrs": [p.hex() for p in pcrs[:8]],
                       "pcr10": cur_pcr10.hex(),
                       "n_entries": len(entries),
                       "files": files},
                      f, indent=2)
        return f"ENROLLED ({len(entries)} entries, {len(files)} files)"

    # --- verification against the enrollment ---
    if not os.path.exists(state_file):
        return "FAIL: not enrolled yet (run --enroll first)"
    with open(state_file) as f:
        known = json.load(f)

    if known["ak"] != ak_blob.hex():
        return "FAIL: unknown device (AK differs)"
    if known["boot_pcrs"] != [p.hex() for p in pcrs[:8]]:
        return "FAIL: boot PCRs 0-7 changed since enrollment"

    n0 = known["n_entries"]
    if len(entries) < n0:
        return "FAIL: IMA log shorter than at enrollment (rebooted/reset?)"

    # Chain the entries added since enrollment onto the enrolled PCR 10 anchor;
    # it must reach the freshly-signed PCR 10. This ties the current log to the
    # quote without needing the (non-zero) boot-time PCR start.
    base = bytes.fromhex(known["pcr10"])
    new_entries = entries[n0:]
    if chain(base, new_entries) != cur_pcr10:
        return "FAIL: IMA log does not extend the enrolled PCR 10"

    # Tamper check: every file measured since enrollment must be known-good.
    for _e, p, h in new_entries:
        if p is None:
            continue
        if known["files"].get(p) != h:
            return f"FAIL: {p} modified or not enrolled"
    return "TRUSTED"


def attest(conn, state_file, enroll, paths, replay_response=None):
    """Send a fresh challenge and validate the live or cached response.

    During a replay test, the real response to the fresh challenge is read and
    discarded to keep the stream synchronized, while the cached response is
    passed to the exact same validation logic. Returns (result, live_response).
    """
    nonce = secrets.token_bytes(32)
    send_msg(conn, CMD_ATTEST + bytes([len(nonce)]) + nonce
             + "\n".join(paths).encode())
    print(f"  sent nonce {nonce.hex()[:16]}... + {len(paths)} files")

    live_response = receive_attestation(conn)
    response_to_check = (replay_response if replay_response is not None
                         else live_response)
    result = check_attestation(nonce, response_to_check, state_file,
                               enroll, paths)
    return result, live_response


# ----------------------------------------------------------- driver
def parse_args():
    ap = argparse.ArgumentParser(
        description="Remote-attestation verifier (TPM + IMA).")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--state", default=DEFAULT_STATE_FILE)

    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--enroll", action="store_true",
                      help="send ONE enroll, then stop")
    mode.add_argument("--benchmark", action="store_true",
                      help="send attests nonstop, no verdict log (Ctrl-C to stop)")
    mode.add_argument("--dos", action="store_true",
                      help="send --count attests, log each verdict, then stop")

    ap.add_argument("--requests", type=int, default=0,
                    help="override the CA's BENCH_REQUESTS (0 = unlimited)")
    ap.add_argument("--runs", type=int, default=0,
                    help="number of runs in --dos (default 1)")
    ap.add_argument("--timeout", type=float, default=120.0,
                    help="per-attest answer timeout in seconds")

    ap.add_argument("--load-level", default="0",
                    help="label + filename for the DoS verdict CSV")
    ap.add_argument("--dos-csv", metavar="FILE", default=None,
                    help="override the DoS verdict CSV path")

    args = ap.parse_args()
    args.auto = args.enroll or args.benchmark or args.dos
    args.done = 0
    args.count = args.requests * args.runs
    if args.dos and args.dos_csv is None:
        args.dos_csv = f"{DOS_OUT_DIR}/verifier_load{args.load_level}.csv"
    return args


def open_verdict_log(dos_csv):
    """Open the DoS verdict CSV and write its header, or (None, None)."""
    if not dos_csv:
        return None, None
    path = os.path.expanduser(dos_csv)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    f = open(path, "w", newline="")
    w = csv.writer(f)
    w.writerow(["seq", "unix_time", "result", "load_level"])
    print(f"logging DoS verdicts to {path}")
    return w, f


def log_verdict(w, f, seq, result, load_level):
    if w:
        w.writerow([seq, f"{time.time():.3f}", result, load_level])
        f.flush()


def serve(conn, args, vw, vf):
    """
    Handle one CA connection.
    Returns True to reconnect (benchmark: CA finished a run) or None to stop
    the verifier (enroll done, DoS run done, denial, or quit).
    """
    while True:
        if args.enroll:
            cmd = "enroll"
        elif args.auto:
            time.sleep(0.2)
            cmd = "attest"
        else:
            cmd = input("Command [enroll / attest / quit]: ").strip()
            if cmd == "quit":
                return None
            if cmd not in ("enroll", "attest"):
                continue

        try:
            result = attest(conn, args.state, cmd == "enroll")
            send_msg(conn, result.encode())
            print(f"  -> {result}")
        except (ConnectionError, OSError) as e:
            if args.dos:
                # Timeout/drop under load: this attest and every remaining one
                # count as denied. Stop the run (no reconnect = no hang).
                print(f"  -> denied: {e}")
                while args.done < args.count:
                    log_verdict(vw, vf, args.done, "TIMEOUT/LOST", args.load_level)
                    args.done += 1
                return None
            return True                  # benchmark: CA ended its run, reconnect
        except ValueError as e:
            print(f"  -> ERROR: {e}")
            continue

        if args.enroll:
            print("  enroll done, stopping the verifier")
            return None
        if args.dos:
            log_verdict(vw, vf, args.done, result.split(":")[0], args.load_level)
        args.done += 1
        if args.count and args.done >= args.count:
            print(f"  done: {args.done} attests")
            return None


def main():
    args = parse_args()
    vw, vf = open_verdict_log(args.dos_csv)

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(1)

    while True:
        done = 0
        print(f"Waiting for the attester on port {args.port}...")
        conn, addr = srv.accept()
        print(f"Attester connected from {addr[0]}")
        conn.settimeout(args.timeout)
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