#!/usr/bin/env python3
"""
verifier.py - remote-attestation verifier for ra_ftpm_ca.

Three non-interactive modes (pick one); without any, it is interactive:
    --enroll      send ONE enroll, then stop            (run once per boot)
    --benchmark   send attests nonstop, no log          (CA drives run length)
    --dos         send --count attests, log each verdict to a CSV, then stop

The CA drives the run: it exits after its BENCH_REQUESTS (benchmark/DoS) or
when this verifier closes the connection. This verifier never enrolls inside
a benchmark/DoS run - enroll separately with --enroll first.

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
NUM_PCRS = 9          # PCRs 0-7 and 16, in that order

DOS_OUT_DIR = "~/optee/dos/results"
DEFAULT_STATE_FILE = "trusted/enrolled_device.json"
DEFAULT_PROTECTED_FILE = "/root/protected.txt"

# Number of messages the CA sends back per attest (ak, quote, sig, pcrs, hashes).
N_RESPONSE_MSGS = 5


class AttestTimeout(Exception):
    """Raised (DoS mode only) when one attest exceeds the per-request timeout
    but the CA is still alive and the stream has been re-synced, so the sweep
    can record this one as denied and keep going."""


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


def resync_after_timeout(conn, remaining):
    """A DoS attest timed out while the CA was still computing its quote for
    the nonce we already sent. The CA will finish and send its full response,
    then block waiting for a verdict. To keep the nonce<->response stream
    aligned for the REST of the sweep we must: (a) swallow the part of that
    in-flight response we didn't read, and (b) send a throwaway verdict so the
    CA unblocks and goes back to waiting for the next nonce.

    Uses a generous timeout so the slow quote has time to arrive. Raises
    ConnectionError if the CA can't be drained cleanly (truly gone/stuck), so
    the caller falls back to stopping the level rather than desyncing.
    """
    orig = conn.gettimeout()
    try:
        conn.settimeout(max(10.0, (orig or 1.0) * 10))
        for _ in range(remaining):
            recv_msg(conn)                      # drain the late response
        send_msg(conn, b"TIMEOUT/LOST")         # release the CA's recv-verdict
    except Exception as e:                       # any failure -> give up cleanly
        raise ConnectionError(f"lost sync after timeout ({e})")
    finally:
        conn.settimeout(orig)


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
def attest(conn, state_file, enroll, paths, dos=False):
    """Send nonce + file list, check the answer.

    dos=True: if the CA's response does not arrive within the socket timeout,
    re-sync the stream and raise AttestTimeout so the sweep can mark this one
    denied and continue (instead of tearing the connection down).
    """
    nonce = secrets.token_bytes(32)
    send_msg(conn, CMD_ATTEST + bytes([len(nonce)]) + nonce
             + "\n".join(paths).encode())
    print(f"  sent nonce {nonce.hex()[:16]}... + {len(paths)} files")

    # Receive the CA's response messages. Reading them in a counted loop lets
    # us know how many are still in flight if a DoS attest times out.
    parts = []
    try:
        while len(parts) < N_RESPONSE_MSGS:
            parts.append(recv_msg(conn))
    except socket.timeout:
        if not dos:
            raise                                   # benchmark/enroll: unchanged
        resync_after_timeout(conn, N_RESPONSE_MSGS - len(parts))
        raise AttestTimeout()
    ak_blob, quote, sig, pcr_blob, hash_blob = parts

    if len(pcr_blob) != NUM_PCRS * 32:
        return "FAIL: wrong number of PCR values"
    pcrs = [pcr_blob[i * 32:(i + 1) * 32] for i in range(NUM_PCRS)]
    if len(hash_blob) != len(paths) * 32:
        return "FAIL: wrong number of file hashes"
    hashes_now = [hash_blob[i * 32:(i + 1) * 32] for i in range(len(paths))]

    try:
        ak_to_key(ak_blob).verify(sig_to_der(sig), quote,
                                  ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return "FAIL: bad signature"

    q_nonce, pcr_digest = read_quote(quote)
    if q_nonce != nonce:
        return "FAIL: wrong nonce (replayed quote?)"
    if hashlib.sha256(b"".join(pcrs)).digest() != pcr_digest:
        return "FAIL: PCR values don't match the signed quote"
    if pcrs[8] != expected_pcr16(nonce, hashes_now):
        return "FAIL: file hashes don't match the signed PCR 16"

    if enroll:
        os.makedirs(os.path.dirname(state_file) or ".", exist_ok=True)
        with open(state_file, "w") as f:
            json.dump({"ak": ak_blob.hex(),
                       "boot_pcrs": [p.hex() for p in pcrs[:8]],
                       "files": {p: h.hex()
                                 for p, h in zip(paths, hashes_now)}},
                      f, indent=2)
        return f"ENROLLED ({len(paths)} files)"

    if not os.path.exists(state_file):
        return "FAIL: not enrolled yet (run --enroll first)"
    with open(state_file) as f:
        known = json.load(f)
    if known["ak"] != ak_blob.hex():
        return "FAIL: unknown device (AK differs)"
    if known["boot_pcrs"] != [p.hex() for p in pcrs[:8]]:
        return "FAIL: boot PCRs 0-7 changed since enrollment"
    for p, h in zip(paths, hashes_now):
        if known["files"].get(p) != h.hex():
            return f"FAIL: {p} has been modified (or is missing)"
    return "TRUSTED"


# ----------------------------------------------------------- driver
def parse_args():
    ap = argparse.ArgumentParser(
        description="Remote-attestation verifier for ra_ftpm_ca.")
    ap.add_argument("--file", action="append", default=[], metavar="PATH",
                    help="file the attester must hash (repeatable)")
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
    args.file = args.file or [DEFAULT_PROTECTED_FILE]
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
    the verifier (enroll done, DoS run done, hard disconnect, or quit).
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
            result = attest(conn, args.state, cmd == "enroll", args.file,
                            dos=args.dos)
            send_msg(conn, result.encode())
            print(f"  -> {result}")
        except AttestTimeout:
            # DoS: one attest was too slow, but the CA is alive and the stream
            # has been re-synced. Record THIS one as denied and keep sweeping.
            print("  -> denied: timed out (continuing)")
            log_verdict(vw, vf, args.done, "TIMEOUT/LOST", args.load_level)
            args.done += 1
            if args.count and args.done >= args.count:
                print(f"  done: {args.done} attests")
                return None
            continue
        except (ConnectionError, OSError) as e:
            if args.dos:
                # Hard disconnect (CA closed/crashed), or re-sync gave up: we
                # can't continue this level, so the rest counts as denied.
                print(f"  -> denied: {e}")
                while args.done < args.count:
                    log_verdict(vw, vf, args.done, "TIMEOUT/LOST", args.load_level)
                    args.done += 1
                return None
            return True                # benchmark: CA ended its run, reconnect
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
        print(f"Waiting for the attester on port {args.port}...")
        conn, addr = srv.accept()
        print(f"Attester connected from {addr[0]}")
        conn.settimeout(args.timeout)
        with conn:
            if serve(conn, args, vw, vf) is None:
                return


if __name__ == "__main__":
    main()