#!/usr/bin/env python3
"""
verifier.py - remote-attestation verifier for ra_ftpm_ca.

Three non-interactive modes (pick one); without any, it is interactive:
    --enroll      send ONE enroll, then stop            (run once per boot)
    --benchmark   send attests nonstop, no log          (CA drives run length)
    --dos         send --count attests, log each verdict to a CSV, then stop

Interactive commands:
    enroll        enroll this device
    attest        verify a fresh attestation
    test-replay   submit a fresh challenge but validate the previous accepted
                  response; the stale nonce should make the replay fail
    quit          exit the verifier

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
def receive_attestation(conn):
    """Read one complete attestation response from the connected attester."""
    return tuple(recv_msg(conn) for _ in range(5))


def check_attestation(nonce, response, state_file, enroll, paths):
    """Validate an attestation response against this request's nonce."""
    ak_blob, quote, sig, pcr_blob, hash_blob = response
    if len(pcr_blob) != NUM_PCRS * 32:
        return "FAIL: wrong number of PCR values"
    pcrs = [pcr_blob[i * 32:(i + 1) * 32] for i in range(NUM_PCRS)]
    if len(hash_blob) != len(paths) * 32:
        return "FAIL: wrong number of file hashes"
    hashes_now = [hash_blob[i * 32:(i + 1) * 32]
                  for i in range(len(paths))]

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


def attest(conn, state_file, enroll, paths, replay_response=None):
    """Send a fresh challenge and validate the live or a replayed response.

    In replay-test mode, consume the current live response to keep the socket
    synchronized, but validate a previously accepted response against this
    request's fresh nonce. Returns (result, live_response).
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
    args.count = args.requests * args.runs             # unlimited; the CA ends each run
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
    last_accepted_response = None

    while True:
        if args.enroll:
            cmd = "enroll"
        elif args.auto:
            time.sleep(0.2)
            cmd = "attest"
        else:
            cmd = input(
                "Command [enroll / attest / test-replay / quit]: "
            ).strip()
            if cmd == "quit":
                return None
            if cmd not in ("enroll", "attest", "test-replay"):
                continue

        if cmd == "test-replay" and last_accepted_response is None:
            print("  -> Cannot test replay yet: run 'enroll' or a successful "
                  "'attest' first.")
            continue

        try:
            replay_response = (last_accepted_response
                               if cmd == "test-replay" else None)
            result, live_response = attest(
                conn, args.state, cmd == "enroll", args.file,
                replay_response=replay_response)
            send_msg(conn, result.encode())
            if result == "TRUSTED" or result.startswith("ENROLLED ("):
                if cmd != "test-replay":
                    last_accepted_response = live_response

            if cmd == "test-replay":
                if result == "FAIL: wrong nonce (replayed quote?)":
                    print("  -> REPLAY TEST PASSED: stale response rejected "
                          "by the nonce check")
                elif result == "TRUSTED":
                    print("  -> REPLAY TEST FAILED: stale response was accepted")
                else:
                    print("  -> REPLAY TEST INCONCLUSIVE: response rejected "
                          f"for another reason: {result}")
                # A replay test is interactive validation, not a benchmark/DoS
                # request, so it must not affect counters or verdict logs.
                continue

            print(f"  -> {result}")
        except (ConnectionError, OSError) as e:
            if args.dos:
                # A timeout/drop under load: this attest and every remaining
                # one count as denied. Stop the run (no reconnect = no hang).
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