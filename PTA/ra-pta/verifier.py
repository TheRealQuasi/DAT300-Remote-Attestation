#!/usr/bin/env python3
"""Interactive network verifier for the OP-TEE Attestation PTA demo.

Run on the host: python3 verifier.py [--port 5000] [--state enrolled_pta.json]
The guest CA connects and remains connected. At the prompt use enroll, attest,
quit. Protocol: server sends one command byte (E/A) plus 64 ASCII hex challenge
bytes; client replies with u16 exponent length, u16 modulus length, u32 evidence
length, then exponent, modulus, evidence. Lengths are network byte order.
"""
import argparse, hashlib, json, os, secrets, socket, struct, time
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes

DIGEST_LEN = 32

def recv_exact(sock, n):
    chunks = bytearray()
    while len(chunks) < n:
        b = sock.recv(n-len(chunks))
        if not b: raise ConnectionError('attester disconnected')
        chunks.extend(b)
    return bytes(chunks)

def recv_response(conn):
    elen, nlen, slen = struct.unpack('!HHI', recv_exact(conn, 8))
    if not (1 <= elen <= 8 and 128 <= nlen <= 1024 and DIGEST_LEN < slen <= 2048):
        raise ValueError('invalid response lengths')
    return (recv_exact(conn, elen), recv_exact(conn, nlen), recv_exact(conn, slen))

def verify_response(challenge, exp_b, mod_b, evidence):
    if len(evidence) <= DIGEST_LEN: raise ValueError('evidence too short')
    pub = rsa.RSAPublicNumbers(int.from_bytes(exp_b, 'big'), int.from_bytes(mod_b, 'big')).public_key()
    digest, sig = evidence[:DIGEST_LEN], evidence[DIGEST_LEN:]
    msg = hashlib.sha256(challenge.encode('ascii') + digest).digest()
    try:
        pub.verify(sig, msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=DIGEST_LEN), utils.Prehashed(hashes.SHA256()))
    except InvalidSignature:
        return None
    return {'exp': exp_b.hex(), 'mod': mod_b.hex(), 'digest': digest.hex()}

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--port', type=int, default=5000)
    ap.add_argument('--state', default='enrolled_pta.json')
    args = ap.parse_args()
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', args.port)); srv.listen(1)
    print(f'Waiting for OP-TEE PTA attester on port {args.port}...')
    while True:
        conn, addr = srv.accept(); print(f'Attester connected from {addr[0]}')
        with conn:
            conn.settimeout(120)
            while True:
                cmd = input('Command [enroll / attest / quit]: ').strip().lower()
                if cmd == 'quit': return
                if cmd not in ('enroll', 'attest'): continue
                if cmd == 'attest' and not os.path.exists(args.state):
                    print('  -> FAIL: not enrolled yet (type enroll first)'); continue
                challenge = secrets.token_hex(32)
                try:
                    conn.sendall((b'E' if cmd == 'enroll' else b'A') + challenge.encode('ascii'))
                    exp_b, mod_b, evidence = recv_response(conn)
                    result = verify_response(challenge, exp_b, mod_b, evidence)
                    if result is None:
                        print('  -> FAIL: invalid signature'); continue
                    if cmd == 'enroll':
                        state = {**result, 'enrolled_at': int(time.time())}
                        with open(args.state, 'w') as f: json.dump(state, f, indent=2)
                        os.chmod(args.state, 0o600)
                        print('  -> ENROLLED (PTA public key and TA digest pinned)')
                    else:
                        with open(args.state) as f: known = json.load(f)
                        if result['exp'] != known['exp'] or result['mod'] != known['mod']:
                            print('  -> FAIL: PTA public key changed')
                        elif result['digest'] != known['digest']:
                            print('  -> FAIL: TA digest changed since enrollment')
                        else: print('  -> TRUSTED')
                except (ConnectionError, OSError, ValueError) as e:
                    print(f'  -> connection/protocol error: {e}'); break
if __name__ == '__main__': main()
