# PTA freshness and replay tests

## Offline verifier-logic test

From the project root, run on the host:

```sh
python3 -m pip install cryptography
python3 RA/PTA/ra-pta/tests/test_verifier_replay.py
```

This generates a temporary synthetic RSA key and proves that valid evidence
verifies for its challenge, while the exact old evidence fails for a new
challenge. It does not connect to QEMU and does not test the C client or TA.

## Live QEMU tests

Start the host verifier and connect the QEMU guest as described in
`RA/PTA/PTA_SETUP_AND_VERIFICATION.md`. After `enroll`, type one of:

- `test-replay`: the verifier obtains a valid response to challenge 1, obtains
  a response to fresh challenge 2, then checks the captured response 1 against
  challenge 2. It should report that the old response is rejected. This
  simulates replaying captured evidence under a new challenge; it does not
  inject a packet into the TCP stream.
- `test-freshness`: the verifier performs two exchanges and checks that both
  fresh challenges receive valid responses bound to their respective challenge.

Normal `attest` remains unchanged and can return `TRUSTED` repeatedly when
separate fresh attestations are valid. That is expected and is not itself a
replay vulnerability.
