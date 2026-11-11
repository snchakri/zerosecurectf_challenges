# PHANTOM LEDGER — Deployment Guide

## Distribution

No server required. Distribute contestant_package/ as a ZIP:
  PHANTOM_LEDGER.zip
    README.md
    night0.bin
    night1.bin
    night2.bin
    server.py
    relay_diagnostic.txt

## Flag Security Checklist

- [ ] Flag is NOT in any contestant file
      (it is embedded as an XOR-encoded base64 blob inside night2.bin,
       only recoverable by performing the full 4-step attack chain)
- [ ] server.py contains no flag (uses os.urandom(16) for KEY -- dynamic)
- [ ] relay_diagnostic.txt contains message content for keystream recovery
      but does NOT contain the flag or the decoded blob
- [ ] night0.bin is genuinely encrypted with a different key (dead end)
- [ ] relay_diagnostic.txt March 20 session: shows night1 plaintext (intentional,
      this is the clue for keystream extension -- organizer-acknowledged)
- [ ] relay_diagnostic.txt coc_key line: shows digit_sum method with Feb session
      as example (coc_key=16 for 2024-02-15 -- does NOT give the March 21 key)

## Verification

Run organizer_only/solve.py from inside contestant_package/:
  cd contestant_package
  python ../organizer_only/solve.py

Confirm output ends with:
  FLAG{wh3n_th3_n0nc3_n3v3r_ch4ng3s_th3_s3cr3t_sl1ps}

## Infrastructure Notes

- Fully offline challenge -- no network service needed
- Binary files are pre-generated (night1 and night2 share same nonce)
- night0 uses a different key -- confirms dead-end design is intentional
- Difficulty: Hard

## Intended Difficulty Management

Hints are written to guide, not to answer. Each hint points contestants
back to a file they already have rather than giving away the step directly.

Release schedule (suggested):
- Hint 1: freely or after 20 minutes -- explains XOR pair analysis
- Hint 2: after 45 minutes or on request -- points to counter reset bug
- Hint 3: after 90 minutes or on request -- tells them to re-read relay_diagnostic.txt
- Hint 4: after 135 minutes or on request -- points to coc_key metadata in log

For competitions with time limits under 4 hours, consider releasing
Hint 3 automatically at the 90-minute mark. Hint 4 should remain
on-request to preserve the challenge for contestants making progress.

## Known Solve Paths

Intended path (full 4-step chain):
  1. Identify AES-CTR nonce reuse from server.py + README
  2. XOR night1^night2, confirm 36 leading zeros
  3. Known-plaintext attack: 26-byte header -> keystream start
  4. Extend keystream using night1 body from relay_diagnostic.txt Session 2
  5. Decrypt night2 fully, extract base64 blob
  6. Apply digit_sum(2024-03-21) = 14 as XOR key -> FLAG

Accepted shortcut (Step 6 only):
  A contestant who reaches the base64 blob may brute-force all 256
  single-byte XOR values and find FLAG{ at key=14. This is intentionally
  accepted -- it only shortcuts the final decoding step, not the crypto work.
  The contestant still completes the full learning arc of the challenge.
