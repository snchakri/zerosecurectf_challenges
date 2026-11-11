# Challenge: Predictable Entropy Leak (crypto_04_mersenne_twister_state_recovery)

**Category:** Cryptography
**Difficulty:** Medium
**Format:** `zerosecure{...}`
**North Star:** Authentic Tradecraft & Realistic Failure Modes

---

## Scenario & Objective
The token foundry in the lower vaults of Castle Doom mints a fresh nonce for
every bot that reports for duty. The foundry's "randomness" is nothing of the
sort: it is an ordinary Mersenne-Twister engine, the same commodity generator
that ships inside a thousand civilian toolkits. A CICADA3301 tap on the audit
bus recorded a long, unbroken run of the nonces the foundry handed out that
shift.

Immediately after that run, the foundry drew from the very same engine to seal
its administrative vault. The seal is a one-time pad in name only — its bytes
came straight off the generator you have been watching. Clone the engine from
what you captured, roll it forward to the bytes that sealed the vault, and the
Doombots' master credential is yours.

## Provided Files
- `prng_stream.txt` — 624 consecutive 32-bit nonces, in order, one per line.
- `sealed_vault.hex` — the sealed administrative vault (hex).
- `generator.py` — the foundry's public emission and sealing mechanism (the
  secret seed and the vault contents are **not** included).

## Compliance
- Universal Format asserted: `zerosecure{...}`
- Zero unreasoned guessiness. The vault is fully determined by the capture.
