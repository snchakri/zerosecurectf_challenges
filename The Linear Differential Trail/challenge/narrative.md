# Challenge: The Linear Differential Trail (crypto_12_feal4_cryptanalysis)

**Category:** Cryptography
**Difficulty:** Hard
**Format:** `zerosecure{...}`
**North Star:** Authentic Tradecraft & Realistic Failure Modes

---

## Scenario & Objective
Doom's field units run a stripped-down FEAL cipher — four Feistel rounds whose
round function leans entirely on byte addition and a two-bit rotate. The engineer
who ported it to the citadel's 32-bit telemetry bus believed four rounds "more
than enough." A CICADA3301 asset with access to the encryptor ran a stack of
chosen plaintexts through it — each paired with a partner that differs by a
single fixed mask — and logged every ciphertext. Separately, the unit's broadcast
key streams the citadel's flag.

Addition leaks structure under XOR differences. Trace how a chosen input
difference marches through the rounds, peel the round keys off one layer at a
time, and the key that drives the keystream is yours.

## Provided Files
- `cipher_spec.py` — the complete cipher definition (round function, 4-round
  Feistel, CTR flag-encryption). The round keys are **secret** and not included.
- `plaintext_pairs.json` — the input difference `alpha`, the chosen-plaintext
  transcript `pairs = [p, enc(p), enc(p ^ (alpha<<16))]`, and the CTR-encrypted
  flag (`nonce`, `flag_ct_hex`).

## Compliance
- Universal Format asserted: `zerosecure{...}`
- Zero unreasoned guessiness. The key is determined (up to an exactly-equivalent
  key that defines the identical cipher) and regenerates the keystream.
