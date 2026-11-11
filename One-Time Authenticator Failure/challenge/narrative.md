# Challenge: One-Time Authenticator Failure (crypto_06_poly1305_nonce_reuse)

**Category:** Cryptography
**Difficulty:** Medium
**Format:** `zerosecure{...}`
**North Star:** Authentic Tradecraft & Realistic Failure Modes

---

## Scenario & Objective
The Doombot dispatch bus authenticates every order with a one-time polynomial
MAC in the field GF(2^130 − 5) — the Poly1305 construction. "One-time" is the
whole point: the key pair `(r, s)` must never sign two messages. A firmware
regression broke the nonce ratchet, and the bus signed two separate dispatches
with the identical `(r, s)`. CICADA3301 captured both message/tag pairs.

With the one-time key reused, its secrecy collapses into simple algebra. Recover
`(r, s)`, forge the authenticator on the standing order
`RELEASE-VAULT-KEYS-TO-BEARER` that the citadel will honour, and the forged tag
is the key that springs the flag vault.

## Provided Files
- `mac_transmissions.json` — the field prime `p`, the two reused-nonce
  message/tag pairs, the target admin message, the sealed flag, and exact
  descriptions of the MAC and the sealing.

## Compliance
- Universal Format asserted: `zerosecure{...}`
- Zero unreasoned guessiness. `(r, s)` is recovered algebraically and the forged
  tag fully opens the vault.
