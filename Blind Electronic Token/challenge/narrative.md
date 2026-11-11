# Challenge: Blind Electronic Token (crypto_10_chaum_blind_signature)

**Category:** Cryptography  
**Difficulty:** Medium  
**Format:** `zerosecurectf{...}`  
**North Star:** Authentic Tradecraft & Realistic Failure Modes  

---

## Scenario & Objective
An anonymous electronic voting gateway issues cryptographic authorizations using RSA blind signatures. The signing authority will sign blinded integers, but forbids signing the plaintext 'ADMIN_AUTH_TOKEN_LEVEL_9'. Use blinding to obtain a valid signature.

## Provided Files
- `blind_signer.py`
- `pubkey.json`
- `solve.py`: Automated solver and verification reference.

## Compliance
- Format asserted: `zerosecurectf{...}`
- Zero unreasoned guessiness.
