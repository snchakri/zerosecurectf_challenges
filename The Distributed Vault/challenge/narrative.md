# Challenge: The Distributed Vault (crypto_05_shamir_secret_sharing_interpolation)

**Category:** Cryptography  
**Difficulty:** Medium  
**Format:** `zerosecurectf{...}`  
**North Star:** Authentic Tradecraft & Realistic Failure Modes  

---

## Scenario & Objective
A corporate enclave divides its root recovery key across 7 executive hardware tokens using a (5, 7) Shamir's Secret Sharing scheme over Mersenne prime field GF(2^127 - 1). Interpolate the recovered shares to extract the root secret.

## Provided Files
- `shares.json`
- `solve.py`: Automated solver and verification reference.

## Compliance
- Format asserted: `zerosecurectf{...}`
- Zero unreasoned guessiness.
