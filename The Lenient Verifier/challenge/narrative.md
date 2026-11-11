# Challenge: The Lenient Verifier (crypto_02_bleichenbacher_signature_forge)

**Category:** Cryptography  
**Difficulty:** Medium  
**Format:** `zerosecurectf{...}`  
**North Star:** Authentic Tradecraft & Realistic Failure Modes  

---

## Scenario & Objective
A legacy enterprise identity provider verifies RSA PKCS#1 v1.5 signatures using an insecure regular expression / prefix check when public exponent e = 3. Forge a valid signature for the administrative token.

## Provided Files
- `verifier.py`
- `solve.py`: Automated solver and verification reference.

## Compliance
- Format asserted: `zerosecurectf{...}`
- Zero unreasoned guessiness.
