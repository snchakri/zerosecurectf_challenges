# Challenge: Side-Channel Padding Cryptanalysis (crypto_03_cbc_padding_oracle)

**Category:** Cryptography  
**Difficulty:** Medium  
**Format:** `zerosecurectf{...}`  
**North Star:** Authentic Tradecraft & Realistic Failure Modes  

---

## Scenario & Objective
A proprietary gateway exposes a status verification endpoint that reports whether encrypted payloads possess valid PKCS#7 padding. Exploit the padding oracle side-channel to recover the secret plaintext.

## Provided Files
- `oracle_service.py`
- `solve.py`: Automated solver and verification reference.

## Compliance
- Format asserted: `zerosecurectf{...}`
- Zero unreasoned guessiness.
