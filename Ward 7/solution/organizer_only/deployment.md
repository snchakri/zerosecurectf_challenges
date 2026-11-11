# C2: WARD 7 — Deployment Guide

## Distribution

No server required. Distribute contestant_package/ as a ZIP:
  C2_WARD_7.zip
    README.md
    keystore.txt
    journalists_notes.txt

## Flag Security Checklist

- [ ] Flag is NOT in any contestant file
      (it is poly-shift encoded inside the RSA-encrypted ciphertext in keystore.txt,
       only recoverable by performing the RSA common modulus attack and then
       applying the digit-sequence cipher key derived from the case reference number)
- [ ] No plaintext flag string appears in any distributed file
- [ ] No server-side flag.txt needed -- fully offline challenge
- [ ] Caesar brute-force BLOCKED: new encoding does not yield FLAG{ under any single shift
- [ ] Digit-sequence cipher requires narrative engagement -- cannot be bypassed without
      knowing the cipher type AND the correct key digits from CASE-1943-29

## Verification

Run organizer_only/solve.py from inside contestant_package/:
  cd contestant_package
  python ../organizer_only/solve.py

Confirm output ends with:
  FLAG{the_record_was_never_corrected}

## Notes

- sympy is NOT required -- pure Python math only, no pip install needed
- solve.py resolves keystore.txt via __file__ path or falls back to CWD
- solve.py runs in a few seconds (pow() with 3 args = fast modular exponentiation)
- New cipher: digit-sequence poly-shift (key digits from CASE-1943-29: [1,9,4,3,2,9])
- Caesar brute-force now blocked by the poly-shift encoding
- The document itself contains the cipher description -- self-documenting for players
- Difficulty: Medium-Hard

