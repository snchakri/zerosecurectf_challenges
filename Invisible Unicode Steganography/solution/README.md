# Invisible Unicode Steganography — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Invisible Unicode Steganography (Zero-Width Codepoint Decoding)


## 1. Vulnerability Analysis & Theoretical Foundations
Zero-width Unicode characters (U+200B ZWSP, U+200C ZWNJ) are invisible in text editors but carry distinct binary codepoints, facilitating data hiding.


## 2. Citations & Academic References
- Unicode Consortium (2021). The Unicode Standard, Version 14.0.
- Petitcolas, F. A., et al. (1999). Information hiding-a survey.


## 3. Step-by-Step Walkthrough
1. Open `carrier_script.py` in Python reading raw codepoints.
2. Identify invisible ZWSP and ZWNJ characters.
3. Demodulate binary bits into 8-bit ASCII characters.


## 4. Exploit Script & Verification
Execute the automated reference solver:
```bash
python solve.py
```
Output:
```text
[+] Successfully recovered flag: zerosecure{unicode_zero_width_stego_hidden_bits_11ff}
```


## 5. Defense Engineering & Remediation
Implement Unicode normalization and character sanitization in CI/CD source code linters.
