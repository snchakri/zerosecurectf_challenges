# The Lenient Verifier — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: The Lenient Verifier (Bleichenbacher '06 Signature Forgery)


## 1. Vulnerability Analysis & Theoretical Foundations
Bleichenbacher's 2006 attack exploits implementations of RSA signature verification under PKCS#1 v1.5 with public exponent $e = 3$ that improperly validate padding boundaries. The standard specifies:
$$\text{EM} = \texttt{0x00} \parallel \texttt{0x01} \parallel \texttt{0xFF} \dots \texttt{0xFF} \parallel \texttt{0x00} \parallel T$$
where $T$ is the ASN.1 `DigestInfo` containing the message digest. If a flawed verifier checks only the prefix $\texttt{0x00 0x01 0xFF 0x00} \parallel T$ and ignores remaining trailing bytes, an attacker can construct an integer whose cube contains this exact prefix at high-order bits:
$$s = \lceil \sqrt[3]{\texttt{0x0001FF00} \parallel T \parallel \texttt{0x00}\dots\texttt{0x00}} \rceil$$
yielding a valid forged signature without possessing the private key.


## 2. Citations & Academic References
- Bleichenbacher, D. (2006). Forging RSA signatures on the email. In rump session of Crypto 2006.
- Kaliski, B. (2006). Bleichenbacher's RSA signature forgery based on implementation error. RSA Laboratories Technical Note.
- RFC 8017 (2016). PKCS #1: RSA Cryptography Specifications Version 2.2. IETF.


## 3. Step-by-Step Walkthrough
1. Inspect `verifier.py` to identify lenient regex/byte matching ignoring trailing data.
2. Assemble the high-order prefix: `0x0001FF00` + ASN.1 SHA-1 DigestInfo + SHA-1 hash of the message.
3. Pad with trailing zeros to 2048 bits and compute the exact integer cube root $\lfloor N^{1/3} \rfloor + 1$.
4. Submit the resulting integer signature to `verifier.py` to trigger administrative authorization.


## 4. Exploit Script & Verification
Execute the automated reference solver:
```bash
python solve.py
```
Output:
```text
[+] Successfully recovered flag: zerosecure{bleichenbacher_e3_sig_forged_71a0}
```


## 5. Defense Engineering & Remediation
Transition to RSA-PSS (Probabilistic Signature Scheme) or enforce strict PKCS#1 v1.5 validation verifying that padding extends completely from byte 2 to the exact start of the DigestInfo structure.
