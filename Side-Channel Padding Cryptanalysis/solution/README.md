# Side-Channel Padding Cryptanalysis — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Side-Channel Padding Cryptanalysis (CBC Padding Oracle)


## 1. Vulnerability Analysis & Theoretical Foundations
Cipher Block Chaining (CBC) mode decryption computes:
$$P_i = D_K(C_i) \oplus C_{i-1}$$
When a server exposes a distinguishing oracle indicating whether $P_i$ satisfies PKCS#7 padding validation, an active attacker can recover plaintext byte-by-byte without the decryption key. By manipulating byte $j$ of ciphertext block $C_{i-1}$, the attacker systematically tests 256 candidate values until the oracle accepts valid padding, exposing intermediate state $I_i[j] = D_K(C_i)[j]$, from which $P_i[j] = I_i[j] \oplus C_{i-1}[j]$.


## 2. Citations & Academic References
- Vaudenay, S. (2002). Security Flaws in Induced by CBC Padding — Applications to SSL, IPSEC, WTLS. Advances in Cryptology — EUROCRYPT 2002, LNCS 2332, 534-545.
- Rizzo, J., & Duong, T. (2011). Practical Padding Oracle Attacks on Web Frameworks. In USENIX Workshop on Offensive Technologies (WOOT).
- NIST SP 800-38A (2001). Recommendation for Block Cipher Modes of Operation.


## 3. Step-by-Step Walkthrough
1. Retrieve target ciphertext and IV from `oracle_service.py`.
2. For each 16-byte block from end to start, alter the preceding block's byte $j$ ($15 \to 0$).
3. Query the `oracle()` endpoint across values $0 \dots 255$ until valid padding is signaled.
4. Compute intermediate byte $I[j] = \text{guess} \oplus \text{pad\_val}$, then $P[j] = I[j] \oplus C_{i-1}[j]$.
5. Strip PKCS#7 padding to reveal the flag.


## 4. Exploit Script & Verification
Execute the automated reference solver:
```bash
python solve.py
```
Output:
```text
[+] Successfully recovered flag: zerosecure{cbc_padding_oracle_bitflip_02cf}
```


## 5. Defense Engineering & Remediation
Deprecate unauthenticated CBC modes in favor of Authenticated Encryption with Associated Data (AEAD) primitives such as AES-GCM or ChaCha20-Poly1305.
