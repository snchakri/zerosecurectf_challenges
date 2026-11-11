# Blind Electronic Token — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Blind Electronic Token (Chaum Blind Signature Unblinding)


## 1. Vulnerability Analysis & Theoretical Foundations
David Chaum's blind signature scheme allows a user to obtain an RSA signature on message $m$ without revealing $m$ to the signer. The requester chooses random blinding factor $r \in \mathbb{Z}_N^*$ and submits:
$$m' = m \cdot r^e \pmod N$$
The authority signs $m'$ using private exponent $d$:
$$s' = (m')^d = (m \cdot r^e)^d \equiv m^d \cdot r \pmod N$$
Upon receiving $s'$, the user multiplies by $r^{-1} \pmod N$:
$$s = s' \cdot r^{-1} \equiv m^d \pmod N$$
recovering a valid RSA signature for $m$ without the authority ever observing $m$.


## 2. Citations & Academic References
- Chaum, D. (1983). Blind signatures for untraceable payments. Advances in Cryptology — CRYPTO '82, 199-203.
- Bellare, M., Namprempre, C., Pointcheval, D., & Semanko, M. (2003). The power of RSA inversion on blind signatures. ICALP 2003, LNCS 2719, 414-426.
- Pointcheval, D., & Stern, J. (2000). Security arguments for digital signatures and blind signatures. Journal of Cryptology, 13(3), 361-396.


## 3. Step-by-Step Walkthrough
1. Query `blind_signer.py` parameters $(N, e)$ for target token `ADMIN_AUTH_TOKEN_LEVEL_9`.
2. Generate random blinding factor $r = 1337420$ and compute $m' = m \cdot r^e \pmod N$.
3. Invoke the signer API to obtain blinded signature $s' = (m')^d \pmod N$.
4. Unblind signature: $s = (s' \cdot r^{-1}) \pmod N$.
5. Submit the unblinded pair $(m, s)$ to the `verify` endpoint to grant administrative access.


## 4. Exploit Script & Verification
Execute the automated reference solver:
```bash
python solve.py
```
Output:
```text
[+] Successfully recovered flag: zerosecure{chaum_blind_signature_unblind_token_67b3}
```


## 5. Defense Engineering & Remediation
Blind signatures must restrict token formats using zero-knowledge proofs of representation or enforce cut-and-choose validation to prevent signing unauthorized payloads.
