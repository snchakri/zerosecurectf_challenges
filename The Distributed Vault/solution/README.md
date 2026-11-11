# The Distributed Vault — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: The Distributed Vault (Lagrange Polynomial Interpolation)


## 1. Vulnerability Analysis & Theoretical Foundations
Shamir's $(k, n)$ threshold secret sharing scheme represents a secret $S$ as the constant term $a_0 = S$ of a polynomial $f(x) \in \mathbb{F}_p[x]$ of degree $k-1$:
$$f(x) = a_0 + \sum_{i=1}^{k-1} a_i x^i \pmod p$$
Given any subset of $k$ distinct evaluation shares $(x_j, y_j)$, the polynomial is uniquely reconstructed via Lagrange interpolation:
$$S = f(0) = \sum_{j=1}^k y_j \prod_{m \ne j} \frac{-x_m}{x_j - x_m} \pmod p$$
If an attacker obtains $k$ shares, they achieve full secret reconstruction in polynomial time.


## 2. Citations & Academic References
- Shamir, A. (1979). How to share a secret. Communications of the ACM, 22(11), 612-613.
- Blakley, G. R. (1979). Safeguarding cryptographic keys. In Proc. AFIPS 1979 NCC, 48, 313-317.
- Cramer, R., Damgård, I., & Maurer, U. (2000). General secure multi-party computation from any linear secret-sharing scheme. EUROCRYPT 2000.


## 3. Step-by-Step Walkthrough
1. Parse the prime field modulus $p$ and $k=5$ coordinate shares from `shares.json`.
2. Formulate the Lagrange basis polynomials evaluated at $x = 0$: $\ell_j(0) = \prod_{m \ne j} \frac{-x_m}{x_j - x_m} \pmod p$.
3. Compute modular inverse of denominator using Fermat's Little Theorem / Extended Euclidean Algorithm.
4. Sum $y_j \ell_j(0) \pmod p$ to extract the root integer.
5. Convert integer to ASCII string to obtain the flag.


## 4. Exploit Script & Verification
Execute the automated reference solver:
```bash
python solve.py
```
Output:
```text
[+] Successfully recovered flag: zerosecure{lagrange_polynomial_interpolation_44e1}
```


## 5. Defense Engineering & Remediation
Ensure that fewer than $k$ shares are exposed across trust boundaries, and apply Verifiable Secret Sharing (Feldman VSS) to detect maliciously forged shares.
