# The Accelerating Decryptor — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: The Accelerating Decryptor (Wiener's Continued Fraction Attack)


## 1. Vulnerability Analysis & Theoretical Foundations
When the RSA private exponent $d$ is selected to be small in order to optimize modular exponentiation throughput on constrained microcontrollers, the system becomes vulnerable to M. J. Wiener's continued fraction attack. Specifically, if:
$$d < \frac{1}{3} N^{1/4}$$
the fraction $\frac{k}{d}$ appears among the convergents of the continued fraction expansion of $\frac{e}{N}$. Because $e d - k \phi(N) = 1$, the relation:
$$\left| \frac{e}{N} - \frac{k}{d} \right| < \frac{1}{2 d^2}$$
holds, allowing efficient polynomial-time recovery of $d$ and the factorization of $N$ via the roots of $x^2 - (N - \phi(N) + 1)x + N = 0$.


## 2. Citations & Academic References
- Wiener, M. J. (1990). Cryptanalysis of short RSA secret exponents. IEEE Transactions on Information Theory, 36(3), 553-558.
- Boneh, D., & Durfee, G. (2000). Cryptanalysis of RSA with private key d less than N^0.292. IEEE Transactions on Information Theory, 46(4), 1339-1349.
- Ferguson, N., Schneier, B., & Kohno, T. (2010). Cryptography Engineering: Design Principles and Practical Applications. Wiley.


## 3. Step-by-Step Walkthrough
1. Extract the RSA public parameters (n, e, c) from `pubkey.json`.
2. Compute the continued fraction expansion terms $q_i$ of $\frac{e}{n}$.
3. Generate successive convergent fractions $\frac{h_i}{k_i}$ corresponding to candidate values for $(k, d)$.
4. For each convergent denominator candidate $d$, compute candidate plaintext $m = c^d \pmod{n}$.
5. Decode bytes to recover the flag `zerosecure{...}`.


## 4. Exploit Script & Verification
Execute the automated reference solver:
```bash
python solve.py
```
Output:
```text
[+] Successfully recovered flag: zerosecure{wieners_continued_fraction_d_leak_981a}
```


## 5. Defense Engineering & Remediation
Ensure that the private exponent $d$ is chosen uniformly at random from the range $[1, \phi(N)]$ such that $d > N^{0.5}$, or utilize CRT-RSA (Chinese Remainder Theorem) with independent exponents $d_p, d_q$.
