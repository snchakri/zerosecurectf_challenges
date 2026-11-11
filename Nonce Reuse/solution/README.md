# Nonce Reuse — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Nonce Reuse — official writeup

**Flag (demo seed):** `zerosecurectf{0ne_reused_n0nce_l3aks_the_key}` (per-instance in production)


## Flaw & attack
When two ECDSA signatures share a nonce k they share r. Then s1-s2 = k^{-1}(m1-m2) gives k, and s1 = k^{-1}(m1 + r*d) gives d = (s1*k - m1) * r^{-1} mod n. This is the PlayStation 3 / many-Bitcoin-wallet incident (CWE-323). The solver needs only the published values and the curve order n.

