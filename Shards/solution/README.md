# Shards — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Shards — official writeup

**Flag (demo seed):** `zerosecurectf{crt_reassembl3s_the_shards}` (per-instance in production)


## Flaw & attack
Given r_i = m mod n_i for three pairwise-coprime n_i whose product exceeds m, CRT gives the unique m mod (n1*n2*n3): m = sum r_i * (P/n_i) * ((P/n_i)^{-1} mod n_i) mod P.

