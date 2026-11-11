# Knapsack — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Knapsack — official writeup

**Flag (demo seed):** `zerosecurectf{sup3rincr3asing_m3ans_greedy_w1ns}` (per-instance in production)


## Flaw & attack
The weights are superincreasing (each exceeds the sum of all smaller ones), so the easy knapsack can be solved greedily: scan weights largest-first, subtract any weight <= the remaining target, and set that bit. The resulting bitstring is the token.

