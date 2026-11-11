# The Prime Concord — solution

Run from the title directory:

```bash
python -m pip install -r solution/requirements.txt
python solution/solve.py
```

The narrative gate answer is **`3301`**. In `challenge/`, run `python open.py gate.bin "3301"` to render the puzzle. The reference solver can also use the identical rendered handout retained in `solution/unlocked/`. The launcher fixes the original station identifier so that renaming the outer folder does not change the gate key.

1. Read the dossier: the Concord seal carries **3301**, which opens the gate.
2. For close RSA primes, start at `ceil(sqrt(n))` and increase `a` until `a²−n` is a square `b²`.
3. Recover `p=a−b`, `q=a+b`; check `p*q==n`. Compute the private exponent and decrypt the ciphertext into ASCII.

The accepted event answer is recorded in `accepted_flags.txt`. The solver derives its result from the challenge data.
