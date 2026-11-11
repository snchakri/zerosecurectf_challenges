# The Unprovable Proof — solution

Run from the title directory:

```bash
python -m pip install -r solution/requirements.txt
python solution/solve.py
```

The narrative gate answer is **`truest`**. In `challenge/`, run `python open.py gate.bin "truest"` to render the puzzle. The reference solver can also use the identical rendered handout retained in `solution/unlocked/`. The launcher fixes the original station identifier so that renaming the outer folder does not change the gate key.

1. Open the narrative gate with **truest**.
2. The Fiat–Shamir challenge is `SHA256(message) mod q`; it omits the commitment `t`. It is fixed before the prover chooses `t`.
3. Choose any `s` (the solver uses 1), then set `t=g^s*(y^c)^−1 mod p`. The verification equation now holds by construction without knowing the secret exponent.
4. Save the forged JSON and submit it to the provided verifier. For local replay the verifier uses the archived accepted answer as its release fixture; the attack derives only the proof.

The accepted event answer is recorded in `accepted_flags.txt`. The solver derives its result from the challenge data.
