# The Static — solution

Run from the title directory:

```bash
python -m pip install -r solution/requirements.txt
python solution/solve.py
```

1. Apply the threshold-two infection rule repeatedly to the gossip graph until it reaches a fixed point. Confirm that the bloom reaches quorum.
2. For each equivocating validator, the two signatures use the same `r`, hence the same nonce. Recover `k=(h1−h2)/(s1−s2) mod q`, then the private key/share `d=(s1*k−h1)/r mod q`.
3. Verify each recovered share against its published public key.
4. Interpolate the required number of Shamir shares at zero, using validator positions as share coordinates, and decode the reconstructed integer.

The accepted event answer is recorded in `accepted_flags.txt`. The solver derives its result from the challenge data.
