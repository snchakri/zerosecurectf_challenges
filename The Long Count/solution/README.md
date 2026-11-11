# The Long Count — solution

1. Open the narrative gate with **notary**.
2. Initialize `key=SHA256(root.encode())`. For each block, search nonces from zero, encoded as eight-byte big-endian integers.
3. Compute `SHA256(previous_key || nonce)` until its first 18 bits are zero. Set the new key to that digest.
4. Append the first seven digest bytes to the keystream and continue for six blocks.
5. XOR the published ciphertext with the concatenated keystream.

```bash
python solution/solve.py
```

The solver reports each nonce and derives the flag from the gated `challenge.json` retained in `solution/unlocked/`.
