# The Chamber of Echoes — solution

Run from the title directory:

```bash
python -m pip install -r solution/requirements.txt
python solution/solve.py
```

1. Compile the public VM source on Linux. `REVEAL` is a decoy; use `PEEK` instead.
2. Push scratch offset **0** and length **512**, then execute `PEEK`, `OUT`, `HALT`. The offset check passes, while the length clamp permits reading through the 256-byte scratch area into the adjacent vault.
3. Discard the first 256 leaked bytes. Parse the `0x5a`, fragment-count header and each `(index,length,ciphertext)` record.
4. The `DE AD` marker is followed by key bytes in **storage order**. XOR each stored fragment with the corresponding consecutive key bytes, then sort the decoded fragments by index and concatenate.

The accepted event answer is recorded in `accepted_flags.txt`. The solver derives its result from the challenge data.
