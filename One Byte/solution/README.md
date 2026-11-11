# One Byte — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# One Byte — official writeup

**Flag (demo seed):** `zerosecurectf{256_k3ys_is_n0t_a_keyspace}` (per-instance in production)


## Flaw & attack
A one-byte key has only 256 values; XOR the ciphertext against each and keep the result that decodes to text starting with the known 'ZSTOKEN_' prefix.

