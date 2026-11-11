# Short Hash — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Short Hash — official writeup

**Flag (demo seed):** `zerosecurectf{s4lt_d0es_n0t_s4ve_a_t1ny_keyspace}` (per-instance in production)


## Flaw & attack
A salt and sha256(salt+token) are given, and the token format 'ZS'+4 hex leaves only 16^4 = 65536 candidates, so an exhaustive search finds it in milliseconds. Short, low-entropy secrets are not protected by salting alone.

