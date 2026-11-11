# Babel — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Babel — official writeup

**Flag (demo seed):** `zerosecurectf{3nc0ding_is_n0t_encrypt10n}` (per-instance in production)


## Flaw & attack
Encodings are not encryption. The blob was produced as hex(base64(reverse(token))); undo it in reverse: hex-decode, base64-decode, then reverse the bytes.

