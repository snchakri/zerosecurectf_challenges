# Quartermaster

**Category:** Web Exploitation

A legacy internal asset-lookup endpoint builds its SQL by string concatenation over sqlite3; the flag lives in a separate restricted registry whose table and column names are per-instance, so only a correctly-shaped UNION after live schema enumeration crosses from the public inventory into the admin-only record. The record itself is never plaintext: the flag is enciphered (permute-then-XOR) and split across two seed-named columns, so capturing it requires a BLIND boolean+length extraction of both the ciphertext and the key, then an offline unscramble (S2/S2a flag-extraction layer).

**Download the attached server source** (`app.py`, partially redacted) — the injection surface and the sealed-schema model are in plain sight; the custody-cipher internals are withheld and must be reconstructed from the described scheme.

**Connect:** `http://<challenge-host>:30067`

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.
