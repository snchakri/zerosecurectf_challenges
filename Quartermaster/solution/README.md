# Quartermaster — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

In one terminal, run the local challenge service:

```bash
python solution/runtime/app.py
```

In another terminal, run the solver:

```bash
python solution/solve.py --url http://127.0.0.1:8000
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Quartermaster — official writeup

**Flag:** `zerosecurectf{un10n_acr0ss_the_cust0dy_b0undary}` (static demo seed;
per-instance in production).

> This document describes the solution and must **not** ship to players. Only
> `challenge/`, `README.md` and (optionally) `challenge.yml` are player-facing.


## The flaw

Quartermaster's asset lookup builds its SQL query by **string concatenation**
over the user-supplied tag — the textbook SQL injection sink
([CWE-89](https://cwe.mitre.org/data/definitions/89.html); OWASP Top 10
[A03:2021 — Injection](https://owasp.org/Top10/A03_2021-Injection/)):

```python
BASE_SELECT = "SELECT tag, name, category, location FROM assets WHERE tag = '"
...
sql = BASE_SELECT + tag_value + "'"     # the tag is glued straight into the SQL text
cur.execute(sql)
```

A normal tag (`AST-1001`) produces a correct query. A crafted tag closes the
string literal with `'` and appends attacker SQL; the template's dangling
closing quote is neutralised with a `--` line comment. The correct fix (shown in
the source for teaching, deliberately *not* used) is parameterisation —
`cur.execute("... WHERE tag = ?", (tag_value,))` — which turns the input into
pure data and closes the challenge entirely (see the Python `sqlite3` docs,
["How to use placeholders to bind values in SQL
queries"](https://docs.python.org/3/library/sqlite3.html#how-to-use-placeholders-to-bind-values-in-sql-queries)).


## Why it is Hard, not a one-liner

Two design facts make the obvious attacks fail and force a real UNION:

1. **The flag is in a different table.** The query reads only from `assets`
   (public inventory). The flag lives in a separate **restricted custody
   registry** that no endpoint exposes. So `' OR '1'='1' --` — the reflex
   injection — just returns all six public assets. To cross from `assets` into
   the restricted table you need a
   [`UNION`](https://www.sqlite.org/lang_select.html#compound_select_statements),
   and SQLite requires both sides of a `UNION` to have **the same number of
   result columns** (otherwise: *"SELECTs to the left and right of UNION do not
   have the same number of result columns"*). The base query selects **four**
   columns, so the injected `SELECT` must too.

2. **The schema is per-instance.** The restricted table's name
   (`cust_<8 hex>`) and the flag's column name (`memo_<8 hex>`) are derived from
   `ZSCTF_SEED` (`_derive()` in the source) and are printed nowhere. You cannot
   hardcode `SELECT flag FROM secrets`; you must **enumerate the live schema**
   against your own instance via
   [`sqlite_master`](https://www.sqlite.org/schematab.html) /
   [`pragma_table_info`](https://www.sqlite.org/pragma.html#pragma_table_info).


## Steps (what `solution/solve.py` does)

0. `GET /whoami` — confirm the instance (public, non-secret fingerprint).
1. **Column count.** Probe `… ' ORDER BY N -- ` for `N = 1, 2, …`. The DB errors
   once `N` exceeds the real column count (and the legacy app reflects that
   error), so the last `N` that succeeded is the arity — here **4**.
2. **Find the restricted table.** The flag isn't in `assets`, so UNION-select
   the table list:
   `__none__' UNION SELECT name,'','','' FROM sqlite_master WHERE type='table' AND name<>'assets' AND name NOT LIKE 'sqlite_%' -- `
   → the per-instance `cust_<hex>` table.
3. **Find its columns.** `__none__' UNION SELECT name,'','','' FROM pragma_table_info('cust_<hex>') -- `
   → `id, tag, ct_<hex>, km_<hex>, clearance`. **The flag is not here in
   plaintext.** Two seed-named columns hold it *enciphered and split*:
   `ct_<hex>` (ciphertext) and `km_<hex>` (key material).
4. **Blind two-channel extraction + offline unscramble** — the flag-extraction
   layer. See the dedicated section below; this is what turns the oracle into
   the flag.

The solver discovers the table and column names at run time, so it works against
any seed without modification. Example run (note the per-instance row order: the
real custody record is **not** always row 1, and the decoy row is rejected by
the strict validator, not by guessing):

```
[+] column count of the base query = 4
[+] restricted registry table = cust_6e37865a
[+] its columns = clearance, ct_7b09402d, id, km_ae669d49, tag
[+] ciphertext channel = ct_7b09402d ; key-material channel = km_ae669d49
[+] custody rows to examine = 2
[+] custody id=1 -> zerosecurectf{f3f3beb9e66aa525-leak}  [decoy (rejected by strict validator)]
[+] custody id=2 -> zerosecurectf{cr0ss_the_cust0dy_b0undary_then_unscramble}  [FLAG]
[+] FLAG = zerosecurectf{cr0ss_the_cust0dy_b0undary_then_unscramble}
```


## Flag extraction 

This challenge satisfies the S2 / S2a organizer directive: solving the SQLi crux
earns you an **oracle**, not the flag. The flag is captured by a bespoke,
multi-step **blind, two-channel extraction** layered on top of the injection.

### Mechanism — a "custody cipher" behind a blind oracle

The flag is **never stored in plaintext** — not in the source, not in `assets`,
not in the restricted registry. The restricted custody record stores it
*enciphered and split across two columns* (`_scramble()` / the `KMASK_HEX`,
`PERM_HEX` seeds in `challenge/app.py`):

```
ct[i]  = flag[P[i]] XOR K[i]        # channel 1  (CT_COL = ct_<hex>): permute, then XOR
keymat = KMASK_HEX || PERM_HEX      # channel 2  (KEY_COL = km_<hex>): the key to invert
```

* `K` is an XOR keystream expanded (SHA-256 counter-mode) from `KMASK_HEX`.
* `P` is a permutation derived (seeded Fisher–Yates) from `PERM_HEX`.
* Both seeds are per-instance (`SHA-256(ZSCTF_SEED | label)`) and printed
  **nowhere** — the white-box source reveals the *algorithm*, never the *key*.

**The blind channel.** Neither column is dumped in bulk. The SQLi grants a
**boolean + length side channel**: inject `__none__' OR <predicate> -- ` and the
base `assets` query returns the public inventory when `<predicate>` is true
(`count > 0`) and nothing when false (`count == 0`). With

```
length((SELECT <col> FROM <tbl> WHERE id=R))                  -- channel length
unicode(substr((SELECT <col> FROM <tbl> WHERE id=R), k, 1)) <= V   -- per-char
```

the solver binary-searches each character of **both** `ct_<hex>` and `km_<hex>`,
one position at a time. The enciphered bytes themselves never appear in any
response — only the boolean does — so the player blind-extracts the ciphertext
**and** the key, then combines them **offline**:

```
flag[P[i]] = ct[i] XOR K[i]        # un-XOR, then invert the permutation P
```

So solving the crux once is *not* enough: a single clean read yields only one
enciphered half; you must earn **both** channels and do the offline unscramble.

### Why the hard invariants hold

* **Not a one-shot read.** No single UNION returns `zerosecurectf{…}`; the flag
  is enciphered and split, so even `UNION SELECT ct||'~'||km …` in one response
  gives only scrambled hex that still needs `K`, `P` and the offline inversion.
  The plaintext flag appears in **no** response. *(test: “single direct read
  does NOT yield the flag”, “ciphertext channel is scrambled, not the flag”.)*
* **The blind channel is real.** The boolean+length oracle is proven directly in
  the test (true/false length probe and a true/false per-byte probe), not merely
  via the solver. *(test: “blind boolean+length oracle exposes enciphered
  bytes”.)*
* **Fully solvable by the intended path.** The reference solver performs the
  FULL character-by-character blind extraction of both channels and the offline
  unscramble, against any seed. *(test: “solver completes FULL blind extraction
  and wins the flag”; proven end-to-end against the Docker container too.)*
* **Guess-exposure 0 — every decoy is rejectable by reasoning.** The published
  strict validator `^zerosecurectf\{[a-z0-9_]{8,48}\}$` is the single
  discriminator:
  - **Skip-the-unscramble trap.** Un-XOR but forget to invert `P` and you get the
    flag's characters *in permuted order* — a format-INVALID near-flag. *(test:
    “skip-the-unscramble path yields a strict-INVALID near-flag”.)*
  - **Decoy custody row.** The registry holds a second record whose plaintext is
    `zerosecurectf{<16 hex>-leak}` — flag-shaped but carrying a **hyphen**, so it
    fails the validator. Row order is seed-chosen, so the real record is not
    always row 1; the solver extracts each row and keeps only the
    validator-passing one. *(test: “decoy custody row is a strict-INVALID
    near-flag”.)*
  - **Public asset decoy.** `AST-0000`’s name is `zerosecurectf{<10 hex
    UPPERCASE>}` — the first flag-shaped string a lazy `OR 1=1` dump surfaces,
    rejectable because its body is uppercase. *(test: “public asset decoy is
    flag-shaped but strict-INVALID”.)*
* **Determinism + per-instance.** The ciphertext, key seeds, column names, decoy
  bodies and row order all derive from `ZSCTF_SEED`; the flag is `ZSCTF_FLAG`
  (default `zerosecurectf{REPLACE_ME_AT_DEPLOY}`). Same seed → byte-identical
  artifact. *(test: determinism checks.)*

### Honest limits (organizer note)

The protection is the **scramble + split + blind channel**, not output hiding.
A solver *could* read the two enciphered columns via UNION substrings instead of
the boolean oracle — but that is the same character-granular work, and it **still
yields only the two enciphered halves**, which are useless without the offline
`K`/`P` inversion. There is deliberately no bulk-read "redaction" filter, because
an output filter is not a real boundary against injection and would be a false
comfort; the genuine floor is that the plaintext flag exists in no column and in
no response. The reference solver uses the boolean+length oracle as the canonical
blind path.


## Why the intended path is the only cheap one

- **No admin endpoint to attack.** There is exactly one data endpoint
  (`/lookup`) and no authentication layer — nothing to brute-force or bypass.
  The restricted registry is reachable *only* through the injection. (This is
  the "broken access control between user and admin data" of the lineage seed,
  realised as SQLi rather than a logic flaw.)
- **Boolean injection is insufficient.** The flag is not in `assets`; the test
  asserts `' OR '1'='1' --` returns the six public rows and no flag.
- **Column count genuinely matters.** A 3-column UNION against the 4-column base
  query errors; the test asserts this.
- **No destructive / stacked injection.** Python's `sqlite3.Cursor.execute()`
  runs exactly one statement — stacked payloads like `'; DROP TABLE assets; --`
  raise `ProgrammingError` and change nothing (see the `sqlite3` docs:
  *"execute() will only execute a single SQL statement"*). The injection is
  strictly **read-only**; the test asserts the stacked payload is rejected and a
  follow-up lookup still works.
- **No answer recall.** The table and column names are seed-derived, so a
  memorised payload or a leaked write-up does not transfer — every team must
  enumerate their own schema. (The in-memory DB and read-only FS mean there is
  no file to read out of band, either.)
- **No guessing.** White-box source; the route is reached purely by reasoning
  about the query grammar, with the reflected DB error as the column-count tell
  (guess-exposure ≈ 0).


## Design notes (for the ZSCTF team)

- **Lineage** (`corpus-genome.yaml`, reconstruction per system.html §17):
  - `zsctf-web-003 "Security Driven"` — borrowed the crux **"chain a user-driven
    primitive into disclosure of an admin-only record"** and the guard
    **"access control between user and admin data."** Operator **`GROUND`**
    (system.html §17.3: *attach a real scenario*) — grounded into a legacy
    internal asset-registry tool with a genuine public/restricted table split.
  - `zsctf-web-013 "wp-admin"` — borrowed the **real-hardening deployment
    posture** (read-only install + blocked egress). Operator **`GUARD-SWAP`**
    (§17.3: *replace an artificial rule with a real mitigation*) — the
    restricted data is separated by real schema/table boundaries and a hardened
    container, not an invented "you may not type UNION" rule.
  - **`PARAMETERISE`** (§17.3: *expose a knob; enables per-instance variants*) —
    the schema names and flag are moved onto `ZSCTF_SEED`.
- **Crux (insight class):** cross a trust boundary that exists only in the
  application's *intent* (public `assets` vs. restricted registry) but not in the
  *query construction*, by supplying a correctly-shaped `UNION` after enumerating
  a per-instance schema.
- **Primitives:** SQL injection (CWE-89); verbose error leakage
  ([CWE-209](https://cwe.mitre.org/data/definitions/209.html)); broken access
  control (OWASP A01:2021); improper neutralisation of input
  ([CWE-20](https://cwe.mitre.org/data/definitions/20.html)).
- **Per-instance:** `ZSCTF_SEED` → restricted table name + flag column name;
  `ZSCTF_FLAG` → the flag; `/whoami` exposes only a non-secret fingerprint. Same
  seed → same schema (verified by the test).
- **Harder variants (extrapolation):**
  - **`CONSTRAIN` → blind (SHIPPED as the flag-extraction layer).** The
    column-count and schema-enumeration steps still reflect rows/errors (so the
    crux stays reasoned, not guessy), but the final *flag read* is now a
    **boolean+length blind** extraction of an enciphered, split custody record
    (see “Flag extraction ”). This raises the tooling axis and
    adds an offline crypto step without making the crux itself guessy.
  - **`SUBSTITUTE-PRIMITIVE` → second-order.** Store the tag safely on write,
    then use it unsafely in a later report query — defeats naive single-request
    scanners and is a cleaner authenticity story for some skins.
  - **`GUARD-SWAP` → a real WAF.** Add a production-style input filter and
    require comment/whitespace/encoding evasion — but this risks drifting from
    "SQLi" to "WAF-bypass trivia" and over-hardening to unsolvable (§17.3's
    flagged GUARD-SWAP risk), so it is tracked, not shipped.

---

