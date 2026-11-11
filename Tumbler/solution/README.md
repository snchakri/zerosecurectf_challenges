# Tumbler — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Tumbler — official writeup

**Flag:** `zerosecurectf{tumbl3rs_f4ll_wh3n_p4dd1ng_t4lks_t00_much}` (static demo seed; per-instance in production)


## The flaw

A CBC decryptor has one job it must do *silently*: if it is going to tell the
world whether the PKCS#7 padding it just stripped was well-formed, it hands an
attacker a decryption oracle for free. Tumbler commits exactly that sin, in the
open:

```python
def padding_ok(blob):
    iv, ct = blob[:BLOCK], blob[BLOCK:]
    pt = AES.new(KEY, AES.MODE_CBC, iv).decrypt(ct)
    try:
        unpad(pt, BLOCK)      # strict PKCS#7; raises on bad padding
        return True           # <-- this one bit is the whole vulnerability
    except ValueError:
        return False
```

It never returns a plaintext byte. It returns one bit — *valid* / *invalid* —
about any ciphertext you like. That is enough to decrypt the entire sealed token
without the key. This is the classic **CBC padding oracle** attack
(Vaudenay, EUROCRYPT 2002), the same bug that later surfaced as **POODLE**
(2014) and, in a timing-leak form, **Lucky Thirteen** (AlFardan–Paterson 2013).
It is Cryptopals Set 3, Challenge 17.


## Why it breaks

Write the sealed blob as `IV || C_1 || C_2 || ... || C_n` with 16-byte blocks.
CBC decryption is:

```
P_t = Dec_K(C_t) XOR C_{t-1}        (with C_0 = IV)
```

Call `I_t = Dec_K(C_t)` the **intermediate state** — the AES block-decryption of
`C_t`, *before* the CBC XOR. It depends only on the key and `C_t`, not on
position. So if we learn `I_t`, we learn the real plaintext for free:
`P_t = I_t XOR C_{t-1}`.

To learn `I_t`, forge a two-block query `B' || C_t` and send it to `CHECK`. The
oracle treats `B'` as the IV, so the plaintext of the second block is:

```
P' = Dec_K(C_t) XOR B' = I_t XOR B'
```

We control `B'` completely, so we can aim `P'` at a chosen padding string and let
the one bit tell us when we hit it. Recover `I_t` byte by byte, from the last
byte (index 15) to the first:

- **Byte 15.** Hold `B'[0..14]` fixed and sweep `B'[15]` over `0..255`. When the
  oracle says *valid*, the last plaintext byte is almost certainly `0x01`, so
  `I_t[15] = B'[15] XOR 0x01`.
- **Byte j (going down).** Having recovered `I_t[j+1..15]`, set the padding
  length `pad = 16 - j` and pin every known byte: `B'[k] = I_t[k] XOR pad` for
  `k > j`. Sweep `B'[j]`; a *valid* answer means plaintext byte `j` is `pad`, so
  `I_t[j] = B'[j] XOR pad`.

**The one subtlety (where naive solvers break):** at byte 15 the oracle also
fires if the tail happens to already read a longer valid padding (e.g. the real
bytes end `... 0x02 0x02`). Disambiguate by perturbing `B'[14]` and re-querying:
if the padding is genuinely length-1 (`0x01`) the answer stays *valid*; if it was
a longer-padding coincidence, it flips to *invalid* and we keep sweeping. The
reference solver (`solution/solve.py`, `recover_intermediate`) does exactly this.

Do this for every block (the first real block uses the published `IV` as
`C_0`), concatenate the `P_t`, strip PKCS#7, and you hold the unlock token —
*without ever knowing the key*.


## Steps

1. Read the `sealed` blob from the banner and split it into 16-byte blocks.
2. For each ciphertext block `C_t`, recover `I_t = Dec_K(C_t)` with the
   byte-by-byte oracle sweep above (~`256 × 16` queries per block worst case).
3. `P_t = I_t XOR C_{t-1}`; concatenate and strip PKCS#7 → the token
   (`ZSCTF-VAULT-<32 hex>`).
4. `UNLOCK <token_hex>` → the vault opens and prints the flag.

Query budget: the published blob is `IV` + three ciphertext blocks, so recovery
costs a few thousand `CHECK` queries and completes in well under a second
locally — comfortably inside the test's 120 s budget.


## Why the intended path is the only cheap one

- **No shortcut past the oracle.** `UNLOCK` compares against a 128-bit token
  (`sha256`-derived), so it cannot be guessed or brute-forced; the only way to
  learn it is to decrypt the blob, and the only decryption handle is the padding
  bit. A static copy of the ciphertext alone is useless — you need the *live*
  oracle. (This is the `CONSTRAIN` move: an online oracle, not a dump.)
- **No break of AES.** Recovering the key is infeasible; the attack sidesteps it
  entirely and never needs it.
- **No guessing.** The leak is visible in the source, so the route is reachable
  purely by reasoning (guess-exposure 0): see the returned bit, model CBC, sweep.
  `PAD OK`/`PAD FAIL` and never emits the token or flag; malformed blobs get a
  structural error rather than a padding verdict; `UNLOCK` with a forged or
  guessed token (including the sealed blob itself) is denied; and the flag is
  unreachable without the real token.


## Design notes (for the ZSCTF team)

- **Lineage:** Cryptopals/CryptoHack symmetric-cipher reservoir — the **CBC
  padding oracle** (Cryptopals Set 3 #17; genome anchors `zsctf-anchor-013/014`
  describe the Cryptopals reservoir). Crux shape borrowed from
  `zsctf-crypto-005 APES` (keyed block-cipher encryption with exploitable
  structure) via `SUBSTITUTE-PRIMITIVE`; the online query-limited oracle model
  borrowed from `zsctf-crypto-017 An Evil Twisted Mind` via `CONSTRAIN`.
  Operators applied: `GROUND` (a sealed-token vault / encrypted-session-cookie
  service — the real setting of POODLE and Lucky13), `CONSTRAIN` (a live
  one-bit oracle, not a static ciphertext dump), `PARAMETERISE` (per-instance
  key/IV/token/flag from `ZSCTF_SEED`). See `corpus-genome.yaml` and
  `system.html` §17.3.
- **Harder variants (extrapolation), to raise the band toward Extreme/Frontier:**
  - *Starve the oracle* (`CONSTRAIN`): a hard per-connection query cap (e.g. a
    few hundred) forces the solver to economise — recovering only a MAC/length
    field, or exploiting structure — rather than sweeping all 256 values per
    byte.
  - *Noise the bit* (`PARAMETERISE`): answer correctly only with probability
    `p < 1`, forcing statistical confirmation per query (ties to the Lucky13
    timing-oracle reality).
  - *Remove the IV* or make it fixed-and-secret: the first block becomes
    unrecoverable, forcing the solver to reason about what is and isn't leaked.
  - *Swap the padding* (`SUBSTITUTE-PRIMITIVE`): an ISO/IEC 7816-4 or ANSI X.923
    scheme changes the sweep logic and defeats copy-pasted PKCS#7 tooling.
  These are tracked as `CONSTRAIN` / `PARAMETERISE` / `SUBSTITUTE-PRIMITIVE`
  neighbours in the design space (§17.3).

---

