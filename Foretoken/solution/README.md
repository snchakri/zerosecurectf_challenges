# Foretoken — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Foretoken — official writeup

**Flag:** `zerosecurectf{624_untemp3r3d_w0rds_f0r3t3ll_th3_n3xt_t0k3n}` (static demo seed; per-instance in production)


## The flaw

Security tokens must be **unpredictable**. Foretoken mints password-reset tokens
with Python's `random` module:

```python
def _mint(rng):
    return "".join("%08x" % rng.getrandbits(32) for _ in range(4))   # 128-bit token
```

`random` is a **Mersenne Twister (MT19937)** — a fast, general-purpose PRNG that
was never designed to resist prediction. Python's own documentation says so in
as many words:

> *"The pseudo-random generators of this module should not be used for security
> purposes. For security or cryptographic uses, see the `secrets` module."*
> — Python Standard Library, `random` ([docs.python.org/3/library/random.html](https://docs.python.org/3/library/random.html))

Using it to generate a password-reset token is exactly **CWE-338: Use of
Cryptographically Weak Pseudo-Random Number Generator (PRNG)**
([cwe.mitre.org/data/definitions/338.html](https://cwe.mitre.org/data/definitions/338.html)),
a specialisation of **CWE-330: Use of Insufficiently Random Values**
([cwe.mitre.org/data/definitions/330.html](https://cwe.mitre.org/data/definitions/330.html)).
"Predict a reset token" is a real account-takeover primitive, which is what makes
the toy service a faithful teaching instance.


## Why it breaks

MT19937's internal state is **624 words of 32 bits**
(Matsumoto & Nishimura, *Mersenne Twister*, ACM TOMACS 8(1), 1998 —
[dl.acm.org/doi/10.1145/272991.272995](https://dl.acm.org/doi/10.1145/272991.272995)).
Every `getrandbits(32)` output is **one state word passed through a fixed
"tempering" transform**:

```
y ^= (y >> 11)
y ^= (y << 7)  & 0x9D2C5680
y ^= (y << 15) & 0xEFC60000
y ^= (y >> 18)
```

Each of those four steps is a bijection on 32-bit words, so the whole transform
is **invertible**. Given an output you can *untemper* it back to the state word
that produced it. Collect **624 consecutive outputs**, untemper all of them, and
you have reconstructed the entire internal state — a perfect clone of the
generator. From there every future output is deterministic.

The service hands you **156 tokens × 4 words = 624 outputs**: exactly one state's
worth, by design. The 157th token (the administrator's) is just the next four
outputs of a generator whose state you now hold.

### The one subtlety: block alignment

MT19937 produces outputs in blocks of 624 and "twists" its state between blocks.
Python seeds via `init_by_array` and leaves the word index at 624, so the **first**
`getrandbits` call triggers the first twist. The first 624 outputs after seeding
are therefore exactly **one block-aligned state** — which is why untempering the
156 issued tokens yields a clean state array, and why reloading it with the word
index set to **624** (so the next draw twists, just as the service's generator
did) reproduces the stream exactly. This is verified end-to-end by the acceptance
test, not merely asserted.


## Steps

1. `HISTORY` → the 156 issued tokens, in order.
2. Split each 32-hex token into four 8-hex words (most-significant word first =
   generation order) → the 624-output stream.
3. `untemper` each output → the 624 state words.
   *(Self-check: re-tempering the recovered words must reproduce the outputs.)*
4. Reload the state into a fresh `random.Random` with index 624:
   `clone.setstate((3, tuple(state + [624]), None))`.
5. Draw the next four words → the administrator's token. `PREDICT <hex>` → flag.

The reference solver ([`solution/solve.py`](solution/solve.py)) does exactly this in
pure standard library: the untempering is the technique, and `random.Random`
carries the forward prediction.


## Why the intended path is the only cheap one

- **No brute force:** the seed is 256-bit and the state is 19937-bit — neither is
  searchable. Only the structural insight (invertible tempering) wins.
- **No single-token shortcut:** one token is four outputs; the attack needs a
  *full* state, i.e. all 624 outputs. Fewer tokens leave the state undetermined.
- **No guessing:** the generator and token construction are visible in the source,
  so the route is reachable purely by reasoning — guess-exposure 0.

---


## Design notes (for the ZSCTF team)

- **Lineage:** `crypto-008 ECLCG` ("ECDSA nonces from an unknown-parameter LCG
  enable key recovery" — the *predictable-generator* crux) → operator **GROUND**
  (a password-reset token service) + **CONSTRAIN** (an online oracle you must
  interact with, not a static dump). See `corpus-genome.yaml` (§17.3 affordances
  `[GROUND, CONSTRAIN, PARAMETERISE]`).
- **Sibling:** shares the GROUND+CONSTRAIN construction with `signet`, but swaps
  the primitive — `signet` is a *secret-but-linear* ECDSA nonce schedule;
  `foretoken` is *public-algorithm, recoverable-state* MT19937 prediction. Same
  weak-randomness family (CWE-330), two different cruxes.
- **Benign by construction:** a self-contained toy service; the solver works only
  against this service and carries nothing weaponizable. Security education only.
