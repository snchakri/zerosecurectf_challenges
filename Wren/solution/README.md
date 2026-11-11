# Wren — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Wren — official writeup

**Flag (demo seed):** `zerosecurectf{a_sm4ll_d_f4lls_t0_w13ner}` (per-instance in production)


## The flaw

To decrypt/sign quickly the device uses a **small private exponent** `d` (well
under `N^0.25`). A small `d` is catastrophic for RSA: because `e·d ≡ 1 (mod
φ(N))` and `e` is correspondingly large, the fraction `e/N` is extremely close
to `k/d` for some small `k`, so `d` appears among the continued-fraction
convergents of `e/N` (Wiener, 1990). CWE-327.


## The attack (Wiener)

1. Expand `e/N` as a continued fraction; walk its convergents `k_i/d_i`.
2. For each convergent, if `(e·d_i − 1)` is divisible by `k_i`, take
   `φ = (e·d_i − 1)/k_i`, form `x² − (N − φ + 1)x + N = 0`, and check the
   discriminant is a perfect square — that identifies the true `d`.
3. Recovering `d` is the **gate**. It does **not** hand you the flag; it earns
   you the device's private operation (RSA decryption, `c^d mod N`) — the
   *means* to run the activation chain below.

Pure Python continued fractions; no `gmpy2`/`sage` needed.


## Flag extraction 

**Invented mechanism — "RSA activation token-chain" (a decryption-linked hash
chain; one fragment per decryption, each decryption earns the next ciphertext).**
This is the S2/S2a layer. It is deliberately *not* secret-sharing, blind
char-by-char oracle, state-machine streaming, per-piece reconstruction,
layer-peel, polynomial interpolation, split-KDF, CRT, or commitment-opening.
Here the recovered private key drives a **chain of RSA decryptions**, and the
*server gates the chain*: it releases ciphertext `i+1` only after you prove you
decrypted ciphertext `i`.

How it is built (`challenge/server.py`, `build_chain`):

1. The flag is split into `n` fragments (`n = ceil(len/5)`, min 2). For stage
   `i` the device builds a fixed 64-byte record
   `b"WREN" | idx | n | link(8) | declen | decoy_frag | reallen | real_frag |
   crc32(real_frag)`, then **encrypts it under the public key**:
   `ct_i = record^E mod N`.
2. Only `ct_0` is published (as the banner's `c`). The 8-byte `link_i` nonce is
   `SHA-256(SEED | "link" | i)[:8]` — unpredictable without talking to the
   device in order.
3. Protocol: the solver decrypts `ct_i` with the recovered `d`
   (`record = ct_i^d mod N`), reads `real_frag` (authenticated by its embedded
   `crc32`) and `link_i`, and sends `LINK <link_i hex>`. The device verifies the
   link and **replies `NEXT <ct_{i+1}>`** (or `DONE` on the last stage).
4. The token is assembled only by concatenating the `n` CRC-authenticated
   `real_frag`s. **It never crosses the wire in cleartext** (only ciphertexts and
   link nonces travel), **no single response contains it**, and a single
   decryption yields only one fragment — so it is not one-shot-decryptable.
   `fpr` in the banner (`crc32` of the whole flag) lets the solver confirm the
   full assembly (verify-before-commit).

Why solving the crux earns only the *means*: `d` lets you decrypt, but the flag
is spread across `n` server-gated ciphertexts you can only obtain one at a time
by proving each prior decryption. See `solution/solve.py::solve` for the full
ciphertext/one response does **not**, that the decoy path fails, and determinism.


## Rabbit-holes 

- **R1 — banner "factory test key" decoy** (`activation=zerosecurectf{FACTORY_TEST_KEY}`).
  First flag-shaped string a lazy `strings`/grep surfaces. *Tell:* UPPERCASE body
  fails the published strict validator `^zerosecurectf\{[a-z0-9_]{8,48}\}$`.
- **R2 — `SUBMIT` footgun** (the textbook "decrypt the ciphertext and submit it"
  reflex, which the *original* challenge rewarded). *Tell:* `SUBMIT` now always
  returns `DENIED staged activation in effect` — it never emits a flag; the
  banner states activation is staged (`stages n`), so a one-shot submit is
  provably insufficient.
- **R3 — decoy fragment fields** inside every record. Concatenating the
  `decoy_frag`s across stages assembles a near-flag (`zerosecurectf{A_SM4LL_D_…}`,
  the UPPERCASED body). *Tell:* each record's `crc32` authenticates the *real*
  fragment, not the decoy; the real assembly matches the banner's `fpr` and the
  decoy fails the strict validator. Guess-exposure 0 — the discriminator (CRC +
  format + `fpr`) is fully present in the artifact.
- **R6 — reframed, not textbook.** The ciphertext is no longer a lone "message
  to decrypt"; it is the head of a gated chain, so pattern-matching "small-d RSA
  → decrypt → done" stops one fragment short and must be reasoned past.

All rabbit-holes cost the *careless* time only; the reference solver documents
the exact escape for each (CRC-authenticated field selection, strict-format and
`fpr` confirmation).


## Why the intended path is the only cheap one

- `N` is 1024-bit → factoring infeasible.
- The token space is large → no brute force.
- Wiener only works *because* `d` is small (the deliberate flaw); the convergent
  test is a conclusive, reasoning-bounded check (guess-exposure 0).

