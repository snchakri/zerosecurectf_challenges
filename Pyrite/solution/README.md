# Pyrite — solution

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

The event accepted recovered flag-shaped tokens from these decoy challenges. The reference analysis also reports why they fail the original strict-format validator. For this archived event, compare each recovered token against `accepted_flags.txt`; do not interpret the original “no flag” design commentary as the event scoring rule.

# Pyrite — official writeup  (solution)

> **State it plainly: Pyrite is a honeypot / tarpit. There is NO real flag
> anywhere reachable, by design.** This document must never reach players: it
> names the trap outright, enumerates the tells, and states the intended
> outcome. Only `challenge/`, `README.md`, and (optionally) `challenge.yml`
> metadata are player-facing.


## What this challenge is

Pyrite presents as an ordinary, slightly abandoned internal "Key Recovery
Service." It deliberately dangles three classic cryptanalysis leads —

1. a **weak-looking RSA** key with a ciphertext (`/params` → `rsa`, `/recover/rsa`),
2. a **reused-nonce** signature pair (`/params` → `ecdsa`, `/recover/nonce`), and
3. a **leaked partial private key** (`/params` → `partial`, `/recover/partial`),

— and it rewards poking at them with plausible, flag-shaped strings from
canned "recovery" oracles. All of it is theatre. **Every "flag" the service can
emit is a decoy that fails two independent checks** (the strict format validator
*and* the integrity digest the service publishes about itself), and **each
advertised weakness is provably a dead end from the published parameters alone.**

The pedagogical target is a genuine, hard-to-teach red-team skill:
**recognise a honeypot / rabbit-hole and disengage** — timebox the target,
weigh evidence over momentum, and stop. This mirrors a real defensive technique:
deception grids / tarpits that feed attackers decoys and false leads to burn
their time and reveal their presence. (Background: MITRE Engage formalises
*Decoy Content* and *Decoy Artifacts* as deliberate active-defense techniques —
https://engage.mitre.org/ ; honeypots/honeytokens are long-standing practice —
L. Spitzner, *Honeypots: Tracking Hackers*, Addison-Wesley, 2002.)


## Why there is provably no flag (the load-bearing tell)

The service publishes, at **`/.well-known/zsctf-manifest.json`**, a field
`flag_sha256` — ostensibly "the sha256 of the correct flag," offered as an
integrity check so you can verify a candidate before submitting (the README even
coaches players to do this). The published value is:

```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

That is **`sha256(b"")` — the digest of the empty string** (a constant any
experienced analyst recognises; e.g. `printf %s "" | sha256sum`, or RFC 6234's
test vectors). The only byte string whose SHA-256 is this value is the empty
string. So the service's own published integrity check says the correct flag is
*empty*: i.e. **there is no flag.** This is the quiet, decisive tell. It is
reinforced by `/validate`, which rejects *every* candidate including the empty
string, so the player can confirm by experiment that nothing this node accepts
exists.

This is intentionally an *inversion* of the usual integrity-check role
(a CWE-345-style "insufficient verification" value, here weaponised as a tell):
the manifest looks like it validates a real flag; reading it closely proves the
opposite.


## The three decoy leads (each dead-ends with a verifiable tell)

All decoy values are per-instance (`ZSCTF_SEED`), so they differ per team while
the conclusion is identical. Every claim below is checkable from `/params`
alone — the solver (`solution/solve.py`) does exactly these checks.

**Lead 1 — "weak RSA".** `/params` → `rsa` publishes `N`, `e=65537`, `c`, with a
note inviting Fermat/low-entropy factoring. `/recover/rsa` returns a candidate:

```
zer0securectf{rsa_modulus_factored_<hex>}
```

*Tells:*
- **`N` is PRIME.** It is built with `next_prime(...)`; `sympy.isprime(N)` (or
  the deterministic-base Miller-Rabin in `solve.py`) confirms it. A prime
  modulus has no non-trivial factorisation — **there is nothing to factor**,
  so Fermat, Pollard rho/p−1, ECM, and factordb all terminate with nothing.
- Even granting that primality makes the key "breakable" (`N` prime ⇒
  `φ(N)=N−1` ⇒ `d=e⁻¹ mod (N−1)` exists), the published `c` is **derived noise,
  not an encryption of anything**. Decrypting it (`m = c^d mod N`) yields
  **garbage bytes with no flag-shaped substring** — the solver performs this
  decryption and shows the result is not a flag.
- The emitted candidate uses the prefix **`zer0securectf`** (a zero), which
  fails the strict validator `^zerosecurectf\{[a-z0-9_]{8,48}\}$`.

**Lead 2 — "reused nonce".** `/params` → `ecdsa` publishes the secp256k1 order
`n` and two signatures `(h1,r1,s1)`, `(h2,r2,s2)` with a note that the signer
reused the per-message nonce `k`. `/recover/nonce` returns:

```
zerosecurectf{NONCE_REUSE_RECOVERED_<HEX>}
```

*Tells:*
- Reusing a nonce `k` forces **`r1 == r2`** (because `r` is derived from `k·G`
  alone, independent of the message). Here **`r1 != r2`**, so **no nonce was
  reused** and the stated vulnerability is false — the private-key recovery
  `k=(h1−h2)/(s1−s2)`, `d=(s1·k−h1)/r mod n` has no valid input. A one-line
  comparison of `r1` and `r2` closes this lead.
- The emitted candidate has an **uppercase body**, failing the `[a-z0-9_]`
  charset.

**Lead 3 — "leaked partial key".** `/params` → `partial` publishes a genuine
1024-bit RSA semiprime `N`, `e=65537`, and `d_low` = the low **32** bits of the
real private exponent `d` (`d_low_bits: 32`). `/recover/partial` returns:

```
zerosecurectf{partial-key-completed-<hex>}
```

*Tells:*
- Known-bits / partial-key-exposure recovery (Coppersmith-type lattice attacks;
  Boneh–Durfee–Frankel, *CRYPTO '98*) requires knowing a **constant fraction —
  about ¼ — of the bits of `N`**, i.e. ~256 bits for a 1024-bit modulus. **32
  bits is provably far too few**; no lattice attack can complete the key from
  it. The check `d_low_bits < N.bit_length()//4` (32 < 256) is script-detectable.
- The emitted candidate contains **hyphens**, failing the charset.


## The full list of tells a skilled analyst uses

1. **`flag_sha256 == sha256("")`** in the published manifest → the correct flag
   is empty → there is no flag. *(decisive)*
2. **`/validate` rejects everything**, including the empty string and the
   service's own decoys → the node admits nothing is acceptable.
3. **Every emitted candidate fails the strict format** (`zer0…`, uppercase,
   hyphens) — three different, deliberate malformations.
4. **The "weak RSA" modulus is prime** → nothing to factor; and its ciphertext
   decrypts to garbage.
5. **The "reused nonce" premise is false** (`r1 != r2`) → no key recoverable.
6. **The "leaked partial key" is insufficient** (32 bits ≪ ~256) → no recovery.
7. **The `/recover/*` oracles are canned** — identical bytes regardless of any
   query input; no computation is happening behind them.
8. **`robots.txt` canary marker** — `honeyfarm canary node -- DECOY tier`,
   `synthetic key material only`, `do-not-promote`.
9. **The index HTML comment** — `build: pyrite-canary * tier=decoy *
   artifacts=synthetic * do-not-promote`.
10. **`/whoami` and `/params` report `"tier": "decoy"`** outright.

No single tell is a billboard; together they are overwhelming and all are
verifiable from responses. A careless solver or naive automation will instead
extract a flag-shaped string, submit it, fail, extract the next, and loop — the
tarpit doing its job.


## Intended outcome — "recognise the honeypot and leave"

The intended solve is a **negative result reached by evidence**: the analyst
investigates with a time budget, notices that the RSA modulus is prime (nothing
to factor), the nonce reuse does not hold (`r1 != r2`), and the partial key is
too short to finish, reads the published manifest and recognises the empty-string
digest (confirmed by `/validate` rejecting even the empty flag), concludes
**"this is a honeypot — there is nothing to capture here,"** and disengages
without submitting anything. `solution/solve.py` performs exactly this analysis and
prints `VERDICT: HONEYPOT / TARPIT -- no reachable flag. DISENGAGE.` (exit 0).
Scoring/triage should credit reaching and *justifying* that conclusion, not a
flag submission.


## Operations notes (for the ZSCTF team)

  asserts that an injected `ZSCTF_FLAG` never appears in any response. Do not
  set a real flag in deployment — there is nothing to inject.
- **Per-instance.** `ZSCTF_SEED` derives the RSA prime modulus and ciphertext,
  the signature pair, the semiprime + leaked `d` bits, the decoy flag bodies,
  and the public node fingerprint. Same seed → same node (verified by the test);
  different seed → different decoys.
- **Zero runtime third-party deps.** Prime generation and primality are pure
  stdlib (deterministic-base Miller-Rabin); Flask is used if present, else the
  stdlib `http.server` fallback. No sympy/pycryptodome/gmpy2 at runtime.
- **Hardening is real** (non-root uid 10001, read-only FS, caps dropped,
  internal/egress-blocked network) so a tarpit never becomes a pivot — but note
  it protects *no* secret, because there is none.
  on both backends (solver agrees), all three decoys present and rejectable,
  `/validate` self-rejects, six distinct tells script-detectable, `ZSCTF_FLAG`
  ignored, and determinism.

---

