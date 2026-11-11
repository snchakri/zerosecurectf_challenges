# Noisefloor — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py challenge/params.json
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Noisefloor — Author's writeup

**Category:** crypto · **Band:** Extreme · **Flag:** `zerosecurectf{...}` (per-instance)

---


## 1. The scenario

A vendor sells a "quantum-proof lockbox." It seals a secret under a
**Learning-With-Errors (LWE)** keypair — the lattice assumption underneath
NIST's post-quantum standards (ML-KEM / Kyber, FIPS 203). The published artifact
`params.json` contains:

```
n = 40, m = 52, q = 1048583 (prime ≈ 2^20)
A ∈ Z_q^{m×n}                       (public)
b = A·s + e  (mod q),  s,e ∈ {-1,0,1}   (public b; private s,e)

n2 = 24, m2 = 30, q2 = 1048583          (a SECOND, independent LWE lockbox)
A2 ∈ Z_q2^{m2×n2}, b2 = A2·s2 + e2 (mod q2),  s2,e2 ∈ {-1,0,1}   (public A2,b2; private s2,e2)

salt, nonce, ciphertext, tag                 (AES-256-GCM sealed real flag)
decoy_nonce, decoy_ciphertext, decoy_tag     (AES-256-GCM sealed near-flag)
key = HKDF-SHA256( SHA256("NOISEFLOOR-SPLITKDF-v2" | canon(s) | "|s2|" | canon(s2)) )
```

The sealing key is **split**: it binds the exact ternary secret `s` of the primary
lockbox *and* the exact ternary secret `s2` of a second, independent lockbox. To
open the box you must recover **both** `s` from `(A, b)` and `s2` from `(A2, b2)`,
derive the split key, and AES-GCM-decrypt the flag. Recovering `s` alone — a clean
primary solve — is necessary but **not sufficient**: GCM auth fails until `s2` is
also recovered. (See "Flag extraction " below.)


## 2. The planted weakness: noise below the floor

LWE is hard only when the error `e` is *large enough* relative to the modulus
`q`. The security intuition (Regev 2005; the LWE "noise rate" `α = σ/q`): if the
noise rate is too small, the Bounded-Distance-Decoding (BDD) instance has a huge
gap and collapses to easy lattice reduction.

Real parameters keep that ratio sane — Kyber uses `q = 3329` with centred-binomial
noise of width ~2–3, a ratio on the order of `q/|e| ≈ 10^3`. Here the vendor, to
eliminate decryption failures, used `q ≈ 2^20 ≈ 10^6` with `|e| ≤ 1`, a ratio of
`~10^6`. That is the vulnerability, and it is visible in `params.json` itself —
no obscurity. This is exactly the corpus anchor **zsctf-crypto-018 "Noise Cheap":
*LWE noise size determines resistance to lattice reduction*** (CWE-327, insecure
cryptographic parameter choice).


## 3. Intended solve — the primal / Kannan embedding + LLL

`b = A·s + e (mod q)` means `e = b − A·s + q·w` for some integer `w`, and `(s, e)`
is *short* (ternary). Build the lattice whose unique shortest nonzero vector is
`(±e, ∓s, ±K)`. With columns `[ m | n | 1 ]` and rows (dimension `d = m+n+1 = 93`):

```
block 1  (m rows):  [ q·I_m          0        0 ]
block 2  (n rows):  [ col_j(A)       I_n      0 ]   # row j carries column j of A
block 3  (1 row):   [ b              0        K ]   # embedding row, K = 1
```

The integer combination with coefficients `(w, s, −1)` gives
`(q·w + A·s − b, s, −K) = (−e, s, −K)` — a vector of norm
`≈ sqrt(|e|² + |s|² + K²) ≈ sqrt(52 + 40 + 1) ≈ 9.6`. Everything else in the
lattice has norm on the order of `det^{1/d} = (q^m · K)^{1/93} ≈ q^{52/93} ≈ 2^{11.2}`.
The gap (≈ 2^8) vastly exceeds LLL's Hermite factor `≈ 1.02^93 ≈ 6.3`, so **LLL
alone** finds the short vector — BKZ is not needed.

Read `s` out of the middle block (fixing the sign by the `±K` coordinate), verify
`b − A·s` is ternary. Then repeat the **same** attack on the second, smaller
instance `(A2, b2)` (embedding dimension `m2+n2+1 = 55`, so a few seconds) to
recover `s2`, and derive the split key:

```python
material = sha256(b"NOISEFLOOR-SPLITKDF-v2|" + bytes((x % 3) for x in s)
                  + b"|s2|" + bytes((x % 3) for x in s2)).digest()
key      = HKDF(material, 32, salt, SHA256, context=b"noisefloor/aes256gcm")
flag     = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
```

The reference solver [`solution/solve.py`](solution/solve.py) implements LLL in **pure
Python** (float Gram–Schmidt with incremental swap updates — Lenstra–Lenstra–
Lovász 1982; Cohen Alg. 2.6.3). No `fpylll`, no `sage`. Measured: **~17 s per
author's reliability sweep: 20/20 at the shipped parameters, and earlier 6/6 at
`n=44`).

```
$ python solution/solve.py public/params.json
[+] recovered ternary private key s (dim 40)
[+] s = [-1, 1, 0, 1, -1, 0, ...]
[+] FLAG = zerosecurectf{...}
```


## 4. Why it does NOT reduce to linear algebra (the band-defining point)

A tempting shortcut: take any `n = 40` rows and solve `A₁·x = b₁ (mod q)` by
Gaussian elimination, ignoring the noise. Because `q` is prime this always yields
*a* solution — but with `±1` noise added to `b`, that solution is
`s + A₁⁻¹·e₁ (mod q)`, and `A₁⁻¹·e₁` is a *uniformly random* vector mod `q`. The
this empirically (`mod-q solution differs from true secret`), and the wrong key
fails AES-GCM authentication (`linear-algebra key fails GCM auth`). Exact
recovery of every one of the 40 coordinates is *forced* by the authenticated
encryption — a one-coordinate perturbation already fails the GCM tag.

So the intended solve **genuinely requires lattice reduction**, not linear
algebra. That is the line the ZSCTF band rubric (system.html §8–§9) draws between
Hard and Extreme, and it is why this is banded **Extreme**.


## Flag extraction 

**Mechanism: SPLIT-KDF (key-derived AEAD with a catch).** The recovered primary
LWE secret `s` is only *half* of the AES-256-GCM key. The real sealing key is

```
key = HKDF-SHA256( SHA256( "NOISEFLOOR-SPLITKDF-v2" | canon(s) | "|s2|" | canon(s2) ), 32, salt )
```

where `s2` is the private key of a **second, independent LWE lockbox** `(A2, b2)`
published in the same `params.json` (`n2=24, m2=30, q2≈2^20`). `s2` is *not*
obtainable from the primary solve — `(A2, b2)` is a disjoint instance — so it must
be earned from a second lattice reduction (the identical primal/Kannan + LLL
attack on a smaller, ~55-dim lattice; a few seconds). This makes the extraction a
graded, two-channel process (S2) via a mechanism distinct from the
secret-sharing / blind-extraction / state-streaming layers used elsewhere (S2a):

- **Primary solve alone decrypts to nothing.** A solver who recovers `s` and
  tries the obvious `HKDF(canon(s))` — the legacy one-shot path — gets a key that
  fails the GCM tag. Likewise a split key with a missing/zero `s2`. The flag is
  provably *not* one-shot-decryptable from the primary crux (asserted in
- **Second channel is genuine work, not a freebie.** Recovering `s2` requires
  building and LLL-reducing a second embedding lattice and reading the ternary
  secret out of the short vector — the same skill as the primary, on fresh public
  data. There is no `s2` hint anywhere; only `(A2, b2)`.
- **Decoy second-secret ⇒ rejectable near-flag.** `params.json` ships a second
  (decoy) ciphertext. It opens under `HKDF(canon(s) | canon(−s2))` — i.e. the
  *sign-flipped* second secret — to a flag-shaped but format-invalid string
  `zerosecurectf{SIGNFLIP_decoy_<8 hex>}` (per-instance via `SHA256("noisefloor-decoy"|seed)`).
  The uppercase body fails the published validator `^zerosecurectf\{[a-z0-9_]{8,48}\}$`.
  A careless solver who reads `s2` from the short vector without fixing the ±sign
  (LLL returns the vector up to sign) lands on `−s2`, opens the decoy, and surfaces
  a confident-looking near-flag — but it is rejectable by reasoning, and `−s2`
  does **not** open the real box (wrong key → GCM auth fails).
- **The real box is the one whose plaintext matches the flag format.** Exactly one
  of the two ciphertexts unseals to a string matching the strict validator; that
  is the published discriminator (guess-exposure 0).

The reference solver performs **both** channels and escapes the footgun the same
way a careful human does: `recover_secret` applies the `b2 − A2·s2 ∈ {−1,0,1}`
ternary-consistency gate, which both verifies the solve and fixes the sign, so it
returns `+s2` (never the decoy `−s2`) and then checks the opened plaintext against
the strict flag validator before reporting.


## Rabbit-holes 

| # | Trap | Operator | Reasoning-based tell that rejects it |
|---|---|---|---|
| 1 | **Stop at the primary solve.** Recover `s`, derive `HKDF(canon(s))`, decrypt — the "obvious" one-shot path. | R2 footgun | GCM auth fails. `params.json`'s `kdf.material` states the key is `SHA256(label | canon(s) | "\|s2\|" | canon(s2))` and publishes a *second* lockbox `(A2,b2)`; an `s`-only key cannot pass the tag. |
| 2 | **Sign-flip on `s2`.** LLL returns the short vector up to ±sign; grab `s2`'s block without disambiguating and you get `−s2`, which opens the decoy ciphertext to a near-flag. | R2 / R1 | The near-flag fails `^zerosecurectf\{[a-z0-9_]{8,48}\}$` (uppercase `SIGNFLIP`). The sign is fixed by the published consistency rule: `b2 − A2·(+s2) (mod q2)` is ternary, `b2 − A2·(−s2)` is a large random residue. |
| 3 | **Decoy ciphertext mistaken for the flag.** Two ciphertexts are published; the decoy opens cleanly (valid GCM) under `−s2`. | R4 / R1 | Only the box whose plaintext matches the strict validator is the flag (stated in `note`). The decoy's uppercase body makes it format-invalid on sight. |
| 4 | **Treat the second channel as linear algebra.** Solve `n2` equations mod `q2` ignoring noise. | R2 | Same as the primary: the ±1 error randomises every mod-`q2` solution; the result is non-ternary and fails the `|b2 − A2·s2| ≤ 1` check, and the derived key fails GCM. |


## 5. Honest band statement

**Extreme — with an explicit, documented caveat.** The solve genuinely needs
lattice reduction (linear algebra provably fails; brute force over `3^40 ≈ 2^63.4`
keys and naive meet-in-the-middle over `~2^31.7` are both out of reach for a CTF).
That clears the Hard/Extreme line honestly.

What we do **not** overclaim: the instance is deliberately **LLL-tractable** — it
does *not* require BKZ or a heavy lattice stack, precisely because the planted
"noise too cheap" bug makes the gap huge. A cryptographer who recognises the
primal embedding solves it in an afternoon with any LLL implementation. We place
it at the **entry to Extreme / lower frontier**: it demands genuine lattice-attack
knowledge and a working reduction, but it is not an open-parameter uSVP that would
need state-of-the-art BKZ. Labelling it "Frontier-hard" would be the band
inflation §9 warns against. Its value to ZSCTF is as a *reliable, authentic,
per-instance* anchor for the Extreme band — a band where we currently have almost
nothing and where a self-contained, testable instance is worth more than an
untestable one we could not run.


## 6. Red-team / AI-resistance (honest)

- **Conceptual recognition is easy for a strong solver.** "Small-secret LWE with
  a giant modulus → primal embedding → LLL" is a canonical pattern; a capable
  agent that knows lattice crypto will name it quickly. The differential is not
  *recognition*.
- **The residual resistance is three real gates.**
  1. **Tooling absence.** `fpylll`/`sage` are unavailable in this environment. A
     solver that reflexively reaches for `sage.matrix(...).LLL()` must instead
     *implement* LLL correctly (Gram–Schmidt, size reduction, Lovász condition,
     incremental updates). Agents frequently ship subtly broken hand-rolled LLL
     (wrong swap bookkeeping, float blow-up). This is a genuine, if modest,
     correctness gate — and the reason the reference solver ships a *tested* one.
  2. **The embedding + sign/consistency details.** Getting the block layout,
     the embedding constant `K`, and the `±s` sign disambiguation right (the
     short vector is recovered up to sign) is where naive attempts produce a
     plausible-but-wrong vector. The ternary-consistency check `|b − A·s| ≤ 1`
     is the disambiguator.
  3. **Exact-recovery gate via AEAD.** There is no partial credit: a near-correct
     `s` fails the GCM tag and yields nothing. A solver that stops at
     "approximately recovered the secret" gets no flag.
- **It is not a wall.** A well-engineered agent that (a) knows the primal attack
  and (b) can emit a correct LLL clears all three gates. We tag this as
  **measurement**, not hard resistance, and log agent failure modes per §9
  (broken hand-rolled LLL; wrong sign; stopped at approximate `s`).


## 7. Contamination note

The technique (primal LWE attack) is public and contaminated; measurement value
rests entirely on **per-instance parameterisation**. `A, s, e`, the second-channel
`A2, s2, e2`, `salt, nonce(s)`, the sealed flag, and the decoy near-flag all derive
deterministically from `ZSCTF_SEED` via a portable SHA-256 DRBG, so a memorised or
leaked solution for one team is worthless against another — only the *method*
transfers, and it was already public. Monitor agent
solve-rate on fresh seeds; treat AI-resistance as perishable and re-test on each
major model release (Nullcon/Evolve-CTF guidance, §9).


## 8. Lineage

- **Direct source:** `snchakri/zerosecurectf2026_challenges` →
  `final1/lwe_lockbox` (read-only, untrusted). It framed an LWE instance
  `b = A·s + e (mod q)` with a short secret, but its *intended path* was a
  fragment-parsing / SHA-256-digest / error-vector-matching puzzle with bot-bait
  decoys — not an actual LWE solve. **Operators applied (system.html §17.3):**
  - `GROUND`: reskinned into a real post-quantum **KEM lockbox key-recovery** —
    the authentic setting of insecure PQ parameter selection — and dropped the
    non-load-bearing fragment/digest/bot-bait theater (security by annoyance, not
    maths).
  - `SUBSTITUTE-PRIMITIVE`: the win condition is no longer "match the error
    vector" but "recover the private key by lattice reduction and open an
    AES-256-GCM lockbox," forcing a genuine lattice attack and exact recovery.
  - `PARAMETERISE`: tuned `(n, m, q, noise)` onto the corpus anchor
    **zsctf-crypto-018 "Noise Cheap"** so the modulus/noise gap is the explicit,
    documented vulnerability and the difficulty is honestly dialable.
- **Corpus anchor:** `zsctf-crypto-018` ("LWE noise size determines resistance to
  lattice reduction"; affordances `PARAMETERISE`, `GROUND`).


## 9. What changed vs. the source (summary)

| Aspect | Source `lwe_lockbox` | Noisefloor |
|---|---|---|
| Win condition | match a SHA-derived error vector via fragment puzzle | recover the private key by lattice reduction, open AEAD lockbox |
| Secret | flag bytes (0–255) as the LWE secret | ternary `{-1,0,1}^40` KEM private key; flag sealed separately |
| Params | `n=60, m=140, q=10007, noise ∈ [-8,8]` | `n=40, m=52, q=1048583(≈2^20), noise ∈ {-1,0,1}` |
| Intended solve | parse 6 fragments → digest → compare vectors | primal/Kannan embedding + LLL → HKDF → AES-GCM |
| Decoys | bot-hint keywords, decoy flags (annoyance) | none; difficulty is the maths + AEAD exact-recovery gate |
| Flag delivery | plaintext constant on vector match | AES-256-GCM under a **split** KDF binding `s` **and** a second-lockbox secret `s2`; primary solve alone can't decrypt |
| Extraction | — | SPLIT-KDF two-channel: second independent LWE `(A2,b2)` → `s2`; sign-flipped `−s2` opens only a format-invalid decoy |
| Honest band | puzzle (not really LWE) | Extreme (lattice reduction genuinely required, now twice) |
| Testability | — | pure-Python LLL solver, 20/20 acceptance checks, exit 0 |
