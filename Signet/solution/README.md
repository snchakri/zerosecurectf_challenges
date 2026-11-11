# Signet — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Signet — official writeup

**Flag:** `zerosecurectf{r3lat3d_n0nc3s_s1nk_th3_f1rmware_s1gn3r}` (static demo seed; per-instance in production)


## The flaw

ECDSA's one hard rule is that the per-signature nonce `k` must be **secret and
unpredictable**. Signet breaks a weaker — and more realistic — version of that
rule: the nonces are secret, but they follow a **linear schedule**.

```python
def nonce(i):
    return (k0 + b * i) % N      # k0, b secret; consecutive nonces differ by a constant step b
```

This is the kind of "deterministic, stateless nonce" an engineer might ship for
reproducibility, not realising it leaks the key.


## Why it breaks

For a signature `(r_i, s_i)` over message hash `m_i`:

```
s_i = k_i^{-1} (m_i + r_i d)   (mod N)
=>  k_i = m_i/s_i + (r_i/s_i) d = alpha_i + beta_i * d     (mod N)
```

So each nonce is an **affine function of the single unknown `d`**. The schedule
makes consecutive nonce *differences* equal:

```
k_1 - k_0 = b = k_2 - k_1
=>  (alpha_1 - alpha_0) + (beta_1 - beta_0) d  =  (alpha_2 - alpha_1) + (beta_2 - beta_1) d
```

That is a **single linear equation in `d`**. Rearranged:

```
d = [ (alpha_2 - alpha_1) - (alpha_1 - alpha_0) ] * [ (beta_1 - beta_0) - (beta_2 - beta_1) ]^{-1}   (mod N)
```

Three signatures (indices 0, 1, 2) are enough. No lattice, no brute force — the
linearity of the schedule collapses the problem to one modular division.


## Steps (crux)

1. `SIGN 0`, `SIGN 1`, `SIGN 2` → three `(r, s, manifest)` triples.
2. Compute `alpha_i = m_i / s_i`, `beta_i = r_i / s_i` (mod N), where `m_i =
   SHA256(manifest_i) mod N`.
3. Solve the linear equation above for `d`. Sanity-check `d·G == Q` (the service
   prints `Q`).

Recovering `d` does **not** hand you the flag. It hands you the *vendor signing
power*: the ability to forge a valid signature over any message. The flag itself
is gated behind the extraction layer below.


## Steps (flag extraction)

4. The banner publishes a Shamir **k-of-n** scheme (`k=3`, `n=5`) over the
   Mersenne-prime field `GF(2^521-1)`, the share x-coordinates (`x_j = j+1`), and
   `n` distinct **attestation tokens** `CHAL[j]` (seed-bound, so per instance).
5. For each of `k` slots `j`, forge the vendor signature over the exact token
   `CHAL[j]` using `d`, and send `ATTEST j r s`. A valid signature returns the
   genuine share `(x_j, f(x_j))`.
6. **Offline**, Lagrange-interpolate the `k` genuine shares at `x = 0` over
   `GF(2^521-1)` to recover the secret integer, decode its big-endian bytes to
   text, and verify it matches `^zerosecurectf\{[a-z0-9_]{8,48}\}$`.


## Why the intended path is the only cheap one

- **No single-signature shortcut:** `k0` and `b` are secret, so one signature
  leaves two unknowns (`d` and the nonce) — unsolvable alone. You need the
  *relationship* between nonces, hence ≥3 signatures.
- **No brute force:** the search space is ~2²⁵⁶; only the structural insight wins.
- **No guessing:** the schedule is visible in the source, so the route is
  reachable purely by reasoning (design invariant §2, guess-exposure 0).


## Flag extraction 

The old build handed over `zerosecurectf{...}` the instant a valid signature over
the malicious manifest was submitted (one-shot `SUBMIT → FLAG`). That trivial
final reveal is eliminated per the S2/S2a standard. The crux (related-nonce ECDSA
key recovery) is **unchanged**; what changed is that solving the crux now earns
the *means* to extract, not the flag.

**Mechanism — Shamir k-of-n attestation (RECONSTRUCTION / SECRET-SHARING, twisted
with a signature gate + silent decoy polynomial).**

- The flag bytes are encoded as a single integer `S < 2^521-1` and made the
  constant term `f(0)` of a degree-`(k-1)` polynomial over the Mersenne-prime
  field `GF(2^521-1)` (`k=3`). The non-constant coefficients are derived
  deterministically from `ZSCTF_SEED` (labels `share-coeff-t`), so the shares are
  byte-identical for a given seed+flag and differ across seeds.
- `n=5` share slots exist; slot `j` has public x-coordinate `x_j = j+1` and
  genuine y-value `f(x_j)`. Share `j` is released **only** against a valid vendor
  ECDSA signature over the distinct, seed-bound attestation token
  `CHAL[j] = attest:flag-share;slot:j;fp:<sha256(seed)[:16]>`. The service never
  signs these tokens itself (`SIGN` serves only benign indices 0..7), so the only
  way to produce the signature is to have recovered `d` — the crux stays the gate.
  To collect `k` genuine shares you must exercise the key over `k` **different**
  messages.
- **No command ever returns the flag whole.** A single share is
  information-theoretically independent of `S` (threshold `k=3`); the flag only
  emerges from an **offline** Lagrange interpolation at `x=0` of `k` genuine
  shares. The plaintext flag is never in the banner, in any single response, in
  the source, or in the compose file.

**The decoy / footgun (guess-exposure still 0).** An `ATTEST` whose signature does
**not** verify is *not* rejected with an error — it silently returns a decoy share
lying on a *second* polynomial whose constant term is a deliberately
format-invalid near-flag, `zerosecurectf{ATTESTATION_FORGED_<fp>}` (UPPERCASE
body → fails the published `[a-z0-9_]` charset). A careless solver who never
recovered `d` (or who re-uses a benign-manifest signature, which is valid over the
*wrong* message) collects decoy shares and reconstructs a near-flag that fails the
strict format. The discriminator is pure reasoning, available in the challenge:
the solver checks `d·G == Q` and signs the **exact** token, so every share it
redeems is genuine; and the published strict validator rejects the decoy
reconstruction outright. There is no path by which a wrong input yields a
format-valid flag.

**Why it is solvable yet non-trivial.** Deterministic (seed+flag fixes every share
and token), fully specified in the public banner (field prime, `k`, `n`,
x-coordinates, and the exact tokens), and requires the genuine key `d` for every
genuine share. The reference solver performs the **full** chain: recover `d` →
forge `k` token signatures → redeem `k` genuine shares → Lagrange-interpolate
real flag, that the flag is absent from banner/single-share/source, that forged
and benign-reused signatures yield decoy shares reconstructing to a
format-invalid near-flag, and determinism across seeds.


## Rabbit-holes 

- **R2 Footgun — silent decoy shares.** `ATTEST` with any non-verifying signature
  returns a well-formed `SHARE` line (no error), so momentum-driven automation
  that never truly recovered `d` happily collects `k` shares and reconstructs a
  near-flag. *Tell:* the result fails the published strict validator
  `^zerosecurectf\{[a-z0-9_]{8,48}\}$` (uppercase body); and a careful solver
  signs with a key verified by `d·G == Q`, so it knows its shares are genuine
  before reconstructing.
- **R2 Footgun — benign-signature replay.** A signature obtained from `SIGN i` is
  valid over the *benign* manifest, not over `CHAL[j]`; replaying it into `ATTEST`
  decoys. *Tell:* ECDSA verification is message-bound; the attestation token is a
  different message, visibly so in the banner.
- **R4 Inert framing.** The “Shamir over GF(2^521-1)” banner looks like extra
  cryptographic machinery to attack, but the field, `k`, `n`, and x-coordinates
  are all public and the interpolation is a one-line offline computation — there
  is nothing to break there; the only secret gate is the ECDSA key `d`.
- **R5 Per-instance misdirection.** Tokens and the decoy near-flag embed the
  seed fingerprint, so a leaked walkthrough or one team’s shares/decoy do not
  transfer.


## Design notes (for the ZSCTF team)

- **Lineage:** `crypto-008 ECLCG` (ECDSA nonces from a linear generator) →
  operator `GROUND` (a firmware-update signer) + `CONSTRAIN` (an oracle, not a
  static dump). See `corpus-genome.yaml`.
- **Harder variants (extrapolation):** make the step itself a full LCG with a
  *secret multiplier* `a` (`k_{i+1} = a·k_i + b`) — recovery then needs resultants /
  a Gröbner basis over `F_N`; or bias only the *top bits* of each nonce — recovery
  then needs lattice reduction (LLL). Both raise the band toward Frontier and are
  tracked as `SUBSTITUTE-PRIMITIVE` / `PARAMETERISE` neighbours.
- **AI note:** on uniform/known parameters an agent solves this from memory; the
  per-instance secret schedule is what forces genuine modelling rather than
  template recall (system.html §9).
