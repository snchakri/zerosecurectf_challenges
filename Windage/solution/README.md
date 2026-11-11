# Windage — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/beacon.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Windage — Author's writeup

**Category:** crypto · **Band:** Extreme · **Flag:** `zerosecurectf{...}` (per-instance)

---


## 1. The scenario

Beacon **WINDAGE-7** signs its status reports with ECDSA over **secp160k1**. It
will sign any of its 45 routine position reports on request. The flag is the
beacon's **decommission authorization code `C`**, and it is *not* handed over
whole. `C` is split by the **Chinese Remainder Theorem** across several
pairwise-coprime moduli `m_0 … m_{K-1}` (published in the banner). For each
segment `j` the beacon releases the residue `C mod m_j` — but **only** when you
file a valid ECDSA signature over a distinct, modulus-bound `DECOMMISSION`
attestation token, a message the beacon will *not* sign for you. Forging even one
token requires the private key `d`; so recovering `d` (below) is the gate, and
collecting the `K` residues and **CRT-reconstructing `C` offline** is the graded
extraction layered on top. (A wrong/forged signature returns a *decoy* residue —
see §Flag extraction.)

The banner states the weakness outright, as an "advisory": the beacon's RNG has a
**windage** — every per-request nonce `k` satisfies `1 <= k < 2^153`. Since the
group order `n` is ~161 bits, the **top ~8 bits of every nonce are zero**. No
obscurity: the flaw is a named, documented bias, exactly as a real leaky RNG
(think the Minerva / TPM-Fail timing leaks, or a truncated hardware RNG) would
present it.


## 2. Why one signature (or three) is not enough

For each signature `(r_i, s_i)` over message hash `h_i` with nonce `k_i`:

```
s_i = k_i^{-1} (h_i + r_i d)  (mod n)
  =>  k_i = a_i d + c_i        (mod n),   a_i = r_i/s_i,  c_i = h_i/s_i   (mod n)
```

So each signature is an **affine equation in `d`** — but with two unknowns per
equation (`d` and `k_i`). With `t` signatures you have `t` equations in `t + 1`
unknowns (`d`, `k_1..k_t`). The system is **underdetermined over `Z_n`**: for
*any* candidate key `d'` there exist `k_i' = a_i d' + c_i (mod n)` satisfying every
congruence. Linear algebra alone recovers nothing. (This is the sharp contrast
with `signet`, where the nonces are *related by a known linear schedule*, which
adds an extra equation and lets three signatures pin `d` by one modular division.
Here there is no such relation — only a size bound.)

The only thing that singles out the true `d` is the extra fact `0 <= k_i < 2^153`.
The true key makes **all** nonces small; a random wrong key makes at least one
nonce span the full range. Exploiting "the solution is the one whose residuals are
halves empirically: the true key yields all-small nonces, a random key violates
the bound, and a 6-signature lattice fails to recover the key.


## 3. Intended solve — the HNP lattice + LLL

This is the **Hidden Number Problem** (Boneh–Venkatesan, CRYPTO 1996; Nguyen–
Shparlinski's (EC)DSA treatment, *Designs, Codes and Cryptography* 30, 2003).

Centre the nonces to halve the bound: with `C = 2^{152}`, write `k_i' = k_i - C`
so `|k_i'| < C`, and `a_i d + c_i' = k_i' (mod n)` with `c_i' = c_i - C`. Build the
`(m+2)`-dimensional lattice (here `m = 45`, dimension `47`), with column weight
`W = floor(n / C)` so that every coordinate of the target vector is `~ n`:

```
rows 0..m-1 :  [ n·W  on the diagonal,   0,   0 ]
row  m      :  [ a_i·W   (i < m),        1,   0 ]     # d-tracking column
row  m+1    :  [ c_i'·W  (i < m),        0,   K ]     # Kannan embedding, K = n
```

The integer combination `(y_0, …, y_{m-1}, d, 1)` (choosing `y_i` so that
`y_i n + a_i d + c_i' = k_i'` exactly) produces the vector

```
coord i (i<m) = W·k_i'     (|·| < W·C ≈ n)
coord m       = d          (< n)
coord m+1     = K = n
```

of norm `≈ n·sqrt(m+2)`. Its logarithm is `≈ log2(n) + ½·log2(m+2)`. Everything
else in the lattice has norm on the order of `det^{1/dim}`, and

```
det = (n·W)^m · K = n^{m+1} · W^m,     dim = m+2
log2(det^{1/dim}) ≈ log2(n) + (ℓ·m − log2 n)/(m+2),   ℓ = leaked bits per nonce ≈ 8
```

so the planted vector is shorter than the generic lattice vector by a factor
`≈ 2^{(ℓ·m − log2 n)/(m+2)}`. With `ℓ·m = 8·45 = 360` and `log2 n ≈ 161`, that gap
is comfortably positive and far exceeds LLL's Hermite factor `≈ 1.02^{47}`. So
**LLL alone** surfaces the vector — BKZ is not required. We read `d` straight out
of the d-tracking column (fixing the overall sign by the `±K` coordinate) and
confirm `d·G == Q`. Then run the CRT extraction (§Flag extraction): forge a valid
signature over each attestation token, collect the residues, and reconstruct `C`.

```
$ python solution/solve.py --local challenge/beacon.py
[+] recovered private key d = ...
[+] CRT-reconstructed the decommission authorization code from residues
[+] FLAG = zerosecurectf{...}
```

### Pure-Python LLL, done exactly

`fpylll` and `sage` are not available, so the solver hand-rolls LLL. The one trap
specific to this challenge: a float Gram–Schmidt (as a textbook/example LLL uses)
**silently fails at 160-bit entries** — a single dot product exceeds `2^300` and a
53-bit IEEE double keeps none of the low bits, so size reduction rounds garbage.
The reference solver therefore uses **exact rational Gram–Schmidt**
(`fractions.Fraction`): no overflow, no precision loss, provably correct. The
control structure (incremental μ/B swap updates) follows Cohen, *A Course in
Computational Algebraic Number Theory*, Alg. 2.6.3; the rational arithmetic stands
in for that algorithm's exact integer book-keeping.


## Flag extraction 

**Assigned mechanism: CRT reconstruction.** Recovering `d` is the *gate*, not the
flag. The flag `C` is extracted by a Chinese-Remainder-Theorem reconstruction
across several modulus-bound ECDSA-attestation gates, each of which still requires
`d`. This is the S2/S2a extraction layer; it is deliberately distinct from the
secret-sharing, blind-oracle, state-streaming and split-KDF mechanisms used by
sibling challenges.

### How it works

1. **Split.** At start-up the beacon computes `C = int.from_bytes(FLAG)` and
   generates `K` pairwise-coprime prime moduli `m_0 … m_{K-1}`
   (`challenge/beacon.py :: _gen_moduli`, pure-stdlib Miller–Rabin, deterministic
   from `ZSCTF_SEED`). Per-modulus size is chosen so that **~6** segments are
   needed, and generation stops the instant `∏ m_j > C`. It publishes the moduli
   and the attestation-token format in the banner. It precomputes
   `REAL_RES[j] = C mod m_j` and `DECOY_RES[j] = C' mod m_j`, where `C'` is a
   decoy flag (below). **`C` itself never leaves the process.**

2. **Gate per residue.** Residue `j` is released only by
   `SUBMIT <j> <r> <s>` where `(r,s)` is a **valid** ECDSA signature (under the
   beacon's public key `Q`) over the distinct, modulus-bound token
   `BEACON WINDAGE-7 :: command=DECOMMISSION; segment=<j>; modulus=<m_j hex>; …`.
   `verify()` binds the signature to that exact byte string, so a signature for
   one segment does not transfer to another, and the beacon never signs any token
   itself (only the 45 fixed reports are signable). **Forging any token needs
   `d`**, so the HNP/LLL crux is unchanged as the gate.

3. **Reconstruct.** The solver forges one signature per segment, collects all `K`
   residues, and CRT-reconstructs `C = CRT({C mod m_j}, {m_j})`
   (`solution/solve.py :: crt`), then decodes the big-endian bytes to the flag and
   verifies it against the strict validator. Because `∏ m_j > C`, the
   reconstruction is **unique**; because the product *without* the last (critical)
   modulus is `≤ C`, **no proper subset of residues reconstructs `C`** — you
   fewer-than-all → not the flag; each single residue `< C`).

### The decoy (guess-exposure 0)

A **wrong or forged** signature does not error — it returns the decoy residue
`C' mod m_j`, where `C'` is the real flag with the classic **`zer0` (digit-zero)**
defect: `zerosecurectf{…}` → `zer0securectf{…}`. A careless solver who skips the
key recovery (or forges with a near-miss key) collects a consistent set of decoy
residues that CRT-reconstruct cleanly to `zer0securectf{…}` — a convincing
near-flag that **fails the published strict validator
`^zerosecurectf\{[a-z0-9_]{8,48}\}$` on the very first character class**. Mixing
real and decoy residues reconstructs to high-entropy junk that also fails. Both
failure modes are rejectable *by reasoning* from the published format rule
(guess-exposure 0), and the reference solver and test both perform the validator
check. The decoy body is the per-instance flag body, so the rabbit-hole varies by
seed (R5) and does not transfer between teams.

### Why this is faithful to the invariants

- **Fully solvable by the reference path:** recover `d` → forge `K` tokens →
- **Flag never whole / not in any single response:** each response carries only
  `C mod m_j` (strictly `< C`); `C` appears in no response, no banner line, and
  not in the source (flag comes from `ZSCTF_FLAG`).
- **Determinism:** moduli, decoy and residues all derive from `ZSCTF_SEED`+`FLAG`
  via the portable SHA-256 DRBG, so same seed → identical, different → different
  (asserted).


## 4. Proof the solver runs end-to-end (measured)

Measured on this machine (Python 3.13, pure Python, one core), reference solver
`solution/solve.py` over the HNP lattice:

| parameters | dim | signatures | success | avg time | max time |
|---|---|---|---|---|---|
| **shipped** `ℓ=8, m=45` | 47 | 45 | **12/12** | **42.5 s** | **50.2 s** |
| `ℓ=8, m=40` | 42 | 40 | 8/8 | 24.2 s | 26.5 s |
| `ℓ=10, m=40` | 42 | 40 | 5/5 | 23.3 s | 25.8 s |

(Measured on one core, Python 3.13, pure Python, exact-rational LLL. The shipped
`m=45` carries deliberate extra margin over the already-100% `m=40`, at a modest
time cost.) The CRT extraction itself (forge `K≈6` signatures + one CRT) adds
runs the solver end-to-end twice (two distinct seeds) plus the CRT-extraction,
no-whole-flag, decoy-rejectability, integrity and determinism checks and exits 0
only if all pass — **28/28 checks passed** on the shipped parameters.

### Why the band is honest (naive / algebraic approaches provably fail)

- **No algebraic shortcut.** As shown in §2, the ECDSA congruences alone are
  underdetermined over `Z_n` — any key satisfies them. There is no 3-signature
  modular-division trick as in `signet` (no linear nonce relation exists). The
  test encodes this (`size bound … pins the key`, `random wrong key violates the
  nonce size bound`).
- **No brute force.** The smallest-entropy nonce still has `153` bits; the key `d`
  has `~161`. Both are astronomically out of reach. You cannot guess a nonce or
  the key.
- **No discrete-log shortcut.** ECDLP on secp160k1 is `~2^80` work (Pollard rho) —
  infeasible for a CTF, so recovering `d` from `Q` directly is not an option.
- **Lattice genuinely required, and genuinely needs many signatures.** With only a
  handful of signatures the lattice does not over-determine the key and LLL
  many-signature HNP lattice works.


## 5. Honest band statement

**Extreme — with the same explicit caveat as `noisefloor`.** The solve genuinely
requires lattice reduction over a many-signature HNP instance: algebra provably
fails, brute force and discrete log are both out of reach. That clears the
Hard/Extreme line honestly (ZSCTF rubric, system.html §8–§9).

What we do **not** overclaim: the instance is deliberately **LLL-tractable** — it
does not require BKZ or a heavy lattice stack, because the per-nonce bias (8 bits
over 45 signatures) makes the planted short-vector gap large. A cryptographer who
recognises the HNP solves it with any correct LLL. We place it at the **lower
frontier of Extreme**: it demands genuine HNP/lattice knowledge *and* a correct
hand-rolled reduction, but it is not an open-parameter uSVP needing state-of-the-
art reduction. Calling it "Frontier-hard" would be the band inflation §9 warns
against. Its value is as a *reliable, authentic, per-instance* Extreme anchor with
a self-contained, testable solver — distinct from `signet` (algebraic) and
`noisefloor` (LWE lattice).

**On the use of secp160k1 rather than secp256k1.** This is a deliberate,
documented parameter choice, directly analogous to `noisefloor`'s "we use LLL, not
BKZ" caveat. The attack is *identical* on full secp256k1; we use the standardized
160-bit Koblitz sibling (same `y^2 = x^3 + 7` shape) so the pure-Python,
exact-arithmetic LLL finishes reliably inside the solver's time budget. The 160-bit
field keeps ECDLP at `~2^80` (infeasible), so nothing about the downscaling opens a
non-lattice shortcut. Shipping a *tested, runnable* instance is worth more than a
256-bit one whose hand-rolled reduction we could not prove terminates in time.


## 6. Red-team / AI-resistance (honest)

- **Conceptual recognition is easy for a strong solver.** "Biased ECDSA nonces →
  Hidden Number Problem → lattice" is a canonical, public pattern; a capable agent
  that knows HNP will name it quickly. The differential is not *recognition*.
- **The residual resistance is three real gates.**
  1. **Tooling absence + precision trap.** `fpylll`/`sage` are unavailable, so the
     solver must *implement* LLL. The non-obvious gate is that a naive float
     Gram–Schmidt **fails at 160-bit entries** (double precision is destroyed by
     `~2^300` dot products). An agent that reflexively copies a textbook float LLL
     will get a wrong/garbage reduction and no key. The reference solver ships an
     *exact* rational LLL precisely because of this.
  2. **The HNP embedding details.** Getting the centring, the column weight `W`,
     the embedding constant `K`, the lattice layout, and the `±` sign recovery
     right is where naive attempts produce a plausible-but-wrong vector. The
     `d·G == Q` check is the disambiguator and the solver iterates candidate rows.
  3. **Enough signatures.** Too few signatures and the lattice simply does not
     work; the solver must query and use *many*. An agent that tries 2–3 (as for a
     nonce-reuse problem) gets nothing.
- **It is not a wall.** A well-engineered agent that (a) recognises the HNP and
  (b) can emit a *correct, exact* LLL clears all three gates. We tag this as
  **measurement**, not hard resistance, and (per §9) log agent failure modes:
  broken/float hand-rolled LLL; wrong embedding or sign; too few signatures;
  attempting ECDLP.


## 7. Unintended-path scan

- **Discrete log on `Q`.** secp160k1 ECDLP is `~2^80` (Pollard rho) — infeasible.
  Closed.
- **Nonce reuse.** All nonces are distinct (per-index DRBG); no two share an `r`.
  Closed (and it would be the `signet`/`noncereuse` challenge, not this one).
- **Related-nonce linear elimination (the `signet` attack).** There is *no* linear
  relation between nonces here — only a size bound. Three-signature elimination
  recovers nothing. Closed (verified: the congruences are underdetermined).
- **Brute force of a nonce or the key.** `≥ 2^153` and `~2^161` respectively.
  Closed.
- **Leaky protocol.** `SUBMIT` only ever returns a single residue `C mod m_j`
  (real or decoy); it is not a signing oracle for arbitrary messages (only the 45
  fixed reports are signable), so you cannot ask the beacon to sign an attestation
  token or anything adaptive. No single response contains `C`; `C` is never
  transmitted whole. Closed.
- **Guessing residues.** A player who never recovers `d` can still `SUBMIT`
  garbage and collect the *decoy* residues; those CRT-reconstruct to the
  fixed near-flag `zer0securectf{…}`, which fails the published strict validator
  `^zerosecurectf\{[a-z0-9_]{8,48}\}$` on sight (guess-exposure 0). Mixing real
  and decoy residues reconstructs to high-entropy junk that also fails. Closed.
- **Small-subgroup / invalid-curve tricks.** `n` is prime, cofactor 1; the service
  computes with fixed `G` only and verifies submissions by the standard equation.
  No point is accepted from the player. Closed.


## 8. Contamination note

The technique (lattice attack on biased-nonce ECDSA / HNP) is public and
contaminated; measurement value rests entirely on **per-instance
parameterisation**. The signing key `d`, the entire biased nonce stream, the
signed reports and the flag all derive deterministically from `ZSCTF_SEED` via a
portable SHA-256 DRBG, so a memorised or leaked solution for one team is worthless
against another — only the *method* transfers, and it was already public. Monitor
agent solve-rate on fresh seeds; treat AI-resistance as perishable and re-test on
each major model release (Nullcon/Evolve-CTF guidance, §9).


## 9. Lineage

- **Sibling `signet`** (`challenges/crypto/signet`): contributed the online,
  query-limited ECDSA signing-oracle framing and the "forge the one refused
  message" win condition. **Operator `CONSTRAIN`:** `signet`'s flaw is a *linear
  nonce schedule* (3 signatures, one modular division — no lattice). Windage
  removes any linear relation and leaves only a *size bias*, which forces a
  genuine HNP lattice over many signatures. The two are deliberately
  non-overlapping in technique.
- **Sibling `noisefloor`** (`challenges/crypto/noisefloor`): contributed the
  "pure-Python LLL is the required, tested tool; honest Extreme banding" template.
  **Operator `SUBSTITUTE-PRIMITIVE`:** noisefloor's lattice is an **LWE primal /
  Kannan embedding**; windage's is an **ECDSA HNP** lattice — a different problem,
  a different lattice, a different solver core.
- **Corpus anchor:** `zsctf-crypto-008` (ECDSA / nonce-structure key recovery),
  affordances `PARAMETERISE` (dial the bias/#signatures onto a reliably
  LLL-tractable point) and `CONSTRAIN` (online oracle, fixed signable set).


## 10. What makes this distinct from its siblings (summary)

| Aspect | `signet` | `noisefloor` | **Windage** |
|---|---|---|---|
| Problem | related-nonce ECDSA | LWE search | **biased-nonce ECDSA (HNP)** |
| Flaw | linear nonce schedule | modulus/noise gap too large | **MSB nonce bias** |
| Math to win | 1 modular division (3 sigs) | primal/Kannan + LLL | **HNP lattice + LLL (many sigs)** |
| Flag extraction | direct reveal | direct reveal | **CRT reconstruction across attestation-gated residues** |
| Needs a lattice? | no | yes (LWE) | **yes (HNP)** |
| Signatures needed | 3 | n/a (static artifact) | **many (~40+)** |
| Curve/structure | secp256k1 | Z_q^{m×n} | **secp160k1** |
| Honest band | Hard | Extreme | **Extreme** |
