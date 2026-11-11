# Origami — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Origami — official writeup

**Flag:** `zerosecurectf{f0ld3d_th3_r3lu_n3t_0p3n_by_1ts_k1nks}` (test seed; per-instance in production)


## TL;DR

A score-returning prediction API hides a one-hidden-layer **ReLU network**
`f(x) = Σ_i v_i·ReLU(w_i·x + b_i) + c`. The output is **piecewise-linear**:
input space is folded into polytopes (one per activation pattern), `f` is affine
on each, and the fold creases are exactly the neuron hyperplanes
`w_i·x + b_i = 0`. Shoot random chords through the box; `f` along a chord is
piecewise-linear with a **kink** wherever the chord crosses one neuron's
hyperplane. At an isolated kink, estimate the gradient just before and just after
it: the **jump** `Δ∇f = v_i·w_i` points along that neuron's weight vector. Localise
the kink by intersecting the two affine pieces to get a point *on* the hyperplane,
giving the offset. Cluster the per-kink normals into `k` groups and you have
**reconstructed the entire first layer**. This is **nonlinear model extraction**,
a strictly stronger primitive than the single-boundary theft in `understudy`.


## The setup

`Kirigami` is a fixed network with `k = 8` hidden ReLU neurons over `d = 24`
inputs in the box `[-1,1]^d`. The first-layer rows `w_i` are **unit vectors**; each
neuron's hyperplane is pinned to a random interior anchor `p_i ∈ [-0.5,0.5]^d`
(so `b_i = -w_i·p_i`), guaranteeing every hyperplane passes through the box and
is therefore crossed by generic chords. Output weights `v_i` are mixed-sign with
magnitudes in `[0.6, 1.4]`, so every neuron's kink is clearly visible in `f`.

The API is **score-based**: `QUERY x` returns the real number `f(x)` (there is
also a batched `QUERYB`). You win by `SUBMIT`-ting a `k × (d+1)` matrix of
hyperplanes `(n_i, t_i)`; the service matches them to the true first layer up to
permutation and per-normal sign, and releases the flag iff **all `k`** match with
`|cos(n_i, n_true)| ≥ 0.9999` and `|t_i − t_true| ≤ 0.01`.


## Why it breaks: a ReLU net leaks its first layer through its creases

`∇f(x) = Σ_{i active} v_i w_i` where neuron `i` is active iff `w_i·x + b_i > 0`.
Crossing neuron `i`'s hyperplane toggles exactly that neuron, so the gradient
changes by **exactly** `v_i w_i`. That is the whole attack:

1. **Find kinks.** Scan `f(a + s·u)` on a grid along a random chord. Its slope in
   `s` is piecewise-constant and jumps at each crossing. Merge adjacent spike
   cells into kink brackets; keep only kinks whose neighbours are far enough away
   to leave a clean linear segment on each side (otherwise two neurons toggle too
   close together to isolate — just use another chord).
2. **Read the weight off the jump.** Place a point a safe `δ` before and after the
   kink (both strictly inside their own linear segments) and estimate the full
   gradient at each by central differences — *exact* here because `f` is affine
   within a segment. `g_after − g_before = v_i w_i`; normalise → unit normal
   `n_i = ±w_i`.
3. **Read the offset.** Intersect the two affine pieces along the chord to get the
   exact crossing `x*` (a point on the hyperplane); then `t_i = n_i·x*`.
4. **Cluster & submit.** Canonicalise each normal's sign and cluster: the `k`
   neurons form `k` tight clusters (cosine ≈ 1 within a cluster). Average each to
   a unit normal and take the median offset. `SUBMIT` the `k` hyperplanes.

Because the recovery is a gradient *difference* across a single toggle plus an
exact line intersection, it is **essentially exact**: recovered cosine `≈ 1.0`
and `|Δt| < 10⁻³` in practice — far inside the win tolerances.


## Steps (against the live service)

```bash
python solution/solve.py --local challenge/server.py     # against the source
python solution/solve.py --remote <host> <port>          # against a deployment
```

The reference solver ([`solution/solve.py`](solution/solve.py)) parses the banner for
`d`, `k`, and the box; samples chords until `k` clusters each have ≥3 clean
observations; runs the win-check; then **REDEEMs each neuron and assembles the
flag** (see next section). Typical run: **~7k (easy seeds) to ~13k (median)
queries** (occasional tail seeds up to ~37k), recovered cosine `≈ 0.999999…`,
`|Δt| ≈ 10⁻⁴`. `REDEEM`/`SUBMIT` do **not** consume the query budget.


## Flag extraction 

**Mechanism: per-piece reconstruction keyed to the extracted secret.** Correctly
reconstructing all `k` neuron hyperplanes is the crux, but it does **not** hand
over the flag. `SUBMIT` now only runs the sound win-check (perfect bipartite
matching of the `k` submitted hyperplanes to `k` distinct true neurons within
`|cos| ≥ 0.9999`, `|Δt| ≤ 0.01`) and returns a `WIN` confirmation with **no
flag**. The flag is obtained piece by piece:

1. **Split.** The flag string `zerosecurectf{…}` is cut into `k` contiguous
   fragments, one per canonical position `p = 0 … k-1`.
2. **Canonical order.** Position `p` is assigned to the true neuron whose
   sign-canonical signed offset `t` has rank `p` (ascending `t`; sign resolved by
   making the largest-magnitude normal component positive — robust under the
   recovery noise). So the `k` fragments are **value-ordered** by neuron offset.
3. **Seal.** Fragment `p` (prefixed with its 2-hex-digit position tag) is XOR-ed
   with a SHA-256 counter-mode keystream whose key is
   `SHA-256("origami-frag-v1" | ZSCTF_SEED | canon_quant(n_p, t_p))`, where
   `canon_quant` is the neuron's unit normal rounded to 5 decimals and offset to
   3 decimals (quantized to the win tolerance). The server keeps only the `k`
   ciphertexts; no plaintext flag slice is retained in module state (the whole
   flag exists only transiently at build time, from the `ZSCTF_FLAG` env var).
4. **Redeem.** `REDEEM <row_hex>` takes one hyperplane `(n̂, t̂)`. If it matches a
   true neuron `j` within the **same** tolerance as the win-check, the server
   re-derives `j`'s key from its exact (canonical, quantized) parameters, unseals
   that ciphertext, and returns `FRAG <tag><body>` — the real fragment. The flag
   is therefore **never returned whole**: the service only ever emits one
   position-tagged fragment at a time, and the player concatenates the `k` real
   bodies in ascending-tag order on their own side.

**Why server-side keying (and not client-side fuzzy key derivation).** A normal
recovered only to `|cos| ≥ 0.9999` differs from the truth by up to ~0.014 per
component, so no fixed per-component quantization can snap the player's noisy
normal to the *same* key bits without an error-correcting secure sketch
(empirically `P(all 24 components land in the same quantization cell) ≈ 0.72²⁴ ≈
6·10⁻⁴`). Making the player derive the key themselves would make the challenge
fragile/unsolvable on edge seeds — violating the "fully solvable + deterministic"
invariant. Instead the key is derived from the **true** neuron and the
match-to-tolerance is the gate: recovering the neuron to tolerance is exactly
what unlocks the server's decryption, binding each fragment to that neuron's exact
geometry while keeping the solve rock-solid. This is an honest design choice, not
a shortcut.

### Rabbit-holes / decoys  — each rejectable by reasoning

Guess-exposure stays **0**: every wrong turn is rejectable from the published
strict validator `^zerosecurectf\{[a-z0-9_]{8,48}\}$` plus the known literal
wrapper, with no information-free dead-ends.

* **Decoy fragment (wrong/approximate neuron).** A `REDEEM` whose hyperplane does
  **not** match a true neuron to tolerance returns a *decoy* fragment derived
  deterministically from the submitted plane. Decoy bodies are drawn from
  `[a-z0-9_]` **plus one guaranteed upper-case character**, so any assembly that
  includes a decoy fails the strict validator (R1 upper-case defect). *Tell:* scan
  the assembled flag's charset — an upper-case letter means at least one neuron
  was not exact. The identical-looking `FRAG` reply for match vs. non-match means
  the only honest discriminator is the fragment format, not a server verdict.
* **Partial set (k-1 exact + 1 off).** Assembles to a near-flag that fails the
  validator (the one off neuron contributes a decoy with an upper-case defect).
  *Tell:* the validator rejects it; you must recover **every** neuron exactly.
  This is what tightens the win — one sloppy neuron now blocks the flag.
* **Wrong assembly order.** Concatenating the real fragments in any order other
  than ascending position tag yields a near-flag that does not begin with the
  literal `zerosecurectf{` (reversed order fails `^zerosecurectf\{` outright).
  *Tell:* the known wrapper anchors the order; sort by the 2-hex-digit tag.
* **"The win-check gave me the flag."** It does not — `SUBMIT` returns only a
  `WIN` confirmation. *Tell:* read the response; it explicitly says to `REDEEM`.
* **Repeated-`REDEEM` oracle.** Decoys are deterministic in the submitted plane,
  so hammering `REDEEM` with random planes yields only reproducible garbage and no
  gradient toward a neuron — in 24-D you cannot reach `|cos| ≥ 0.9999` by search;
  you must run the kink extraction. Guess-exposure remains ~0.


## Why the cheap shortcuts fail (the heart of the Extreme band)

The two tricks that *do* trivialise a linear model, and the one that solves
`understudy`, provably do **not** work here. All numbers below are from

* **One-shot weight read-off (the linear-model trick) fails.** For a linear model
  `f(x)=w·x+b`, a single finite-difference gradient *is* `w` (and `d+1` queries
  recover everything). Here a gradient is `Σ_{active} v_i w_i`. In a region where
  several neurons are active it is a **blend** that matches no single neuron
  (observed `|cos|` to the nearest neuron `0.77–0.93`). It occasionally equals one
  neuron exactly — but only in a region where a *single* neuron is active, and
  even then it gives **one** direction out of `k` and, crucially, **no offset at
  all** (a gradient is translation-invariant). You cannot win from gradients
  alone; you must localise kinks. This is why the test asserts "correct normals
  but wrong offsets → DENIED".
* **Single-hyperplane SVD (the `understudy` attack) fails.** Pool critical points
  from many chords and fit one normal by total least squares (exactly what wins
  `understudy`). The points come from `k` *different* hyperplanes, so the fit
  converges to a meaningless average direction: **best `|cos|` to any neuron
  `≈ 0.58`** across seeds (need `0.9999`). A submission built from it is rejected.
* **Guessing fails.** A random unit direction in 24-D has expected `|cos|` to a
  neuron `≈ 1/√24 ≈ 0.20`; you must hit `0.9999` on **all 8** simultaneously,
  with correct offsets. Guess-exposure is effectively zero.

The only route that works is per-neuron kink extraction — the published
nonlinear-extraction technique — so the challenge genuinely *needs* the advanced
method, which is the bar for the band.


## Distinctness from the other AI/ML challenges

| | misc/hairline | ai-ml/understudy | **ai-ml/origami** |
|---|---|---|---|
| Access | white-box weights | black-box, **label**-only | black-box, **score**-returning |
| Model | linear | linear | **nonlinear (ReLU net)** |
| Primitive | evasion (ML01) | model theft (ML05) | **nonlinear model theft (ML05)** |
| What you produce | an input perturbation | **one** decision hyperplane | **all `k`** neuron hyperplanes |
| Core maths | gradient ascent on a known model | line search + **one** SVD | **critical-point search + gradient-jump differencing + clustering** |

Origami is the escalation `understudy → nonlinear`: the lift the `understudy`
writeup itself flagged as the Frontier target (`SUBSTITUTE-PRIMITIVE` to a
ReLU-MLP region; Jagielski et al. 2020; Carlini et al. 2020).


## Dual measurement & calibration (for the ZSCTF team)

Measured end-to-end (reference solver ⇄ server over the stdio protocol) across 12
distinct seeds with the shipped `make_instance` (`d=24, k=8`):

* **Solvable (reference path).** **16/16 seeds win** (readiness re-measurement,
  box-enforced server). Recovered cosine `≥ 0.999999` on every neuron of every
  seed; `|Δt|` max `< 10⁻³`. Queries (counted as individual input vectors, the
  same unit as the `10⁶` budget): **min 6 920, median ~12 960, mean ~14 780, max
  37 306** across 16 seeds; the test seed `zsctf-origami-test-0001` costs **7 018**.
  (Earlier drafts advertised "~1.5e4"; the honest figure is ~7k on easy seeds and
  a ~13k median, with a heavy right tail — corrected here and in the banner.)
  Wall-clock ≈ **1 s** per solve (Python 3.13). Huge margin over the `0.9999` /
  `0.01` win gates.
* **Feasible for every seed.** Every neuron hyperplane is pinned to an interior
  anchor, so it always crosses the box; the solver keeps sampling chords until all
  `k` clusters are populated (it does not stop at a kink count), which closes the
  rare "one neuron under-sampled" case seen in an early prototype.
* **Shortcuts provably blocked (measured).** Single-SVD best `|cos|` to any neuron
  `≈ 0.58`; a generic-region gradient blends to `|cos| 0.77–0.93`; random
  directions `≈ 0.20`. None approaches the `0.9999` gate.

**Determinism.** `make_instance` is a pure function of the seed, using numpy's
`default_rng` (PCG64, a version-stable bit stream; numpy pinned in
`deploy/requirements.txt`). Same `ZSCTF_SEED` → identical `W, b, v, c`; the
acceptance test asserts this and that a different seed gives a different network.

### Honest RED-TEAM / AI-RESISTANCE note

* **What this resists.** It targets the system.html §9 AI/ML hard-end gap with a
  **nonlinear** model-extraction primitive that is a *strict escalation* of
  `understudy`. The two cheap linear shortcuts (one-gradient read-off,
  single-hyperplane SVD) **provably fail** (measured above), so an agent cannot
  recycle the `understudy` solver or the linear-model reflex — it must recognise
  the piecewise-linear structure and run per-neuron kink extraction. The secret
  is a fresh per-instance network, so template recall and solution-sharing do not
  transfer: the agent must actually execute the attack against *this* oracle.
* **What this does NOT resist (stated plainly).** The *technique* — "recover a
  ReLU layer from the gradient jumps at its critical points" — is a **published
  result** (Rolnick & Kording, "Reverse-engineering deep ReLU networks", ICML
  2020; Jagielski et al., "High Accuracy and High Fidelity Extraction of Neural
  Networks", USENIX Security 2020; Carlini et al., "Cryptanalytic Extraction of
  Neural Network Models", CRYPTO 2020). For a **single** hidden layer the recovery
  is *exact* (cosine ≈ 1.0), so a practitioner who knows the kink trick will
  derive the solver without a deep conceptual leap; the difficulty is in
  **recognising the structure and executing cleanly** (finding isolated kinks,
  avoiding contaminated jumps, clustering, getting offsets) rather than in an open
  problem. This is why the band is **Extreme** on the *strength and distinctness of
  the required primitive and the zero guess-exposure*, while we note honestly that
  its **conceptual novelty is moderate** and the depth is single-hidden-layer. The
  framing matches `understudy`/`signet`: per-instance secrecy forces genuine
  modelling and defeats recall, but we do not pretend the method is unknown.
* **Is it really Extreme and not Hard?** It clears the task's explicit bar — it
  *truly needs* the advanced technique and the shortcut that trivialises a linear
  model demonstrably does not work (measured). It is a strict superset of
  `understudy` (which we band Hard): nonlinear target, `k` hyperplanes instead of
  one, score-oracle reasoning, clustering and full-layer disentangling. We place
  it at **Extreme** on that basis, with the caveat above. A reviewer who weights
  *conceptual novelty* heavily could reasonably call it **Hard+**; we would not
  argue strenuously, and we prefer to state the trade-off rather than inflate.
* **Harder variants (extrapolation, tracked for future bands).**
  - *Rounded / quantised scores* (`PARAMETERISE`): return `f(x)` to a few decimals
    (as real APIs do). Naïve tiny-`ε` gradients then die to rounding noise; the
    attacker must use large-`ε` least-squares slope fits inside each region. A real
    execution-difficulty lift; kept out of v1 to guarantee rock-solid solvability.
  - *Two hidden layers* (`ESCALATE`): the gradient jump of a second-layer neuron is
    a *sign-dependent* combination of first-layer weights, so extraction becomes
    the genuinely hard **sign-recovery** problem of Carlini et al. (CRYPTO 2020) —
    the true multi-layer frontier.
  - *Tight query budget* (`CONSTRAIN`): push toward the information-theoretic
    minimum so random chords no longer suffice and an active chord-design is forced.
  - *Noisy scores* (`PARAMETERISE`): additive noise forces robust (repeated-query /
    regression) jump estimation.


## Unintended-path scan

* **Read the answer from the source?** No. Players get `server.py`, but `W, b, v, c`
  are derived from the *secret* per-team `ZSCTF_SEED` (an env var, never on disk or
  in the image). The source documents the method, not the instance.
* **Win with the easy neurons only?** No. The win requires a perfect matching of
  **all `k`** submitted hyperplanes to distinct true neurons; the test's
  "partial (k-1 correct)" case confirms a near-miss loses.
* **Brute force / random SUBMIT?** Needs `|cos| ≥ 0.9999` on all 8 normals *and*
  offsets within `0.01` in 24-D simultaneously — astronomically unlikely; the test
  confirms a random submission is DENIED.
* **Degenerate kinks (two neurons toggling together) corrupting a jump?** The
  solver discards kinks whose neighbours are closer than a margin and relies on the
  many clean crossings from other chords; measured recovery stays exact.
* **Protocol abuse?** `QUERY`/`QUERYB` only ever return `f(x)` (a finite float);
  malformed input is rejected with `ERR`; `SUBMIT` only ever returns a match
  verdict (a `WIN` confirmation, never the flag); `REDEEM` only ever returns one
  position-tagged fragment (real or decoy). The flag is never emitted whole.
  There is no file, network, or state side channel — the service is a pure numpy
  function plus a query counter.
* **Querying outside the box?** The threat model says inputs live in
  `[-1,1]^d`; the service now **enforces** this — a `QUERY`/`QUERYB` with any
  coordinate outside `[LO,HI]` is rejected with `ERR ... outside the box` and is
  not evaluated (readiness fix: previously only `isfinite` was checked, which
  contradicted the "inside the box" framing). The intended kink solver stays well
  inside the box anyway (measured min margin of any query to a face ≈ `4e-4`,
  far larger than the `1e-5` finite-difference step), so enforcement never
  in-box queries still answer.


## Lineage (corpus reconstruction, system.html §17)

* **Seed `zsctf-misc-008` — *what-a-jpeg-is* (DiceCTF Quals 2024).** The corpus'
  single hard AI/ML seed (`reconstruct_idea: "extend toward the §9 AI/ML frontier
  gap"`). **Borrowed:** the "attack a fixed, queryable model for the flag" framing.
  - Operator **SUBSTITUTE-PRIMITIVE**: evasion / adversarial example →
    **model extraction**.
  - Operator **ESCALATE**: `understudy`'s *linear* single-boundary theft →
    **nonlinear** ReLU-network *first-layer* extraction — the lift `understudy`'s
    writeup named as the Frontier target.
  - Operator **GROUND**: a realistic score/logit prediction-API deployment where
    the asset at risk is the model's learned parameters.

See `corpus-genome.yaml` (`zsctf-misc-008`, affordances `[GROUND, PARAMETERISE,
CHAIN(X)]`) and the companion `ai-ml/understudy` (same model-theft family, one band
below).
