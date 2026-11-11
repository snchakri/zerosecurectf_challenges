# Understudy — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Understudy — official writeup

**Flag:** `zerosecurectf{st0l3n_b0undary_fr0m_a_l4b3l_0nly_0racl3}` (static demo seed; per-instance in production)


## TL;DR

A label-only prediction API hides a rare class behind a secret linear boundary
`h · x = theta`. Shoot rays from the published foothold, binary-search where each
ray leaves the rare class to get points **on** the boundary, and recover the
hyperplane by SVD (total least squares). Three times the input dimension of
boundary points reconstructs the normal to cosine `> 0.99999` — far inside the
`0.999` tolerance. This is **model extraction** (model stealing), not an
adversarial example.


## The setup

Sortilege is a fixed linear classifier with `C = 12` classes over `d = 96`
features in the box `[0,1]^d`. Classes `0..C-2` are ordinary ("background")
linear classes; class `T = C-1` is special. Its score is a **steep linear ramp**
across a secret hyperplane:

```python
s_j(x) = Wbg[j] . x + bbg[j]          # j = 0 .. C-2   (background)
s_T(x) = KAPPA * (h . x - theta)      # T, with KAPPA = 1e4, |h| = 1
predict(x) = argmax_j s_j(x)
```

`theta` is set to the `1 - 1e-6` quantile of `h · x` over the box, so class `T`
is the argmax only in a razor-thin region (~`1e-6` of the box volume). With
`KAPPA` large, that region is, to a very good approximation, the half-space
`{ x in box : h · x > theta }`, and its boundary is the single hyperplane
`h · x = theta`.

The API is **decision-based**: `QUERY x` returns only `argmax` — the class label.
No scores, no probabilities, no gradients. You also get:

* `FOOTHOLD` → a vector `x0` **guaranteed** to be in class `T` (your way in; the
  rare region is far too small to find by random querying), and
* `SUBMIT h_hat theta_hat` → wins iff your reconstructed hyperplane matches the
  secret one: after normalising to a unit normal, `cosine(h_hat, h) >= 0.999`
  and `|theta_hat - theta| <= 0.02`, with class `T` on the `h · x > theta` side.


## Why it breaks: a label-only API still leaks its decision surface

The classic result: you cannot read secret weights out of a label-only API in
one shot, but you *can* reconstruct a decision boundary geometrically by finding
points that sit on it (Lowd & Meek, "Adversarial Learning", KDD 2005; Tramèr,
Zhang, Juels, Reiter & Ristenpart, "Stealing Machine Learning Models via
Prediction APIs", USENIX Security 2016, the Lowd-Meek and decision-based
discussion).

Concretely, the boundary of class `T` is the hyperplane `h · x = theta`. Any
point exactly on it satisfies that single linear equation. Collect enough
boundary points and the normal `h` is the one direction orthogonal to all of
them:

1. **Find boundary points.** Start at the foothold `x0` (inside `T`). Pick a
   random direction `u` and walk `x0 + lambda*u` with growing `lambda`. If the
   ray *decreases* `h · x` it eventually crosses out of `T` — the label flips
   away from `T`. Binary-search `lambda` between the last in-`T` point and the
   first out-of-`T` point; the midpoint converges to a point **on**
   `h · x = theta`. (Rays that *increase* `h · x` go deeper into `T` and hit the
   box wall first — just discard those; about half of random directions work.)

2. **Fit the hyperplane.** With `~3d` boundary points `p_k`, they all satisfy
   `h · p_k = theta`, i.e. they lie on a `(d-1)`-dimensional flat. Centre them and
   take the **smallest right singular vector** of the matrix of centred points
   (total least squares): that is the unit normal `h_hat`. Orient it so the
   foothold is on the `h · x > theta` side, and read
   `theta_hat = h_hat · mean(p_k)`.

3. **Submit** `(h_hat, theta_hat)`.

No scores, no gradients, no brute force — line search plus one SVD.


## Steps (against the live service)

```bash
python solution/solve.py --local challenge/server.py     # against the source
python solution/solve.py --remote <host> <port>          # against a deployment
```

The reference solver ([`solution/solve.py`](solution/solve.py)) parses the banner for
`d`, `C`, the target index and the foothold `x0`; calls `boundary_point` along
`3d` random rays; runs the SVD; and submits. Typical run: **~20,000 queries**,
recovered cosine **≈ 0.99999997**, `|dtheta| ≈ 1e-4` — comfortably inside the
`0.999` / `0.02` win tolerances.


## Why the intended path is the only cheap one

* **No weight read-off.** The API is label-only: one query is one bit of
  region-membership, not a score. You cannot solve a linear system for the
  weights (that would need the scores). You must reconstruct the surface
  geometrically.
* **No stumbling onto the class.** The `T` region is ~`1e-6` of the box. Random
  querying essentially never returns `T` (measured: 0 hits in 2000 protocol
  queries; ~1 hit per `1e6` random points). The published foothold is the only
  practical way in — and a single interior point does **not** reveal the normal;
  you need `~d` boundary points.
* **No guessing the answer.** A random unit direction in 96-D has expected
  `|cosine|` to `h` of `~1/sqrt(96) ≈ 0.08`; over `2e5` random directions the max
  observed was `0.48` — nowhere near the `0.999` needed. Guessing is hopeless;
  the route is reachable only by the geometric reconstruction (guess-exposure 0,
  everything is in the source).
* **The foothold `x0` does not hand you the normal (readiness fix).** An earlier
  foothold walked a straight line from the `T`-maximising cube vertex
  `v = 1[h>0]` to the box centre, which collapsed every coordinate onto one of
  **two** values keyed by `sign(h_j)`. Thresholding `x0` at its own mean then
  recovered **~100% of `sign(h)` for free** (0 queries) and a direction with
  cosine `≈ 0.80` to `h` — a real leak that undercut the label-only premise. The
  hardened foothold instead starts from a **random near-corner** point of the box
  (each coordinate near one wall by a fair coin *independent of `h`*) and projects
  it onto the boundary slab `{x : h·x = theta + 0.01}` by alternating projection
  (project onto the hyperplane, clip into an interior band). Being far from the
  centre, the forced `h`-component of `x0 − centre` (the tiny margin `theta − mu`)
  is a small fraction of `|x0 − centre|`, so the zero-query MAP direction
  `x0 − mean` has only cosine `≈ 0.38` to `h`, and because the dominant
  per-coordinate signal is the *random* corner, thresholding/clustering recovers
  `sign(h)` only at **chance** (measured `0.56`, vs `1.00` before; chance-fold
  `≈ 0.54` for `d=96`). A single published in-`T` point cannot leak *nothing* — its
  Bayes-optimal estimate of `h` is exactly `x0 − centre`, whose `h`-component is
  pinned to the margin — but this construction pushes that residual down to the
  information-theoretic floor, far below the `0.999` win gate, so the line-search
  + SVD extraction is still mandatory. The foothold stays a hair inside `T`
  (margin `0.01`) with coordinates held in `[0.05, 0.95]` so the solver's rays
  still have room to cross the boundary; the reference solver wins with cosine
  sign recovery, and that submitting the zero-query direction is DENIED).


## Distinctness from the adversarial-example challenge (Hairline)

This is deliberately a **different** ML-security primitive from `misc/hairline`:

| | Hairline | Understudy |
|---|---|---|
| Access | **White-box** (weights published) | **Black-box**, label-only API |
| Primitive | Adversarial example / evasion (OWASP ML01) | Model extraction / model theft (OWASP ML05, MITRE ATLAS "Exfiltration via ML Inference API") |
| What you produce | a bounded input perturbation | the reconstructed secret decision boundary |
| Core maths | gradient ascent on a known model | line search + SVD on an unknown model |


## Dual measurement & calibration (for the ZSCTF team)

The challenge constants are calibrated so that, across seeds, the problem is
simultaneously solvable, rare, and feasible. Numbers below are from in-process
measurement over 10–12 seeds with the shipped `make_instance`
(`d=96, C=12, KAPPA=1e4, P_SMALL=1e-6`):

* **Solvable (reference path).** Recovered cosine across seeds:
  `min 0.99999997, max 0.99999999`; `|dtheta|` max `1.5e-4`; queries `~20k`
  (budget `1e6`). Huge margin over the `0.999` / `0.02` win thresholds.
* **Feasible for every seed.** The deepest-in-`T` point is the cube vertex
  `v = 1[h>0]`, with `h·v - theta` in `[2.48, 2.71] > 0` across seeds, so `T` is
  always non-empty and the foothold always exists.
* **Genuinely rare.** Realised `T` fraction of the box `~1e-6` (0–3 hits per
  `2e6` uniform samples). Because a sum of 96 bounded uniforms has
  lighter-than-Normal tails, the analytic CLT threshold yields a fraction
  **at or below** the `1e-6` target — rarity is honest, not just asymptotic.
* **Unwinnable by chance.** Random 96-D direction `|cosine|` to `h`: mean `0.08`,
  99.99th percentile `0.39`, max over `2e5` samples `0.48` — the `0.999` gate is
  never approached by guessing.

**Determinism.** `make_instance` is a pure function of the seed, using numpy's
`default_rng` (PCG64, a version-stable bit stream; numpy pinned in
`deploy/requirements.txt`) and the stdlib `NormalDist` quantile — so the same
`ZSCTF_SEED` yields the identical background weights, boundary `(h, theta)` and
foothold `x0` on any host. The acceptance test asserts this (same seed → same
foothold and same boundary).

### Honest RED-TEAM / AI-RESISTANCE note

* **What this resists.** The challenge targets the system.html §9 AI/ML
  hard-end gap with a *second, distinct* AI/ML primitive (model extraction, vs.
  Hairline's evasion). It is not solvable from memorised templates: the secret
  direction `h` is a fresh per-instance 96-D vector, so an agent must *actually*
  run a label-only boundary-reconstruction attack against this specific oracle,
  not recall a known answer. There is no single-query or closed-form shortcut:
  the label-only constraint provably removes the cheap "solve a linear system
  from scores" route that would make a linear model trivial.
* **What this does NOT resist (stated plainly).** The *technique* — "label-only
  linear boundary extraction via line search + SVD" — is a textbook attack with
  public references (Lowd-Meek 2005; Tramèr et al. 2016). A capable agent or
  practitioner who recognises the geometry will derive the ~40-line solver
  without difficulty, much as Signet's related-nonce attack is textbook once
  seen. The effort is in **execution** (methodical querying, a clean
  reconstruction) rather than in a deep conceptual leap. This is why the band is
  **Hard**, not Frontier: depth and search/tooling are real, but novelty is
  moderate and guess-exposure is zero. The honest framing matches Signet and
  Hairline: per-instance secrecy forces genuine modelling and defeats template
  recall and solution-sharing, but does not pretend the underlying method is
  unknown.
* **Harder variants (extrapolation, tracked for future bands).**
  - *Nonlinear target* (`SUBSTITUTE-PRIMITIVE`): make class `T` a small ReLU-MLP
    region. Label-only extraction then requires piecewise-linear region discovery
    (Jagielski et al., "High Accuracy and High Fidelity Extraction of Neural
    Networks", USENIX Security 2020; Carlini et al., "Cryptanalytic Extraction of
    Neural Network Models", CRYPTO 2020) — a genuine Frontier lift.
  - *Query budget pressure* (`CONSTRAIN`): cut the budget toward the information-
    theoretic minimum so the attacker must use an optimal active-sampling design
    rather than `3d` random rays.
  - *Noisy / rate-limited labels* (`PARAMETERISE`): randomly flip a small
    fraction of labels, forcing robust (e.g. RANSAC / repeated-query) boundary
    estimation.


## Lineage (corpus reconstruction, system.html §17)

* **Seed `zsctf-misc-008` — *what-a-jpeg-is* (DiceCTF Quals 2024).** The corpus'
  single hard AI/ML seed (an adversarial-ML robustness problem). **Borrowed:** the
  "attack a fixed, queryable model for the flag" framing.
  - Operator **SUBSTITUTE-PRIMITIVE**: swap the evasion / adversarial-example
    crux for a **model-extraction** crux (steal the decision boundary).
  - Operator **CONSTRAIN**: tighten model access from white-box (weights handed
    out, as in Hairline) to a **black-box, label-only** prediction API — the move
    that makes extraction non-trivial.
  - Operator **GROUND**: a realistic prediction-API / model-as-a-service
    deployment, where the asset at risk is the model's learned decision surface.

See `corpus-genome.yaml` (`zsctf-misc-008`, affordances `[GROUND, PARAMETERISE,
CHAIN(X)]`, `reconstruct_idea: "extend toward the §9 AI/ML frontier gap"`).
