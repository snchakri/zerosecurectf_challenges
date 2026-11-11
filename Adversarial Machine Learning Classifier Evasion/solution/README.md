# Adversarial Machine Learning Classifier Evasion — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Adversarial Feature Perturbation


## 1. Artifact
`dist/model_weights.json` holds a binary linear classifier:
`score(x) = w . x + bias`, decision at `score = 0`. It also provides a benign
probe `x_input` with `score(x_input) > 0` (class AUTHORISED) and states the
objective: the minimal perturbation that places `x_input` exactly on the
decision boundary, where the boundary point is an ASCII byte vector. Dimension
`D = 60` (= flag length).


## 2. The mathematics
The decision boundary is the hyperplane `H = { y : w . y + b = 0 }`. The
*minimal-L2* perturbation taking `x_input` to `H` is the orthogonal projection:

```
delta* = -((w . x_input + b) / (w . w)) * w
x_adv  = x_input + delta*          # lies exactly on H:  w . x_adv + b = 0
```

By construction of the challenge, `x_adv` equals the gateway's secret enrolment
template `v`, whose components are the flag's ASCII byte values. (Build-side:
`b = -(w . v)` and `x_input = v + t*w`, so the projection returns exactly `v`.)


## 3. Why naive attacks fail
A sign-based FGSM step `x_input - eps * sign(w)` is an L-infinity move; it
crosses the boundary but lands on non-integer coordinates that do not decode to
ASCII. Only the exact L2 projection yields integer, byte-valued coordinates.
The build script asserts that FGSM does NOT accidentally recover the flag.


## 4. Intended solution / solver
`solve.py --dist ./dist`:
1. load `w`, `b`, `x_input` from the JSON;
2. compute `x_adv = x_input - ((w.x_input + b)/(w.w)) * w` in float64;
3. `round` to nearest integers and decode as bytes -> the flag.

```
python solve.py --dist ./dist
zerosecure{adversarial_perturbation_classifier_evasion_32ba}
```

The solver contains no flag string and never reads `./flag`.


## 5. Leak safety
Only `w`, `bias`, and `x_input = v + t*w` are published; the template `v` (the
flag) is never stored. `x_input`'s components are non-integer reals, so the flag
bytes do not appear in any form (confirmed by the leak check).


## 6. Defensive note
Linear/soft biometric gates are exploitable by exactly this projection; robust
deployments add margin, non-linearity, input quantisation defences, and
rejection of out-of-distribution feature vectors.
