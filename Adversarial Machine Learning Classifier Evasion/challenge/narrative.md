# Challenge: Adversarial Feature Perturbation (misc_02_adversarial_ml_feature_perturbation)

**Category:** Miscellaneous
**Difficulty:** Medium
**Format:** `zerosecure{...}`
**North Star:** Authentic Tradecraft & AI Reality

---

## Scenario & Objective
The inner sanctum of the citadel is guarded by a biometric lattice: a linear
classifier that scores each supplicant's feature vector and swings the gate open
only for those it deems *authorised*. Doom trusts mathematics where he does not
trust men.

CICADA3301's analysts lifted the model itself -- its weights, its bias, and one
captured probe vector that the gate currently waves through. They do not want to
be waved through. They want the *exact* template the gate holds in its heart:
the single enrolment vector that sits precisely on the decision boundary. Reach
that point with the smallest possible nudge, and the citadel's secret falls out
of the numbers.

## Provided Files
- `dist/model_weights.json` -- the linear model (`weights`, `bias`,
  `decision_threshold`), the benign probe `x_input` (currently class
  AUTHORISED), and the stated objective.

## Your Task
Find the minimal-energy perturbation that moves `x_input` onto the decision
boundary. The boundary point is a byte-valued vector; read it as text to recover
the flag. The answer is unique -- determined entirely by the model.

## Compliance
- Flag format: `zerosecure{...}`
- Zero unreasoned guessiness. One exact vector satisfies the geometry.
