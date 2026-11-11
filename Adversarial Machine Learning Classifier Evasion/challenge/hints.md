# Staged Hint Ladder: Adversarial Feature Perturbation

### Hint Level 1 (Orientation)
The model is linear: `score(x) = w . x + bias`, and the decision boundary is the
hyperplane `score(x) = 0`. `x_input` sits on the AUTHORISED side (`score > 0`).
The objective asks for the *minimal* perturbation that lands exactly on the
boundary, and tells you the boundary point is an ASCII byte vector.

### Hint Level 2 (Reframe)
"Minimal" matters. A sign-based / L-infinity FGSM step (`x - eps * sign(w)`)
crosses the boundary but lands on arbitrary real values that do not quantise to
bytes. You want the *closest* point on the hyperplane to `x_input` -- the
orthogonal projection, i.e. the minimal-L2 solution.

### Hint Level 3 (Strong Nudge)
The orthogonal projection of a point `x` onto `{y : w . y + b = 0}` is
`x_adv = x - ((w . x + b) / (w . w)) * w`. Compute it in float64, round each
component to the nearest integer, and decode the resulting bytes as ASCII.

---
*Note: Crux Floor invariant: the geometric identity is pointed at, but the final
"round and decode" assembly is left to the solver.*
