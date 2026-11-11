# Hairline — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Hairline — official writeup

**Flag (demo seed):** `zerosecurectf{a_h4irline_nudg3_flips_th3_v3rdict}` (per-instance in production)


## The task

The service exposes a fixed (per-instance) classifier, a benign base sample `x0`,
a target class `t`, and an L-infinity budget `eps`. It releases the flag only if
you submit `x` with `||x - x0||_inf <= eps` that the model classifies as `t` with
confidence above a threshold. This is an **evasion / adversarial-example** attack
(the real problem behind adversarial ML robustness).


## The attack

- A random in-budget perturbation almost never flips the label (the test checks
  that thousands of random tries fail) — you need a *directed* perturbation.
- Compute the model's gradient of the target-class score with respect to the
  input and step along its sign up to the budget (an FGSM / projected-gradient
  step), projecting back into the L-infinity ball each iteration until the model
  crosses the confidence threshold for `t`.
- Submit the resulting vector; the service verifies the budget and the
  classification and returns the flag.

The reference solver implements this with numpy (no ML framework required).


## Why only this path

- Random/benign inputs stay in the original class (verified by the integrity
  checks) — brute force in the budget ball does not win.
- The budget is tight enough that the perturbation must be adversarially aimed,
  not noise.
- Guess-exposure is 0: the gradient direction is a reasoned, computable handle.

