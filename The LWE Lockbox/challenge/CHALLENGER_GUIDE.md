# Challenger Guide

## Cheesy Overview

You are not cracking a lock. You are polishing cosmic grime off a quantum vault window.
The matrix is the glass, the noise is the dust, and your six fragments are the cleaning recipe.
Get the recipe right, wipe the noise, and the hidden message appears.

## Your Objective

1. Provide exactly six fragments in this format:
   - `S1=<value>` through `S6=<value>`
   - Optional recovery form for one missing core slot: `R:Sx=<value>`
2. Run the integrator.
3. Use generated artifacts:
   - `A_matrix.txt`
   - `b_vector.txt`
   - `e_hat_vector.txt`
4. Solve externally:
   - Compute `b - e_hat (mod q)`
   - Solve linear system over `Z_q`: `A*s = b - e_hat`
   - Decode `s` as ASCII and remove deterministic padding

## Important

- A decoy flag may be shown on failure paths. It is not score-valid.
- The true flag appears only when the true vector is regenerated.
- Flag format: `ZeroSecure_CTF{...}`

## Troubleshooting (Anti-Decoy)

- If the script prints a flag but your math solve does not reconstruct clean ASCII, treat that flag as decoy output.
- First validate fragment format and slot identity (`S1`..`S6` or one valid `R:Sx` replacement).
- Re-run with the same six fragments twice. If `e_hat_vector.txt` differs between runs, your input normalization is inconsistent.
- Use only `A_matrix.txt`, `b_vector.txt`, and `e_hat_vector.txt` for solving. Ignore `false_vector_bait.txt`.
- Score-valid success requires exact true-vector match and a final flag in `ZeroSecure_CTF{...}` format.
