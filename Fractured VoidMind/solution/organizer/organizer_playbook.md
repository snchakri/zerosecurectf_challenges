# Organizer Playbook

## Intent
Deliver a full-scope offline challenge requiring Path A, B, C, D, and final synthesis.

## Canonical Constraint
Final plaintext must be exactly:
`zerosecurectf{genius_of_generation}`

## Baseline Bring-Up
1. Run generator:
   - `python -m generator.build_challenge`
2. Build binary:
   - `make`
3. Run verification matrix:
   - `python -m verify.test_matrix`

## Hidden Lane Tokens (Organizer Only)
- Path A: `r3tr41n::void`
- Path B: `inv::heisen`
- Path C: `memb::lane`
- Path D: `adv::skew`

## Path C Forensic Note
The participant artifact remains numpy-loadable and carries an appended SQLite payload.
To inspect that payload with sqlite3 CLI during organizer analysis:

1. Extract payload:
   - `python tools/extract_appended_sqlite.py build/generated/void_dataset.npz build/generated/void_dataset_payload.db`
2. Inspect:
   - `sqlite3 build/generated/void_dataset_payload.db 'select * from membership_lane;'`

## Full Verification Expected Output
- `[ok] Path A solved and share verified`
- `[ok] Path B solved, anti-debug decoy behavior verified`
- `[ok] Path C solved and polyglot lane verified`
- `[ok] Path D solved and skew lane verified`
- `[ok] Final boss reconstruction + optimization decrypt checks out`
- `[ok] full verification matrix complete`

## Current Implementation Stage
Full implementation package is complete for current project scope:
- deterministic generator pipeline
- embedded runtime data header generation
- A/B/C/D hidden lanes with share emission
- final-boss optimization/decrypt verifier
- participant + organizer deliverables packaging

## Governance
- No scope cuts for v1.
- Keep telemetry-free offline operation.
- Maintain patch-and-rotate procedure before release.
