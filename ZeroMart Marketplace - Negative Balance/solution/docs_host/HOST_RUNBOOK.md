# Host Runbook - ch1_negative_balance

## Purpose
This runbook defines host-only operations for building, verifying, and packaging the challenge without leaking internal assets.

## Directory Contract
- Keep all challenge work inside `ch1_negative_balance`.
- Host-only assets:
  - `src/`
  - `host/`
  - `tests/`
  - `docs_host/`
- Participant-only release payload:
  - `participant_deliverables/`

## Mandatory Build Directives for Ubuntu PWN
Compile with:
- `-fno-stack-protector`
- `-z execstack`
- `-no-pie`

Current host Makefile includes all required directives and also uses `-O0 -g` for stable debugging.

## Build Workflow
From `host/`:
1. `make clean build`
2. `make verify`
3. `make test`
4. `make package`
5. `make release-check`

Or run one command:
1. `./build.sh`
2. `./package_participant.sh`

## Verification Targets
- PIE disabled (ELF type EXEC).
- No stack canary dependency (`__stack_chk_fail` absent).
- Executable stack enabled (GNU_STACK execute flag present).

## Guardrails for Intended Solve Path
- Input handling must remain bounded and parse-validated.
- Do not add unsafe string/input calls for menu or quantity handling.
- Quantity range is intentionally capped to avoid extreme signed multiplication wraparound confusion while preserving the negative-quantity exploit path.

## Packaging Policy
- Package only from `participant_deliverables/`.
- Do not copy host notes, source files, tests, or internal metadata into participant deliverables.
- Release-check includes a participant-only sandbox solve that uses only files from `participant_deliverables/`.

## Flag Contract
- Format: `ZeroSecure_CTF{...}`
- This build currently emits: `ZeroSecure_CTF{negative_balance_exploit_finance_mode}`
