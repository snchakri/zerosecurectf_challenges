# HOST_RUNBOOK - ch3_echo_chamber

## Purpose
Deliver a deterministic format-string challenge where the intended win path sets global `is_admin` to exactly `1337` and reveals only the true flag.

## True Vector Contract
- Vulnerability class: uncontrolled format string via `printf(buffer, ...)`.
- Required gate state: `is_admin == 1337`.
- True flag string: `0`.
- Any other flag-like string in the binary is a decoy.

## Directory Contract
- Keep all host internals under this challenge directory only.
- Release payload must include only:
  - `echo_chamber`
  - `README.md`
  - `echo_chamber.sha256`

## Mandatory Build Directives
The challenge must compile with:
- `-fno-stack-protector`
- `-z execstack`
- `-no-pie`

Additional format-string solvability settings used:
- `-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0`
- warning suppression for intentional format sink.

## Build and Validation Workflow
From `host/`:
1. `make clean build verify`
2. `make test`
3. `make package`
4. `make release-check`

Or use helper script:
1. `./build.sh`

## Verification Targets
`verify_binary.sh` must pass:
- ELF type `EXEC` (PIE disabled)
- no `__stack_chk_fail` symbol
- `GNU_STACK` executable flag present

`checksec` output is secondary and optional.

## Test Expectations
- `smoke_test.sh`: startup hints, echo behavior, clean EXIT, no accidental true-flag disclosure.
- `stability_test.sh`: malformed/awkward input does not break intended playability; wrong `%n` write resets gate.
- `participant_isolated_solve.sh`: validates package file-set, checksum, then solves using pwntools in sandbox.

## Guardrails
- Do not add alternate admin unlock paths.
- Do not expose true flag through non-admin commands.
- Keep decoys harmless and non-winning.

## Troubleshooting
- If `verify` fails on stack flags, ensure linker includes `-z execstack`.
- If participant solve fails due missing pwntools, install in host environment before release checks.
- If offsets drift after source edits, update only the solve payload format in isolated solve test.
