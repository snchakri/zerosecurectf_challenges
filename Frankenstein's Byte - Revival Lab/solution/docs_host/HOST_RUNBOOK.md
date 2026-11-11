# HOST_RUNBOOK - ch3_frankensteins_byte

## Purpose
Deliver a deterministic off-by-one challenge that teaches little-endian least-significant-byte overwrite behavior.

## True Vector Contract
- Vulnerability class: off-by-one write via `read(0, state.monster_name, 33)` into a 32-byte local array inside a local struct.
- Target primitive: 33rd byte overwrites LSB of adjacent `state.gate_value`.
- Required gate state: `state.gate_value == 0x00000005`.
- True flag string: `ZeroSecure_CTF{frankensteins_byte_lsb_awakened}`.
- Any other flag-like string in the binary is a decoy.

## Directory Contract
- Keep all host internals under this challenge directory only.
- Release payload must include only:
  - `frankensteins_byte`
  - `README.md`
  - `frankensteins_byte.sha256`

## Mandatory Build Directives
The challenge must compile with:
- `-fno-stack-protector`
- `-z execstack`
- `-no-pie`

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
- `smoke_test.sh`: positive/negative byte-level exploit assertions.
- `stability_test.sh`: edge-input behavior and no unintended flag leakage.
- `participant_isolated_solve.sh`: validates package file-set, checksum, and solve path in sandbox with zero-dependency Python.

## Guardrails
- Do not change struct field order or remove local struct scope.
- Do not add alternate flag unlock paths.
- Keep decoys harmless and non-winning.

## Troubleshooting
- If verification fails for GNU_STACK, ensure linker includes `-z execstack`.
- If smoke positive case fails, confirm payload is exactly 33 bytes with trailing `0x05`.
- If isolated solve fails file-set check, regenerate with `make -C host package`.
