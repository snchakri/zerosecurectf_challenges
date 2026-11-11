# VALIDATION_CHECKLIST - ch3_echo_chamber

Use this before final release.

## Build and Mitigation State
- [ ] `make -C host clean build verify` passes.
- [ ] ELF type is `EXEC` (PIE disabled).
- [ ] `__stack_chk_fail` symbol is absent (stack canary disabled).
- [ ] `GNU_STACK` contains execute permission.

## Functional Behavior
- [ ] Startup prints gate address and required value.
- [ ] Standard echo usage does not print true flag.
- [ ] `EXIT` path closes cleanly.
- [ ] Wrong `%n` writes trigger guard reset behavior.
- [ ] Only `is_admin == 1337` triggers true flag.

## Decoys and Leakage
- [ ] Decoy flags/messages are visible as bait.
- [ ] Decoys do not satisfy win condition.
- [ ] No host-only secrets leak into participant artifacts.

## Tests
- [ ] `bash tests/smoke_test.sh` passes.
- [ ] `bash tests/stability_test.sh` passes.
- [ ] `bash tests/participant_isolated_solve.sh` passes.

## Packaging
- [ ] `make -C host package` generates participant files.
- [ ] `participant_deliverables` contains exactly:
  - [ ] `echo_chamber`
  - [ ] `README.md`
  - [ ] `echo_chamber.sha256`
- [ ] `host/ch3_echo_chamber_participant.tar.gz` is created.

## Release Gate
- [ ] `make -C host release-check` passes from clean state.
- [ ] Final flag contract confirmed: `ZeroSecure_CTF{echo_in_silence}` via intended format-string write vector only.
