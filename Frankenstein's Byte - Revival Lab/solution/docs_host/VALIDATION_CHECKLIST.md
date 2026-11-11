# VALIDATION_CHECKLIST - ch3_frankensteins_byte

Use this before final release.

## Build and Mitigation State
- [ ] `make -C host clean build verify` passes.
- [ ] ELF type is `EXEC` (PIE disabled).
- [ ] `__stack_chk_fail` symbol is absent (stack canary disabled).
- [ ] `GNU_STACK` contains execute permission.

## Functional Behavior
- [ ] Positive payload (`32 x 'A' + 0x05`) unlocks true flag.
- [ ] `33 x 'A'` does not unlock and shows wrong-byte feedback.
- [ ] Short input (<=32 bytes) does not unlock and shows failure path.
- [ ] True flag appears only on intended vector.

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
  - [ ] `frankensteins_byte`
  - [ ] `README.md`
  - [ ] `frankensteins_byte.sha256`
- [ ] `host/ch3_frankensteins_byte_participant.tar.gz` is created.

## Release Gate
- [ ] `make -C host release-check` passes from clean state.
- [ ] Final flag contract confirmed: `ZeroSecure_CTF{frankensteins_byte_lsb_awakened}` via 33rd-byte LSB overwrite vector only.
