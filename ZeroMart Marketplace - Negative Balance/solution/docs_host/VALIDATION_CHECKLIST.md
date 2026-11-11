# Validation Checklist - ch1_negative_balance

## Functional
- [ ] Start balance is 100.
- [ ] Flag purchase threshold is 9,999,999.
- [ ] Normal purchases do not practically reach flag threshold.
- [ ] Negative quantity purchase can raise balance enough to unlock flag.

## Input Safety (Guardrail A)
- [ ] Overlong text input does not crash process.
- [ ] Non-numeric menu entries are rejected cleanly.
- [ ] Non-numeric quantity entries are rejected cleanly.
- [ ] Program loop remains stable after invalid input.

## Arithmetic Boundary Control (Guardrail B)
- [ ] Quantity cap enforced for all purchases.
- [ ] Test quantities: `-2147483648`, `-2147483647`, `-1`, `0`, `1`, `2147483647`.
- [ ] Test cap edge values: `-10000`, `10000`, `-10001`, `10001`.
- [ ] Extreme values do not create confusing wraparound behavior.

## Binary Mitigation State
- [ ] Stack canary disabled.
- [ ] Executable stack enabled.
- [ ] PIE disabled.

## Packaging Separation
- [ ] `participant_deliverables/` contains only binary, README, checksum.
- [ ] No source or host docs in participant package.
- [ ] Archive produced only from `participant_deliverables/`.

## Solve Path Timing
- [ ] Intended path remains easiest route (~20 min median for fresh participants).
- [ ] Early checksec-based misdirection still exists.
