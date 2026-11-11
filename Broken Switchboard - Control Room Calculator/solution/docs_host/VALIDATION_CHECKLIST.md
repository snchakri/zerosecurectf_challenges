# Validation Checklist - ch2_broken_switchboard

## Functional
- [ ] Program starts and accepts username payload bytes.
- [ ] Normal channels 1-4 perform add/sub/mul/div.
- [ ] Division by zero is handled without crash.
- [ ] Out-of-bounds channel path can redirect control to `admin_shell`.

## Exploit Path
- [ ] Channel 5 or 6 reaches data adjacent to operations table.
- [ ] Packed pointer payload can route execution to `admin_shell`.
- [ ] Successful exploit yields shell spawn behavior and flag output.

## Input Safety / Stability
- [ ] Non-numeric menu entries are rejected cleanly.
- [ ] Out-of-range channel values are handled gracefully.
- [ ] Short payload input does not break normal calculator loop.
- [ ] Program loop remains stable after invalid input attempts.

## Binary Mitigation State
- [ ] Stack canary disabled.
- [ ] Executable stack enabled.
- [ ] PIE disabled.

## Packaging Separation
- [ ] `participant_deliverables/` contains only binary, README, checksum.
- [ ] No source or host docs in participant package.
- [ ] Archive produced only from `participant_deliverables/`.

## Solve Path Timing
- [ ] Intended path remains easiest route (~25 min median for fresh participants).
- [ ] Discovery flow points participants toward global data/function pointers instead of stack overflow assumptions.
