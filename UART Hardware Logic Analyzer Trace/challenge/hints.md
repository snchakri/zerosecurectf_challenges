# Staged Hint Ladder: UART Logic-Analyzer Capture

### Hint Level 1 (Orientation)
A VCD stores only *changes*: `#<time>` lines set the current timestamp and a
`<value><id>` line (e.g. `0!` / `1!`) sets the wire. Reconstruct the full
piecewise-constant level of `rx` over time. The line idles high.

### Hint Level 2 (Reframe)
This is asynchronous UART, 8-N-1: each byte is a frame of one start bit (low),
8 data bits (LSB first), one stop bit (high). You need the bit period. Do not
trust a label blindly -- you can recover it straight from the waveform: every
edge lands on a bit boundary, so the greatest common divisor of all the gaps
between consecutive edges is exactly one bit period T.

### Hint Level 3 (Strong Nudge)
For each falling edge out of idle (start bit at t0), sample the 8 data bits at
their centres `t0 + (k + 1.5)*T` for k = 0..7, assemble LSB first, and check the
stop bit (`t0 + 9.5*T`) is high. Concatenate the decoded bytes to get the flag.

---
*Note: Crux Floor invariant: framing and period-recovery are described; writing
the sampler and byte assembly is left to the solver.*
