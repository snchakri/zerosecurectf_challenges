# UART Hardware Logic Analyzer Trace — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: UART Logic-Analyzer Capture


## 1. Artifact
`dist/uart_trace.vcd` is a Value Change Dump of a single 1-bit wire `rx`, idle
high, at 1 ns timescale. `dist/parameters.txt` notes: asynchronous UART, 8-N-1,
115200 bps (~8.68 us/bit). The trace carries one 10-bit frame per flag byte
(47 frames) with idle-high gaps.


## 2. Reconstructing the signal
Parse the VCD: `#<t>` lines set the timestamp, `0!`/`1!` set the wire. Build a
piecewise-constant `level(t)`. Because a VCD records only transitions, the level
between two events is constant.


## 3. Recovering the bit period from the waveform
Every edge occurs on a bit boundary, so every inter-edge gap is an integer
multiple of the bit period T. Hence `T = gcd(all gaps)`. (Here T = 8681 ns,
matching ~115200 bps; the solver derives it, it is not assumed.)


## 4. Demodulating 8-N-1
For each falling edge from idle (a start bit beginning at t0):
- data bit k (k = 0..7) is sampled at its centre `t0 + (k + 1.5)*T`;
- assemble the byte LSB first: `byte |= bit_k << k`;
- verify the stop bit at `t0 + 9.5*T` is high;
- jump to `t0 + 10*T` and continue to the next start edge.

Concatenating the bytes yields the flag.


## 5. Solver
`solve.py --dist ./dist` parses the VCD, derives T via GCD of edge spacings,
walks the falling edges, samples at bit centres LSB-first, and prints the flag:

```
python solve.py --dist ./dist
zerosecure{uart_vcd_timing_signal_decoded_92ee}
```

It contains no flag string and never reads `./flag`.


## 6. Leak safety
The flag exists only as bit-level timing transitions in the VCD; there is no
ASCII run of the flag (LSB-first serialisation further scrambles byte order at
the character level). Confirmed by the leak check.


## 7. Defensive note
Debug headers that expose plaintext UART are a classic hardware leak. Disable or
lock production debug UARTs, or carry only authenticated/encrypted framing on
exposed pins.
