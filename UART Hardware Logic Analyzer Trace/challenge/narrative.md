# Challenge: UART Logic-Analyzer Capture (misc_05_serial_uart_logic_analyzer_vcd)

**Category:** Miscellaneous
**Difficulty:** Medium
**Format:** `zerosecure{...}`
**North Star:** Authentic Tradecraft & Hardware Reality

---

## Scenario & Objective
Deep in the citadel's maintenance crawlspace, a CICADA3301 operative clipped a
logic-analyzer probe onto an unmarked debug header on one of Doom's service
boards. For a few hundred microseconds the single data line chattered, and the
probe faithfully dumped every rising and falling edge into a Value Change Dump.

No one labelled the line. No one wrote down the speed. But the pin never lies:
the edges carry an ordinary asynchronous serial transmission, and whatever the
board whispered to itself is sitting there in the timing, waiting for someone
patient enough to clock it out.

## Provided Files
- `dist/uart_trace.vcd` -- the capture: one 1-bit wire `rx`, idle high, recorded
  at 1 ns resolution (only level changes are stored).
- `dist/parameters.txt` -- the bus parameters noted at capture time.

## Your Task
Recover the serial timing from the waveform, demodulate the frames, and read out
the message the line transmitted. It is the flag.

## Compliance
- Flag format: `zerosecure{...}`
- Zero unreasoned guessiness. The bytes are fully determined by the edges.
