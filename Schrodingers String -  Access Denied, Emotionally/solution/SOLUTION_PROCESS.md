# ch1_schrodingers_string - Solution Process

## Intended path (dynamic)

1. Run binary under debugger.
2. Set breakpoint after reconstruction and before wipe.
3. Inspect heap/stack memory buffer.
4. Extract plaintext flag and submit.

## Alternate path

- Instrument runtime and dump process memory during sleep window.

## Expected tooling

- gdb or x64dbg
- memory viewer / hexdump helper
