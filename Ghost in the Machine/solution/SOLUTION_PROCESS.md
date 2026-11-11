# ch4_ghost_in_the_machine - Solution Process

## Intended path (hybrid)

1. Inspect network/devtools and identify wasm module.
2. Trace JS bridge to wasm export.
3. Analyze wasm logic through disassembly/decompilation.
4. Derive valid password and submit.

## Alternate path

- dynamic instrumentation in browser to log intermediate comparisons.

## Expected tooling

- browser devtools
- wasm analysis utilities
- optional script helpers
