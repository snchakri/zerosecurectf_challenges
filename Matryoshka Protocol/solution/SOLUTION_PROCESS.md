# ch2_matryoshka_protocol - Solution Process

## Intended path (dynamic)

1. Execute wrapper while monitoring temp directory.
2. Capture dropped file before deletion.
3. Analyze captured executable to recover output/flag.

## Alternate path (static)

1. Extract encrypted byte array from wrapper.
2. Identify XOR routine and key.
3. Decode bytes offline and reconstruct executable.

## Expected tooling

- debugger / process monitor
- hex editor
- Python for decode scripts
