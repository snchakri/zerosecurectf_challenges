# ch5_corrupted_save_state - Solution Process

## Intended path

1. Open save in hex editor.
2. Identify key field offsets and endianness.
3. Patch required values (example: level and gold).
4. Reload save in runner and recover flag.

## Alternate path

- write small parser script to locate and patch fields automatically.

## Expected tooling

- hex editor
- optional Python script
