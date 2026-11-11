# The Chamber of Echoes

**Category:** Binary Exploitation

**Category:** pwn  |  **Flag format:** `zerosecurectf{...}`

The VM offers a 'telemetry' peek over its scratch buffer; the true record lives just past it. The
direct REVEAL opcode faults. Leak the flag.  Run: ./checker.exe <your_prog.bin> vault.bin

## Files
- `vm.c`
- `checker.exe`
- `vault.bin`

Submit the `zerosecurectf{...}` string you recover.

**Binaries** are Windows (MinGW) builds; the C source is included — recompile with `gcc -O2 -o checker vm.c` (or the matching source) for Linux/macOS.
