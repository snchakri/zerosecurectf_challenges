# The Keystone Seal

**Category:** Reverse Engineering

**Category:** rev  |  **Flag format:** `zerosecurectf{...}`

A seal written as a system, not a lock. The register-VM checks its argument with coupled arithmetic
over GF(257). Recover the argument.  Run: ./checker.exe <flag>

## Files
- `vm.c`
- `program.bin`
- `checker.exe`

Submit the `zerosecurectf{...}` string you recover.

**Binaries** are Windows (MinGW) builds; the C source is included — recompile with `gcc -O2 -o checker vm.c` (or the matching source) for Linux/macOS.
