# The Bridge of Bells

**Category:** Reverse Engineering

**Category:** rev  |  **Flag format:** `zerosecurectf{...}`

Cross in the right rhythm and the bells fall silent. The bytecode (program.bin) run by the VM (vm.c)
accepts exactly one argument. Find it.  Run: ./checker.exe <flag>

## Files
- `vm.c`
- `program.bin`
- `checker.exe`

Submit the `zerosecurectf{...}` string you recover.

**Binaries** are Windows (MinGW) builds; the C source is included — recompile with `gcc -O2 -o checker vm.c` (or the matching source) for Linux/macOS.
