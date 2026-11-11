# The Hundred Steps

**Category:** Reverse Engineering

**Category:** rev  |  **Flag format:** `zerosecurectf{...}`

A benign kernel schedules out of order and deadlocks, then recovers. The circular wait it reports is
where - and how - the flag is hidden in boot.img.

## Files
- `kernel.c`
- `kernel.exe`
- `boot.img`

Submit the `zerosecurectf{...}` string you recover.

**Binaries** are Windows (MinGW) builds; the C source is included — recompile with `gcc -O2 -o checker vm.c` (or the matching source) for Linux/macOS.
