# Thermal Boundary - Complete Design and Solution Writeup

## 1. Challenge Summary

- Name: Thermal Boundary
- Category blend: Reverse Engineering + VM Architecture + Side-Channel
- Format: Downloadable binary
- Participant artifact: `thermal_boundary.exe`
- Intended solve style: Detect and ignore decoy paths, pivot to VM timing side-channel

This challenge is intentionally designed so common first instincts (crypto RE, pwn path, network analysis) consume time but do not lead to the real flag.

## 2. Delivery Artifacts

### Participant package

- Path: `deliverables/participants/thermal_boundary/thermal_boundary.exe`
- SHA256: `E2053C20FE047A2D9BCFBED5BE6A6C265579C740121F72CBC2FF0B0E162B492A`
- Size: 31744 bytes

### Author-side implementation and tooling

- VM runtime: `src/vm.c`
- Dispatcher: `src/main.c`
- Mirages: `src/mirage.c`
- Secret decode/zeroize: `src/secret.c`
- Bytecode loader: `src/bytecode_loader.c`
- Assembler: `tools/assembler.py`
- Reference solver: `tools/reference_solver.py`
- Verification suite: `tests/run_all.py`

## 3. Architecture Overview

The binary has three decoy vectors and one true vector.

### False vector 1: Crypto mirage

- Trigger: `ENABLE_ECC=1`
- Behavior: Runs ECC-like arithmetic chain and outputs a false flag.
- Purpose: Pull static analyzers into deep but irrelevant math path.

### False vector 2: Pwn mirage

- Trigger: Trace detection or `TB_FORCE_PWN=1`
- Behavior: Interactive heap-console with exploitable UAF-style logic; can reveal false flag.
- Purpose: Rewards pwn instincts but yields decoy result.

### False vector 3: Network mirage

- Trigger: enabled by default unless `NO_NET=1`
- Behavior: Emits encoded false-flag packet structure.
- Purpose: Looks like covert exfil path to distract packet analysts.

### True vector: VM micro-architectural leak

- VM executes custom bytecode in a deterministic environment.
- VM simulates cache hit/miss latency and exposes cycle timing via `RDTSC`.
- `TRIGGER_SECRET` touches probe-table cache line derived from one flag byte index.
- Solver uses Flush+Reload style probing in VM bytecode to recover each character.

## 4. VM Model (Implementation-Level)

- Registers: `r0..r7` (`r0` is zero)
- Memory: shared flat model with probe area
- Probe table base: `0x2000`
- Cache line size: `64`
- Cache lines: `256`
- Instruction timing:
  - Base instruction cost: `1`
  - Hit latency: `2`
  - Miss latency: `20`
  - Flush latency: `10`

### Key opcodes used by solver

- `RDTSC rd`
- `CLFLUSH rs1`
- `TRIGGER_SECRET`
- `LD rd, off(rs1)`
- `PRINT rs1`

## 5. End-User Solve Process (Beginner Friendly)

This is the same solve path a participant can use without deep CTF background.

### Step 1: Run with solver-friendly environment

Use:

- `NO_NET=1` to disable network noise
- `TB_QUIET=1` to keep output parseable
- `TB_FORCE_ASCII=1` to avoid terminal encoding noise

### Step 2: Generate probing bytecode and execute repeatedly

For each flag index `i`:

1. Set `r1 = i`
2. Flush candidate probe lines
3. Execute `TRIGGER_SECRET`
4. Reload candidates and time each using `RDTSC`
5. Pick the minimum-latency candidate as byte `i`

### Step 3: Stop when `}` is recovered

Recovered bytes form:

- `zerosecurectf{the_realist_flag}`

## 6. Practical Solve Commands (Ready-to-Run)

### One-command solver script

```powershell
$env:Path = "C:\msys64\ucrt64\bin;$env:Path"
powershell -ExecutionPolicy Bypass -File .\scripts\solve_true_vector.ps1
```

### Direct solver command

```powershell
$env:NO_NET = "1"
$env:TB_QUIET = "1"
$env:TB_FORCE_ASCII = "1"
python tools/reference_solver.py --binary build/thermal_boundary.exe --assembler tools/assembler.py --max-len 40
```

Expected tail output:

- `recovered: zerosecurectf{the_realist_flag}`

## 7. Why `.\thermal_boundary.exe 1` Fails

The challenge does not accept solve input via argv.
It expects raw VM bytecode on stdin using the `TBVM` bytecode format header.

## 8. Verification Matrix (All Levels)

Executed with:

```powershell
$env:Path = "C:\msys64\ucrt64\bin;$env:Path"
mingw32-make verify PYTHON=python
```

Checks include:

- Smoke VM execution
- Bytecode loader rejection checks
- Cache miss/hit timing separation
- `CLFLUSH` semantics
- Single-byte side-channel leak
- Full reference solver extraction
- Crypto mirage false-flag route
- Pwn mirage false-flag route
- Network mirage packet decode
- Plaintext true-flag absence in release artifact

Current result: all pass.

## 9. Security/Integrity Notes

- True flag is not embedded as plaintext literal in release binary.
- Runtime decodes obfuscated flag material in memory and zeroizes buffer after use.
- Loader validates magic/version/size/entry and exact payload length.

## 10. Organizer Operational Notes

### Build release

```powershell
$env:Path = "C:\msys64\ucrt64\bin;$env:Path"
mingw32-make release PYTHON=python
```

### Package for participants

- Distribute only: `deliverables/participants/thermal_boundary/thermal_boundary.exe`
- Keep this writeup private.

### Optional no-spoiler participant hint strategy

- Hint 1: "Not every valid flag is the right flag."
- Hint 2: "Time is data in this machine."
- Hint 3: "Look below software logic, inside execution model."

## 11. Full Truth Table of Paths

- Crypto path solved: returns false flag
- Pwn path exploited: returns false flag
- Network path decoded: returns false flag
- VM side-channel solved: returns true flag

That makes the challenge difficult through misdirection while remaining fully solvable via the intended vector.
