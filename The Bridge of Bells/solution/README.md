# The Bridge of Bells — solution

Run from the title directory:

```bash
python -m pip install -r solution/requirements.txt
python solution/solve.py
```

1. Read `vm.c` and map the stack opcodes: input bytes, constants, XOR, addition, subtraction, and equality.
2. Lift each bytecode operation to an 8-bit expression so arithmetic wraps exactly as in the VM. Collect each equality check.
3. Solve the resulting constraints. The `ENDCHK` operand confirms the input length. The recovered byte string is the unique accepted argument.

The accepted event answer is recorded in `accepted_flags.txt`. The solver derives its result from the challenge data.
