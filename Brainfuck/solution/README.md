# Brainfuck — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Brainfuck — official writeup

**Flag (demo seed):** `zerosecurectf{just_1mplement_the_interpreter}` (per-instance in production)


## Flaw & attack
Brainfuck has eight commands over a byte tape. Implement the interpreter (pointer moves, cell inc/dec with wraparound, output on '.'), run the given program with no input, and its printed output is the token.

