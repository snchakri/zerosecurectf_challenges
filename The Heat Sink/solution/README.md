# The Heat Sink — solution

Run from the title directory:

```bash
python -m pip install -r solution/requirements.txt
python solution/solve.py
```

The narrative gate answer is **`primes`**. In `challenge/`, run `python open.py gate.bin "primes"` to render the puzzle. The reference solver can also use the identical rendered handout retained in `solution/unlocked/`. The launcher fixes the original station identifier so that renaming the outer folder does not change the gate key.

1. Open the narrative gate with **primes**.
2. The Concord clue identifies the real cells by prime-valued temperatures. Select exactly the required number of cells.
3. Sort them by increasing temperature: the order is part of the key derivation.
4. Pass their IDs, in that order, to the supplied orchestrator. Its `HEAT` tags and complete fragment index set verify the reconstruction.

The accepted event answer is recorded in `accepted_flags.txt`. The solver derives its result from the challenge data.

## Event/source difference

The solver derives its answer from the preserved artifact. Its output differs from, or has no matching entry in, the CTFd `accepted_flags.txt` snapshot. Both are retained as historical evidence; the expected event answer is not silently substituted into the solver.
