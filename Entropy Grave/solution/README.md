# Entropy Grave — solution

Run commands from this challenge directory unless the retained author instructions specify another working directory.

1. Read the original player brief in `challenge/README.md`.
2. Follow `organizer_only/hints.md` to identify the hidden artifact and its transformation.
3. Run the author reference solver under `solution/organizer_only/` with the corresponding artifact from `challenge/`.
4. Use `organizer_only/deployment.md` for the full reconstruction and expected result.

Author procedures and reference material:

- [organizer_only/deployment.md](organizer_only/deployment.md)
- [organizer_only/hints.md](organizer_only/hints.md)

**Verification:** archived reference; not rerun. Original event-only links may no longer respond.

## Runnable recovery

This wrapper executes the unmodified author solver in a temporary copy of the original layout. It reads the supplied player artifact and keeps generated files out of `challenge/`.

```bash
python solution/solve.py
```
