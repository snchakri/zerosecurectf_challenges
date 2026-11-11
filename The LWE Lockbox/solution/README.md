# The LWE Lockbox — solution

Run commands from this challenge directory unless the retained author instructions specify another working directory.

1. Collect the six true fragments `S1` through `S6` from the preceding challenge chain.
2. Pass the fragments in that order to `solution/integrator.py`.
3. The integrator validates the fragments, derives the LWE lockbox material, and reconstructs the final flag.
4. Use `HOST_GUIDE.md` and `host_assets/true_fragments.env` to reproduce the author fixture; those values belong only in the solution folder.

Author procedures and reference material:

- [HOST_GUIDE.md](HOST_GUIDE.md)
- [host_assets/config/seed_rotation_policy.md](host_assets/config/seed_rotation_policy.md)

**Verification:** archived reference; not rerun. Original event-only links may no longer respond.
