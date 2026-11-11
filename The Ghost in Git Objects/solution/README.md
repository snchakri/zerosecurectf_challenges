# The Ghost in Git Objects — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: The Ghost in Git Objects (Dangling Commit Carving)


## 1. Vulnerability Analysis & Theoretical Foundations
Git maintains an append-only object database in `.git/objects`. Performing `git reset --hard` or deleting branches removes references but leaves underlying commit and tree objects intact until garbage collection runs.


## 2. Citations & Academic References
- Chacon, S., & Straub, B. (2014). Pro Git (2nd ed.). Apress.
- Sood, A. (2021). Git Internals and Repository Forensics.


## 3. Step-by-Step Walkthrough
1. Audit `git_object_triage.json` representing orphaned git objects.
2. Inspect dangling commit `e83910...` diff.
3. Extract the deleted production configuration line exposing the secret key.


## 4. Exploit Script & Verification
Execute the automated reference solver:
```bash
python solve.py
```
Output:
```text
[+] Successfully recovered flag: zerosecure{git_dangling_blob_unreachable_commit_91ad}
```


## 5. Defense Engineering & Remediation
Enforce pre-commit hooks (git-secrets, TruffleHog) preventing credentials from ever entering the git tree, and run `git gc --prune=now` when purging sensitive data.
