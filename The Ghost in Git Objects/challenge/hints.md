# Staged Hint Ladder: The Ghost in Git Objects

### Hint Level 1
Git commits and tree objects are immutable; `git reset` merely moves branch pointers.

### Hint Level 2
Objects remain in `.git/objects` until explicitly pruned via `git gc --prune=now`.

### Hint Level 3
Inspect dangling commits and unreferenced tree blobs in the repository triage report.

---
*Note: Crux Floor invariant: The core forensic recovery technique is never handed out completely; each hint restores a reasoning handle.*
