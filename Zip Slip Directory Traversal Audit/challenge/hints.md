# Staged Hint Ladder: Zip Slip Directory Traversal Audit

### Hint Level 1
The 'Zip Slip' vulnerability occurs when archive extractors fail to validate member filenames against directory traversal sequences (`../`).

### Hint Level 2
Inspect raw archive headers for relative directory components.

### Hint Level 3
Recover the targeted destination path and embedded payload.

---
*Note: Crux Floor invariant: The core systems / analytical insight is never handed out completely; each hint restores a reasoning handle.*
