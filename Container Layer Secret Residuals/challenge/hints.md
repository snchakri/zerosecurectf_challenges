# Staged Hint Ladder: Container Layer Secret Residuals

### Hint Level 1
Docker images are composed of immutable stacked filesystem layers.

### Hint Level 2
Unsetting an environment variable or deleting a file in a later layer only masks it in the union filesystem; the underlying layer retains it.

### Hint Level 3
Inspect the layer construction commands in the container image manifest.

---
*Note: Crux Floor invariant: The core forensic recovery technique is never handed out completely; each hint restores a reasoning handle.*
