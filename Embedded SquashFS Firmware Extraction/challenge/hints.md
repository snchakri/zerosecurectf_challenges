# Staged Hint Ladder: Embedded SquashFS Firmware Extraction

### Hint Level 1
Embedded firmware images frequently bundle Linux root filesystems compressed with SquashFS.

### Hint Level 2
Examine backup files (`.bak`, `.old`, `.swp`) left by installation scripts in `/etc/`.

### Hint Level 3
Recover the credentials preserved in `/etc/shadow.bak`.

---
*Note: Crux Floor invariant: The core forensic recovery technique is never handed out completely; each hint restores a reasoning handle.*
