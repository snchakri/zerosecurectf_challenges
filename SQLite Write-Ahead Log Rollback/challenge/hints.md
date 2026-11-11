# Staged Hint Ladder: SQLite Write-Ahead Log Rollback

### Hint Level 1
In SQLite WAL mode, changes are written sequentially to the `-wal` file before checkpointing into the main `.db`.

### Hint Level 2
Even if a transaction is rolled back or aborted, the frame bytes persist in the WAL file until overwritten by a checkpoint.

### Hint Level 3
Inspect uncommitted frames in the WAL transaction log.

---
*Note: Crux Floor invariant: The core forensic recovery technique is never handed out completely; each hint restores a reasoning handle.*
