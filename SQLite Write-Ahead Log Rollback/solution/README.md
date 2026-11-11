# SQLite Write-Ahead Log Rollback — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: SQLite Write-Ahead Log Rollback (Uncommitted Frame Forensics)


## 1. Vulnerability Analysis & Theoretical Foundations
SQLite in WAL mode appends database transactions to a `-wal` file prior to checkpointing. When a transaction is aborted or rolled back, the modified frames remain physically in the WAL file until overwritten by subsequent checkpoints.


## 2. Citations & Academic References
- Owens, M., & Allen, G. (2010). The Definitive Guide to SQLite. Apress.
- SANS Digital Forensics (2018). SQLite Forensics: WAL and Rollback Journal Analysis.


## 3. Step-by-Step Walkthrough
1. Inspect `sqlite_wal_audit.json` representing WAL file frames.
2. Filter frames with status `ROLLED_BACK`.
3. Parse the uncommitted SQL `INSERT` statement to recover the sensitive secret.


## 4. Exploit Script & Verification
Execute the automated reference solver:
```bash
python solve.py
```
Output:
```text
[+] Successfully recovered flag: zerosecure{sqlite_wal_rollback_frame_recovered_29cd}
```


## 5. Defense Engineering & Remediation
Execute `PRAGMA wal_checkpoint(TRUNCATE)` upon closing sensitive SQLite databases to zero out stale transaction frames.
