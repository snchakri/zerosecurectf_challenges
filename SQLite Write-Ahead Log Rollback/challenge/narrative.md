# Challenge: SQLite Write-Ahead Log Rollback (forensics_11_sqlite_wal_journal_rollback)

**Category:** Forensics  
**Difficulty:** Medium  
**Format:** `zerosecurectf{...}`  
**North Star:** Authentic Tradecraft & Realistic Forensic Artifacts  

---

## Scenario & Objective
A banking app stores user sessions in a SQLite database configured in WAL (Write-Ahead Logging) mode. A confidential transaction was initiated but aborted prior to checkpointing. Reconstruct the aborted frame from the `-wal` file.

## Provided Files
- `sqlite_wal_audit.json`
- `solve.py`: Automated solver and verification reference.

## Compliance
- Universal Format asserted: `zerosecurectf{...}`
- Zero unreasoned guessiness.
