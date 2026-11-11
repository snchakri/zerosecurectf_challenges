# Staged Hint Ladder: PowerShell Script Block Logging (Event 4104)

### Hint Level 1
Windows Event ID 4104 captures the complete un-obfuscated script block code executed by the PowerShell engine.

### Hint Level 2
Attackers often execute complex one-liners; the event log records the de-obfuscated code buffer.

### Hint Level 3
Extract the parameter variables defined within the script block payload.

---
*Note: Crux Floor invariant: The core forensic recovery technique is never handed out completely; each hint restores a reasoning handle.*
