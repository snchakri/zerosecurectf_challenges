# Staged Hint Ladder: Systemd Journal Transient Service Triage

### Hint Level 1
Systemd journal binary logs store structured key-value fields per event.

### Hint Level 2
Fields prefixed with an underscore (`_`) are trusted attributes populated directly by the journald daemon from the kernel.

### Hint Level 3
Inspect custom environment exports captured within the service execution frame.

---
*Note: Crux Floor invariant: The core systems / analytical insight is never handed out completely; each hint restores a reasoning handle.*
