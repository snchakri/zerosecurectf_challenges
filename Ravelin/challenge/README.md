# Ravelin

**Category:** Web Exploitation

A small internal incident portal with three layers of trust. No single bug suffices: an IDOR on /api/snapshot leaks the session-signing key; forging the HMAC-signed rav_session cookie with it escalates to role=auditor and yields the vault query-signing key; and a mass-assignment / unsafe-deserialisation bug in the SavedQuery render path lets a forged blob inject a `target` attribute the UI never sets, reading the internal vault that holds the flag. Each stage is load-bearing and gated in sequence.

**Connect:** `http://<challenge-host>:30068`

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.
