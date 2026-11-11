# SSRF to Nowhere

**Category:** Web Exploitation

The bunker's monitoring console can still "preview" a sensor feed by URL.
There's also an admin panel. It only talks to localhost.
Deploy on Linux. The intended bypass relies on Linux treating a connection to
`0.0.0.0` as loopback (Windows rejects it), so solve against the container,
not a bare Windows host.

**Connect:** `http://<challenge-host>:30070`

**Download the attached file** (source, for reference).

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.
