# Barbican

**Category:** Web Exploitation

A two-tier web app puts a public edge gateway in front of an internal upstream; the edge refuses the privileged /admin path (403) but frames request bodies by Content-Length while the upstream honours a chunked Transfer-Encoding, so a single CL/TE-desynced request is one allowed request to the edge and two requests to the upstream — the smuggled second being GET /admin, whose response is queued on the edge's shared keep-alive upstream connection and delivered to the attacker's next benign request, yielding the flag.

**Connect:** `http://<challenge-host>:30062`

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.
