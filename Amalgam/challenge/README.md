# Amalgam

**Category:** Web Exploitation

A workspace "preferences" service deep-merges a JSON patch into your profile; the merge was hardened against prototype pollution by blocklisting only the "__proto__" key, so the constructor.prototype vector still pollutes Object.prototype and flips the isAdmin/clearance the admin gate reads off a fresh object. The admin console then never reveals the flag whole: it is a per-byte export stream whose cursor is ALSO read off a fresh object, so each byte is extracted by re-using the same pollution, masked by a seed-derived keystream and verifiable against a published digest.

**Connect:** `http://<challenge-host>:30061`

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.
