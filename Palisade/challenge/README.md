# Palisade

**Category:** Web Exploitation

A "link safety inspector" fetches URLs on your behalf behind an SSRF guard that blocks every internal address; the guard and the fetcher parse the URL host differently, so a userinfo trick folds the request back to loopback and into an egress-isolated internal vault that holds the flag.

**Connect:** `http://<challenge-host>:30064`

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.
