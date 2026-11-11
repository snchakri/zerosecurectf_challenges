# Broadsheet

**Category:** Web Exploitation

A newsletter studio renders editor-supplied template snippets for a "preview" (textbook SSTI) behind two real mitigations — a template sandbox and a substring content filter — but the sandbox only blocks code execution (not reading data the app itself put in the render context) and the filter is a raw-substring deny-list, so reassembling a blocked name at evaluation time reads an in-app secret bag that holds the flag.

**Connect:** `http://<challenge-host>:30063`

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.
