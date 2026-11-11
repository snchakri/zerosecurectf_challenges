# Warden

**Category:** Binary Exploitation

A toy "license warden" daemon reads a license key into a fixed-size on-stack field without a bounds check. Overflow it to overwrite the saved return address and redirect control to the unreachable grant() routine, which discloses the flag. Classic ret2win on a -no-pie binary.

**Connect:** `nc <challenge-host> 30052`

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.
