# Helios Relay

**Category:** Binary Exploitation

A solar-array telemetry relay renders an operator-supplied label template through the C line formatter; abuse the format string to drive a four-byte %hhn write into the control-plane authorisation word and unlock the flag.

**Download the attached binary** (the exact build running on the server).

 `nc <challenge-host> 30050`

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.
