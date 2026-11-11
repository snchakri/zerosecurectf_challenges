# Flotsam

**Category:** Digital Forensics

A benign plain-HTTP file download, captured out of order with a retransmission and a decoy flow. Reassemble the server's TCP stream by sequence number, strip the HTTP headers, parse the ZIP body and inflate the entry (CRC-32 gated) to read the flag — ordinary protocol analysis, not guessing.

**Download the attached file** and recover the flag.
