# DNS Zone Transfer

**Category:** Miscellaneous

An misconfigured authoritative DNS nameserver allowed unauthenticated AXFR zone transfers (`dig @ns AXFR corp.zerosecure.internal`). Analyze the dumped zone file records (TXT, LOC, SRV) for sensitive configuration entries.

**Download the attached file** and recover the flag.
