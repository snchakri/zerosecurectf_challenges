# Challenge: DNS Zone Transfer (AXFR) Record Audit (misc_08_dns_zone_transfer_axfr_file)

**Category:** Miscellaneous  
**Difficulty:** Medium  
**Format:** `zerosecurectf{...}`  
**North Star:** Authentic Tradecraft & Systems / Scripting / AI Reality  

---

## Scenario & Objective
An misconfigured authoritative DNS nameserver allowed unauthenticated AXFR zone transfers (`dig @ns AXFR corp.zerosecure.internal`). Analyze the dumped zone file records (TXT, LOC, SRV) for sensitive configuration entries.

## Provided Files
- `zone_transfer_axfr.txt`
- `solve.py`: Automated solver and verification reference.

## Compliance
- Universal Format asserted: `zerosecurectf{...}`
- Zero unreasoned guessiness.
