# Challenge: Encrypted Tunnel Inspection (TLS Key Log) (forensics_03_tls_session_ticket_pcap)

**Category:** Forensics  
**Difficulty:** Medium  
**Format:** `zerosecurectf{...}`  
**North Star:** Authentic Tradecraft & Realistic Forensic Artifacts  

---

## Scenario & Objective
Incident responders captured encrypted TLS 1.3 traffic between an insider workstation and an external C2 server. Concurrently, a triage script retrieved an `sslkeylog.txt` file from the client process memory.

## Provided Files
- `sslkeylog.txt`
- `decrypted_http2_frame.txt`
- `solve.py`: Automated solver and verification reference.

## Compliance
- Universal Format asserted: `zerosecurectf{...}`
- Zero unreasoned guessiness.
