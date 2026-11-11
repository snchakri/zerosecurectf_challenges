# Challenge: Systemd Journal Transient Service Triage (misc_06_systemd_journal_slice_forensics)

**Category:** Miscellaneous  
**Difficulty:** Medium  
**Format:** `zerosecurectf{...}`  
**North Star:** Authentic Tradecraft & Systems / Scripting / AI Reality  

---

## Scenario & Objective
A volatile transient systemd service (`systemd-run`) was spawned on a Linux production node and terminated within 3 seconds. Parse the binary systemd journal metadata and cgroup environment fields to extract the executed command parameters.

## Provided Files
- `journal_slice.json`
- `solve.py`: Automated solver and verification reference.

## Compliance
- Universal Format asserted: `zerosecurectf{...}`
- Zero unreasoned guessiness.
