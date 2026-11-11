# ENTROPY GRAVE
**CTF Challenge — Cryptography / Forensics**
Flag format: `flag{...}`

---

Operation CARTOGRAPHER closed three weeks ago.
The subject — a data broker operating between two intelligence networks —
was apprehended during a scheduled dead-drop.

A field team secured the laptop before the wipe completed.
Lucky.

The device ran a lightweight key management system.
It generated an RSA-1024 key pair and encrypted a report
seconds before the arrest team entered.
The report is believed to contain source identities tied
to active operations.

But something in the device log raises a question.
Something about entropy.

---

## Files

| File | Description |
|------|-------------|
| `evidence.img` | Raw DD image of primary drive (partial wipe confirmed) |

---

## Notes

This is a disk image, not a mounted filesystem.
Standard forensic tools work on it.
Internet access is permitted.

```bash
file evidence.img
```

No special setup required.

---

*"The wipe didn't finish. Neither did the encryption."*
— triage note, CARTOGRAPHER case file
