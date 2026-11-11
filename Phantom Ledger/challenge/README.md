# PHANTOM LEDGER
**CTF Challenge — Cryptography**
Flag format: `FLAG{...}`

---

Three nights ago, Meridian Capital went into emergency lockdown.
The kind that doesn't make the news.

Someone on their analytics desk had been walking out with
encrypted transmissions every night at 02:00 UTC. Not bulk
data — just short, tight packages. The kind that looks like
heartbeat traffic if you're not paying attention.

Their security team noticed on March 21st. By then it was
too late. The analyst — they only ever used the name GHOST —
was already gone.

We pulled three nights of traffic off the relay node before
Meridian wiped it. We also recovered a copy of the relay
software and a diagnostic log extract from a February test run.

Something in that code is wrong.
Their own cryptographer signed off on it.
The last transmission GHOST sent is in there somewhere.

---

## Files

| File | Description |
|------|-------------|
| `night0.bin` | 2024-03-19 02:00 UTC — old relay instance |
| `night1.bin` | 2024-03-20 02:00 UTC — new relay, first night |
| `night2.bin` | 2024-03-21 02:00 UTC — last transmission (GHOST's final message) |
| `server.py` | Recovered from relay-03 backup archive |
| `relay_diagnostic.txt` | Fragment from relay-03 diagnostic log, February 2024 |

---

## What We Know

A fragment recovered from an unencrypted probe packet sent
during a relay test in February:

    b"PHANTOM-LEDGER // GHOST // "

Every transmission begins with this string.

Infrastructure notes from the recovered backup:

- The relay node reboots automatically at 01:55 UTC nightly
- AES key rotates daily through the HSM — each night is
  a fresh key, provisioned at reboot
- On the night of March 21st, the relay **crashed mid-session
  and rebooted a second time** before the 02:00 window opened
- The old relay instance (night0) was decommissioned after
  March 19th. A new instance took over on March 20th.

---

## Setup

```bash
pip install cryptography
```

Load a capture:
```python
data = open('night1.bin', 'rb').read()
```

---

*"The encryption was fine. The implementation wasn't."*
— anonymous tip, March 22
