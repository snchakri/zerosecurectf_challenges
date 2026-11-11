# NULL STREAM
**CTF Challenge — Cryptography / Reverse Engineering**
Flag format: `flag{...}`

---

During last Tuesday's coordinated seizure of a Static Brotherhood
workstation, the operator was mid-process when the arrest team made entry.
Two files survived before the wipe completed.

The first is a stripped binary. No symbols. No version info.
No library signatures. Whatever it does, they built it themselves.

The second is `transmission.null`. Open it.
There is no readable structure. No headers you'll recognise.
No metadata. Just static.

Intel says the file matters. We can't afford to leave it unread.

---

## Files

| File | Description |
|------|-------------|
| `encode` | Executable recovered from operator workstation (x86-64 Linux) |
| `transmission.null` | Recovered output file, source unknown |

---

## Notes

The binary runs on Linux. If you are on Windows, use WSL or a VM.

```bash
chmod +x encode
./encode
```

No network connection required.

---

*"They built everything themselves. That's usually where the cracks are."*
— field analyst note, 14 NOV 2024
