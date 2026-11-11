# WARD 7
**CTF Challenge — Cryptography**
Flag format: `FLAG{...}`

---

In November 2003, the IT department of Klinik Svratka began
migrating their legacy relay systems to new infrastructure.
During the cleanup, a contractor named Novak found something
in the backup archives he was not supposed to find.

He did not report it through official channels.

He sent a copy to a journalist he had met once at a bar in
Brno. Then he stopped answering his phone. His apartment was
empty when his landlord checked three weeks later.

What Novak found was a keystore export and one encrypted
transmission from March 2003. The transmission was sent late
at night. Both senior administrators had authorisation keys
on the system. The IT setup was built by an external contractor
the previous January — same person, same week, both keys.

The journalist held onto the files for twenty years.
She never published anything. She said she could not open them.

You have the files now.

---

## Files

| File | Description |
|------|-------------|
| `keystore.txt` | Recovered config export from relay-admin-01 (contains public keys and encrypted transmissions) |
| `journalists_notes.txt` | Notes recovered from the journalist's personal archive |

---

## What We Know

The journalist's notes included one line she had written to
herself after speaking with Novak:

> "He said the contractor cut every corner. Both keys,
>  same week, same machine. Nobody checked."

She also wrote:

> "The case number is the only thing that survived
>  outside the system."

---

*"Some things stay buried not because they are well hidden.*
*Because nobody looked."*

---

## Setup

```bash
# Only standard Python required — no pip install needed
python --version   # Python 3.6+ sufficient
```

---

## Notes for Contestants

- The case number referenced in the recovered document is significant
- When you recover the document, read it carefully — it describes its own encoding

