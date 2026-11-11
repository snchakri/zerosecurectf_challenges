# Solution - Format String Illusion Reimplemented

## Expected Flag
`ZeroSecure_CTF{CASE_CHANNEL_BACON}`

## Walkthrough
Only alphabetic character case carries the signal.

1. Keep letters only (`A-Z`, `a-z`) in original order.
2. Convert case into Baconian symbols:
   - uppercase -> `A`
   - lowercase -> `B`
3. Split stream into groups of 5.
4. Decode each 5-symbol group with Baconian mapping (`AAAAA=A`, `AAAAB=B`, ...).

The extracted stream length is 90 symbols:

```
90 / 5 = 18 letters
```

First 10 groups:

```
AAABA AAAAA BAABA AABAA BABBB AAABA AABBB AAAAA ABBAB ABBAB
```

Decoded plaintext:

```
CASEXCHANNELXBACON
```

In this challenge, `X` is a separator. Convert `X` -> `_`:

```
CASE_CHANNEL_BACON
```

Final flag:

```
ZeroSecure_CTF{CASE_CHANNEL_BACON}
```

## Example One-Liner (Python)

```python
from pathlib import Path
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
text = Path("challenge.txt").read_text(encoding="utf-8")
ab = "".join("A" if c.isupper() else "B" for c in text if c.isalpha())
msg = "".join(alphabet[int(ab[i:i+5].replace("A", "0").replace("B", "1"), 2)] for i in range(0, len(ab), 5))
print(f"ZeroSecure_CTF{{{msg.replace('X', '_')}}}")
```
