# Solution - Format String Illusion

## Expected Flag
`ZeroSecure_CTF{FORMAT_STRING_ILLUSION}`

## Walkthrough
The log text itself is a decoy. Only capitalization matters.

1. Keep alphabetic characters only (`A-Z` and `a-z`) in original order.
2. Convert each letter into Baconian symbols using this challenge mapping:
	- uppercase -> `A`
	- lowercase -> `B`
3. Group the resulting symbol stream into chunks of 5.
4. Decode each 5-symbol chunk with Baconian mapping (`AAAAA=A`, `AAAAB=B`, ...).

The extracted stream has 110 symbols, so:

```
110 / 5 = 22 letters
```

Decoded plaintext:

```
FORMATXSTRINGXILLUSION
```

In this challenge, `X` is used as a separator, so convert it to `_`:

```
FORMAT_STRING_ILLUSION
```

Final flag:

```
ZeroSecure_CTF{FORMAT_STRING_ILLUSION}
```

## Example One-Liner (Python)

```python
from pathlib import Path
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
text = Path("challenge.txt").read_text(encoding="utf-8")
letters = [c for c in text if c.isalpha()]
ab = "".join("A" if c.isupper() else "B" for c in letters)
msg = "".join(alphabet[int(ab[i:i+5].replace("A", "0").replace("B", "1"), 2)] for i in range(0, len(ab), 5))
print(f"ZeroSecure_CTF{{{msg.replace('X', '_')}}}")
```
