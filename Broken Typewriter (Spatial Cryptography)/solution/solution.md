# Solution - Broken Typewriter

## Expected Flag
`ZeroSecure_CTF{KEYBOARD_SHIFT_RIGHT}`

## Walkthrough
Input ciphertext (`challenge.txt`):

```
XrtpDrvitr_VYG{LRUNPSTF_DJOGY_TOHJY}
```

The rule is keyboard-based, not alphabetical:
- Each original letter was typed one key to the right on QWERTY.
- So for decryption, move each letter one key to the left.
- Keep non-letter characters unchanged.

Examples:
- `X -> Z`
- `r -> e`
- `t -> r`
- `p -> o`
- `L -> K`

Applying this to the whole ciphertext gives:

```
ZeroSecure_CTF{KEYBOARD_SHIFT_RIGHT}
```

## Example One-Liner (Python)

```python
left = dict(zip("wertyuiopsdfghjklxcvbnm", "qwertyuioasdfghjkzxcvbn"))
s = "XrtpDrvitr_VYG{LRUNPSTF_DJOGY_TOHJY}"
out = []
for ch in s:
	low = ch.lower()
	if low in left:
		plain = left[low]
		out.append(plain.upper() if ch.isupper() else plain)
	else:
		out.append(ch)
print("".join(out))
```
