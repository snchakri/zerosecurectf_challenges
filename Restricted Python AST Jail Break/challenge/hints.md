# Staged Hint Ladder: Restricted-AST Python Jail

### Hint Level 1 (Orientation)
Read `jail.py` carefully. It rejects your input on two grounds: a character
blacklist (no `_ . ' " [ ] { }`, no backslash/semicolon, a few banned words) and
an AST whitelist (only calls, names, integer literals, arithmetic operators and
generator expressions -- Attribute, Subscript and string/bytes literals are
rejected). It exposes a small set of safe names plus `data`, `S`, `T`.

### Hint Level 2 (Reframe)
`data` is the flag masked with a keystream `ks[i] = (S + i*T) % 256`. Rebuilding
the flag *bytes* is easy and legal: a generator expression
`(c ^ ((S + i*T) % 256) for i, c in enumerate(data))` uses no banned character.
Wrap it in `bytes(...)`. The hard part is turning those bytes into text when you
cannot type a dot, a quote, or a bracket.

### Hint Level 3 (Strong Nudge)
You cannot write `.decode()` -- `.` is banned -- and you cannot write the string
`"decode"` -- quotes are banned. But `getattr(obj, name)` reaches an attribute
without a dot, and `name` can be assembled from integers:
`chr(100)+chr(101)+chr(99)+chr(111)+chr(100)+chr(101)`. Compose
`getattr(bytes(...), <that>)()`. (Equivalently: the jail prints a bytes/bytearray
result decoded, so returning the bytes works too.)

---
*Note: Crux Floor invariant: the dot/quote-bypass technique is named, but the
exact winning expression is left for the solver to assemble.*
