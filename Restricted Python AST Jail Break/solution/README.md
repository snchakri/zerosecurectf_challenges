# Restricted Python AST Jail Break — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Restricted-AST Python Jail


## 1. Artifact and why it is offline-fair
`dist/jail.py` reads one expression from stdin and evaluates it only if it passes
BOTH a source blacklist (no `_ . ' " [ ] { }`, no backslash/semicolon, no
`import/eval/exec/compile/open/system/global/builtin`) and an AST whitelist
(only `Call`, `Name`, integer `Constant`, `BinOp` over `^ + - * %`,
`GeneratorExp`/`comprehension`, `Tuple`). `Attribute`, `Subscript` and
string/bytes literals are rejected. Evaluation runs with `__builtins__ = {}` and
a tiny exposed scope.

A classic pyjail reads a flag from a live server. To make this a genuinely
offline, self-contained challenge with a *recoverable* flag, the flag is
embedded in the jail in **encoded** form -- `data[i] = flag[i] ^ ((S + i*T) %
256)` -- so it never appears as plaintext, and it is turned back into text only
by a rules-compliant payload that the shipped jail executes. No network, no
external flag file.


## 2. The restrictions and the escape
- Rebuilding the flag bytes is legal: a generator expression
  `(c ^ ((S + i*T) % 256) for i, c in enumerate(data))` uses only allowed nodes
  and no banned characters, and `bytes(...)` turns it into a bytes object.
- Converting bytes to text is the puzzle: `.decode()` needs a dot (banned) and
  `"decode"` needs quotes (banned). The classic bypass:
  - reach the attribute without a dot: `getattr(obj, name)`;
  - build the method name without quotes: `chr(100)+chr(101)+chr(99)+chr(111)+chr(100)+chr(101)` == "decode".

Intended payload (one line, no `_ . ' " [ ] { }`):

```
getattr(bytes(c ^ ((S + i*T) % 256) for i,c in enumerate(data)), chr(100)+chr(101)+chr(99)+chr(111)+chr(100)+chr(101))()
```

The jail parses it (all nodes whitelisted), evaluates it, and prints the flag.
(The jail also decodes a bytes/bytearray result, so simply returning
`bytes(...)` is an accepted alternative.)


## 3. Solver
`solve.py --dist ./dist` constructs exactly that payload, launches the shipped
`dist/jail.py` with it on stdin, and prints the jail's output:

```
python solve.py --dist ./dist
zerosecure{pyjail_subclasses_builtin_traversal_78ac}
```

The solver contains no flag string and never reads `./flag`; it recovers the
flag only by making the jail execute an in-rules payload against the encoded
`data` shipped inside the jail.


## 4. What is rejected (teeth)
The build's self-check confirms that the naive `bytes(...).decode()` (contains
`.`) and `getattr(data, 'decode')()` (contains a string literal) are both
rejected, so the escape genuinely requires the getattr+chr technique.


## 5. Defensive note
Never rely on AST/string filtering for isolation. `getattr`+`chr` reconstructs
any attribute access the filter tried to ban. Run untrusted code in a real
sandbox (separate process with seccomp, a container, gVisor, or WebAssembly).
