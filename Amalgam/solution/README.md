# Amalgam — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

In one terminal, run the local challenge service:

```bash
node solution/runtime/app.js
```

In another terminal, run the solver:

```bash
python solution/solve.py --url http://127.0.0.1:8000
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Amalgam — official writeup

**Flag:** `zerosecurectf{pr0t0_p0lluti0n_inherits_the_cr0wn}` (static demo seed; per-instance in production)


## The flaw

Amalgam deep-merges a user's JSON preference patch into a stored profile:

```js
function deepMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__') continue;      // <<< THE GUARD >>> blocks exactly one key
    const sVal = source[key];
    const tVal = target[key];
    if (isMergeable(sVal) && isMergeable(tVal)) {
      deepMerge(tVal, sVal);                 // descend into the EXISTING child
    } else {
      target[key] = sVal;
    }
  }
  return target;
}
```

This is the textbook vulnerable recursive merge — with one realistic twist. A
prior pentest flagged it for **prototype pollution (CWE-1321)**, and the fix
that shipped is the one real teams ship under pressure: *skip the one key the
report named.* The block names exactly `"__proto__"`, and nothing else.

Two facts defeat that block:

1. `JSON.parse('{"__proto__": …}')` creates `__proto__` as an ordinary **own,
   enumerable** property (unlike an object literal, where `__proto__:` sets the
   prototype). So the guard's `key === '__proto__'` does see — and skip — that
   key. Good... but it is not the only route to `Object.prototype`.
2. Every object also inherits `constructor`, and `Object.prototype.constructor`
   is the `Object` function, whose `.prototype` **is** `Object.prototype`. The
   merge recurses into whatever mergeable value already lives at a key
   (`isMergeable` is true for functions too), so it will walk
   `target.constructor` → `.prototype` and write straight onto the shared
   prototype.


## The exploit (intended path)

The admin gate reads a **fresh** object, never a stored preference:

```js
function authorize() {
  const policy = {};                                   // no own isAdmin / clearance
  return policy.isAdmin === true && policy.clearance === REQUIRED_CLEARANCE;
}
```

For a guest both reads are `undefined`. But if `Object.prototype` carries those
keys, every fresh object inherits them — including this one. So:

1. **Read the per-instance clearance code** (public):

   ```
   GET /whoami  ->  { "fingerprint": "...", "required_clearance": "clr_xxxxxxxxxxxx", ... }
   ```

2. **Pollute** `Object.prototype` via the `constructor.prototype` vector that
   the `__proto__` block does not cover:

   ```
   POST /api/preferences
   Content-Type: application/json

   {"constructor":{"prototype":{"isAdmin":true,"clearance":"clr_xxxxxxxxxxxx"}}}
   ```

   The merge walks `prefs.constructor` (the `Object` function) → `.prototype`
   (`Object.prototype`) and sets `isAdmin = true` and `clearance = "clr_…"` on
   it. (Optional confirmation: `GET /api/me` now reports `"authorized": true`.)

3. **Open the admin console and extract the flag byte-by-byte.** A fresh policy
   object now inherits both properties, so the console authorizes — but it does
   **not** return the flag whole. It is a per-byte export stream (see
   *Flag extraction* below). The reference solver `solution/solve.py` drives the
   full extraction with the Python standard library.

The crux is three requests (whoami → pollute → authorized manifest); the
extraction then adds one pollute+read round-trip per flag byte.


## Flag extraction 

This challenge satisfies the organizer hardening directive **S2 / S2a**: solving
the prototype-pollution crux earns you the *means* to extract the flag, not the
flag itself. The flag is **never returned whole in any single response.**

**Mechanism — "inherited-cursor keystream export" (bespoke to this challenge).**
The admin console (`GET /api/flag`) is not a bulk reveal; it is a per-byte export
stream driven by the *same* prototype-pollution primitive that opens the gate:

1. The first authorized `GET /api/flag` returns only a **manifest** (no flag
   bytes): the keystream root key `stream_key` (seed-derived, 128-bit, disclosed
   *only* behind the gate), the flag `length`, a verification `digest =
   SHA-256(flag)[:16]`, and an inert decoy `cache_preview`.
2. Which byte you get is a per-request **export offset**, and the console reads
   `exportOffset` off a **fresh object** — exactly like it reads `isAdmin` /
   `clearance`. A fresh object has no own `exportOffset`, so the only way to
   carry one in is for it to live on `Object.prototype`. **Advancing the cursor
   one byte at a time therefore re-uses the prototype pollution for every byte**
   — the extraction channel *is* the crux primitive, applied N times.
3. Each valid offset returns exactly one masked byte:
   `mask = flag[offset] XOR keystream(offset)`, where
   `keystream(offset) = SHA-256(stream_key | "|" | offset)[0]`.
4. Reassemble all offsets, XOR out the keystream, and **verify**
   `SHA-256(flag)[:16] == digest`. The digest is the verifiable gate that makes
   every wrong reassembly (off-by-one, decoy, forgotten XOR) rejectable by
   reasoning — **guess-exposure 0**.

Why this fits the domain: the cursor-on-the-prototype makes the *extraction* a
second, self-similar instance of the very bug being taught, rather than a bolted-
on side channel. The keystream binding is the S2 "floor" — it keeps the flag off
the wire in cleartext and keeps `stream_key` behind the gate — while the per-byte
cursor supplies the graded, incremental channel on top.

**Honest difficulty note.** The crux band is unchanged (**Hard**). The extraction
is mechanical *once you are admin* (iterate offsets, XOR, verify), so it does not
raise the band on its own; its purpose is to satisfy S2 (no bulk reveal; flag
never whole in one response) and to reinforce the lesson by making the solver
wield the pollution primitive per byte. It is not claimed to add cryptographic
secrecy against someone who has already solved the crux.

**Reference-solver / test evidence.**
reconstructs exactly `ZSCTF_FLAG`; the reconstruction matches the manifest digest
and length; the flag appears whole in **no** single response (manifest, every
masked-byte body, `/`, `/whoami`, `/api/me`); the decoy `cache_preview` is a
format-invalid near-flag; and concatenating the raw masked bytes (forgetting the
XOR) is neither the flag nor format-valid. Determinism checks additionally assert
same-seed → same `stream_key` + `digest`, different-seed → different `stream_key`.


## Rabbit-holes 

Each trap is rejectable by reasoning from information present in the challenge
(guess-exposure 0); it costs the *careless* time only.

| Trap | Where | The reasoning-based tell that rejects it |
|---|---|---|
| **Decoy preview flag** (`cache_preview`, e.g. `zerosecurectf{STREAM_<FP>}`) | export manifest | Fails the *published* strict validator `^zerosecurectf\{[a-z0-9_]{8,48}\}$` on sight (UPPERCASE body); also fails the manifest `digest`. Seed-varying (uses the instance fingerprint), so it does not transfer between teams (R1/R5). |
| **"The flag is right there" on first `/api/flag`** | manifest | The first authorized response is a manifest carrying `stream:true`, a `length` and a `digest` but **zero flag bytes** — the shape itself says "stream, not reveal" (R2). |
| **Forgetting the keystream XOR** | per-byte reassembly | Concatenating the raw `mask` bytes yields non-ASCII junk that fails the strict validator and the `digest`; the manifest `note` states `mask = flag[offset] XOR keystream(offset)` (R2/R3). |
| **Type-confusing the offset** (array / string / out-of-range `exportOffset` hoping to dump many bytes) | export stream | The console validates `Number.isInteger(offset) && 0 <= offset < length`; anything else falls back to the bytes-free manifest. Verified by probe — no multi-byte dump is reachable (R4). |
| **Off-by-one / wrong byte order** | reassembly | Each byte response echoes its own `offset`, and the final `digest` check catches any mis-ordered or short reassembly (R2). |


## Why the intended path is the only one


- **You cannot flip the flag with a stored preference.** The gate reads a fresh
  `policy = {}`, not your profile. Saving `{"isAdmin":true,"clearance":"…"}` as
  ordinary keys sets them *on your profile object*, which the gate never looks
  at → still denied. (check 6)
- **`__proto__` is closed.** The patch `{"__proto__":{"isAdmin":true,…}}` is
  skipped by the guard at every recursion level, so it never reaches the
  prototype → still denied. The `constructor.prototype` vector is the *only*
  surviving route to `Object.prototype`. (check 5)
- **Benign use never escalates.** Ordinary nested patches (`theme`, `layout`,
  `notifications`, …) merge normally and grant nothing. (check 4)
- **The per-instance clearance is load-bearing.** Polluting `isAdmin` alone, or
  with the wrong clearance string, is still denied — you must read *this*
  instance's `required_clearance` and inject it, so a payload copied from
  another team's instance fails. (check 8)
- **No shortcut leak.** The flag is only ever returned by the gated endpoint; it
  is not in the HTML, not in `/whoami`, and lives only in the process
  environment (never on disk or in an image layer). (check 7)
- **Egress is blocked in deployment**, so there is no "exfiltrate the flag to my
  server" alternative; the win must happen in-process, which the intended path
  does.


## Unintended paths considered and closed

| Candidate shortcut | Closed by | Test |
|---|---|---|
| Save `isAdmin`/`clearance` as ordinary prefs and have the gate read them | Gate reads a fresh `{}`, never the profile | check 6 |
| Classic `{"__proto__":{…}}` payload | `key === '__proto__'` blocklist at every level | check 5 |
| Nested `{"x":{"__proto__":{…}}}` | Same blocklist runs inside the recursion; and a never-before-seen key is assigned, not recursed | probe + check 5 |
| Pollute `isAdmin` only (skip clearance) / wrong clearance | Gate requires the exact per-instance clearance code | check 8 |
| Replay another instance's payload | Clearance code is seed-derived and differs per instance | check 10 |
| Read the flag from HTML / `/whoami` / disk | Flag only in env, only returned (masked, per-byte) by the gated endpoint | check 7 |
| Grab the whole flag from one `/api/flag` response | Console is a per-byte export stream; manifest has 0 bytes, each byte body has 1 masked byte | check 9c |
| Dump many bytes via a crafted `exportOffset` (array/string/OOB) | Strict `Number.isInteger && 0<=offset<length`; else bytes-free manifest | probe + check 9 |
| Treat a masked byte / the decoy preview as the flag | Fails the strict validator and the manifest `digest` | checks 9d/9e |
| Route confusion from a polluted prototype (`routes["isAdmin"]`) | Routing is explicit path comparison; response payloads use own-key / null-proto objects | code review + probe |
| Exfiltrate the flag to an attacker host | `internal: true` network blocks all egress | compose config |


## Design notes (for the ZSCTF team)

- **Lineage:** web corpus seeds `zsctf-web-014 NoteNinja` (a hardened app where
  the *intended* client/server path must be found and the known unintended route
  is closed before reuse) and `zsctf-web-003 Security Driven` (chain user input
  into disclosure of an admin-only secret). Operators: `GROUND` (a real
  workspace-preferences deep-merge product + the real "fix the one key the
  pentest named" story) → `GUARD-SWAP` (replace "no guard" with a realistic but
  incomplete `__proto__` blocklist — the real mitigation teams actually ship) →
  `PARAMETERISE` (expose the clearance code as a per-instance knob). See
  `corpus-genome.yaml` and `system.html` §17.3.
- **CWEs / references:** CWE-1321 (Improperly Controlled Modification of Object
  Prototype Attributes — "Prototype Pollution"); CWE-915 (Improperly Controlled
  Modification of Dynamically-Determined Object Attributes); OWASP A01:2021
  Broken Access Control. The `constructor.prototype` bypass of a `__proto__`
  blocklist is documented by PortSwigger (Web Security Academy, "Prototype
  pollution") and by Olivier Arteau's original research ("Prototype pollution
  attack in NodeJS application", NorthSec 2018).
- **AI note (system.html §9):** on fixed/known parameters an agent solves from
  memory; the per-instance clearance is what forces a genuine runtime read
  rather than pure template recall.
