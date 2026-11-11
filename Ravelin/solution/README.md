# Ravelin — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

In one terminal, run the local challenge service:

```bash
python solution/runtime/app.py
```

In another terminal, run the solver:

```bash
python solution/solve.py --url http://127.0.0.1:8000
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Ravelin — Organizer Write-up

**Category:** web · **Band:** Extreme · **Flag:** `zerosecurectf{...}` from `ZSCTF_FLAG`


## One-line crux

Three independent, standard web bugs stacked so each one only unlocks the input
to the next: an **IDOR** leaks the session key; forging a **signed cookie** with
that key escalates to `auditor` and yields the vault query key; and a
**mass-assignment / unsafe-deserialisation** bug in the SavedQuery render path
lets a forged blob inject a `target` attribute that reads the internal vault.
Remove any one stage and the chain dead-ends at a `403`, a `guest` role, or
benign rows.


## Why this is banded Extreme (honest assessment)

Extreme is claimed on the basis that the flag is **unreachable without all three
stages performed in sequence**, and the test proves each is load-bearing:

- **Stage gating is real, not cosmetic.** Stage 2 needs the exact 64-hex key
  leaked in stage 1 (the HMAC gate rejects anything else — asserted). Stage 3
  needs the vault key that is *only* disclosed at `/auditor/config`, which is
  `403` to a guest and only reachable with the forged auditor cookie from stage
  2 (asserted). Stage 3's privileged read needs the injected `target` field that
  the legitimate query builder strips, so an auditor who never performs the
  object-injection gets only benign rows (asserted).
- **Three distinct primitives / CWEs**, not one bug three times: CWE-639 (IDOR),
  CWE-347 + CWE-285 (signature trust → broken access control), CWE-915 + CWE-502
  (mass assignment / unsafe deserialisation).
- **Each stage requires reasoning, not recognition.** The signing scheme is a
  bespoke `b64url(json).hmac` (not a labelled JWT), so stage 2 is not a one-shot
  `alg:none`/`jwt_tool` pattern-match; the deserialisation is attribute
  injection via `__dict__.update`, which the player must spot in source and tie
  to the `target`-only vault path.

**Where it could be argued down to Hard:** it is a **white-box** challenge, so a
strong reviewer reading `app.py` can see all three defects quickly; the
difficulty is in *composing* them and in not being derailed by the decoys,
rather than in discovering a hidden primitive. If a scoreboard treats white-box
composition chains as Hard, Ravelin sits at the **Hard/Extreme boundary**; we
band it Extreme because the mandatory "no single bug suffices, all stages
load-bearing and gated in sequence" property is genuinely met and enforced by
the test. We do not claim resistance the traps do not provide (see below).


## Full chain (organizer walkthrough)

### Stage 1 — IDOR (CWE-639): leak the session-signing key
`GET /api/snapshot/<id>` returns any snapshot with no ownership check. Walking
ids `41xx` turns up two `secret-material` snapshots:
- `4105` — `status: retired`, holds a **decoy** key (see Rabbit-holes R2/R3);
- `4108` — `status: active`, holds the **live** `hmac_key_hex` (64 hex chars) =
  the session-signing key.

### Stage 2 — signed-cookie forgery → auditor (CWE-347 / CWE-285)
The `rav_session` cookie is `b64url(json) + "." + b64url(HMAC-SHA256(key, b64url(json)))`.
Forge `{"user":"attacker","role":"auditor"}` signed with the stage-1 key. The
server verifies the signature and then **trusts the `role` claim**, so
`/api/whoami` now reports `role: auditor` and the `/auditor/*` area opens.
`GET /auditor/config` legitimately returns the **vault query-signing key** and a
`vault_index` listing each handle with its `source`.

### Stage 3 — mass assignment / unsafe deserialisation (CWE-915 / CWE-502)
A SavedQuery blob is `b64url(json).hmac` signed with the **vault** key. The
render endpoint does:

```python
q = SavedQuery()                 # defaults: name, filter — NO target
fields = payload["fields"]
q.__dict__.update(fields)        # <-- copies EVERY field, including target
...
if getattr(q, "target", None):   # privileged path, only if target was injected
    return render_vault(target)  # 'flag' -> sealed manifest / per-cell opening
```

`POST /auditor/query/new` (the legit builder) only ever emits
`fields = {name, filter}` — it strips any client `target`. So the exploit is to
**forge the blob yourself** with the vault key and inject
`fields = {"name":"x","filter":"","target":"flag"}`. `POST .../query/render`
then reaches the vault — but the `flag` handle is **sealed**: instead of the
flag it returns a **manifest of commitments** (see *Flag extraction* below). The
mass-assignment is still the only way to reach the vault, and is also the
primitive used for every subsequent *opening*.

Reference solver: [`solution/solve.py`](solution/solve.py). It performs all three
stages plus the extraction, proving each (it checks the HMAC gate actually flips
the role, confirms the legit path is benign, confirms `target='flag'` yields a
sealed manifest rather than a flag), derives the opening order, opens every cell
and verifies each fragment against its commitment, and validates the assembled
flag against `^zerosecurectf\{[a-z0-9_]{8,48}\}$`.


## Flag extraction 

**Mechanism — commitment / opening in a key-derived order** (S2/S2a). Reaching
the vault earns you the *means* to extract, not the flag. The `flag` handle is
sealed into `N = 8` commitment cells:

- The flag is split into `N` contiguous fragments `FLAG_CHUNKS[0..7]`
  (concatenating them in index order reproduces the flag).
- `order = _seal_order()` is a **derangement** of `range(8)` — a Fisher-Yates
  shuffle whose byte stream is `SHA256(vault_sign_key | "sealed-cells/v1/order|<ctr>|<j>")`,
  rejection-sampled until it has **no fixed point**. `order[step]` is the cell id
  that must be opened at that step. Cell `c`'s correct step is `SEAL_INV[c]`.
- Each cell publishes a commitment
  `commit[c] = b64url(SHA256( nonce[c] | "|" | FLAG_CHUNKS[SEAL_INV[c]] ))`, where
  `nonce[c] = SHA256(vault_sign_key | "sealed-cells/v1/nonce|" | c)`. The manifest
  (`target='flag'`, no `cell`/`step`) returns **only these hashes** — never the
  fragments. The flag is therefore not present whole in any single response.

**Opening.** Injecting `target='flag'` **plus integer `cell` and `step`** into a
forged SavedQuery opens one cell:

- if `order[step] == cell` → the **real** fragment `FLAG_CHUNKS[step]`;
- otherwise → a **per-step decoy** `DECOY_CHUNKS[step]`.

Opening cell `order[0]` at step 0, `order[1]` at step 1, …, and concatenating the
revealed fragments yields the flag. An auditor verifies each opening against the
published commitment (`b64url(SHA256(nonce[cell] | "|" | fragment)) == commit[cell]`),
which holds **iff** the cell was opened at its correct step.

**Why the naive path fails (R6 footgun).** Because `order` is a derangement,
opening *cell i at step i* (the obvious "open everything in index order") is
wrong at **every** position, so it returns `DECOY_CHUNKS[0..7]`, which
concatenate to a flag-**shaped** near-miss
`zerosecurectf{WRONG_ORDER_<12 hex>}`. Its body is UPPERCASE, so it fails the
strict validator `^zerosecurectf\{[a-z0-9_]{8,48}\}$` on sight — a rejectable
decoy, **guess-exposure 0** (the real order is *computed* from the earned vault
key, never guessed; any wrong opening is caught by the commitment check and any
wrong assembly by the strict format).

Per-instance (**R5**): `order`, every `commit[c]`, and the decoy near-miss all
derive from the vault key (hence `ZSCTF_SEED`), so a leaked walkthrough for one
team does not transfer.


## Rabbit-holes 

All decoys vary per `ZSCTF_SEED` (operator **R5**), have **guess-exposure 0**
(each is rejectable by a verifiable discriminator), and **none opens a shortcut
to the real flag** (scan below).

- **R1 — rejectable decoy flag (operator R1).** Snapshot `4102` ("Archived
  finding", a low id surfaced early) contains a flag-shaped token
  `zer0securectf{ARCHIVED_<10 hex, UPPERCASE>}`. **Tell:** it fails the published
  validator `^zerosecurectf\{[a-z0-9_]{8,48}\}$` twice over — the `zer0` prefix
  (zero, not `o`) and the UPPERCASE body. A careful solver rejects it on sight;
  the solver prints that it ignored it.
- **R2 / R3 — near-miss signing key (operators R2 footgun + R3 representation
  differential).** Snapshot `4105` holds a `secret-material` record that looks
  exactly like the real one but is `status: retired` with a different
  `hmac_key_hex`. **Tell:** forging a cookie with it produces a signature that
  fails the server's HMAC verification — `/api/whoami` stays `guest` and
  `/auditor/config` returns `403`. The gate gives a definite, verifiable
  rejection (verify-before-commit); snapshot `4106`'s runbook also states the
  active key is the one with `status=active`.
- **R4a — inert SSRF-looking endpoint (operator R4).** `/api/healthcheck` accepts
  `url=`/`probe=` parameters that look like an SSRF probe (palisade-style).
  **Tell / proof of inertness:** it performs **no** outbound request — it only
  returns `sha256(probe|fingerprint)[:16]` and the literal note
  `"diagnostic only; no outbound request is performed"`. Reading `app.py`
  confirms there is no socket/urllib call in the handler. Backed by the
  egress-blocked network: even an intended SSRF would have nowhere to go.
- **R4b — QA fixture vault handle (operator R4).** The vault exposes a
  `flag_sample` handle alongside `flag`. **Tell:** `/auditor/config` tags it
  `source: qa-fixture` and its value is watermarked `zerosecurectf{sample_...}`.
  Rendering it is allowed but the result carries `source: qa-fixture`; the
  README's integrity rule says a `sample` fixture is never valid. The solver
  selects the handle whose `source == live-vault`.


## Unintended-path scan (do the decoys open a shortcut? — No)

- **Decoy flag (R1):** a static string in a snapshot; never equals `ZSCTF_FLAG`
  and never passes the validator. No code path treats it as the flag.
- **Near-miss key (R2/R3):** only consumed by HMAC verification, which fails →
  it cannot produce an `auditor` session, so it reaches neither `/auditor/config`
  nor the vault. Dead end by construction.
- **Healthcheck (R4a):** the handler has no network/file/vault access; it cannot
  read `FLAG`, `SESSION_KEY`, or `VAULT_SIGN_KEY`. Asserted that its output
  contains none of them.
- **Fixture handle (R4b):** `VAULT_PLAIN["flag_sample"]` is a distinct constant
  (a plain handle); it can never return the sealed `VAULT_SEALED["flag"]`. The
  mass-assignment path still requires the
  vault key (stage 2), so R4b is not a stage-skip either.
- **No stage bypass:** `/auditor/*` is uniformly gated on `role == auditor`
  (one helper, `_require_auditor`); the only way to that role is a validly
  signed cookie, i.e. stage 1 + stage 2. The vault is only readable through the
  `target` branch of `SavedQuery.render`, i.e. stage 3 — including every
  *opening*, which is itself a `target='flag'`+`cell`+`step` mass-assignment, so
  stage 3 stays load-bearing for the whole extraction. The flag exists only in
  `VAULT_SEALED["flag"]` (process memory), never in a snapshot, the landing
  page, `/api/whoami`, the manifest (hashes only), or any single opening
- **`?include=` on `/api/snapshot`:** accepted and ignored (inert); no snapshot
  gains extra fields from it.

### Does the sealed layer open a shortcut? — No

- **Flag never whole:** the manifest carries only `commit[c]` hashes; each
  opening returns exactly one fragment. No single response contains the flag
  (asserted). Reassembly happens client-side.
- **Commitments are not grindable:** `commit[c] = SHA256(nonce[c] | frag)` and a
  fragment is short, but `nonce[c]` is a 256-bit preimage-resistant value; you
  cannot recover `frag` from `commit[c]` without already knowing it. The
  commitment confirms an opening; it does not leak one.
- **Order is derived, not guessed:** `order` is a deterministic function of the
  vault key, which the solver already holds after stage 2 — so computing it is
  one line, never a guess. The derangement space is only a *footgun bound* for a
  careless solver who ignores the key and brute-forces orderings against the
  strict-format oracle (all-or-nothing: any wrong position injects an UPPERCASE
  decoy chunk), not a security claim.
- **The “commitment sweep” is the long way round, not a bypass.** A white-box
  solver *could* open every `(cell, step)` pair (`N² = 64` requests) and use the
  published commitments to identify, per cell, the step at which its opening
  verifies — thereby recovering `order` without reading the derivation. This is
  bounded, deterministic (guess-exposure 0), and **strictly more work** than
  computing `order` from the key; crucially it still requires all three stages
  (auditor role + the `target` mass-assignment for every open) and never yields
  the flag whole. It recovers the *same* key-derived order the intended path
  computes directly, so it bypasses no stage and no crux — it is documented here
  for completeness, and the reference solver takes the intended computed path.


## Determinism

`ZSCTF_SEED` seeds SHA-256 derivations for the fingerprint, `SESSION_KEY`,
`VAULT_SIGN_KEY`, the sealed-cell **opening order** and **commitments**, and all
decoys. Same seed → byte-identical secrets (asserted: same fingerprint, same
leaked session key, **same opening order and same commitments**); different seed
→ different (asserted for all of them). `ZSCTF_FLAG` injects the flag; unset →
placeholder `zerosecurectf{REPLACE_ME_AT_DEPLOY}` with a stderr WARNING.


## Acceptance

end-to-end inside the hardened Docker image (`BUILD_EXIT=0`; see final report).
