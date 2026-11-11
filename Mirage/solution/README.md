# Mirage — solution

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

The event accepted recovered flag-shaped tokens from these decoy challenges. The reference analysis also reports why they fail the original strict-format validator. For this archived event, compare each recovered token against `accepted_flags.txt`; do not interpret the original “no flag” design commentary as the event scoring rule.

# Mirage — official writeup  (solution)

> **State it plainly: Mirage is a honeypot / tarpit. There is NO real flag
> anywhere reachable, by design.** This document must never reach players: it
> names the trap outright, enumerates the tells, and states the intended
> outcome. Only `challenge/`, `README.md`, and (optionally) `challenge.yml`
> metadata are player-facing.


## What this challenge is

Mirage presents as an ordinary, slightly neglected internal CI/CD
"Continuous Delivery Console." It deliberately dangles the classic build-server
jackpots that attackers hunt for —

1. an **operator sign-in** (`/api/login`),
2. a **path-traversal artifact fetcher** (`/api/artifact?path=`),
3. a **leaked runner-environment dump** (`/api/env`), and
4. a **live deploy-token minter** (`/api/token/mint`),

— and it rewards poking at them with plausible, flag-shaped strings (a deploy
token, a promoted artifact, a leaked env var). All of it is theatre. Every lead
is canned, every lead circles back, and **every "flag" the service can emit is a
decoy that fails two independent checks** (the strict format validator *and* the
integrity digest the service publishes about itself).

The pedagogical target is a genuine, hard-to-teach red-team skill:
**recognise a honeypot / rabbit-hole and disengage** — timebox the target,
weigh evidence over momentum, and stop. This mirrors a real defensive technique:
deception / decoy services (and deliberately bloated or slow "tarpit" services)
that feed attackers decoy content and circular leads to burn their time and
reveal their presence.

### Evidence / background (verifiable)

- **MITRE Engage** (the successor to MITRE Shield) catalogues *Decoy Content*
  (EAC0005 / the "Decoy Artifacts" family) and *Decoy Systems* as deliberate
  adversary-engagement techniques — planting attractive but fake artifacts and
  systems to waste adversary effort and gather intelligence.
  See <https://engage.mitre.org/> (Engage Matrix → *Prepare/Expose/Affect*;
  the earlier framework is archived at <https://shield.mitre.org/>).
- **Tarpits** as a defensive "waste the attacker's time" primitive are long
  established — e.g. LaBrea (T. Liston, 2001) which deliberately stalls
  connections; and SMTP teergruben. General honeypot theory: L. Spitzner,
  *Honeypots: Tracking Hackers* (Addison-Wesley, 2002).
- The **empty-string SHA-256** constant used as the decisive tell is
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`; reproduce
  it with `printf %s "" | sha256sum`. (NIST FIPS 180-4 defines SHA-256; this is
  simply its value on zero-length input.)


## Why there is provably no flag (the load-bearing tell)

The service publishes, at **`/.well-known/zsctf-manifest.json`** (and in the
`/api/status` build banner, and the `--tcp` greeting), a field `flag_sha256` —
ostensibly "the sha256 of the correct flag," offered as an integrity check so you
can verify a candidate before submitting (the README even coaches players to do
this). The published value is:

```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

That is **`sha256(b"")` — the digest of the empty string**. The only byte string
whose SHA-256 is this value is the empty string. So the service's own published
integrity check says the correct flag is *empty*: i.e. **there is no flag.** This
is the quiet, decisive tell — a fair, verifiable fact sitting in plain sight. It
is reinforced by `/validate` (and the `SUBMIT` verb over TCP), which rejects
*every* candidate including the empty string, so the player can confirm by
experiment that nothing this node accepts exists.

This is intentionally an *inversion* of the usual integrity-check role
(CWE-345-style trust of an unverified value, here weaponised as a tell): the
manifest looks like it validates a real flag; reading it closely proves the
opposite.


## The three decoy leads (each dead-ends with a visible tell)

All decoy values are per-instance (`ZSCTF_SEED`), so they differ per team while
the conclusion is identical.

**Lead 1 — login → deploy-token mint.** `/api/artifact?path=ci/secrets.env`
leaks `OPERATOR_API_KEY=<key>` (a real-looking credential leak). Signing in at
`/api/login` with it sets a session cookie and unlocks `/api/token/mint`, which
returns a `deploy_token`:

```
zerosecurectf{deploy-token-<hex>}
```

*Tell:* the body contains **hyphens**, failing the `[a-z0-9_]` charset of
`^zerosecurectf\{[a-z0-9_]{8,48}\}$`. The mint response also points to
`/api/artifact?path=build/manifest.json`, which points back to `/api/login` —
the lead **circles**. And the minter is canned: **the same token is returned for
any `scope`** (deploy, admin, …); no real credential is ever minted.

**Lead 2 — path traversal / artifact fetch.**
`/api/artifact?path=build/flag.txt` returns:

```
zerosecurectf{BUILD_ARTIFACT_<HEX>}
```

*Tell:* the body is **uppercase**, failing the `[a-z0-9_]` charset. And the
"traversal" is **sealed**: `/api/artifact` normalises away `.`/`..` and serves
only from a fixed in-memory dict. Any non-canned path — including
`../../../../etc/passwd` — returns a **byte-identical** 404 stub. Different
inputs → identical bytes is proof there is no filesystem behind it.

**Lead 3 — leaked environment dump.** `/api/env` returns a "runner environment
snapshot" containing:

```
PROMOTED_FLAG = zer0securectf{env_promoted_<hex>}
```

*Tell:* the prefix is **`zer0securectf`** (a zero), not `zerosecurectf`. It fails
the strict validator. Crucially, this dump is a **fixed canned dict — the real
process environment is never read**, so an injected `ZSCTF_FLAG` (if an operator
wrongly set one) does **not** appear here or anywhere else.


## The full list of tells a skilled analyst uses

1. **`flag_sha256 == sha256("")`** in the published manifest / status banner / TCP
   greeting → the correct flag is empty → there is no flag. *(decisive)*
2. **`/validate` (and `SUBMIT`) rejects everything**, including the empty string
   and the service's own decoys → the node admits nothing is acceptable.
3. **Every emitted flag-shaped string fails the strict format** (hyphens,
   uppercase, `zer0…`) — three different, deliberate malformations.
4. **`/api/artifact` is canned & sealed** — identical stub for any non-canned /
   traversal input; no real file reads.
5. **`/api/build/<id>/log` is canned** — identical bytes for any build id; no real
   build system.
6. **`/api/token/mint` is canned** — identical token regardless of scope; no real
   minting.
7. **`robots.txt` canary marker** — `honeyfarm canary node -- DECOY tier`,
   `synthetic artifacts only`, `do-not-promote`.
8. **The index HTML comment** — `build: mirage-canary * tier=decoy *
   artifacts=synthetic * do-not-promote`.
9. **`/whoami` and `/api/status` report `"tier": "decoy"`** outright.
10. **The leads circle** — `secrets.env` → login → mint → `build/manifest.json`
    → login; no new ground is ever reached.

No single tell is a billboard; together they are overwhelming and all are
verifiable from responses. A careless solver or naive automation will instead
extract a flag-shaped string, submit it, fail, extract the next, and loop — the
tarpit doing its job.


## Intended outcome — "recognise the honeypot and leave"

The intended solve is a **negative result reached by evidence**: the analyst
investigates with a time budget, notices that every lead produces canned content
and malformed flags, reads the published manifest and recognises the empty-string
digest (confirmed by `/validate`/`SUBMIT` rejecting even the empty flag),
concludes **"this is a honeypot — there is nothing to capture here,"** and
disengages without submitting anything. `solution/solve.py` performs exactly this
analysis and prints `VERDICT: HONEYPOT / TARPIT -- no reachable flag. DISENGAGE.`
(exit 0). Scoring/triage should credit reaching and *justifying* that conclusion,
not a flag submission.


## Operations notes (for the ZSCTF team)

  asserts that an injected `ZSCTF_FLAG` never appears in any HTTP or TCP
  response. Do not set a real flag in deployment — there is nothing to inject.
- **Per-instance.** `ZSCTF_SEED` derives the decoy operator key, decoy session
  token, decoy deploy token, decoy flag bodies, and the public node fingerprint.
  Same seed → same node (verified by the test); different seed → different decoys.
- **Hardening is real** (non-root uid 10001, read-only FS, caps dropped,
  internal/egress-blocked network) so a tarpit never becomes a pivot — but note
  it protects *no* secret, because there is none.
  both HTTP backends, all three decoys present and rejectable, `/validate` self-
  rejects (incl. empty), six distinct tells script-detectable, the raw `--tcp`
  surface mirrors the same honeypot behaviour (banner digest, canned leads, self-
  rejecting `SUBMIT`, no flag leak), `ZSCTF_FLAG` ignored, and determinism.

---

