# Oubliette — solution

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

# Oubliette — official writeup  (solution)

> **State it plainly: Oubliette is a honeypot / tarpit. There is NO real flag
> anywhere reachable, by design.** This document must never reach players: it
> names the trap outright, enumerates the tells, and states the intended
> outcome. Only `challenge/`, `README.md`, and (optionally) `challenge.yml`
> metadata are player-facing.


## What this challenge is

Oubliette presents as an ordinary, slightly neglected internal "Document Archive
Portal." It deliberately dangles three classic web-exploitation sinks —

1. a **staff login** (`/login`),
2. a **path-traversal / LFI** document viewer (`/view?doc=`), and
3. an **SSRF** link-preview fetcher (`/fetch?url=`),

— and it rewards poking at them with plausible, flag-shaped strings. All of it
is theatre. Every lead is canned, every lead circles back, and **every "flag"
the service can emit is a decoy that fails two independent checks** (the strict
format validator *and* the integrity digest the service publishes about itself).

The pedagogical target is a genuine, hard-to-teach red-team skill:
**recognise a honeypot / rabbit-hole and disengage** — timebox the target,
weigh evidence over momentum, and stop. This mirrors a real defensive technique:
deception grids / tarpits that feed attackers decoys and circular leads to burn
their time and reveal their presence. (Background: MITRE Engage / the older
MITRE Shield active-defense framework formalises *Decoy Content* and
*Decoy Systems* as deliberate techniques; honeypots/honeytokens are long-
standing practice — L. Spitzner, *Honeypots: Tracking Hackers*, 2002.)


## Why there is provably no flag (the load-bearing tell)

The service publishes, at **`/.well-known/zsctf-manifest.json`**, a field
`flag_sha256` — ostensibly "the sha256 of the correct flag," offered as an
integrity check so you can verify a candidate before submitting (the README even
coaches players to do this). The published value is:

```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

That is **`sha256(b"")` — the digest of the empty string** (a constant any
experienced analyst recognises; e.g. `printf %s "" | sha256sum`). The only
byte string whose SHA-256 is this value is the empty string. So the service's
own published integrity check says the correct flag is *empty*: i.e. **there is
no flag.** This is the quiet, decisive tell — not an insult to the player, but a
fair, verifiable fact sitting in plain sight. It is reinforced by `/validate`,
which rejects *every* candidate including the empty string, so the player can
confirm by experiment that nothing this node accepts exists.

This is intentionally an *inversion* of the usual integrity-check role
(CWE-345-style trust of an unverified value, here weaponised as a tell): the
manifest looks like it validates a real flag; reading it closely proves the
opposite.


## The three decoy leads (each dead-ends with a visible tell)

All decoy values are per-instance (`ZSCTF_SEED`), so they differ per team while
the conclusion is identical.

**Lead 1 — login → vault.** `/view?doc=config/credentials.ini` leaks
`archivist = <pw>` (a real-looking credential leak). Signing in at `/login` with
it sets a session cookie and unlocks `/vault`, which returns a `restored_flag`:

```
zer0securectf{s3ss10n_restored_<hex>}
```

*Tell:* the prefix is **`zer0securectf`** (a zero), not `zerosecurectf`. It fails
the strict validator `^zerosecurectf\{[a-z0-9_]{8,48}\}$`. The vault also points
to `/view?doc=archive/manifest.json`, which points back to `/login` — the lead
**circles**.

**Lead 2 — LFI / path traversal.** `/view?doc=secret/flag.txt` returns:

```
zerosecurectf{ARCHIVE_UNSEALED_<HEX>}
```

*Tell:* the body is **uppercase**, failing the `[a-z0-9_]` charset. And the
"LFI" is **sealed**: `/view` normalises away `.`/`..` and serves only from a
fixed in-memory dict. Any non-canned path — including `../../../../etc/passwd` —
returns a **byte-identical** 404 stub. Different inputs → identical bytes is
proof there is no filesystem behind it.

**Lead 3 — SSRF.** `/fetch?url=<anything>` returns a cached "instance metadata"
preview containing:

```
zerosecurectf{imds-token-<hex>}
```

*Tell:* the body contains **hyphens**, failing the charset. And the "SSRF" is
sealed: the preview is **byte-identical regardless of the URL** (loopback,
`169.254.169.254`, a host you control — all the same bytes). No socket is ever
opened; nothing varies with the target. (Deployment also blocks egress, so even
a hypothetical un-seal reaches nothing real.)


## The full list of tells a skilled analyst uses

1. **`flag_sha256 == sha256("")`** in the published manifest → the correct flag
   is empty → there is no flag. *(decisive)*
2. **`/validate` rejects everything**, including the empty string and the
   service's own decoys → the node admits nothing is acceptable.
3. **Every emitted flag-shaped string fails the strict format** (`zer0…`,
   uppercase, hyphens) — three different, deliberate malformations.
4. **`/view` is canned & sealed** — identical stub for any non-canned/traversal
   input; no real file reads.
5. **`/fetch` is canned** — identical preview regardless of URL; no real fetch.
6. **`robots.txt` canary marker** — `honeyfarm canary node -- DECOY tier`,
   `synthetic artifacts only`, `do-not-promote`. A hint for the sharp-eyed who
   read robots.txt (as attackers do).
7. **The index HTML comment** — `build: oubliette-canary * tier=decoy *
   artifacts=synthetic * do-not-promote`.
8. **`/whoami` reports `"tier": "decoy"`** outright.
9. **The leads circle** — credentials → login → vault → manifest → login; no new
   ground is ever reached no matter how many hops.

No single tell is a billboard; together they are overwhelming and all are
verifiable from responses. A careless solver or naive automation will instead
extract a flag-shaped string, submit it, fail, extract the next, and loop — the
tarpit doing its job.


## Intended outcome — "recognise the honeypot and leave"

The intended solve is a **negative result reached by evidence**: the analyst
investigates with a time budget, notices that every lead produces canned content
and malformed flags, reads the published manifest and recognises the empty-string
digest (confirmed by `/validate` rejecting even the empty flag), concludes
**"this is a honeypot — there is nothing to capture here,"** and disengages
without submitting anything. `solution/solve.py` performs exactly this analysis and
prints `VERDICT: HONEYPOT / TARPIT -- no reachable flag. DISENGAGE.` (exit 0).
Scoring/triage should credit reaching and *justifying* that conclusion, not a
flag submission.


## Operations notes (for the ZSCTF team)

  asserts that an injected `ZSCTF_FLAG` never appears in any response. Do not
  set a real flag in deployment — there is nothing to inject.
- **Per-instance.** `ZSCTF_SEED` derives the decoy login password, decoy session
  token, decoy flag bodies, and the public node fingerprint. Same seed → same
  node (verified by the test); different seed → different decoys.
- **Hardening is real** (non-root, read-only FS, caps dropped, internal/egress-
  blocked network) so a tarpit never becomes a pivot — but note it protects *no*
  secret, because there is none.
  both backends, all three decoys present and rejectable, `/validate` self-
  rejects, four distinct tells script-detectable, `ZSCTF_FLAG` ignored, and
  determinism.

---

