# Palisade — solution

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

# Palisade — official writeup

**Flag:** `zerosecurectf{unres0lvable_is_n0t_unreachable}` (static demo seed;
per-instance in production).


## The flaw

Palisade is a fetch-on-your-behalf URL inspector — the textbook Server-Side
Request Forgery (SSRF, [CWE-918](https://cwe.mitre.org/data/definitions/918.html))
sink. It defends itself with a guard that refuses URLs pointing at internal
addresses. The guard is genuinely careful: it blocks `127.0.0.1`, `localhost`,
`0.0.0.0`, the whole of `127.0.0.0/8` (e.g. `127.0.0.2`), `::1`, and — on a
resolver that honours them — `inet_aton` forms such as the decimal
`2130706433`, because they all **parse or resolve to a non-routable address**
and are rejected. Blind bypass-catalogue spraying of bare hosts does not work.

The bug is not a missing entry in a block-list. It is a **parse differential**
([CWE-20](https://cwe.mitre.org/data/definitions/20.html); the canonical study
is Orange Tsai, *"A New Era of SSRF — Exploiting URL Parsers"*, Black Hat USA
2017): the component that *validates* the URL and the component that *fetches*
it disagree about what the URL's host is.

```python
# GUARD (hand-rolled regex parse). Strips a trailing :port, but NOT userinfo:
#   authority = "inspector@127.0.0.1:<IPORT>"  ->  host string = "inspector@127.0.0.1"
# That string is not an IP and does not resolve, so the guard hits its flawed rule:
except (socket.gaierror, UnicodeError, ValueError):
    # "egress/DNS is blocked, so a host we cannot resolve cannot reach anything
    #  internal -> allow it."
    return True, "host ... does not resolve; treated as external/offline"
```

```python
# FETCHER (stdlib urlsplit, RFC-3986 compliant). Correctly drops userinfo:
sp = urlsplit("http://inspector@127.0.0.1:<IPORT>/...")
sp.hostname   # -> "127.0.0.1"   <-- connects to the loopback internal port
```

The guard's reasoning — *"a host I can't resolve can't reach anything"* — is
exactly backwards. **Unresolvable-by-the-guard is not the same as
unreachable-by-the-fetcher.** The fetcher parses `inspector@127.0.0.1` into the
real host `127.0.0.1` and connects to loopback: straight into the internal
results service, which lives on an unpublished loopback port inside the
container.


## Why that yields the flag

The internal results service (`/internal/...`) runs on its **own** listener,
bound to `127.0.0.1` on an ephemeral port that is **never published** and is
**not** served on the public port (requesting `/internal` on the public port is
a plain 404). It is additionally gated by a shared **edge credential** — a
per-instance secret header (`X-Palisade-Edge`) that the inspector injects on
**every** outbound request. This is a real internal-service-mesh pattern (a
private service reachable only from inside, a gateway stamps a trusted header,
the service trusts it). Two independent barriers therefore stand between a
player and the vault: (a) the internal port is not reachable from the public
interface, and (b) even on loopback it demands the edge credential. An SSRF that
rides the inspector clears **both** at once — the fetch reaches the loopback
port *and* carries the credential. Crucially, a leaked/guessed edge credential
alone is useless: there is nothing to send it to on the public port. So:

1. **`GET /whoami`** — public; learn the instance's internal loopback port (the
   pivot target). It is advertised but non-secret: the port is loopback-only and
   unpublished, so knowing it does not make the service reachable off the pivot.
2. **Hop 1 — reach the internal index:**
   `GET /inspect?url=http://inspector@127.0.0.1:<IPORT>/internal/`
   The guard allows it (unresolvable host string); the fetcher connects to the
   loopback internal port and adds the edge credential; the internal index comes
   back and lists the per-instance vault path `vault/<token>`.
3. **Hop 2 — read the vault:**
   `GET /inspect?url=http://inspector@127.0.0.1:<IPORT>/internal/vault/<token>`
   Same pivot → the vault returns `FLAG: zerosecurectf{...}`, which the inspector
   echoes back in its preview.

`solution/solve.py` does exactly this and prints the flag.


## Why the intended path is the only cheap one

- **No direct access.** `/internal/*` requires the edge credential. A player
  never sees that secret (128-bit, seed-derived, never reflected in any
  response body), so even knowing the route and the token, a direct request is
  `403`.
- **No bare-host SSRF.** `127.0.0.1`, `localhost`, `0.0.0.0`, `127.0.0.2`,
  decimal/`::1` are all refused by the guard. You cannot reach the internal
  service with a naive payload — you must find the validator/fetcher
  disagreement. (The acceptance test asserts all of these are refused.)
- **No credential exfiltration.** The inspector stamps the edge credential onto
  *every* outbound fetch — so if you could make it fetch a host you control, you
  could steal the secret and then hit the vault directly. **Egress is blocked**,
  so that alternate path is dead: the only reachable destinations are the
  container's own loopback. This is why the egress cut is *load-bearing*, not
  mere safety wrapping.
- **No guessing.** White-box source; the route is reached purely by reasoning
  about URL grammar. Guess-exposure is ~0.


## Design notes (for the ZSCTF team)

- **Lineage** (`corpus-genome.yaml`, reconstruction per system.html §17):
  - `zsctf-web-013 wp-admin` — borrowed the **blocked-egress hardening as a
    load-bearing guard** (the only reachable target is internal). Operators
    `GUARD-SWAP` + `GROUND` (a hardened internal-service topology).
  - `zsctf-web-003 Security Driven` — borrowed **chaining a server-side fetch
    into disclosure of an admin-only secret** (the two-hop internal pivot).
    Operators `GROUND` + `CHAIN`.
- **Crux (insight class):** validator/requester URL **parse differential** on
  userinfo, armed by the flawed invariant *"unresolvable ⇒ unreachable,"* with a
  shared-credential trust boundary and an egress cut that prunes the alternative.
- **Primitives:** SSRF (CWE-918), URL parser confusion (CWE-20), trust-boundary
  header confusion (CWE-348, reliance on untrusted inputs), broken access
  control (OWASP A01:2021).
- **Per-instance:** `ZSCTF_SEED` derives the vault token and the edge credential;
  `ZSCTF_FLAG` the flag; `/whoami` exposes only a non-secret fingerprint. Same
  seed → same instance (verified by the test).
- **Harder variants (extrapolation):** (a) replace the userinfo differential
  with a **DNS-rebinding** TOCTOU (`PARAMETERISE` the resolver), raising the
  tooling/timing axes; (b) move the vault behind a **second** internal hop that
  itself must be SSRF'd with a different primitive (`CHAIN(X)`); (c) tighten the
  guard to resolve-then-check *and* re-validate after connect, forcing a true
  parser-differential rather than the allow-on-unresolvable shortcut.

---


## Rabbit-holes 

The hardening retrofit adds deliberate, **provably-inert** misdirection. None of
it changes the crux (the userinfo parse differential), the real flag, the real
vault token, or the edge credential, and none opens a new path to them (the
acceptance test asserts this). All decoy content is `ZSCTF_SEED`-derived, so a
leaked walkthrough or one team's notes **do not transfer** (R5). Every trap is
rejectable by the published strict validator `^zerosecurectf\{[a-z0-9_]{8,48}\}$`
and/or a response marker. Operators applied: **R1, R2, R3, R4, R5**.

| # | Trap | Operator | Reasoning-based tell (the escape) |
|---|------|----------|-----------------------------------|
| 1 | `GET /debug` — public JSON diagnostics dump carrying a `"flag"` field `zer0securectf{<seed>}`. The first thing a dirbuster/scanner surfaces. | R1, R4 | The prefix is `zer0…` (zero→`0` homoglyph), not `zerosecurectf{…}`: it can never match the published format. The endpoint is a static stub — its `edge_hint` is explicitly redacted and is **not** the real `X-Palisade-Edge` value, so it authenticates nothing (direct `/internal/` stays `403`). Inert. |
| 2 | `GET /backup` — a config-backup text stub with `FLAG=ZEROSECURECTF{<seed>}` and a `<redacted-32-byte-edge-credential>` placeholder. | R1, R4 | Body is UPPERCASE → fails `[a-z0-9_]`. The "credential" is a literal `<redacted…>` placeholder, not a secret. Nothing here is load-bearing. |
| 3 | **Staging-cache vault** `/internal/vault/<STAGING_TOKEN>` — listed **first** on the internal index (reached via the *same* SSRF pivot), returning `FLAG: zerosecurectf{STAGING-FIXTURE-<seed>-DO-NOT-SUBMIT}`. | R2, R3 | The internal index lists two self-consistent `vault/<hex>` entries; only one is the live vault (the other is labelled "fixture data … not the live vault"). The fixture flag is UPPERCASE + hyphens → fails the strict validator. A solver that greps the **first** `vault/<hex>` and submits its flag loses; the careful move is *verify-before-commit*: read every candidate and accept only the format-valid one. The reference solver documents exactly this escape. |

**Why no new path to the real flag:** `/debug` and `/backup` contain only
format-invalid decoys and redacted placeholders (no real `FLAG`, `VAULT_TOKEN`
or `EDGE_SECRET`); the acceptance test asserts none of the three real secrets
appears in either body. The staging vault still sits behind the same edge-credential
gate and returns a *fixture*, never the live flag (asserted). The real flag
remains reachable **only** through the userinfo parse differential → real
token-gated vault.

**Honest banding:** band stays **hard**. The crux is unchanged; the traps mainly
cost a *careless* or *momentum-driven* solver time (a lazy first-token grab or a
scanner hit lands on a decoy that fails the format rule on reflection). We do not
claim the traps raise the fundamental difficulty of the parse-differential insight.

### Platform note (verification integrity)

The acceptance test runs on Windows, where only `127.0.0.0/8` literals reach
loopback (the OS resolver rejects `inet_aton`/`0.0.0.0` forms); on the Linux
deployment image those extra forms resolve and are therefore *also* caught by
the guard's resolve-then-check branch. The intended payload
(`userinfo@127.0.0.1`) is pure Python string logic plus a loopback connect, so it
in-container solve on the Linux image.
