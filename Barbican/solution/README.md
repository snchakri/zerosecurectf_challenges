# Barbican — solution

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

# Barbican — official writeup

**Flag:** `zerosecurectf{tw0_t1ers_0ne_truth_the_edge_never_kn0ws}` (static demo
seed; per-instance in production).

> Do **not** ship this file to players. Player-facing files are `challenge/`,
> `README.md`, and (optionally) `challenge.yml`.


## The flaw

Barbican is a two-tier deployment — a public **edge gateway** in front of an
internal **upstream application** — which is the standard shape of almost every
real site (reverse proxy / CDN in front of an app server). The edge enforces one
access-control rule: the privileged path `/admin` is refused from the public
side (`403`). The upstream does not re-check that rule; it trusts the edge.

The bug is a **request desync** between the two tiers
([CWE-444](https://cwe.mitre.org/data/definitions/444.html), "Inconsistent
Interpretation of HTTP Requests"; the canonical study is James Kettle,
*"HTTP Desync Attacks: Request Smuggling Reborn,"* PortSwigger / Black Hat USA
2019, <https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn>).
The two tiers disagree about **where a request's body ends**:

```python
# EDGE: frames the body by Content-Length, forwards the bytes verbatim.
cl = int(headers.get("content-length", "0") or "0")
body = reader.read_exactly(cl) if cl else b""
...
POOL.forward(raw + body)          # request line + headers + CL bytes

# UPSTREAM: when a chunked transfer-coding is present, decodes the body as
# chunked and treats "0\r\n\r\n" as the end of the body.
if "chunked" in headers.get("transfer-encoding", "").lower():
    read_chunked(reader)          # stops at the zero-size chunk
else:
    ... content-length
```

This is the classic **CL.TE** variant: the front end uses `Content-Length`, the
back end uses `Transfer-Encoding: chunked`. Craft one request that carries both
headers, with a `Content-Length` that *covers* a chunk terminator **plus** a
second request hidden after it:

```
POST /app HTTP/1.1
Host: edge
Content-Length: 41
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: upstream

```

- The **edge** parses the first request line (`POST /app`, allowed — not
  `/admin`), reads exactly `Content-Length` body bytes (`0\r\n\r\n` + the hidden
  `GET /admin ...`), and forwards all of it to the upstream.
- The **upstream** honours the chunked coding: `0\r\n\r\n` ends the body of
  request #1 (`POST /app`), and the leftover `GET /admin ...` is parsed as a
  **second** request on the same connection.

The smuggled `GET /admin` never passed the edge's path check, so the edge's
access control is bypassed.


## Why that yields the flag

The edge multiplexes all client traffic onto a **single long-lived keep-alive
connection** to the upstream (a connection pool of one — a thrifty but entirely
realistic reverse-proxy configuration) and reads **exactly one response per
forwarded request**. After the crafted request, the upstream has produced **two**
responses: one for `POST /app` and one for the smuggled `GET /admin`. The edge
returns the first and leaves the second **queued** on the shared connection. The
attacker's next, perfectly benign request is answered with that queued `/admin`
response — which carries `FLAG: zerosecurectf{...}` and
`X-Flag-Source: live-admin`.

`solution/solve.py` does exactly this:

1. Send the crafted `POST /app` (CL/TE desync hiding `GET /admin`); read one
   response (the `/app` page).
2. Send a benign `GET /app`; read the queued `/admin` response.
3. Verify `X-Flag-Source: live-admin` and that the flag is not a `sample`
   fixture; print the flag.


## Why the intended path is the only cheap one

- **No direct admin access.** `GET /admin` at the edge is `403`. (Asserted.)
- **No direct upstream access.** The upstream binds an ephemeral `127.0.0.1`
  port that is never published; in the container, only the edge port is exposed.
  There is no route to the upstream except through the edge.
- **The desync is load-bearing.** The crafted request's *first* response has no
  flag; the flag lives only in the *second*, queued response. (Asserted on a
  fresh instance: "single crafted request yields no flag".)
- **No guessing.** White-box source; the route is reached purely by reasoning
  about HTTP body framing. Guess-exposure is ~0.


## The decoy (genuine §7-style)

The edge offers a **QA preview** of the admin area via the `X-Barbican-Preview`
request header. It returns an official-looking `zerosecurectf{...}` string **with
no desync at all** — so it is tempting: it looks like you bypassed access
control. It is a **honeypot fixture**:

- watermarked with the literal token `sample`
  (`zerosecurectf{sample_preview_fixture_<hex>}`),
- tagged `X-Flag-Source: qa-fixture` (the live flag is `live-admin`),
- it violates the published valid-flag rule `^zerosecurectf\{[a-z0-9_]+\}$`.

A careful solver **rejects it by reasoning** against the published integrity rule
in the README. It is **bounded**: one endpoint, one fixed fixture per instance,
no rabbit hole. The acceptance test asserts the decoy flag differs from the real
flag, contains `sample`, and is served with `X-Flag-Source: qa-fixture`.


## Design notes (for the ZSCTF team)

- **Lineage** (`corpus-genome.yaml`; reconstruction per system.html §17):
  - `zsctf-web-016 phpnotes` — the explicit desync seed ("exploit
    request-handling inconsistencies across a front end and two back ends";
    scenario "request smuggling / desync"). Operators **GROUND** (into a concrete
    edge-gateway / internal-app deployment with a real access-control rule) and
    **SUBSTITUTE-TARGET** (tier stack varied to two stdlib HTTP tiers — the
    seed's own `reconstruct_idea` is "vary the tier stack for new instances").
    **PARAMETERISE** supplies per-instance fingerprint + fixture.
  - `zsctf-web-013 wp-admin` — **GUARD-SWAP**: blocked-egress hardening as a
    real, load-bearing deployment guard (closes the blind/timing side channel).
  - `zsctf-web-003 Security Driven` — **CHAIN**: a front-tier action chained into
    disclosure of an admin-only secret across an access-control boundary.
- **Crux (insight class):** front-end/back-end **body-framing differential**
  (CL.TE), armed by a "trust-the-gateway" upstream and a shared keep-alive
  connection that **queues** the smuggled response to the next request.
- **Primitives:** HTTP request smuggling / desync (CWE-444), broken access
  control (OWASP A01:2021), trust-boundary violation (CWE-501).
- **Per-instance:** `ZSCTF_SEED` derives the public fingerprint and the QA
  fixture; `ZSCTF_FLAG` the flag. Same seed → same instance (verified).
- **Harder variants (extrapolation):** (a) **TE.CL** or **TE.TE** with a header
  obfuscation the edge *normalises differently* from the upstream, raising the
  tooling axis; (b) `CHAIN(X)` a second internal hop that must itself be reached
  by a distinct primitive; (c) move to a true victim-poisoning model (the
  smuggled response is served to a *different* client's request), which raises
  difficulty but trades away single-player determinism — kept out here on
  purpose (see §testing: deterministic, retriable).

---

