# Sargasso — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py challenge/sargasso.pcap
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

The event accepted recovered flag-shaped tokens from these decoy challenges. The reference analysis also reports why they fail the original strict-format validator. For this archived event, compare each recovered token against `accepted_flags.txt`; do not interpret the original “no flag” design commentary as the event scoring rule.

# Sargasso — official writeup  (solution)

> **State it plainly: Sargasso is a honeypot / defensive tarpit. There is NO
> real flag anywhere reachable, by design.** `awards_flag: false`. This document
> must never reach players: it names the trap outright, enumerates the decoys and
> tells, and states the intended outcome. Only `challenge/` (the generator and
> the `.pcap`), `README.md`, and the player-safe parts of `challenge.yml` are
> player-facing.


## What this challenge is

Sargasso is a short, benign internal packet capture (Ethernet/IPv4 over TCP and
UDP — plain HTTP plus DNS) that is *dressed* to look like it carries an
exfiltrated or encoded flag across three tempting channels. It carries nothing.
Every channel is an inert decoy, and the capture's own bytes prove it. The
challenge models a real defensive technique: defenders deploy **decoy traffic /
decoy services** to burn attacker (and automation) time and to surface its
presence. (Background: MITRE Engage formalises *Decoy Content* and *Decoy
Artifacts* as active-defence techniques — https://engage.mitre.org/ ;
honeypots/honeytokens are long-standing practice — L. Spitzner, *Honeypots:
Tracking Hackers*, Addison-Wesley, 2002.)

The pedagogical target is a genuine, hard-to-teach skill: **recognise a trap and
disengage** — timebox the target, weigh evidence over momentum, sanity-check each
"channel" against the bytes, and stop.

The name is the lesson: the **Sargasso Sea** is the archetypal becalming / ship
trap of maritime legend — a place that looks navigable but only wastes the time
of anyone who presses on. (It sits in ZSCTF's network water-word lineage with
*Flotsam* and *Undertow*.)


## Why there is provably no flag (the load-bearing tell)

The capture publishes an integrity manifest in two places:

- the `/export/backup.json` HTTP response body, field `integrity_sha256`; and
- a DNS TXT record for `_integrity.chan.sargasso.internal`, `flag_sha256=...`.

Both carry the value:

```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

That is **`sha256(b"")` — the digest of the empty string** (RFC 6234 test
vector; `printf %s "" | sha256sum`). The only byte string whose SHA-256 is this
value is the empty string. So the capture's own published integrity check says
the "correct flag" is *empty*: i.e. **there is no flag.** This is the quiet,
decisive tell, an intentional *inversion* of the usual integrity-check role (a
CWE-345-style "insufficient verification" value, here weaponised as a tell): the
manifest looks like it validates a real flag; reading it closely proves the
opposite.


## The three decoy leads (each dead-ends with a verifiable tell)

All decoy values are per-instance (`ZSCTF_SEED` derives the 8-hex node
fingerprint `fp8` and all the wire randomness), so they differ per team while
the conclusion is identical. Every claim below is checkable from the capture
bytes alone — `solution/solve.py` does exactly these checks.

**Lead A — "base64 export blob".** `GET /export/backup.json` returns JSON with
`blob` (base64), `declared_len`, `declared_crc32`, and `integrity_sha256`.
Decoding `blob` yields self-describing DECOY text ending in a token:

```
token: zer0securectf{decoy_export_<fp8>}
```

*Tells:*
- The token prefix is **`zer0securectf`** (a zero, not an `o`) → fails the strict
  validator `^zerosecurectf\{[a-z0-9_]{8,48}\}$`.
- **`declared_len` and `declared_crc32` exactly match the decoded bytes.** The
  server is publishing an integrity proof *of its own bytes* — so the blob is
  precisely the canned noise it declares, with nothing hidden, appended or
  layered underneath. (This is the inverse of a covert payload, where metadata
  would not describe the carrier so completely.)
- The decoded text self-describes: `DECOY-CANARY tier=honeyfarm synthetic
  do-not-promote`.

**Lead B — "DNS covert channel".** A run of DNS A queries
`s<NN><hex>.chan.sargasso.internal`, emitted interleaved with other traffic,
looks like index-ordered exfiltration. Sorting by the two-digit index `<NN>` and
hex-decoding the concatenated chunks yields:

```
CANARY|DECOY-TARPIT|do-not-promote|n=<NNN>|token=zerosecurectf{DECOY-NO-FLAG-<FP8-UPPER>}
```

*Tells:*
- The reassembled token `zerosecurectf{DECOY-NO-FLAG-...}` has the right prefix
  but **uppercase letters and hyphens** → fails the `[a-z0-9_]` charset.
- The marker **self-describes** as `CANARY|DECOY-TARPIT|do-not-promote`.
- It even declares its own segment count `n=NNN`, and that value **does not match
  the number of `s<NN>` segments actually on the wire** (it is deliberately one
  too high). A real reassembly channel is internally consistent; this one is a
  stage prop.

**Lead C — "hidden telemetry field".** `GET /metrics` returns a `state=<hex>`
field under an `X-Payload-CRC32: 0x...` header.

*Tells:*
- The declared `X-Payload-CRC32` **does not match** `CRC-32(state bytes)` — the
  "channel" is internally inconsistent (the field is generated as random bytes;
  the declared CRC is their actual CRC XOR `0xFFFFFFFF`, so a mismatch is
  guaranteed and script-detectable).
- The bytes are high-entropy noise with **no flag-shaped substring** under raw,
  hex, or base64 decoding — a dead, abandoned field.


## The full list of tells a skilled analyst uses

1. **`integrity_sha256 == sha256("")`** (HTTP body *and* DNS `_integrity` TXT) →
   the correct flag is empty → there is no flag. *(decisive)*
2. **Lead A** blob is self-consistent canned noise (`declared_len` +
   `declared_crc32` match) and self-describes as DECOY; its token uses
   `zer0securectf` (zero) → fails the validator.
3. **Lead B** reassembles to a self-describing `CANARY|DECOY-TARPIT` marker whose
   token has uppercase+hyphens → fails charset, and whose declared `n` ≠ the
   segments on the wire → internally inconsistent.
4. **Lead C** `X-Payload-CRC32` ≠ `CRC-32(state)` → internally inconsistent; the
   bytes carry no flag under any decoding → dead noise.
5. **Canary markers** — an HTTP `X-Canary: honeyfarm-decoy; tier=decoy;
   do-not-promote` header and a DNS `_canary ... v=canary tier=decoy synthetic
   do-not-promote` TXT.
6. **Every flag-shaped string in any channel/decoding fails the strict format.**

No single tell is a billboard; together they are overwhelming and all are
verifiable from the bytes. A careless solver or naive automation will instead
extract a flag-shaped string, submit it, fail, extract the next, and loop — the
tarpit doing its job.


## Intended outcome — "recognise the trap and leave"

The intended solve is a **negative result reached by evidence**: the analyst
investigates with a time budget, decodes each lead, notices that the base64 blob
is an integrity proof of its own canned noise, that the DNS channel reassembles
to a self-labelled DECOY marker with an inconsistent segment count, and that the
telemetry field's CRC does not validate — and above all recognises the
`sha256("")` manifest digest — then concludes **"this is a decoy / tarpit, there
is nothing to capture here,"** and disengages without submitting anything.
`solution/solve.py` performs exactly this analysis and prints
`VERDICT: HONEYPOT / TARPIT -- no reachable flag. DISENGAGE.` (exit 0).
Scoring/triage should credit reaching and *justifying* that conclusion, not a
flag submission.


## Operations notes (for the ZSCTF team)

  asserts that an injected `ZSCTF_FLAG` never appears in the capture (raw or in
  any decoding). Do not set a real flag in deployment — there is nothing to
  inject.
- **Per-instance.** `ZSCTF_SEED` derives the node fingerprint (decoy token
  suffixes), the TCP ISNs, client ephemeral ports, IP IDs, DNS transaction IDs,
  the emission/shuffle order of the DNS lookups, the telemetry noise bytes, the
  benign-noise hostnames/addresses and the TTLs. Same seed → byte-identical pcap
  (verified by the test); different seed → different bytes, same conclusion.
- **Pure stdlib.** `struct`, `zlib`, `hashlib`, `base64`, `json` only. No scapy;
  the pcap bytes are written by hand with valid Ethernet/IPv4/TCP/UDP checksums.
- **Static artifact.** The Docker image is a *generator* (no ports, no socket);
  it self-verifies at build time by running the DISENGAGE analysis over a smoke
  instance. Hardening is real (non-root, read-only FS, caps dropped,
  `network_mode: none`, pids/mem limits) so a decoy generator never becomes a
  pivot — but it protects *no* secret, because there is none.
  checksums, TCP+UDP present); no extractable valid flag by any documented
  decoding; all three decoy leads present and each rejectable; the reference
  analysis independently reaches DISENGAGE; six tells script-detectable;
  `ZSCTF_FLAG` ignored; determinism (same seed identical, different seed differs).

---

