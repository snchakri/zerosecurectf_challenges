# Shallows — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py challenge/shallows.pcap
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Shallows — intended solution & design notes

**Category:** network · **Band:** Easy (beginner on-ramp) · **Flag:** `zerosecurectf{...}` (from `ZSCTF_FLAG`)
Default artifact flag: `zerosecurectf{REPLACE_ME_AT_DEPLOY}` (placeholder — replace at deploy)

---


## 1. The artifact

A single classic libpcap file (`.pcap`, Ethernet → IPv4 → TCP), ~2 KB, 14
packets. It opens cleanly in Wireshark / `tshark` / `tcpdump` / scapy. It
contains two ordinary, benign TCP conversations from one workstation
(`10.50.3.14`), each a complete tiny HTTP/1.1 exchange (handshake, `GET`,
`200 OK`, FINs), delivered **in order** in single segments:

- a plain-HTTP fetch of `/wiki/triage.txt` from an internal wiki host
  `10.50.3.27:80` (the §7 decoy — a plaintext note), emitted **first**, and
- a plain-HTTP **authenticated** request to an internal status host
  `10.50.3.8:80` that carries an `Authorization: Basic <base64>` header, emitted
  **second**.

There is deliberately **no reassembly puzzle** here (that is the harder sibling
challenge *flotsam*): everything is in order and each payload fits in one
segment, so Wireshark's "Follow HTTP/TCP Stream" shows each whole conversation
at a glance. The single idea a beginner practices is: *plain HTTP Basic auth
leaks your credentials, base64-encoded, on the wire.*


## 2. Intended solution (one small, standard step)

### Step 1 — open the capture, see the two flows

Group packets into TCP conversations (Wireshark *Statistics → Conversations*, or
just scroll). Two flows: a wiki note and a status request.

### Step 2 — find the authenticated request

One flow's client→server request has an `Authorization` header:

```
GET /status HTTP/1.1
Host: status.internal
User-Agent: curl/8.5.0
Accept: */*
Authorization: Basic b3BlcmF0b3I6emVyb3NlY3VyZWN0Zns...
```

Wireshark's HTTP dissector recognises Basic auth and shows the decoded value
directly as **Credentials: `username:password`** under the HTTP header tree.

### Step 3 — base64-decode the credential

HTTP Basic auth is `base64(username ":" password)` (RFC 7617). Decode it:

```bash
echo 'b3BlcmF0b3I6emVyb3NlY3VyZWN0Zns...' | base64 -d
# operator:zerosecurectf{...}
```

The password (everything after the first `:`) is the flag.

The reference solver [`solution/solve.py`](solution/solve.py) does exactly this in
stdlib only (`struct`, `base64`, `re`): walk the pcap, reassemble each flow by
TCP sequence number, find the `Authorization: Basic` header, base64-decode it,
and read the password. It does **not** import the generator — it reconstructs
the method from the (standard, in-capture) protocol.

### Why the stated facts are verifiable

  **and** TCP checksum (over the standard pseudo-header) and asserts they are
  valid; scapy/Wireshark parse it without warnings.
- *Flag never appears as literal bytes:* checks 4 assert neither the flag nor
  `zerosecurectf{` occurs in the raw `.pcap` — because the flag is the password
  inside a **base64-encoded** Basic-auth header, it is not literal text.
- *The field is load-bearing:* check 6 scans the raw bytes, finds the
  `Authorization: Basic <b64>` header, base64-decodes it and confirms it yields
  the flag, while a plain scan for `zerosecurectf{` finds nothing — so
  identifying the right field and decoding it is the required step.
- *Deterministic + per-instance:* check 3 (same seed+flag ⇒ byte-identical) and
  check 5 (different seed ⇒ different bytes, still recoverable; different flag ⇒
  recovered correctly).


## 3. An honest note on the integrity model (design choice)

The ZSCTF default gate for a forensics artifact is "the flag string and
`zerosecurectf{` are absent from the raw bytes." For a *plaintext-protocol* easy
challenge that gate can legitimately be impossible — if the flag genuinely sat
in clear text in a stream, it *would* appear in the bytes, and the honest move
would be to instead assert that the decoy is surfaced first by `strings` and
that the real flag requires identifying the correct stream/field.

Shallows is a fortunate middle case and we take the **stronger** path on
purpose: HTTP Basic auth base64-encodes the credential, so the flag is *not*
literal bytes **and** we still require field identification. We therefore assert
**all** of it: (a) the flag / `zerosecurectf{` are absent from the raw bytes
(check 4), (b) the decoy token is present in clear text and surfaces **before**
the authenticated flow in byte order (check 7 — the first `strings`-style hit),
and (c) the flag is recoverable only by locating the `Authorization` field and
base64-decoding it (check 6). This is documented here so the choice is explicit
rather than implicit: base64 is a real, standard encoding of HTTP Basic auth,
not an added obfuscation layer.


## 4. Why this is fair and not guessy (the §19 invariant)

Every step has a concrete reasoning handle, so the design respects the "no
guessing" invariant (system.html §2, §19):

| Could be guessed? | The tell that removes the guess |
|---|---|
| "Which flow matters?" | one flow's request carries an `Authorization: Basic` header; the other has none |
| "Is the header value the answer?" | it base64-decodes to `username:` + a string that matches `zerosecurectf{...}` |
| "Is the plaintext token the flag?" | it is `zsctf_sample{...}`, which fails the `zerosecurectf{...}` format |

There is no noise without a tell: the authenticated flow is unambiguous (it is
the only one with credentials), and the decode is deterministic.


## 5. Red-team / AI-resistance

**Honest banding first.** This is an **Easy, beginner on-ramp** item. Reading an
HTTP Basic-auth header and base64-decoding it is one of the most common
beginner network-forensics exercises; it is heavily represented in training data
and fully automated by Wireshark's HTTP dissector (which prints the decoded
credentials). We make **no** claim of AI resistance or difficulty here. A
capable agent — or a beginner with Wireshark — solves this in minutes. That is
the intent: an on-ramp that teaches one real lesson (plain HTTP leaks
credentials) cleanly.

**The one place a careless solver slips.** The single easiest thing to find — a
`strings` hit that *looks* like a flag (`zsctf_sample{...}`) — is the wrong
answer, and it is the **first** token the capture surfaces. A solver that
pattern-matches "token-in-braces = flag" submits it and is rejected on format.
The correct move is to notice it fails `zerosecurectf{...}` and that the real
secret is the credential in the authenticated flow. This is the small,
deliberate friction that keeps the challenge from being a pure `strings` gimme
while staying honestly easy.

**Contamination note.** The *techniques* (HTTP, Basic auth, base64) are all
public and in LLM training data — deliberately, so the challenge is fair. What
is **not** in any corpus is *this instance*: the flag, the ISNs, ports, IP IDs,
username, path, Date headers and the note filler are generated per team from
`ZSCTF_SEED`/`ZSCTF_FLAG`, so no public writeup or cached solver output can be
replayed. A leaked solution for one team is inert for another (verified by

**Human–AI differential (summary).** Near parity. Both a trained human and a
capable agent recover the flag quickly once pointed at the capture. The only
edge is the orientation step — rejecting the easy plaintext decoy in favour of
the credential field — and even that edge is small. This item earns its place as
a **confidence-building on-ramp**, not as a differential.


## 6. The §7 decoy (bounded)

The first conversation (`10.50.3.27:80`, `GET /wiki/triage.txt`) is a benign
plaintext wiki note whose body contains, in clear text:

```
token: zsctf_sample{this_is_a_scratch_note_not_the_flag}
```

It is deliberately the **first** flag-looking thing a `strings` pass turns up
(the decoy flow is emitted before the authenticated flow), which makes it a
genuine trap. It is **rejectable by reasoning on two independent grounds**:

1. **Format.** It is `zsctf_sample{...}`, not `zerosecurectf{...}` — it fails the
   stated flag format.
2. **Structure.** The real secret is a *credential* carried in an
   `Authorization: Basic` header in the *other* flow; this note has no
   credential at all.

It is bounded: a single short flow, no second puzzle, no rabbit-hole — it exists
only to reward the format check over the `strings` reflex.


## 7. Unintended-path scan

- **`strings` / `grep zerosecurectf`** → finds nothing (the flag is
  base64-encoded); the only brace-token it surfaces is the decoy. No leak.
  (Asserted by checks 4 and 6.)
- **`strings` of the whole file + submit first token** → yields the decoy, which
  is format-rejected. Intended friction, not an unintended solve.
- **`binwalk` / entropy / carve** → nothing to carve; there is no embedded file,
  archive or compressed blob (unlike *flotsam*). No alternate path.
- **Decoding every base64-looking run in the capture** → the only credential-
  shaped base64 is the Authorization value; decoding it is the intended path, so
  this "shortcut" is just the solution by another name. Still requires the flag
  to be present (per-instance), so it cannot be replayed across teams.
- **Guessing the flag** → per-instance `ZSCTF_FLAG`, so guessing one team's flag
  does not help another; and the format gate rejects the decoy.
- **Tampering with the pcap** → the solver and the test recompute IP/TCP
  checksums; a corrupted capture simply fails to parse as valid traffic.

No unintended shorter path was found that bypasses "locate the Authorization
field and base64-decode it."


## 8. Lineage (corpus deconstruction → reconstruction)

Grounded in `system.html` (§16, §17, §18-B, §23, §24) and the existing ZSCTF
network family in this repository.

- **Category / family.** Network-forensics, benign sub-family. It is a
  deliberate **EASE-DOWN** sibling of the repo's existing network challenges:
  - *flotsam* (TCP-stream reassembly + ZIP inflate, Medium–Hard) — Shallows
    keeps its benign plain-HTTP framing and its format-gated `strings` decoy but
    **removes** the reassembly/retransmission burden and the compressed-archive
    layer, leaving a single base64-decode step.
  - *undertow* (DNS covert-channel) — distinct protocol and mechanic; Shallows
    shares none of its DNS machinery.
- **Operators applied (system.html §17.3).**
  - `GROUND` (G9) — attach a concrete, benign scenario (an operator hitting an
    internal status page) and a fully self-contained, standard-protocol artifact.
  - `SIMPLIFY / EASE` — strip every layer that makes *flotsam* medium-hard
    (out-of-order delivery, retransmission, HTTP object extraction, ZIP parse,
    DEFLATE, CRC gate) down to one standard field decode, to serve as a genuine
    beginner on-ramp.
  - `PARAMETERISE` (§24) — `ZSCTF_SEED` → ISNs, ports, IP IDs, username, path,
    Date headers, note filler → equally-easy per-instance variants, and
    `ZSCTF_FLAG` → the flag (the base64 Basic-auth password).
- **Knob (system.html §18-B).** Signal-to-noise is deliberately **low**: one
  decoy flow, one authenticated flow, in order. Difficulty is held at Easy on
  purpose; the only tell-bearing "noise" is the format-mismatched decoy, which
  §4's tell-table satisfies ("noise with no tell → guessiness" is avoided).
- **Class / banding.** Static-artifact delivery (§23: "file delivery + integrity
  hash; no live service; flag inside the artifact or per-instance §24"),
  network-forensics **easy / beginner on-ramp** → regenerate the artifact per
  seed.


## 9. Safety / scope

Benign by construction and by intent. Shallows is **ordinary network-protocol
inspection**: a well-formed packet capture of a legitimate authenticated
plain-HTTP request, solved by reading one header and base64-decoding it. It is
**not** malware, not C2, not beaconing, not exfiltration, not an intrusion, and
nothing in it is weaponizable. The educational point is the standard, widely
taught lesson that **plain HTTP Basic authentication exposes credentials on the
wire** — which is exactly why HTTPS exists. The Docker image is a generator that
writes a file and exits (`network_mode: none`, read-only root FS, all caps
dropped, no-new-privileges, non-root uid 10001, bounded pids/memory).
