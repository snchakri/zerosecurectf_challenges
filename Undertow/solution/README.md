# Undertow — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py challenge/undertow.pcap
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Undertow -- full solution, red-team, and lineage


## Scenario

A benign internal DNS conversation. An appliance fleet resolves
`up-<N>.cfg.fleet.internal` names against its configuration coordinator
(`10.77.5.x`); the coordinator answers each with a single A record in the
fictional internal shared-address pool `100.x.y.z`. Interleaved with these are
ordinary member lookups (package mirror, NTP) and a TXT opt-out advisory. No
malware, C2, beaconing or intrusion -- just traffic to read carefully.


## The mechanism (no obscurity)

The coordinator publishes its firmware-manifest digest -- here, the flag -- to
the members by spraying it across the three low octets of the A-record answers:

```
answer for up-N.cfg.fleet.internal  ==  100 . b0 . b1 . b2
                                          ^tag   \__ 3 payload bytes __/
```

Before spraying, the flag is `zlib.compress`-ed, so it never appears as literal
bytes on the wire. The capture emits the query/response pairs in a
**seed-shuffled** order; the correct order is carried in the `up-<N>` label.


## Intended solve (the chain)

1. **Parse** the classic little-endian libpcap and walk
   Ethernet -> IPv4 -> UDP -> DNS for every frame.
2. **Index queries** by `(txid, client_port, qname)` and collect responses.
3. **Isolate the signal**: keep responses that (a) echo a question matching
   `up-(\d+)\.cfg\.fleet\.internal`, (b) carry an A record whose first octet is
   the pool tag `100`, and (c) answer a real outstanding query (matching txid +
   client port + question). This rejects the benign noise, the TXT decoy, and
   any unsolicited response.
4. **Order** the kept segments by the integer `N` from the label -- *not* by
   capture order.
5. **Reassemble**: concatenate the three low octets of each answer in `N` order.
6. **Inflate**: `zlib.decompressobj().decompress(blob)`. The trailing Adler-32
   in the zlib stream validates the whole reassembly; a wrong order will not
   inflate. The inflated bytes are `zerosecurectf{...}`.

`solution/solve.py` does exactly this in ~100 lines of stdlib. Run:

```bash
python solution/solve.py challenge/undertow.pcap
```


## Why `strings` fails

The only flag-shaped text in the capture is the **decoy** `zsctf_demo{...}`
token (wrong prefix). The real flag is DEFLATE-compressed and split three octets
at a time across binary A-record RDATA, so `strings undertow.pcap | grep
zerosecurectf` returns nothing. The acceptance test asserts both
`zerosecurectf{` and the full flag are absent from the raw bytes.


## Why ordered reassembly is load-bearing

The pairs are emitted shuffled, so reading the signal A records top-to-bottom in
capture order yields a scrambled byte stream. That stream has no valid zlib
header/Adler-32, so it fails to inflate -- it never produces the flag. The test
(`ordering-is-the-crux`) performs exactly this naive recovery and asserts it
does **not** expose the flag. The ordering step -- using the `up-<N>` label --
is the crux, not decoration.


## Section-7 decoy (bounded, benign, rejectable)

A second, unrelated DNS flow resolves `telemetry-optout.svc.fleet.internal` as a
TXT record whose string contains `zsctf_demo{optout_advisory_<hex>}`. It is a
realistic opt-out advisory and an immediate `strings` hit, but it is rejectable
on two independent grounds:

1. **Wrong channel** -- it is a TXT record under a different service name, not
   the `up-<N>.cfg` A-record signal channel.
2. **Wrong format** -- `zsctf_demo{...}` is not `zerosecurectf{...}`.

The test confirms the token is present yet a decoy-only recovery never yields a
valid flag.


## Determinism & per-instance

`build(seed, flag)` is pure integer/hash arithmetic over fixed inputs plus a
fixed zlib level, so `same ZSCTF_SEED + same ZSCTF_FLAG` -> byte-identical pcap
(a `DRBG` built from `SHA-256(seed || counter)` -- version-independent, unlike
relying on `random`'s internal state). A different seed changes txids, ephemeral
ports, IP ids, the shuffle, TTLs, the coordinator/member addresses, the benign
noise, and the decoy suffix -- different bytes, same solvable structure. The
flag text comes only from `ZSCTF_FLAG`.


## HONEST difficulty band: **Medium-Hard**

Grounds for the band (not inflated):

- **Depth / chain (moderate):** four real steps -- signal isolation, query/
  response linkage, label-ordered reassembly, inflate-with-integrity-gate. More
  than a one-liner, but each step is a standard analyst operation.
- **Guessiness: minimal.** Every discriminator is a concrete, documented
  invariant (`up-<N>.cfg.fleet.internal`, pool tag `100`, A-record RDATA). There
  is nothing to brute-force; the Adler-32 gate tells you when the order is right.
- **Not Hard:** the covert channel is a well-known pattern (data in A-record
  octets), the encoding is linear, and there is no cryptographic or
  heavy-search component. A competent analyst with Wireshark + a short script
  finishes in well under an hour.


## Lineage (system.html section 17)

- **Source:** `snchakri/zerosecurectf2026_challenges: networking/ch5_mirage_resolver`
  -- "DNS covert channel where the real payload hides in A-record response IP
  octets while the query names are intentional misdirection." (Read read-only as
  untrusted reference; no source code executed; nothing copied verbatim.)
- **Operators applied (section 17.3):**
  - **RESKIN** -- new name/scenario/data/flag: a benign appliance-fleet manifest
    publisher instead of a "mirage resolver".
  - **CONSTRAIN** -- added strict query<->response linkage (txid + client port +
    echoed question) so unsolicited responses are rejected, and tightened the
    decoy to a channel+format double-rejection.
  - **GROUND** (from `zsctf-forensics-008` RoastToRoot) -- traffic-only
    visibility as the sole guard.
- **What changed vs the source (harder + no-strings):**
  1. payload is **zlib-compressed** before spraying, so `strings` cannot recover
     it (source octets were plaintext-recoverable);
  2. capture order is **seed-shuffled** and the true order lives in the `up-<N>`
     label, making **ordered reassembly** the crux (source was readable in
     capture order);
  3. a **zlib Adler-32 self-verifying gate** replaces "just read the octets";
  4. full **per-instance** variation via a SHA-256 DRBG.
- **corpus-genome.yaml:** this challenge is a RESKIN/CONSTRAIN/GROUND composite
  of the networking DNS-covert-channel genome; see `challenge.yml: lineage` for
  the machine-readable record.


## Safety / scope

Benign network-protocol forensics on an ordinary internal DNS conversation. No
malware, C2, beaconing, exfiltration tooling or intrusion technique is present
or implied. The only skill exercised is correct DNS parsing, signal isolation,
ordered reassembly and inflation -- standard analyst work.
