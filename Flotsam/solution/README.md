# Flotsam — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py challenge/flotsam.pcap
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Flotsam — intended solution & design notes

**Category:** network · **Band:** Medium–Hard · **Flag:** `zerosecurectf{...}` (from `ZSCTF_FLAG`)
Default artifact flag: `zerosecurectf{tcp_stream_reassembled_then_zip_inflated}`

---


## 1. The artifact

A single classic libpcap file (`.pcap`, Ethernet → IPv4 → TCP), ~4 KB, 26
packets. It opens cleanly in Wireshark / `tshark` / `tcpdump` / scapy. It
contains two ordinary, benign TCP conversations from one workstation
(`10.42.7.21`):

- a plain-HTTP **download** of `site-backup-XXXX.zip` from an internal file
  server `10.42.7.9:80` (3-way handshake, `GET`, a segmented `200 OK`, FINs), and
- a plain-HTTP fetch of `notes.txt` from an internal wiki host `10.42.7.33:80`.

Casual byte tools (`strings`, `grep`, `binwalk`, hex scan) do **not** reveal the
flag: by construction the flag only exists DEFLATE-compressed inside a ZIP that
is itself carried, segmented and reordered, inside the download's TCP stream.


## 2. Intended solution (ordinary network-protocol forensics)

### Step 1 — separate the conversations

Group packets into TCP flows by the 4-tuple (src IP, src port, dst IP, dst
port). There are two: the file download and the wiki note. In Wireshark this is
*Statistics → Conversations* or right-click → *Follow → TCP Stream*.

### Step 2 — reassemble the download **by sequence number**

The server→client segments of the `200 OK` were captured **out of order** (the
generator permutes their emission order with the per-instance seed) and include
one **retransmission** (a duplicated segment). Concatenating payloads in capture
(file) order is therefore *wrong*. Order the data-bearing segments by their TCP
sequence number and lay each segment's bytes at its absolute offset
(`seq − first_data_seq`); identical retransmissions are idempotent at the same
offset. This is exactly what Wireshark's "Follow TCP Stream" / `tcp.reassembled`
does; the reference solver does it by hand in `reassemble()`.

### Step 3 — split HTTP headers from body

The reassembled server stream begins:

```
HTTP/1.1 200 OK
Server: nginx/1.24.0
Content-Type: application/zip
Content-Disposition: attachment; filename="site-backup-XXXX.zip"
Content-Length: <N>
Connection: close

<N bytes of ZIP>
```

Split at the blank line (`\r\n\r\n`) and take `Content-Length` bytes of body.

### Step 4 — parse the ZIP and inflate

The body starts with the ZIP local-file-header magic `PK\x03\x04`. Walk each
local file header:

```
sig(4)=0x04034b50 | ver(2) | flags(2) | method(2) | time(2) | date(2)
   | crc32(4) | comp_size(4) | uncomp_size(4) | name_len(2) | extra_len(2)
   | name | extra | compressed-data
```

The entries are stored with method **8 (DEFLATE)**, so the compressed data is a
**raw DEFLATE** stream — inflate it with `zlib.decompress(data, -15)`. One entry
is a benign README (seed-varied filler); the other is a short "restore record"
whose text contains `flag: zerosecurectf{...}`.

### Step 5 — the self-verifying gate

Each ZIP entry stores a **CRC-32** of its *uncompressed* contents. The solver
recomputes `zlib.crc32(inflated)` and checks it against the stored value. This
is the analogue of a CRC-framed payload: a wrong segment order, a dropped or
duplicated byte, or a wrong header/body split produces a corrupt archive whose
entry CRC will not match. Correct recovery validates and yields the flag; there
is nothing to brute-force or guess.

The reference solver [`solution/solve.py`](solution/solve.py) does all of this in
stdlib only (`struct`, `zlib`, `re`) and prints the flag. It does **not** import
the generator — it reconstructs the method from the (standard, in-capture)
protocols.

### Why the stated facts are verifiable

  **and** TCP checksum (over the standard pseudo-header) and asserts they are
  valid; scapy/Wireshark parse it without warnings.
- *Flag never appears as bytes:* check 4 asserts neither the flag nor
  `zerosecurectf{` occurs in the raw `.pcap`; the flag only exists after
  reassembly + inflation.
- *Reassembly is load-bearing:* check 6 performs the naive file-order
  concatenation of all port-80 payloads and asserts the flag does **not** fall
  out — sequence reassembly is required, not decoration.
- *Deterministic + per-instance:* check 3 (same seed+flag ⇒ byte-identical) and
  check 5 (different seed ⇒ different bytes, still recoverable; different flag ⇒
  recovered correctly).


## 3. Why this is fair and not guessy (the §19 invariant)

Every step has a concrete reasoning handle, so the design respects the "no
guessing" invariant (system.html §2, §19):

| Could be guessed? | The tell that removes the guess |
|---|---|
| "Which flow matters?" | one flow's reassembled body is a ZIP (`PK\x03\x04`); the other is plain text |
| "File order or sequence order?" | sequence numbers are present and visibly non-monotonic in capture order; following by seq yields a clean `HTTP/1.1 200` |
| "Where is the payload?" | `Content-Type: application/zip` + a ZIP magic + a standard ZIP directory |
| "How is it compressed?" | ZIP method field = 8 (DEFLATE); inflate with raw-deflate |
| "Did I get it right?" | the per-entry **CRC-32** validates or it doesn't |

The "signal in noise" difficulty (reordering + a decoy flow + a retransmission)
is raised *with a tell at every layer*, which is the discipline system.html
§18-B demands — "noise with no tell → guessiness."


## 4. Red-team / AI-resistance

**Honest banding first.** This is a **Medium–Hard** network-forensics item, not
Frontier. TCP reassembly and ZIP parsing are standard, well-documented analyst
tasks that are heavily represented in training data and fully automated by
Wireshark's "Follow TCP Stream" + any ZIP reader. We do **not** claim this is
unsolvable, or even hard, for a capable agent with tool access. We claim a
*modest, real* differential concentrated in a few specific places, and we say
exactly where.

**How an AI agent (or any solver) would attempt it.**
1. `file`/`capinfos` → "pcap". `strings flotsam.pcap` → immediately finds the
   decoy `zsctf_demo{...}` token (intended trap) and the HTTP headers, but no
   flag and no readable archive contents.
2. Load into Wireshark/`tshark`/scapy, list conversations, "Follow TCP Stream"
   on the download. A competent agent *can* do this; it is a standard move.
3. Export the HTTP object / ZIP body, open the archive, read the entry. Also
   standard.

**Where solvers actually stumble (the real differential).**
- **Rejecting the decoy by reasoning, not reflex.** The single easiest thing to
  find — a `strings` hit that *looks* like a flag — is the wrong answer. A
  solver that pattern-matches "token-in-note = flag" submits `zsctf_demo{...}`
  and is rejected on format. The correct move is to notice it fails the
  `zerosecurectf{...}` format *and* that the real payload is an archive in the
  other flow. Fraction-of-relevant-material-is-low is a documented agent
  weakness (system.html §18-B: signal-to-noise ⇒ "↑↑ AI-differential").
- **Sequence reassembly vs. file order.** An agent that scripts its own parse
  (rather than leaning on Wireshark) may concatenate payloads in capture order
  and be silently corrupted by the reordering + the retransmission. The only
  feedback that something is wrong is the ZIP failing to parse / the CRC failing
  — there is no partial credit and no hint which convention was off. Getting the
  retransmission dedup and the absolute-offset placement right at once is the
  friction point.
- **Header/body + raw-deflate conventions.** Splitting exactly at `\r\n\r\n`,
  honouring `Content-Length`, and inflating ZIP data as **raw** DEFLATE
  (`wbits=-15`, not zlib-wrapped) are each a small convention that must be right
  before the CRC turns green.

**Is the resistance real?** Partially, and we do not overstate it. A strong
agent with Wireshark-equivalent tooling will likely solve Flotsam quickly,
because the platform does the reassembly and the archive step for it. The value
is as a *Medium–Hard* network item that (a) rewards correct protocol reasoning,
(b) punishes the "first `strings` hit = flag" reflex with a format-gated decoy,
(c) punishes naive file-order reassembly with a sequence-gated, CRC-verified
payload, and (d) is **per-instance parameterised** so a memorised walkthrough
does not transfer. The genuinely AI-hard regimes (long-horizon, novel formalism)
are explicitly *not* claimed here.

**The mechanism rejects guessing.** The payload is gated twice: it is not a
flag until you (1) reassemble the right flow by sequence and (2) inflate a ZIP
entry whose CRC-32 validates. Any deviation fails the CRC with no readable
output. You either reconstruct the method or you get nothing.

**Contamination note.** The *techniques* (TCP reassembly, HTTP, ZIP/DEFLATE,
CRC-32) are all public and in LLM training data — deliberately, so the challenge
is fair. What is **not** in any corpus is *this instance*: the flag, the ISNs,
ports, IP IDs, segment sizes, the reordering permutation, the archive member
names and the filler are generated per team from `ZSCTF_SEED`/`ZSCTF_FLAG`, so
no public writeup or cached solver output can be replayed. A leaked solution for
secret algorithm whose leak breaks all instances; secrecy lives only in the
per-instance seed.

**Human–AI differential (summary).** A human analyst with a forensics habit
reaches for "Follow TCP Stream", *sees* the ZIP, exports it and reads the entry;
the decoy is dismissed on sight because the format is wrong and it is not an
archive. Agents are strong once pointed at the right flow, but weaker at the
*orientation* step (reject the easy decoy; recognise the archive lives in the
reordered flow) and at holding the exact reassembly/parse conventions consistent
with zero feedback until the CRC. Net: a modest, real edge to a trained human at
the orientation and assembly steps; near-parity once the method is framed.


## 5. The §7 decoy (bounded)

The second conversation (`10.42.7.33:80`, `GET /triage/notes.txt`) is a benign
plaintext wiki note whose body contains, in clear text:

```
token: zsctf_demo{this_is_a_scratch_note_not_the_flag}
```

It is deliberately the **easiest** thing in the capture to find (a plain
`strings` hit), which makes it a genuine trap. It is **rejectable by reasoning
on two independent grounds**:

1. **Format.** It is `zsctf_demo{...}`, not `zerosecurectf{...}` — it fails the
   stated flag format.
2. **Structure.** The real payload is an *archive* carried over a *reassembled*
   stream; this flow's body is plain text and not a ZIP. The solver rejects it
   at the `body.startswith(b"PK\x03\x04")` check.

It is bounded: a single short flow, no second puzzle, no rabbit-hole — it exists
only to reward the format/structure check over the `strings` reflex.


## 6. Lineage (corpus deconstruction → reconstruction)

Grounded in `corpus-genome.yaml` and `system.html` (§16, §17, §18-B, §23).

- **Category:** forensics / DFIR seeds, network sub-family (system.html §16).
  The corpus has no benign *network*-forensics item — all 12 forensics seeds are
  R-class reconstructions of real incidents (intrusion, ransomware, C2). Flotsam
  is a deliberate **benign re-grounding** of the network sub-family: ordinary
  protocol analysis of a legitimate transfer, no attack framing.
- **Operators applied (system.html §17.3).**
  - `GROUND` (G9) — attach a concrete, benign scenario (a routine internal
    backup download) and a fully self-contained, standard-protocol artifact.
  - `CONSTRAIN` (G4) — visibility is *capture-only* and the flag is not
    byte-readable, forcing the reassemble-then-parse path. This is the explicit
    knob of `zsctf-forensics-008` *RoastToRoot* ("tighten visibility
    (traffic-only) as a knob") re-skinned benignly.
  - `PARAMETERISE` (§24) — `ZSCTF_SEED` → ISNs, ports, IP IDs, segment sizes,
    reorder permutation, member names → equally-hard per-instance variants, and
    `ZSCTF_FLAG` → the flag.
- **Affordance donors (genome `affordances`).**
  - `zsctf-forensics-008` *RoastToRoot* — crux *"detect … purely from captured
    traffic,"* affordances `[GROUND, CONSTRAIN]`, `reconstruct_idea: "tighten
    visibility (traffic-only) as a knob."` We borrow the **traffic-only
    visibility constraint** and re-cast the task benignly as *reconstructing a
    legitimate transfer* (no credential attack, no intrusion).
  - `zsctf-forensics-007` *Gh0stNet* — the abstract **"signal in noise"** crux
    shape and the SNR knob (§18-B). Re-cast benignly here as **out-of-order
    delivery + a retransmission + a second flow** (the "noise") against which
    sequence reassembly is the "signal." No C2, no beaconing.
  - `zsctf-forensics-011` *randomware* — affordance `PARAMETERISE`
    (*"per-instance weak key"*) supports the per-instance seed-derived capture.
- **Knob (system.html §18-B).** Signal-to-noise / reassembly burden: ↑ segment
  count, ↑ reorder entropy, ↑ decoy flows raise difficulty and the AI
  differential, with the explicit caveat *"noise with no tell → guessiness,"*
  which §3's tell-table and the CRC gate satisfy.
- **Class / banding.** Static-artifact delivery (§23: "file delivery + integrity
  hash; no live service; flag inside the artifact or per-instance §24"),
  network-forensics "medium–hard, regenerate the artifact per seed" → **Medium–Hard**.


## 7. Safety / scope

Benign by construction and by intent. Flotsam is **ordinary network-protocol
forensics**: a well-formed packet capture of a legitimate plain-HTTP file
download, solved by standard TCP reassembly + ZIP parsing. It is **not** malware,
not C2, not beaconing, not exfiltration, not an intrusion, and nothing in it is
weaponizable. Although affordance donors `forensics-007/008` are literally C2 /
credential-attack seeds, we imported **only** their abstract "signal in noise"
and "traffic-only visibility" shapes and deliberately re-grounded them as a
benign backup download with out-of-order delivery. The Docker image is a
generator that writes a file and exits (`network_mode: none`, read-only root FS,
all caps dropped, non-root).
