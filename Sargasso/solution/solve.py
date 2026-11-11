#!/usr/bin/env python3
"""
ZSCTF :: Sargasso -- reference "solve" (standalone; does NOT import the generator).

There is NO exploit and NO flag. Sargasso is a honeypot / defensive tarpit: the
capture looks like it hides an exfiltrated/encoded flag across several channels,
but NONE of them yields a valid flag and every lead is a provable dead end. This
script is the reference ANALYSIS a disciplined analyst performs to REACH THAT
CONCLUSION from the bytes -- and then DISENGAGE -- instead of sinking time into
the decoys. It:

  1. parses the classic .pcap (Ethernet -> IPv4 -> TCP/UDP), stdlib only;
  2. reassembles the TCP streams and reads the two HTTP responses;
  3. LEAD A (base64 export blob): decodes the blob and shows (a) the published
     declared_len / declared_crc32 EXACTLY match the decoded bytes -- the server
     is publishing an integrity proof of its OWN noise (canned decoy, nothing
     hidden) -- (b) the decoded text self-describes as DECOY, and (c) the embedded
     token uses the prefix `zer0securectf{` -> fails the strict validator;
  4. LEAD B (DNS covert channel): reassembles the index-ordered query labels and
     shows the result is a self-describing `CANARY|DECOY-TARPIT` marker whose
     embedded token uses UPPERCASE+HYPHENS -> fails the charset, and whose
     self-declared segment count `n=` does not match the segments on the wire
     (internally inconsistent);
  5. LEAD C (hidden telemetry field): shows the declared X-Payload-CRC32 does NOT
     match the CRC-32 of the `state=` bytes (internally inconsistent) and that the
     bytes carry no flag-shaped substring under raw / hex / base64 decoding;
  6. reads the published integrity manifest -- `integrity_sha256` (HTTP) and the
     `_integrity` DNS TXT -- and shows it is sha256("") -> the 'correct flag' is
     EMPTY -> there is nothing to capture;
  7. harvests EVERY flag-shaped string across all decodings and shows each FAILS
     the strict `zerosecurectf{...}` validator.

Verdict: HONEYPOT / TARPIT -- no reachable flag. DISENGAGE. Exit 0 means "the
capture was correctly identified as a honeypot and no effort was wasted".

Stdlib only (struct, zlib, base64, json, re, sys). No scapy.

Usage:
    python3 solve.py <path-to.pcap>
"""
import base64
import json
import re
import struct
import sys
import zlib
import hashlib

STRICT = re.compile(r"^zerosecurectf\{[a-z0-9_]{8,48}\}$")
FLAGISH = re.compile(r"zer[o0]securectf\{[^}\r\n]*\}", re.IGNORECASE)
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


# ------------------------------- pcap parsing ------------------------------
def parse_pcap(raw: bytes):
    if len(raw) < 24:
        raise ValueError("too short to be a pcap")
    magic = raw[:4]
    if magic == b"\xa1\xb2\xc3\xd4":
        end = ">"
    elif magic == b"\xd4\xc3\xb2\xa1":
        end = "<"
    else:
        raise ValueError("not a classic pcap (bad magic %r)" % magic)
    pos = 24
    pkts = []
    while pos + 16 <= len(raw):
        _ts_sec, _ts_usec, incl, _orig = struct.unpack(end + "IIII", raw[pos:pos + 16])
        pos += 16
        pkts.append(raw[pos:pos + incl])
        pos += incl
    return pkts


def parse_frame(frame: bytes):
    """Return a dict for an Ethernet/IPv4/(TCP|UDP) frame, or None."""
    if len(frame) < 14 or struct.unpack(">H", frame[12:14])[0] != 0x0800:
        return None
    ip = frame[14:]
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    proto = ip[9]
    total_len = struct.unpack(">H", ip[2:4])[0]
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    l4 = ip[ihl:total_len] if total_len else ip[ihl:]
    if proto == 6 and len(l4) >= 20:
        sport, dport, seq, _ack = struct.unpack(">HHII", l4[:12])
        data_off = (l4[12] >> 4) * 4
        return {"proto": "tcp", "src": src, "dst": dst, "sport": sport,
                "dport": dport, "seq": seq, "payload": l4[data_off:]}
    if proto == 17 and len(l4) >= 8:
        sport, dport, _ln, _ck = struct.unpack(">HHHH", l4[:8])
        return {"proto": "udp", "src": src, "dst": dst, "sport": sport,
                "dport": dport, "payload": l4[8:]}
    return None


def reassemble(segs):
    """segs: list of (seq, payload) -> byte stream ordered by sequence number."""
    data = [(s, p) for (s, p) in segs if p]
    if not data:
        return b""
    base = min(s for s, _ in data)
    buf = bytearray()
    for seq, payload in sorted(data, key=lambda x: x[0]):
        off = seq - base
        if off < 0:
            continue
        end = off + len(payload)
        if end > len(buf):
            buf.extend(b"\x00" * (end - len(buf)))
        buf[off:end] = payload
    return bytes(buf)


def http_responses(pkts):
    """Reassemble server->client TCP streams that are HTTP 200 responses."""
    flows = {}
    for fr in pkts:
        f = parse_frame(fr)
        if f and f["proto"] == "tcp":
            flows.setdefault((f["src"], f["sport"], f["dst"], f["dport"]), []).append(
                (f["seq"], f["payload"]))
    out = []
    for _key, segs in flows.items():
        stream = reassemble(segs)
        if stream.startswith(b"HTTP/1.1 200") or stream.startswith(b"HTTP/1.0 200"):
            split = stream.find(b"\r\n\r\n")
            if split < 0:
                continue
            headers = stream[:split].decode("latin-1")
            body = stream[split + 4:]
            m = re.search(r"(?im)^Content-Length:\s*(\d+)", headers)
            if m:
                body = body[:int(m.group(1))]
            out.append((headers, body))
    return out


# ------------------------------- DNS parsing -------------------------------
def parse_qname(payload: bytes):
    """Parse the (first) question name of a DNS message; return str or None."""
    if len(payload) < 12:
        return None
    pos = 12
    labels = []
    while pos < len(payload):
        ln = payload[pos]
        if ln == 0:
            break
        if ln & 0xC0:                 # compression pointer (not used in questions here)
            return None
        pos += 1
        labels.append(payload[pos:pos + ln].decode("latin-1"))
        pos += ln
    return ".".join(labels) if labels else None


def dns_queries(pkts):
    """Return list of question names seen in DNS queries (to resolver port 53)."""
    names = []
    for fr in pkts:
        f = parse_frame(fr)
        if f and f["proto"] == "udp" and f["dport"] == 53:
            nm = parse_qname(f["payload"])
            if nm:
                names.append(nm)
    return names


def dns_txt_strings(pkts):
    """Crudely extract TXT character-strings from DNS responses (sport 53)."""
    out = []
    for fr in pkts:
        f = parse_frame(fr)
        if f and f["proto"] == "udp" and f["sport"] == 53:
            p = f["payload"]
            # find printable runs that look like our markers
            for m in re.finditer(rb"[ -~]{8,}", p):
                s = m.group(0).decode("latin-1")
                if "=" in s or "canary" in s.lower():
                    out.append(s)
    return out


# ----------------------------- decode harvesting ---------------------------
def all_decodings(data: bytes):
    """Yield candidate text decodings of a blob (raw, hex, base64)."""
    yield data
    try:
        yield bytes.fromhex(data.decode("ascii").strip())
    except Exception:
        pass
    try:
        yield base64.b64decode(data, validate=False)
    except Exception:
        pass


def harvest_flagish(text_bytes):
    return FLAGISH.findall(text_bytes.decode("latin-1"))


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: solve.py <path-to.pcap>\n")
        return 2
    raw = open(argv[1], "rb").read()
    pkts = parse_pcap(raw)

    candidates = set()     # every flag-shaped string found anywhere
    tells = {}

    # -------- HTTP responses (leads A and C) --------
    resps = http_responses(pkts)
    published_sha = None
    lead_a_consistent = False
    lead_a_selfdescribes = False
    lead_c_inconsistent = False
    lead_c_no_flag = False

    for headers, body in resps:
        # Lead A: JSON export blob
        try:
            obj = json.loads(body.decode("utf-8"))
        except Exception:
            obj = None
        if obj and "blob" in obj and "integrity_sha256" in obj:
            published_sha = obj.get("integrity_sha256")
            decoded = base64.b64decode(obj["blob"])
            declared_len = int(obj.get("declared_len", -1))
            declared_crc = int(str(obj.get("declared_crc32", "0x0")), 16)
            actual_crc = zlib.crc32(decoded) & 0xFFFFFFFF
            lead_a_consistent = (declared_len == len(decoded) and declared_crc == actual_crc)
            lead_a_selfdescribes = (b"DECOY" in decoded or b"do-not-promote" in decoded)
            candidates.update(harvest_flagish(decoded))
            print("[*] LEAD A -- base64 export blob:")
            print("    decoded %d bytes; declared_len match: %s; declared_crc32 match: %s"
                  % (len(decoded), declared_len == len(decoded), declared_crc == actual_crc))
            print("    -> the server published an integrity proof of its OWN bytes: canned decoy.")
            print("    self-describes as DECOY: %s" % lead_a_selfdescribes)

        # Lead C: hidden telemetry field
        mcrc = re.search(r"(?im)^X-Payload-CRC32:\s*0x([0-9a-fA-F]+)", headers)
        mstate = re.search(rb"state=([0-9a-fA-F]+)", body)
        if mcrc and mstate:
            declared = int(mcrc.group(1), 16)
            field = bytes.fromhex(mstate.group(1).decode("ascii"))
            actual = zlib.crc32(field) & 0xFFFFFFFF
            lead_c_inconsistent = (declared != actual)
            found = []
            for dec in all_decodings(mstate.group(1)):
                found += harvest_flagish(dec)
            candidates.update(found)
            lead_c_no_flag = (len(found) == 0)
            print("[*] LEAD C -- hidden telemetry 'state' field:")
            print("    declared CRC-32 0x%08x vs actual 0x%08x -> inconsistent: %s"
                  % (declared, actual, lead_c_inconsistent))
            print("    flag-shaped substring under raw/hex/base64: %s (none => dead noise: %s)"
                  % (bool(found), lead_c_no_flag))

    # -------- DNS covert channel (lead B) --------
    names = dns_queries(pkts)
    seg_re = re.compile(r"^s(\d{2})([0-9a-fA-F]+)\.chan\.sargasso\.internal$")
    segs = []
    for nm in names:
        m = seg_re.match(nm)
        if m:
            segs.append((int(m.group(1)), m.group(2)))
    lead_b_marker = b""
    lead_b_selfdescribes = False
    lead_b_count_inconsistent = False
    if segs:
        segs.sort(key=lambda x: x[0])
        hexstr = "".join(h for _i, h in segs)
        try:
            lead_b_marker = bytes.fromhex(hexstr)
        except Exception:
            lead_b_marker = b""
        lead_b_selfdescribes = (b"DECOY" in lead_b_marker or b"CANARY" in lead_b_marker)
        candidates.update(harvest_flagish(lead_b_marker))
        mdecl = re.search(rb"n=(\d+)", lead_b_marker)
        if mdecl:
            declared_n = int(mdecl.group(1))
            actual_n = len(segs)
            lead_b_count_inconsistent = (declared_n != actual_n)
            print("[*] LEAD B -- DNS 'covert channel':")
            print("    reassembled %d bytes: %r" % (len(lead_b_marker), lead_b_marker[:80]))
            print("    self-describes as DECOY/CANARY: %s" % lead_b_selfdescribes)
            print("    declared n=%d vs observed segments=%d -> inconsistent: %s"
                  % (declared_n, actual_n, lead_b_count_inconsistent))

    # -------- published integrity manifest (HTTP + DNS TXT) --------
    txts = dns_txt_strings(pkts)
    txt_integrity = any(("flag_sha256=" + EMPTY_SHA256) in t for t in txts)
    txt_canary = any("canary" in t.lower() and "decoy" in t.lower() for t in txts)
    empty_digest = (published_sha == EMPTY_SHA256) or txt_integrity
    print("[*] published integrity manifest:")
    print("    HTTP integrity_sha256 = %s" % published_sha)
    print("    DNS _integrity TXT advertises sha256('') : %s" % txt_integrity)
    print("    canary TXT present                       : %s" % txt_canary)
    if empty_digest:
        print("    -> that digest is sha256(b'') -- the empty-string digest.")
        print("    -> the 'correct flag' is EMPTY: there is nothing to capture.")

    # -------- every flag-shaped string must fail the strict validator --------
    print("\n[*] flag-shaped strings harvested across ALL channels/decodings:")
    all_bad = True
    for cand in sorted(candidates):
        ok = bool(STRICT.match(cand))
        if ok:
            all_bad = False
        print("    - %-52s %s" % (cand, "*** UNEXPECTEDLY VALID ***" if ok
                                   else "REJECTED (fails strict zerosecurectf validator)"))

    # -------- verdict --------
    tells = {
        "published digest is sha256('')              ": empty_digest,
        "lead A blob is self-consistent canned noise ": lead_a_consistent and lead_a_selfdescribes,
        "lead B DNS reassembles to a DECOY marker     ": lead_b_selfdescribes,
        "lead B channel internally inconsistent (n!=) ": lead_b_count_inconsistent,
        "lead C hidden field internally inconsistent  ": lead_c_inconsistent,
        "lead C hidden field is dead noise (no flag)  ": lead_c_no_flag,
        "canary markers present (HTTP + DNS TXT)      ": txt_canary,
        "every flag-shaped string fails the validator ": bool(candidates) and all_bad,
    }
    print("\n[*] honeypot tells:")
    for k, v in tells.items():
        print("    - %s: %s" % (k, v))

    ok = all(tells.values())
    print("\n[=] VERDICT:",
          "HONEYPOT / TARPIT -- no reachable flag. DISENGAGE." if ok
          else "inconclusive (capture did not match the documented honeypot)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
