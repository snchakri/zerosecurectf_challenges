#!/usr/bin/env python3
"""
ZSCTF :: Undertow -- reference solver (standalone; does NOT import the generator).

Intended path -- ordinary network-protocol forensics on THIS capture:

  1. Parse the classic .pcap. Walk Ethernet -> IPv4 -> UDP -> DNS per packet.
  2. Collect DNS *queries* (QR=0) and *responses* (QR=1), keyed by
     (transaction-id, client-ephemeral-port, question-name).
  3. SIGNAL isolation: keep responses that
       - echo a question name matching  up-<N>.cfg.fleet.internal ,
       - carry an A record in the 100.0.0.0/8 tag pool, and
       - answer a real outstanding query (matching txid + port + question).
     Everything else -- benign noise A records outside the pool, and the TXT
     opt-out decoy carrying a `zsctf_demo{...}` token -- is rejected.
  4. ORDER the kept segments by the integer <N> from the query label (NOT by
     capture order; the pairs are emitted shuffled).
  5. Take the three low octets of each A record (octet 0 is the constant pool
     tag) and concatenate the 3-byte groups in N order.
  6. zlib-inflate the result. The trailing Adler-32 is the self-verifying gate:
     a wrong ordering will not inflate. The inflated bytes are the flag.

Stdlib only (struct, zlib, re, sys). No scapy, no numpy.

Usage:
    python3 solve.py <path-to.pcap>      # prints the flag (only) to stdout
"""
import re
import struct
import sys
import zlib

ZONE_RE  = re.compile(r"^up-(\d+)\.cfg\.fleet\.internal$")
POOL_TAG = 100


def walk_frames(raw):
    assert raw[:4] == b"\xd4\xc3\xb2\xa1", "bad pcap magic (expected classic LE libpcap)"
    pos = 24
    while pos + 16 <= len(raw):
        ts_sec, ts_usec, incl, orig = struct.unpack("<IIII", raw[pos:pos + 16])
        pos += 16
        yield raw[pos:pos + incl]
        pos += incl


def parse_name(buf, off):
    """Decode a DNS name (handles a single terminal compression pointer).
    Returns (name_str, offset_after_name_in_this_record)."""
    labels = []
    jumped = False
    end = off
    while True:
        length = buf[off]
        if length & 0xC0 == 0xC0:               # compression pointer
            ptr = ((length & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                end = off + 2
            off = ptr
            jumped = True
            continue
        if length == 0:
            off += 1
            if not jumped:
                end = off
            break
        labels.append(buf[off + 1:off + 1 + length].decode("latin1"))
        off += 1 + length
    return ".".join(labels), end


def parse_dns(buf):
    """Return a dict or None if not a parseable DNS message."""
    if len(buf) < 12:
        return None
    txid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", buf[:12])
    off = 12
    questions = []
    for _ in range(qd):
        name, off = parse_name(buf, off)
        qtype, qclass = struct.unpack(">HH", buf[off:off + 4])
        off += 4
        questions.append((name, qtype))
    answers = []
    for _ in range(an):
        _name, off = parse_name(buf, off)
        atype, aclass, ttl, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
        off += 10
        rdata = buf[off:off + rdlen]
        off += rdlen
        answers.append((atype, rdata))
    return dict(txid=txid, qr=(flags >> 15) & 1, questions=questions, answers=answers)


def dns_records(raw):
    """Yield (udp_sport, udp_dport, dns_dict) for every DNS packet."""
    for fr in walk_frames(raw):
        if len(fr) < 14 or struct.unpack(">H", fr[12:14])[0] != 0x0800:
            continue
        ip = fr[14:]
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 17:                          # UDP only
            continue
        total = struct.unpack(">H", ip[2:4])[0]
        udp = ip[ihl:total]
        if len(udp) < 8:
            continue
        sport, dport, ulen, _ck = struct.unpack(">HHHH", udp[:8])
        if 53 not in (sport, dport):
            continue
        dns = parse_dns(udp[8:ulen])
        if dns is not None:
            yield sport, dport, dns


def solve(raw):
    # index outstanding queries by (txid, client_port, qname)
    queries = set()
    responses = []
    for sport, dport, dns in dns_records(raw):
        if not dns["questions"]:
            continue
        qname = dns["questions"][0][0]
        qtype = dns["questions"][0][1]
        if dns["qr"] == 0:                       # query: client(sport) -> :53
            queries.add((dns["txid"], sport, qname, qtype))
        else:                                    # response: :53 -> client(dport)
            responses.append((dns["txid"], dport, qname, qtype, dns["answers"]))

    segments = {}
    for txid, cport, qname, qtype, answers in responses:
        m = ZONE_RE.match(qname)
        if not m or qtype != 1:
            continue
        # must answer a real outstanding query (reject unsolicited/mismatched)
        if (txid, cport, qname, 1) not in queries:
            continue
        for atype, rdata in answers:
            if atype == 1 and len(rdata) == 4 and rdata[0] == POOL_TAG:
                segments[int(m.group(1))] = rdata[1:4]
                break

    if not segments:
        raise SystemExit("no signal segments found")

    blob = b"".join(segments[i] for i in sorted(segments))
    # self-verifying gate: zlib stream + trailing Adler-32; trailing zero pad
    # lands in unused_data and is ignored.
    dco = zlib.decompressobj()
    flag = dco.decompress(blob)
    flag += dco.flush()
    return flag.decode("utf-8")


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: solve.py <path-to.pcap>\n")
        return 2
    with open(sys.argv[1], "rb") as fh:
        raw = fh.read()
    print(solve(raw))
    return 0


if __name__ == "__main__":
    sys.exit(main())
