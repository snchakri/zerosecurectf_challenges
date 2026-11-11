#!/usr/bin/env python3
"""
ZSCTF :: Shallows -- reference solver (standalone; does NOT import the generator).

Intended path -- ordinary, beginner-level network-protocol inspection:

  1. Parse the classic .pcap. Walk Ethernet -> IPv4 -> TCP for every packet.
  2. Group packets into directed TCP flows (src_ip, src_port, dst_ip, dst_port)
     and reassemble each flow's byte stream by TCP sequence number. (The flows
     are small and in order -- this is a plain "Follow TCP Stream".)
  3. Find the flow that is an authenticated HTTP request: one that carries an
     `Authorization: Basic <base64>` header. (Wireshark's HTTP dissector shows
     the decoded "Credentials: user:password" for exactly this header.)
  4. Base64-decode the header value -> "user:password"; the password is the flag.

The decoy flow (a plaintext wiki note with a `zsctf_sample{...}` token) has no
Authorization header and is simply never selected.

Stdlib only (struct, base64, re, sys). No scapy, no numpy.

Usage:
    python3 solve.py <path-to.pcap>      # prints the flag (only) to stdout
"""
import base64
import re
import struct
import sys

FLAG_RE = re.compile(r"zerosecurectf\{[^}\r\n]*\}")
AUTH_RE = re.compile(rb"(?im)^Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)\s*$")


# ------------------------------- pcap parsing ------------------------------
def parse_pcap(raw: bytes):
    """Yield (ts, frame_bytes) for a classic libpcap file (any endianness)."""
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
        ts_sec, ts_usec, incl, orig = struct.unpack(end + "IIII", raw[pos:pos + 16])
        pos += 16
        frame = raw[pos:pos + incl]
        pos += incl
        pkts.append((ts_sec + ts_usec / 1e6, frame))
    return pkts


def parse_eth_ip_tcp(frame: bytes):
    """Return (src_ip, dst_ip, sport, dport, seq, flags, payload) or None."""
    if len(frame) < 14:
        return None
    ethertype = struct.unpack(">H", frame[12:14])[0]
    if ethertype != 0x0800:
        return None
    ip = frame[14:]
    if len(ip) < 20:
        return None
    ver_ihl = ip[0]
    if (ver_ihl >> 4) != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    proto = ip[9]
    if proto != 6:
        return None
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    total_len = struct.unpack(">H", ip[2:4])[0]
    tcp = ip[ihl:total_len] if total_len else ip[ihl:]
    if len(tcp) < 20:
        return None
    sport, dport, seq, ack = struct.unpack(">HHII", tcp[:12])
    data_off = (tcp[12] >> 4) * 4
    flags = tcp[13]
    payload = tcp[data_off:]
    return (src, dst, sport, dport, seq, flags, payload)


# --------------------------- stream reassembly -----------------------------
def reassemble(segs):
    """segs: list of (seq, payload). Rebuild the byte stream by sequence number.

    Trivial here (in-order, single segments) but done properly by sequence so
    the solver is robust to any ordering a tool might record.
    """
    data_segs = [(s, p) for (s, p) in segs if p]
    if not data_segs:
        return b""
    base = min(s for s, _ in data_segs)
    buf = bytearray()
    for seq, payload in sorted(data_segs, key=lambda x: x[0]):
        off = seq - base
        if off < 0:
            continue
        end = off + len(payload)
        if end > len(buf):
            buf.extend(b"\x00" * (end - len(buf)))
        buf[off:end] = payload
    return bytes(buf)


# --------------------------------- recover ---------------------------------
def recover(path: str) -> str:
    raw = open(path, "rb").read()
    pkts = parse_pcap(raw)

    flows = {}   # (src,sport,dst,dport) -> list of (seq, payload)
    for _ts, frame in pkts:
        parsed = parse_eth_ip_tcp(frame)
        if not parsed:
            continue
        src, dst, sport, dport, seq, _flags, payload = parsed
        flows.setdefault((src, sport, dst, dport), []).append((seq, payload))

    # Find the authenticated request flow: its reassembled client->server stream
    # carries an "Authorization: Basic <base64>" header.
    for key, segs in flows.items():
        stream = reassemble(segs)
        m = AUTH_RE.search(stream)
        if not m:
            continue
        try:
            cred = base64.b64decode(m.group(1), validate=True)
        except Exception:
            continue
        # HTTP Basic auth is "user:password"; the password is the flag.
        text = cred.decode("utf-8", "replace")
        if ":" not in text:
            continue
        _user, password = text.split(":", 1)
        fm = FLAG_RE.search(password) or FLAG_RE.search(text)
        if fm:
            return fm.group(0)

    raise ValueError("no Basic-auth credential decoding to a zerosecurectf{...} flag")


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: solve.py <path-to.pcap>\n")
        return 2
    try:
        flag = recover(argv[1])
    except Exception as e:  # noqa: BLE001
        sys.stderr.write("[-] recovery failed: %s\n" % e)
        return 1
    sys.stderr.write("[+] located Authorization: Basic header; base64-decoded "
                     "credentials; flag recovered\n")
    print(flag)              # stdout = exactly the flag
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
