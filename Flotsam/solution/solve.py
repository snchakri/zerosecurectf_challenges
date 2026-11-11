#!/usr/bin/env python3
"""
ZSCTF :: Flotsam -- reference solver (standalone; does NOT import the generator).

Intended path -- ordinary network-protocol forensics on THIS capture:

  1. Parse the classic .pcap. Walk Ethernet -> IPv4 -> TCP for every packet.
  2. Group packets into directed TCP flows (src_ip, src_port, dst_ip, dst_port).
     There are two conversations: the file download and a decoy plaintext note.
  3. For each directed flow, reassemble the byte stream by TCP SEQUENCE NUMBER
     (NOT capture/file order -- the download's segments are reordered and one is
     retransmitted). Duplicate/overlapping bytes are resolved by sequence.
  4. Find the flow whose reassembled stream is an HTTP 200 response whose body
     is a ZIP archive (magic PK\\x03\\x04). The decoy response is plain text and
     is rejected here (not an archive).
  5. Split headers from body at the blank line; honour Content-Length.
  6. Parse the ZIP by hand: for each local file header, inflate the raw-DEFLATE
     data and VERIFY the stored CRC-32. A wrong reassembly fails this check.
  7. Read the flag (zerosecurectf{...}) out of the recovered files.

Stdlib only (struct, zlib, re, sys). No scapy, no numpy.

Usage:
    python3 solve.py <path-to.pcap>      # prints the flag (only) to stdout
"""
import re
import struct
import sys
import zlib

FLAG_RE = re.compile(rb"zerosecurectf\{[^}\r\n]*\}")


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

    Handles out-of-order delivery and retransmissions/overlap: bytes are placed
    at their absolute sequence offset relative to the lowest observed data seq.
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
        # write bytes; identical retransmissions are idempotent.
        buf[off:end] = payload
    return bytes(buf)


# ------------------------------- ZIP parsing -------------------------------
def zip_entries(blob: bytes):
    """Yield (name, inflated_bytes) for each local file header; verify CRC-32."""
    pos = 0
    out = []
    while True:
        sig = blob.find(b"PK\x03\x04", pos)
        if sig < 0:
            break
        hdr = blob[sig:sig + 30]
        if len(hdr) < 30:
            break
        (_, _, flags, method, _, _, crc, csize, usize,
         nlen, elen) = struct.unpack("<IHHHHHIIIHH", hdr)
        name_off = sig + 30
        name = blob[name_off:name_off + nlen].decode("utf-8", "replace")
        data_off = name_off + nlen + elen
        comp = blob[data_off:data_off + csize]
        try:
            if method == 8:
                raw = zlib.decompress(comp, -15)
            elif method == 0:
                raw = comp
            else:
                pos = data_off + csize
                continue
        except zlib.error:
            pos = data_off + csize
            continue
        crc_ok = (zlib.crc32(raw) & 0xFFFFFFFF) == crc
        out.append((name, raw, crc_ok))
        pos = data_off + csize
    return out


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

    # Reassemble every directed flow; keep the HTTP responses.
    responses = []
    for key, segs in flows.items():
        stream = reassemble(segs)
        if stream.startswith(b"HTTP/1.1 200") or stream.startswith(b"HTTP/1.0 200"):
            responses.append((key, stream))

    if not responses:
        raise ValueError("no HTTP 200 response stream reassembled")

    # Pick the response whose body is a ZIP archive (rejects the plaintext decoy).
    for key, stream in responses:
        split = stream.find(b"\r\n\r\n")
        if split < 0:
            continue
        headers = stream[:split].decode("latin-1")
        body = stream[split + 4:]
        m = re.search(r"(?im)^Content-Length:\s*(\d+)", headers)
        if m:
            body = body[:int(m.group(1))]
        if not body.startswith(b"PK\x03\x04"):
            continue   # decoy / non-archive response -> reject by reasoning

        entries = zip_entries(body)
        if not entries:
            continue
        # The ZIP's per-entry CRC-32 is the self-verifying gate: a wrong
        # reassembly corrupts the archive and fails here.
        for name, data, crc_ok in entries:
            if not crc_ok:
                raise ValueError("ZIP entry %r failed CRC-32 "
                                 "(reassembly corrupt)" % name)
        for name, data, _ in entries:
            fm = FLAG_RE.search(data)
            if fm:
                return fm.group(0).decode("ascii")

    raise ValueError("no flag found in any reassembled archive")


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: solve.py <path-to.pcap>\n")
        return 2
    try:
        flag = recover(argv[1])
    except Exception as e:  # noqa: BLE001
        sys.stderr.write("[-] recovery failed: %s\n" % e)
        return 1
    sys.stderr.write("[+] TCP stream reassembled; ZIP CRC-32 verified; flag recovered\n")
    print(flag)              # stdout = exactly the flag
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
