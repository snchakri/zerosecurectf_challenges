#!/usr/bin/env python3
"""
ZSCTF :: Palimpsest -- reference solver (standalone; does NOT import the generator).

Intended path -- pure reasoning about the ZIP container in front of you:

  1. Open the archive the normal way (`zipfile`).  It lists a handful of benign
     files and nothing else.  Record each visible entry's LOCAL-HEADER OFFSET.
  2. Scan the raw bytes for every local-file-header signature "PK\\x03\\x04".
     There are MORE of them than the central directory admits to: the surplus
     records are ORPHANED -- physically present, but unreferenced by the index
     (the archiver rewrote the directory to "remove" files without erasing their
     data).  Parse and CRC-validate each one; keep those whose offset is not a
     visible entry.  THIS is the crux -- normal tools read only the directory.
  3. One orphan is a residual index: its data starts with MAGIC "ZPMF" and lists,
     in logical order, the CRC-32 of each payload segment.  The other orphans are
     the segments themselves (stored verbatim).
  4. Match each segment to its slot by CRC, concatenate in that order, and
     DEFLATE-inflate the result.  Out comes a self-verifying frame
         MAGIC "ZPLM" | VER | FLEN(2,BE) | FLAG | CRC32(4,BE)
     Wrong assembly fails the MAGIC/CRC; correct assembly yields the flag.
     Nothing is guessed.

Usage:
    python3 solve.py <path-to.zip>        # prints the flag (only) to stdout
"""
import io
import struct
import sys
import zipfile
import zlib

FRAME_MAGIC = b"ZPLM"
INDEX_MAGIC = b"ZPMF"
SIG_LFH = b"PK\x03\x04"


def visible_header_offsets(raw: bytes):
    """Offsets of the local headers the central directory actually references."""
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        return {zi.header_offset for zi in z.infolist()}, list(z.namelist())


def carve_local_headers(raw: bytes):
    """Find and CRC-validate every real local file header in the body.

    Returns a list of dicts: {offset, name, method, data}.  A bare "PK\\x03\\x04"
    that happens to occur inside compressed data is rejected because its implied
    fields will not be self-consistent or its CRC will not match.
    """
    out = []
    pos = raw.find(SIG_LFH)
    while pos != -1:
        rec = _parse_lfh(raw, pos)
        if rec is not None:
            out.append(rec)
        pos = raw.find(SIG_LFH, pos + 1)
    return out


def _parse_lfh(raw: bytes, off: int):
    if off + 30 > len(raw):
        return None
    (_sig, _ver, _flag, method, _t, _d, crc, comp, uncomp, nlen, elen) = \
        struct.unpack("<IHHHHHIIIHH", raw[off:off + 30])
    if method not in (0, 8) or nlen > 1024 or elen > 4096:
        return None
    name_end = off + 30 + nlen
    data_start = name_end + elen
    data_end = data_start + comp
    if data_end > len(raw):
        return None
    name = raw[off + 30:name_end]
    data = raw[data_start:data_end]
    # validate against the stored CRC-32 (over the *uncompressed* bytes).
    if method == 0:
        if (zlib.crc32(data) & 0xFFFFFFFF) != crc:
            return None
        plain = data
    else:
        try:
            plain = zlib.decompress(data, -15)
        except zlib.error:
            return None
        if (zlib.crc32(plain) & 0xFFFFFFFF) != crc:
            return None
        if len(plain) != uncomp:
            return None
    return {"offset": off, "name": name, "method": method, "data": data}


def parse_index(data: bytes):
    """Residual index -> list of segment CRC-32s in logical order."""
    if data[:4] != INDEX_MAGIC:
        raise ValueError("not an index record")
    ver = data[4]
    n = data[5]
    body_end = 6 + 4 * n
    crcs = [struct.unpack(">I", data[6 + 4 * i:10 + 4 * i])[0] for i in range(n)]
    stored = struct.unpack(">I", data[body_end:body_end + 4])[0]
    if (zlib.crc32(data[:body_end]) & 0xFFFFFFFF) != stored:
        raise ValueError("index self-CRC mismatch")
    return crcs


def parse_frame(blob: bytes) -> str:
    frame = zlib.decompress(blob)                      # zlib stream (with header)
    if frame[:4] != FRAME_MAGIC:
        raise ValueError("frame MAGIC mismatch -- wrong reassembly")
    _ver = frame[4]
    (flen,) = struct.unpack(">H", frame[5:7])
    end = 7 + flen
    flag = frame[7:end]
    (crc,) = struct.unpack(">I", frame[end:end + 4])
    if (zlib.crc32(frame[:end]) & 0xFFFFFFFF) != crc:
        raise ValueError("frame CRC mismatch -- recovery not validated")
    return flag.decode("utf-8")


def recover(path: str) -> str:
    raw = open(path, "rb").read()
    if raw[:4] != SIG_LFH and SIG_LFH not in raw[:4]:
        pass  # not all zips start at offset 0; we scan regardless
    visible_offsets, _visible_names = visible_header_offsets(raw)

    headers = carve_local_headers(raw)
    orphans = [h for h in headers if h["offset"] not in visible_offsets]
    if not orphans:
        raise ValueError("no orphaned local headers -- nothing to recover")

    # locate the residual index among the orphans.
    index_recs = [h for h in orphans if h["data"][:4] == INDEX_MAGIC]
    if len(index_recs) != 1:
        raise ValueError("expected exactly one residual index, found %d" % len(index_recs))
    order = parse_index(index_recs[0]["data"])
    segments = [h for h in orphans if h["data"][:4] != INDEX_MAGIC]

    # match each segment to its logical slot by CRC-32 of its stored bytes.
    by_crc = {}
    for h in segments:
        by_crc.setdefault(zlib.crc32(h["data"]) & 0xFFFFFFFF, []).append(h["data"])
    ordered = []
    for want in order:
        if not by_crc.get(want):
            raise ValueError("segment with CRC %08x missing" % want)
        ordered.append(by_crc[want].pop(0))
    blob = b"".join(ordered)

    return parse_frame(blob)


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: solve.py <path-to.zip>\n")
        return 2
    try:
        flag = recover(argv[1])
    except Exception as e:  # noqa: BLE001
        sys.stderr.write("[-] recovery failed: %s\n" % e)
        return 1
    sys.stderr.write("[+] reassembled from orphaned local headers; frame MAGIC+CRC ok\n")
    print(flag)                       # stdout = exactly the flag
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
