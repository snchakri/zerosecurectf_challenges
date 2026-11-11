#!/usr/bin/env python3
"""
Minimal traditional-PKWARE ("ZipCrypto") zip writer.

Python's stdlib zipfile can READ ZipCrypto (with pwd=) but cannot WRITE it, and
this box has no `zip`/`7z`/`pyzipper`. So we author one encrypted, STORED entry
by hand. Weak passwords in a wordlist crack instantly with fcrackzip/john, which
is exactly the intended "crack the zip" path.
"""
import os
import struct
import zlib

# Info-ZIP style CRC32 table (no pre/post inversion) used by the key schedule.
_CRCTAB = []
for i in range(256):
    c = i
    for _ in range(8):
        c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
    _CRCTAB.append(c)


def _crc32(crc, ch):
    return ((crc >> 8) ^ _CRCTAB[(crc ^ ch) & 0xFF]) & 0xFFFFFFFF


class _Keys:
    def __init__(self, pw: bytes):
        self.k0, self.k1, self.k2 = 0x12345678, 0x23456789, 0x34567890
        for b in pw:
            self.update(b)

    def update(self, b):
        self.k0 = _crc32(self.k0, b)
        self.k1 = (self.k1 + (self.k0 & 0xFF)) & 0xFFFFFFFF
        self.k1 = (self.k1 * 134775813 + 1) & 0xFFFFFFFF
        self.k2 = _crc32(self.k2, (self.k1 >> 24) & 0xFF)

    def stream_byte(self):
        t = (self.k2 | 2) & 0xFFFF
        return ((t * (t ^ 1)) >> 8) & 0xFF

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray()
        for p in data:
            out.append(p ^ self.stream_byte())
            self.update(p)
        return bytes(out)


def make_encrypted_zip(filename: str, data: bytes, password: str,
                       header_rand: bytes = None) -> bytes:
    """Return bytes of a .zip holding one ZipCrypto-encrypted, STORED file."""
    pw = password.encode()
    crc = zlib.crc32(data) & 0xFFFFFFFF

    # 12-byte encryption header; last byte is the CRC check byte (bit-3 unset).
    if header_rand is None:
        header_rand = os.urandom(11)
    check = (crc >> 24) & 0xFF
    enc_header_plain = header_rand + bytes([check])

    keys = _Keys(pw)
    enc_header = keys.encrypt(enc_header_plain)
    enc_data = keys.encrypt(data)
    blob = enc_header + enc_data

    name = filename.encode()
    flags = 0x0001          # encrypted
    method = 0              # stored
    mtime, mdate = 0x6000, 0x5000
    comp_size = len(blob)
    uncomp_size = len(data)

    local = struct.pack("<IHHHHHIIIHH",
                        0x04034B50, 20, flags, method, mtime, mdate,
                        crc, comp_size, uncomp_size, len(name), 0) + name
    local_off = 0
    local_record = local + blob

    central = struct.pack("<IHHHHHHIIIHHHHHII",
                         0x02014B50, 20, 20, flags, method, mtime, mdate,
                         crc, comp_size, uncomp_size, len(name),
                         0, 0, 0, 0, 0, local_off) + name

    cd_off = len(local_record)
    cd_size = len(central)
    eocd = struct.pack("<IHHHHIIH",
                      0x06054B50, 0, 0, 1, 1, cd_size, cd_off, 0)

    return local_record + central + eocd


if __name__ == "__main__":
    import io, zipfile
    z = make_encrypted_zip("classified.txt", b"DOOM{test_flag}\n", "trustno1")
    with zipfile.ZipFile(io.BytesIO(z)) as zf:
        print("read back:", zf.read("classified.txt", pwd=b"trustno1"))
