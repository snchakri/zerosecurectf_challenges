#!/usr/bin/env python3
"""
DISK SLACK - build script.

Authors a small raw FAT12 disk image (dist/evidence.img) by hand, planting
one decoy in each of the three classic "there's nothing left" spots:

  * a DELETED file (dir entry marked 0xE5, data still on disk)  -> BAIT
  * SLACK SPACE of a live file (bytes between EOF and cluster end) -> EARNED-FAKE
  * an UNALLOCATED cluster (no dir entry, FAT entry free)        -> EGG

Decoy strings (LOCKED):
  bait        : DOOM{d3l3t3d_n0t_g0n3}      (recovered deleted file secret.txt)
  earned-fake : DOOM{sl4ck_sp4c3_sn00p3r}   (slack space of readme.txt)
  egg         : "unallocated and unpopulated, like this bunker. no flag was ever written here."
"""
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")

BAIT = "DOOM{d3l3t3d_n0t_g0n3}"
EARNED_FAKE = "DOOM{sl4ck_sp4c3_sn00p3r}"
EGG = "unallocated and unpopulated, like this bunker. no flag was ever written here."

# ---- geometry ----
BPS = 512            # bytes per sector
SPC = 1              # sectors per cluster
RESERVED = 1         # reserved sectors (boot)
NFATS = 2
ROOT_ENTS = 16       # 16 * 32 = 512 = 1 sector
SPF = 1              # sectors per FAT
TOTAL_SECTORS = 128  # 64 KiB image

# derived
FAT_START = RESERVED                       # sector 1
ROOT_START = RESERVED + NFATS * SPF        # sector 3
DATA_START = ROOT_START + (ROOT_ENTS * 32 + BPS - 1) // BPS  # sector 4
DATA_SECTORS = TOTAL_SECTORS - DATA_START
NUM_CLUSTERS = DATA_SECTORS                # SPC=1

# cluster assignments
CL_README = 2
CL_SECRET = 3        # deleted file's old data cluster
CL_EGG = 10          # never referenced by any directory entry


def boot_sector() -> bytes:
    b = bytearray(BPS)
    b[0:3] = b"\xEB\x3C\x90"                     # jmp + nop
    b[3:11] = b"DOOMSDAY"                          # OEM
    struct.pack_into("<H", b, 11, BPS)             # bytes/sector
    b[13] = SPC                                     # sectors/cluster
    struct.pack_into("<H", b, 14, RESERVED)        # reserved sectors
    b[16] = NFATS                                   # number of FATs
    struct.pack_into("<H", b, 17, ROOT_ENTS)       # root entries
    struct.pack_into("<H", b, 19, TOTAL_SECTORS)   # total sectors (16-bit)
    b[21] = 0xF8                                     # media descriptor
    struct.pack_into("<H", b, 22, SPF)             # sectors/FAT
    struct.pack_into("<H", b, 24, 18)              # sectors/track
    struct.pack_into("<H", b, 26, 2)               # heads
    b[38] = 0x29                                     # extended boot sig
    struct.pack_into("<I", b, 39, 0xD00D5DA7)      # volume id
    b[43:54] = b"BUNKER VOL ".ljust(11)[:11]        # volume label
    b[54:62] = b"FAT12   "                          # fs type
    b[510:512] = b"\x55\xAA"                         # boot signature
    return bytes(b)


def pack_fat12(entries) -> bytes:
    out = bytearray()
    i = 0
    while i < len(entries):
        a = entries[i] & 0xFFF
        c = (entries[i + 1] & 0xFFF) if i + 1 < len(entries) else 0
        out.append(a & 0xFF)
        out.append(((a >> 8) & 0x0F) | ((c & 0x0F) << 4))
        out.append((c >> 4) & 0xFF)
        i += 2
    return bytes(out)


def dir_entry(name8, ext3, attr, first_cluster, size, deleted=False) -> bytes:
    e = bytearray(32)
    nm = (name8.ljust(8)[:8] + ext3.ljust(3)[:3]).encode()
    e[0:11] = nm
    if deleted:
        e[0] = 0xE5
    e[11] = attr
    struct.pack_into("<H", e, 22, 0x6000)   # write time
    struct.pack_into("<H", e, 24, 0x5000)   # write date
    struct.pack_into("<H", e, 26, first_cluster)
    struct.pack_into("<I", e, 28, size)
    return bytes(e)


def main():
    os.makedirs(DIST, exist_ok=True)
    img = bytearray(TOTAL_SECTORS * BPS)

    # boot sector
    img[0:BPS] = boot_sector()

    # FAT: cluster 0/1 reserved, readme=EOC, secret freed (deleted), egg free
    entries = [0x000] * NUM_CLUSTERS
    entries[0] = 0xFF8
    entries[1] = 0xFFF
    entries[CL_README] = 0xFFF   # EOC for readme
    entries[CL_SECRET] = 0x000   # freed on delete (data remains)
    entries[CL_EGG] = 0x000      # unallocated
    fat = pack_fat12(entries).ljust(SPF * BPS, b"\x00")
    for n in range(NFATS):
        off = (FAT_START + n * SPF) * BPS
        img[off:off + len(fat)] = fat

    # root directory
    readme_text = (
        b"BUNKER README\r\n"
        b"all systems nominal. perimeter cold. morale: lower.\r\n"
        b"if you are reading this, you got in. there is nothing to take.\r\n"
    )
    secret_text = (
        b"SECRET // for the eyes of the duty officer only\r\n"
        + BAIT.encode() + b"\r\n"
        b"burn after reading. (it was not burned.)\r\n"
    )

    root = bytearray()
    root += dir_entry("BUNKER", "", 0x08, 0, 0)  # volume label entry
    root += dir_entry("README", "TXT", 0x20, CL_README, len(readme_text))
    root += dir_entry("SECRET", "TXT", 0x20, CL_SECRET, len(secret_text),
                      deleted=True)
    root = root.ljust(ROOT_ENTS * 32, b"\x00")
    img[ROOT_START * BPS: ROOT_START * BPS + len(root)] = root

    def cluster_off(cl):
        return (DATA_START + (cl - 2) * SPC) * BPS

    # readme cluster: content, then SLACK (earned-fake + residue) to cluster end
    off = cluster_off(CL_README)
    clustersz = SPC * BPS
    slack = (
        b"\x00"  # a byte of residue
        + b"[residual sector data] " + EARNED_FAKE.encode()
        + b" [overwritten log fragment]"
    )
    buf = readme_text + slack
    buf = buf.ljust(clustersz, b"\xE5")   # typical uninitialised residue
    img[off:off + clustersz] = buf

    # secret (deleted) cluster: the old data is still there
    off = cluster_off(CL_SECRET)
    img[off:off + len(secret_text)] = secret_text

    # unallocated cluster: the egg
    off = cluster_off(CL_EGG)
    egg_blob = EGG.encode() + b"\r\n"
    img[off:off + len(egg_blob)] = egg_blob

    out = os.path.join(DIST, "evidence.img")
    with open(out, "wb") as f:
        f.write(img)

    # --- self-verification: parse the image back, as a tool would -----------
    data = bytes(img)

    # boot signature + fs type
    assert data[510:512] == b"\x55\xAA", "bad boot signature"
    assert data[54:62] == b"FAT12   ", "fs type not FAT12"

    # root dir: find deleted SECRET.TXT (0xE5 first byte, rest 'ECRET   TXT')
    found_deleted = found_readme = False
    for i in range(ROOT_ENTS):
        e = data[ROOT_START * BPS + i * 32: ROOT_START * BPS + i * 32 + 32]
        if e[0] == 0xE5 and e[1:11] == b"ECRET  TXT":
            fc = struct.unpack_from("<H", e, 26)[0]
            sz = struct.unpack_from("<I", e, 28)[0]
            recovered = data[cluster_off(fc):cluster_off(fc) + sz]
            assert BAIT.encode() in recovered, "bait not recoverable"
            found_deleted = True
        if e[0:11] == b"README  TXT":
            fc = struct.unpack_from("<H", e, 26)[0]
            sz = struct.unpack_from("<I", e, 28)[0]
            filedata = data[cluster_off(fc):cluster_off(fc) + sz]
            assert EARNED_FAKE.encode() not in filedata, "earned-fake leaked into file body"
            slack_region = data[cluster_off(fc) + sz: cluster_off(fc) + clustersz]
            assert EARNED_FAKE.encode() in slack_region, "earned-fake not in slack"
            found_readme = True
    assert found_deleted and found_readme, "expected dir entries missing"

    # egg lives in an unallocated cluster (FAT free, no dir entry references it)
    egg_region = data[cluster_off(CL_EGG):cluster_off(CL_EGG) + clustersz]
    assert EGG.encode() in egg_region, "egg not in unallocated cluster"

    print("[10 DISK SLACK] build OK")
    print(f"  image: {TOTAL_SECTORS * BPS} bytes, FAT12, {NUM_CLUSTERS} clusters")
    print("  deleted file -> bait | readme slack -> earned-fake | unalloc -> egg")


if __name__ == "__main__":
    main()
