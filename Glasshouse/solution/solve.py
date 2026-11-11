#!/usr/bin/env python3
"""
ZSCTF :: Glasshouse -- reference solver (OFFLINE; reads only local bundle files).

Intended correlation chain (no network, no scraping, nothing but local files):

  1. HANDLE PIVOT  (profile_*.html)
     The three snapshot pages share one handle. The microblog/devforum pages warn
     that an "@<handle>-official" account is an impersonator. The devforum pinned
     post leaks the persona's own vault-key recipe:
         K = sha256( handle ":" place ":" author ":" serial )

  2. PLACE  (field_01.jpg EXIF GPS  +  gazetteer.json)
     Parse the synthetic EXIF: the Artist tag confirms WHICH handle owns the photo
     (defeating the impersonator), and the GPS tags give coordinates. Resolve the
     coordinates against the offline gazetteer -> the landmark's slug.

  3. AUTHOR  (journal.pdf /Info /Author)
     The persona's reused pen name, read from the PDF metadata.

  4. SERIAL  (ct_log.json)
     The TLS cert serial for the persona's OWN subdomain "<handle>.<domain>" --
     NOT the look-alike "<handle>-official.<domain>" entry (the decoy).

  5. REASSEMBLE -> decrypt vault.enc
     Compute K, verify the HMAC tag, decrypt the ciphertext -> the flag.

No single artifact yields the flag; the key only exists once the breadcrumbs are
correlated. Run:
    python solve.py                 # auto-locates ../challenge/bundle
    python solve.py --bundle DIR
"""
import os, re, sys, json, struct, base64, hashlib, hmac, argparse, pathlib

# ---------------------------------------------------------------------------
# 1. Handle pivot
# ---------------------------------------------------------------------------
def load_handle(bundle: pathlib.Path):
    micro = (bundle / "profile_microblog.html").read_text(encoding="utf-8")
    # "my only real handle is <b>@handle</b>" -- the authoritative handle.
    m = re.search(r"only real handle is <b>@([A-Za-z0-9_]+)</b>", micro)
    if not m:
        raise RuntimeError("could not find authoritative handle")
    handle = m.group(1)
    # The impersonator is explicitly flagged; capture it so we can reject it.
    d = re.search(r"@([A-Za-z0-9_]+-official)", micro)
    decoy = d.group(1) if d else None
    return handle, decoy

# ---------------------------------------------------------------------------
# 2. EXIF parsing (pure stdlib) + gazetteer resolution
# ---------------------------------------------------------------------------
def _find_app1_exif(jpeg: bytes):
    assert jpeg[:2] == b"\xff\xd8", "not a JPEG"
    i = 2
    while i + 4 <= len(jpeg):
        if jpeg[i] != 0xFF:
            i += 1
            continue
        marker = jpeg[i + 1]
        if marker == 0xD9 or marker == 0xDA:  # EOI / SOS -> stop scanning headers
            break
        seg_len = struct.unpack(">H", jpeg[i + 2:i + 4])[0]
        seg = jpeg[i + 4:i + 2 + seg_len]
        if marker == 0xE1 and seg[:6] == b"Exif\x00\x00":
            return seg[6:]  # TIFF stream
        i = i + 2 + seg_len
    raise RuntimeError("no EXIF APP1 segment")

def _parse_ifd(tiff, offset, le):
    end = "<" if le else ">"
    (count,) = struct.unpack(end + "H", tiff[offset:offset + 2])
    entries = {}
    p = offset + 2
    for _ in range(count):
        tag, typ, cnt = struct.unpack(end + "HHI", tiff[p:p + 8])
        valoff = tiff[p + 8:p + 12]
        entries[tag] = (typ, cnt, valoff)
        p += 12
    return entries

def _read_value(tiff, typ, cnt, valoff, le):
    end = "<" if le else ">"
    sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8}
    bytelen = sizes.get(typ, 1) * cnt
    if bytelen <= 4:
        raw = valoff[:bytelen]
    else:
        (off,) = struct.unpack(end + "I", valoff)
        raw = tiff[off:off + bytelen]
    if typ == 2:  # ASCII
        return raw.split(b"\x00", 1)[0].decode("ascii", "replace")
    if typ == 5:  # RATIONAL
        out = []
        for k in range(cnt):
            num, den = struct.unpack(end + "II", raw[k * 8:k * 8 + 8])
            out.append((num, den))
        return out
    if typ in (1, 3, 4):
        return list(raw)
    return raw

def parse_exif(jpeg: bytes):
    tiff = _find_app1_exif(jpeg)
    le = tiff[:2] == b"II"
    end = "<" if le else ">"
    (ifd0_off,) = struct.unpack(end + "I", tiff[4:8])
    ifd0 = _parse_ifd(tiff, ifd0_off, le)

    result = {}
    if 0x013B in ifd0:  # Artist
        typ, cnt, vo = ifd0[0x013B]
        result["artist"] = _read_value(tiff, typ, cnt, vo, le)
    if 0x0132 in ifd0:  # DateTime
        typ, cnt, vo = ifd0[0x0132]
        result["datetime"] = _read_value(tiff, typ, cnt, vo, le)

    if 0x8825 in ifd0:  # GPS IFD pointer
        (gps_off,) = struct.unpack(end + "I", ifd0[0x8825][2])
        gps = _parse_ifd(tiff, gps_off, le)

        def dms_to_deg(tag_rats, ref):
            d = tag_rats[0][0] / tag_rats[0][1]
            m = tag_rats[1][0] / tag_rats[1][1]
            s = tag_rats[2][0] / tag_rats[2][1]
            val = d + m / 60.0 + s / 3600.0
            if ref in ("S", "W"):
                val = -val
            return val

        lat_ref = _read_value(tiff, *gps[0x0001], le)
        lat = _read_value(tiff, *gps[0x0002], le)
        lon_ref = _read_value(tiff, *gps[0x0003], le)
        lon = _read_value(tiff, *gps[0x0004], le)
        result["lat"] = dms_to_deg(lat, lat_ref)
        result["lon"] = dms_to_deg(lon, lon_ref)
    return result

def resolve_place(bundle: pathlib.Path, lat, lon):
    gaz = json.loads((bundle / "gazetteer.json").read_text(encoding="utf-8"))
    best, best_d = None, None
    for row in gaz["landmarks"]:
        d = (row["lat"] - lat) ** 2 + (row["lon"] - lon) ** 2
        if best_d is None or d < best_d:
            best, best_d = row, d
    # landmarks are globally far apart; the nearest must be a clear match.
    if best_d is None or best_d > 0.05:
        raise RuntimeError("no gazetteer landmark near the EXIF coordinates")
    return best["slug"], best, best_d

# ---------------------------------------------------------------------------
# 3. PDF /Author
# ---------------------------------------------------------------------------
def load_author(bundle: pathlib.Path):
    data = (bundle / "journal.pdf").read_bytes()
    m = re.search(rb"/Author\s*\(((?:[^()\\]|\\.)*)\)", data)
    if not m:
        raise RuntimeError("no /Author in journal.pdf")
    return m.group(1).decode("latin-1")

# ---------------------------------------------------------------------------
# 4. CT-log serial for the persona's OWN subdomain (reject the look-alike)
# ---------------------------------------------------------------------------
def load_serial(bundle: pathlib.Path, handle, decoy):
    ct = json.loads((bundle / "ct_log.json").read_text(encoding="utf-8"))
    own_prefix = handle + "."
    decoy_prefix = (decoy + ".") if decoy else None
    chosen = None
    for e in ct["entries"]:
        sans = e.get("sans", [])
        is_decoy = decoy_prefix and any(s.startswith(decoy_prefix) for s in sans)
        is_own = any(s.startswith(own_prefix) for s in sans) and not is_decoy
        if is_own:
            chosen = e
            break
    if chosen is None:
        raise RuntimeError("no CT entry for the persona's own subdomain")
    return chosen["serial_hex"]

# ---------------------------------------------------------------------------
# 5. Reassemble and decrypt the vault
# ---------------------------------------------------------------------------
def _keystream(K: bytes, n: int) -> bytes:
    out, ctr = b"", 0
    while len(out) < n:
        out += hashlib.sha256(K + struct.pack(">Q", ctr)).digest()
        ctr += 1
    return out[:n]

def vault_open(bundle: pathlib.Path, handle, slug, author, serial):
    vault = json.loads((bundle / "vault.enc").read_text(encoding="utf-8"))
    K = hashlib.sha256(("%s:%s:%s:%s" % (handle, slug, author, serial)).encode()).digest()
    ct = base64.b64decode(vault["ciphertext"])
    want = hmac.new(K, b"glasshouse-v1" + ct, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, vault["tag"]):
        raise RuntimeError("vault tag mismatch -- wrong correlation (a decoy token?)")
    pt = bytes(a ^ b for a, b in zip(ct, _keystream(K, len(ct))))
    return pt.decode("utf-8", "replace")

# ---------------------------------------------------------------------------
def solve(bundle: pathlib.Path, verbose=True):
    def say(*a):
        if verbose:
            print(*a)

    handle, decoy = load_handle(bundle)
    say("[1] authoritative handle : @%s" % handle)
    say("    flagged impersonator : @%s (rejected)" % decoy)

    jpeg = (bundle / "field_01.jpg").read_bytes()
    exif = parse_exif(jpeg)
    say("[2] EXIF Artist          : %s" % exif.get("artist"))
    if exif.get("artist") != handle:
        raise RuntimeError("EXIF Artist does not match the authoritative handle")
    slug, place, dist = resolve_place(bundle, exif["lat"], exif["lon"])
    say("    EXIF GPS             : lat=%.5f lon=%.5f" % (exif["lat"], exif["lon"]))
    say("    resolved landmark    : %s -> slug=%s" % (place["name"], slug))

    author = load_author(bundle)
    say("[3] PDF /Author          : %s" % author)

    serial = load_serial(bundle, handle, decoy)
    say("[4] CT serial (own sub)  : %s" % serial)

    flag = vault_open(bundle, handle, slug, author, serial)
    say("[5] vault decrypted OK")
    return flag

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", default=None, help="path to the OSINT bundle dir")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    here = pathlib.Path(__file__).resolve().parent
    bundle = pathlib.Path(args.bundle) if args.bundle else (here.parent / "challenge" / "bundle")
    if not bundle.exists():
        print("[-] bundle not found at %s (run challenge/generate.py first)" % bundle)
        return 2
    flag = solve(bundle, verbose=not args.quiet)
    print("[+] FLAG =", flag)
    return 0

if __name__ == "__main__":
    sys.exit(main())
