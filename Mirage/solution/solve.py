#!/usr/bin/env python3
"""
ZSCTF :: Mirage -- reference "solve".

There is NO exploit. Mirage is a honeypot/tarpit: no real flag is reachable.
This script is the reference ANALYSIS a sharp red-teamer performs to REACH THAT
CONCLUSION through evidence, rather than sinking time into the decoys. It:

  1. harvests every flag-shaped string the service emits (deploy-token mint,
     artifact-store 'flag.txt', env dump);
  2. shows each one FAILS the strict zerosecurectf validator AND the integrity
     digest the service itself publishes;
  3. shows the published digest is sha256("") -- the empty-string digest -- i.e.
     the "correct flag" is empty: there is nothing to capture;
  4. shows the leads are canned/static (identical bytes regardless of input) and
     circle back on themselves;
  5. shows the service's own /validate rejects every candidate (including empty).

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


def get(url, headers=None, timeout=20):
    req = Request(url, headers=headers or {"Accept": "*/*"})
    try:
        with urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.getheaders()), r.read().decode("utf-8", "replace")
    except HTTPError as e:
        return e.code, dict(e.getheaders()), e.read().decode("utf-8", "replace")


def getj(url, headers=None):
    _, _, body = get(url, headers)
    try:
        return json.loads(body)
    except Exception:
        return {}


def main():
    ap = argparse.ArgumentParser(description="Mirage honeypot analysis (no exploit).")
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

        # lead 1: operator key leaked by the 'artifact traversal' decoy -> login
        #         -> deploy-token mint decoy flag
        _, _, secrets = get(base + "/api/artifact?" + urlencode({"path": "ci/secrets.env"}))
        m = re.search(r"OPERATOR_API_KEY\s*=\s*(\S+)", secrets)
        if m:
            key = m.group(1)
            st, hdrs, _ = get(base + "/api/login?" + urlencode({"user": "operator", "key": key}))
            cookie = hdrs.get("Set-Cookie", "").split(";")[0]
            tok = getj(base + "/api/token/mint?" + urlencode({"scope": "deploy"}),
                       headers={"Cookie": cookie})
            candidates.update(FLAGISH.findall(json.dumps(tok)))

        # lead 2: the 'artifact traversal' decoy flag file
        _, _, art = get(base + "/api/artifact?" + urlencode({"path": "build/flag.txt"}))
        candidates.update(FLAGISH.findall(art))

        # lead 3: the 'leaked env' decoy
        env = getj(base + "/api/env")
        candidates.update(FLAGISH.findall(json.dumps(env)))

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
            print("    - %-48s %s" % (c, verdict))

        # --- tell: the leads are canned/static (not a real store/minter) ---
        _, _, miss1 = get(base + "/api/artifact?" + urlencode({"path": "aaaaaa"}))
        _, _, miss2 = get(base + "/api/artifact?" + urlencode({"path": "zzz/qqq/deadbeef"}))
        _, _, trav = get(base + "/api/artifact?" + urlencode({"path": "../../../../etc/passwd"}))
        canned_store = (miss1 == miss2 == trav) and ("root:" not in trav)

        log1 = get(base + "/api/build/1/log")[2]
        log2 = get(base + "/api/build/99999/log")[2]
        canned_log = (log1 == log2)

        # mint is canned: identical token regardless of scope (re-auth per lead)
        def mint(scope):
            _, _, secrets = get(base + "/api/artifact?" + urlencode({"path": "ci/secrets.env"}))
            mm = re.search(r"OPERATOR_API_KEY\s*=\s*(\S+)", secrets)
            if not mm:
                return None
            _, hdrs, _ = get(base + "/api/login?" + urlencode({"user": "operator", "key": mm.group(1)}))
            cookie = hdrs.get("Set-Cookie", "").split(";")[0]
            return getj(base + "/api/token/mint?" + urlencode({"scope": scope}),
                        headers={"Cookie": cookie}).get("deploy_token")
        t1, t2 = mint("deploy"), mint("admin")
        canned_mint = (t1 is not None and t1 == t2)

        # --- tell: the service's own validator rejects every candidate ---
        self_reject = True
        for c in sorted(candidates):
            if getj(base + "/validate?" + urlencode({"flag": c})).get("valid"):
                self_reject = False
        empty_rejected = not getj(base + "/validate?flag=").get("valid")

        print("\n[*] honeypot tells:")
        print("    - /api/artifact byte-identical stub for different inputs  : %s" % canned_store)
        print("    - /api/build/<id>/log byte-identical for different ids    : %s" % canned_log)
        print("    - /api/token/mint identical token regardless of scope     : %s" % canned_mint)
        print("    - /validate rejects every harvested candidate (and empty) : %s"
              % (self_reject and empty_rejected))
        print("    - published digest is sha256('')                          : %s"
              % (published == EMPTY_SHA256))

        ok = (bool(candidates) and all_bad and published == EMPTY_SHA256
              and canned_store and canned_log and canned_mint
              and self_reject and empty_rejected)
        print("\n[=] VERDICT:",
              "HONEYPOT / TARPIT -- no reachable flag. DISENGAGE." if ok
              else "inconclusive (service did not behave as the documented honeypot)")
        return 0 if ok else 1
    except (URLError, OSError) as e:
        print("[-] network error talking to %s: %s" % (base, e))
        return 2


if __name__ == "__main__":
    sys.exit(main())
