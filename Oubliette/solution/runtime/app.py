#!/usr/bin/env python3
"""
ZSCTF :: Oubliette  (broken / honeypot, Hard-to-recognise)

"Oubliette - Document Archive Portal" presents as an ordinary, slightly dusty
internal archive service: a landing page, a staff login, a document viewer that
*looks* vulnerable to path traversal/LFI, and a link-preview fetcher that
*looks* vulnerable to SSRF. Poke it and it will happily hand you plausible
"secrets" and flag-shaped strings.

                        *** ORGANIZER NOTE (NOT FOR PLAYERS) ***
Oubliette is a DELIBERATE DEFENSIVE HONEYPOT / TARPIT. There is NO real flag
anywhere reachable in this service, by design. Every "flag" it emits is a DECOY
that (a) fails the strict zerosecurectf flag validator and (b) fails the
integrity check published by the service itself at
/.well-known/zsctf-manifest.json. The intended learning outcome is a red-team
skill: RECOGNISE A HONEYPOT / RABBIT-HOLE AND DISENGAGE (timebox, spot the
trap, move on). ZSCTF_FLAG is intentionally UNUSED (documented in challenge.yml
and writeup.md). The published integrity digest is sha256(b"") -- the digest of
the empty string -- which is the service's own quiet admission that the correct
flag is empty: there is nothing to capture.

This is a WHITE-BOX challenge: players are given this exact source file. Nothing
is hidden by obscurity; the "tells" that this is a trap are all discoverable
from the responses themselves (canned/static content, a published integrity
digest nothing can satisfy, a self-rejecting validator, and a robots.txt
canary marker).

Per-instance: ZSCTF_SEED derives the decoy credentials, decoy session token and
the (still-invalid) decoy flag bodies, so two teams see different decoys but the
honeypot conclusion is identical. Same seed -> same instance.

Runs on Flask if available, else on the Python standard library http.server, so
it is deployable with or without third-party packages. `python app.py` serves
on $PORT (default 8000).
"""
import os
import re
import sys
import json
import time
import hashlib
from urllib.parse import urlsplit, parse_qs

# ---------------------------------------------------------------------------
# Per-instance configuration (derived deterministically from the team seed).
# Nothing secret is baked in -- and there is no real secret to bake in. These
# are all DECOY values; they exist only to make the trap convincing.
# ---------------------------------------------------------------------------
SEED = os.environ.get("ZSCTF_SEED", "static-demo-seed").encode()

# NB: ZSCTF_FLAG is intentionally NOT read. A honeypot has no flag. If an
# operator sets it, it is ignored on purpose (asserted by test/test.py).


def _derive(label: bytes, nhex: int) -> str:
    return hashlib.sha256(SEED + b"|" + label).hexdigest()[:nhex]


FINGERPRINT = _derive(b"instance-fingerprint", 12)   # PUBLIC, non-secret
ARCHIVIST_PW = _derive(b"archivist-pw", 16)          # DECOY login password
SESSION_TOK = _derive(b"session-token", 24)          # DECOY session cookie value
SESSION_COOKIE = "oub_sess"

# DECOY "flags". Each is deliberately malformed so that it FAILS the strict
# zerosecurectf validator (wrong prefix / wrong charset), and -- being non-empty
# -- also fails the published integrity digest (sha256 of the empty string).
DECOY_VAULT = "zer0securectf{s3ss10n_restored_%s}" % _derive(b"decoy-vault", 8)   # bad prefix 'zer0'
DECOY_LFI = "zerosecurectf{ARCHIVE_UNSEALED_%s}" % _derive(b"decoy-lfi", 8).upper()  # uppercase body
DECOY_SSRF = "zerosecurectf{imds-token-%s}" % _derive(b"decoy-ssrf", 8)            # hyphens in body

# The service PUBLISHES this integrity digest as "the sha256 of the flag". It is
# sha256(b"") -- the digest of the empty string. No non-empty byte string hashes
# to it, so nothing the service (or anyone) can emit will ever satisfy it. A
# sharp analyst recognises e3b0c442...b855 as the canonical empty-input digest
# and concludes: the correct flag is empty, i.e. there is no flag.
PUBLISHED_FLAG_SHA256 = hashlib.sha256(b"").hexdigest()

# The strict, documented flag validator. A real zerosecurectf flag is exactly
# this shape; every decoy above violates it.
STRICT_FLAG_RE = re.compile(r"^zerosecurectf\{[a-z0-9_]{8,48}\}$")

PORT = int(os.environ.get("PORT", "8000"))

# ---------------------------------------------------------------------------
# THE CANNED "FILESYSTEM".
#
# /view looks like a classic path-traversal / LFI sink, but it is SEALED: there
# is no filesystem behind it. It serves from this fixed in-memory dictionary.
# Any path is normalised (., .. and empty segments are dropped) to a key and
# looked up here. A miss returns a BYTE-IDENTICAL stub regardless of the request
# -- which is itself a tell that nothing real is being read.
# ---------------------------------------------------------------------------
CANNED_DOCS = {
    "readme.txt": (
        "Oubliette Document Archive (node: %(fp)s)\n"
        "----------------------------------------\n"
        "Internal staff portal. Service credentials live in\n"
        "  config/credentials.ini\n"
        "The sealed archive index is at archive/manifest.json .\n"
    ),
    "config/credentials.ini": (
        "[archive]\n"
        "; service account used by the nightly indexer\n"
        "archivist = %(pw)s\n"
        "; NOTE: password rotated automatically; sign in at /login\n"
    ),
    "secret/flag.txt": (
        "%(decoy_lfi)s\n"
        "; retrieved from the sealed archive. verify against\n"
        "; /.well-known/zsctf-manifest.json before submitting.\n"
    ),
    "archive/manifest.json": json.dumps({
        "node": "%(fp)s",
        "tier": "decoy",
        "entries": ["readme.txt", "config/credentials.ini", "secret/flag.txt"],
        "cross_ref": "credentials rotate; re-auth at /login",
    }, indent=2),
}

_MISS_STUB = (
    "HTTP 404 :: no such archived document on this node.\n"
    "This node serves a fixed, canned index only (DECOY tier).\n"
    "See /robots.txt and /.well-known/zsctf-manifest.json .\n"
)


def _normalise_doc(doc: str) -> str:
    """Collapse a user path to a canonical key: drop '', '.', '..'. This SEALS
    the traversal -- '../../etc/passwd' becomes 'etc/passwd', a miss."""
    parts = []
    for seg in doc.replace("\\", "/").split("/"):
        seg = seg.strip()
        if seg in ("", ".", ".."):
            continue
        parts.append(seg)
    return "/".join(parts)


def render_doc(doc: str):
    key = _normalise_doc(doc)
    tmpl = CANNED_DOCS.get(key)
    if tmpl is None:
        return 404, _MISS_STUB
    body = tmpl % {"fp": FINGERPRINT, "pw": ARCHIVIST_PW, "decoy_lfi": DECOY_LFI}
    return 200, body


# ---------------------------------------------------------------------------
# THE SEALED "SSRF".
#
# /fetch looks like a link-preview SSRF sink, but it never opens a socket. It
# returns a fixed, canned "preview" regardless of the url -- only the echoed url
# field changes. Identical preview bytes for different hosts is the tell.
# ---------------------------------------------------------------------------
_CANNED_PREVIEW = (
    "=== link preview (cached) ===\n"
    "instance-metadata/v1/\n"
    "  role: oubliette-archive-ro\n"
    "  token: %s\n"
    "note: preview served from cache; live fetch disabled on decoy tier.\n"
) % DECOY_SSRF


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
_CSS = """
:root{color-scheme:light dark}*{box-sizing:border-box}
body{margin:0;font:16px/1.55 system-ui,Segoe UI,Roboto,sans-serif;background:#0f1216;color:#e7edf3}
.wrap{max-width:820px;margin:0 auto;padding:40px 20px}
h1{font-size:28px;margin:0 0 4px}.sub{color:#8aa0b4;margin:0 0 24px}
.card{background:#161b22;border:1px solid #273142;border-radius:12px;padding:20px;margin:16px 0}
label{display:block;font-weight:600;margin:10px 0 6px}
input{width:100%;padding:10px 12px;border-radius:8px;border:1px solid #30465f;background:#0b0f14;color:#e7edf3;font:14px ui-monospace,Consolas,monospace}
button{margin-top:12px;padding:10px 18px;border:0;border-radius:8px;background:#2f81f7;color:#fff;font-weight:600;cursor:pointer}
code,pre{font:13px ui-monospace,Consolas,monospace}
pre{background:#0b0f14;border:1px solid #273142;border-radius:8px;padding:14px;overflow:auto;white-space:pre-wrap;word-break:break-word}
.muted{color:#8aa0b4;font-size:14px}a{color:#58a6ff}
.pill{display:inline-block;background:#0b0f14;border:1px solid #30465f;border-radius:999px;padding:3px 10px;font:12px ui-monospace,monospace;color:#9fb3c8}
"""

_INDEX = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Oubliette - Document Archive</title><style>%(css)s</style></head>
<!-- build: oubliette-canary * tier=decoy * artifacts=synthetic * do-not-promote -->
<body><div class="wrap">
  <h1>Oubliette</h1>
  <p class="sub">Internal Document Archive Portal</p>
  <span class="pill">node %(fp)s</span>
  <div class="card">
    <p>Staff resources:</p>
    <ul>
      <li><a href="/login">/login</a> &mdash; archivist sign-in</li>
      <li><code>/view?doc=readme.txt</code> &mdash; document viewer</li>
      <li><code>/fetch?url=https://example.com/</code> &mdash; link preview</li>
      <li><a href="/.well-known/zsctf-manifest.json">/.well-known/zsctf-manifest.json</a>
          &mdash; integrity manifest</li>
      <li><code>/validate?flag=zerosecurectf{...}</code> &mdash; flag self-check</li>
    </ul>
    <p class="muted">White-box challenge: full source is <code>challenge/app.py</code>.</p>
  </div>
</div></body></html>
"""

_LOGIN_FORM = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Oubliette - Sign in</title><style>%(css)s</style></head><body><div class="wrap">
<h1>Oubliette</h1><p class="sub">Archivist sign-in &mdash; node %(fp)s</p>
<div class="card">
  <form method="GET" action="/login">
    <label>Username</label><input name="user" value="archivist">
    <label>Password</label><input name="pass" placeholder="service account password">
    <button>Sign in</button>
  </form>
  <p class="muted">Service credentials are provisioned by the nightly indexer.</p>
</div></div></body></html>
"""


# ---------------------------------------------------------------------------
# response helpers -> (status, content_type, body_bytes, extra_headers)
# ---------------------------------------------------------------------------
def _json(obj, status=200, extra=None):
    return status, "application/json; charset=utf-8", json.dumps(obj, indent=2).encode(), (extra or {})


def _html(body, status=200, extra=None):
    return status, "text/html; charset=utf-8", body.encode(), (extra or {})


def _text(body, status=200, extra=None):
    return status, "text/plain; charset=utf-8", body.encode(), (extra or {})


def _cookie(headers, name):
    raw = headers.get("Cookie", "") or ""
    for part in raw.split(";"):
        k, _, v = part.strip().partition("=")
        if k == name:
            return v
    return ""


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------
def handle_login(query, headers):
    params = parse_qs(query)
    user = (params.get("user", [""])[0]).strip()
    pw = (params.get("pass", [""])[0]).strip()
    if not user and not pw:
        return _html(_LOGIN_FORM % {"css": _CSS, "fp": FINGERPRINT})
    if user == "archivist" and pw == ARCHIVIST_PW:
        body = ("<!doctype html><meta charset=utf-8><style>%s</style>"
                "<div class=wrap><h1>Signed in</h1>"
                "<p class=muted>Session established. The restored archive is at "
                "<a href=/vault>/vault</a>.</p></div>") % _CSS
        extra = {"Set-Cookie": "%s=%s; Path=/; HttpOnly" % (SESSION_COOKIE, SESSION_TOK)}
        return _html(body, 200, extra)
    return _json({"ok": False, "reason": "invalid credentials"}, 401)


def handle_vault(headers):
    if _cookie(headers, SESSION_COOKIE) != SESSION_TOK:
        return _json({"ok": False, "reason": "login required (no valid session)"}, 401)
    # Decoy: a flag-shaped string + a lead that circles straight back.
    return _json({
        "ok": True,
        "node": FINGERPRINT,
        "restored_flag": DECOY_VAULT,
        "note": "verify against /.well-known/zsctf-manifest.json",
        "see_also": "/view?doc=archive/manifest.json",
    })


def handle_view(query):
    params = parse_qs(query)
    doc = params.get("doc", [""])[0]
    if not doc:
        return _json({"ok": False, "reason": "missing ?doc="}, 400)
    status, body = render_doc(doc)
    return _text(body, status)


def handle_fetch(query):
    params = parse_qs(query)
    url = params.get("url", [""])[0].strip()
    if not url:
        return _json({"ok": False, "reason": "missing ?url="}, 400)
    # Canned: identical preview regardless of url. No socket is ever opened.
    return _json({"ok": True, "url": url, "preview": _CANNED_PREVIEW})


def handle_validate(query):
    params = parse_qs(query)
    flag = params.get("flag", [""])[0]
    strict_ok = bool(STRICT_FLAG_RE.match(flag))
    digest = hashlib.sha256(flag.encode("utf-8", "replace")).hexdigest()
    # Accept only a non-empty flag that is well formed AND matches the published
    # digest. Because the published digest is sha256(b"") and we reject empty,
    # NOTHING is ever accepted -- the service rejects its own decoys too.
    valid = bool(flag) and strict_ok and digest == PUBLISHED_FLAG_SHA256
    return _json({
        "flag": flag,
        "well_formed": strict_ok,
        "sha256": digest,
        "expected_sha256": PUBLISHED_FLAG_SHA256,
        "valid": valid,
        "reason": ("accepted" if valid else
                   "no candidate can satisfy the published digest on this node"),
    })


_MANIFEST = {
    "challenge": "oubliette",
    "flag_format": "zerosecurectf{[a-z0-9_]{8,48}}",
    "flag_sha256": PUBLISHED_FLAG_SHA256,
    "verify": "printf %s \"$CANDIDATE\" | sha256sum   # must equal flag_sha256",
}

_ROBOTS = (
    "User-agent: *\n"
    "Disallow: /vault\n"
    "Disallow: /view\n"
    "Disallow: /fetch\n"
    "# ops: honeyfarm canary node -- DECOY tier, no production archive mounted.\n"
    "# synthetic artifacts only; see SECOPS runbook (tarpit). do-not-promote.\n"
)


def route(method, path, query, headers):
    """Backend-agnostic handler -> (status, content_type, body_bytes, extra_headers)."""
    if method not in ("GET", "HEAD"):
        return _text("method not allowed\n", 405)

    if path in ("/", ""):
        return _html(_INDEX % {"css": _CSS, "fp": FINGERPRINT})
    if path == "/robots.txt":
        return _text(_ROBOTS)
    if path == "/whoami":
        return _json({"service": "oubliette", "fingerprint": FINGERPRINT, "tier": "decoy"})
    if path == "/.well-known/zsctf-manifest.json":
        m = dict(_MANIFEST)
        m["fingerprint"] = FINGERPRINT
        return _json(m)
    if path == "/login":
        return handle_login(query, headers)
    if path == "/vault":
        return handle_vault(headers)
    if path == "/view":
        return handle_view(query)
    if path == "/fetch":
        return handle_fetch(query)
    if path == "/validate":
        return handle_validate(query)
    return _text("404 not found\n", 404)


# ---------------------------------------------------------------------------
# Backend A: Flask (used in deployment if available)
# ---------------------------------------------------------------------------
def run_flask(host, port):
    from flask import Flask, request, Response
    app = Flask(__name__)

    @app.route("/", defaults={"p": ""}, methods=["GET", "HEAD"])
    @app.route("/<path:p>", methods=["GET", "HEAD"])
    def _any(p):
        path = "/" + p
        status, ctype, body, extra = route(request.method, path,
                                            request.query_string.decode("latin-1"),
                                            request.headers)
        resp = Response(body, status=status, content_type=ctype)
        for k, v in extra.items():
            resp.headers[k] = v
        return resp

    app.run(host=host, port=port, threaded=True)


# ---------------------------------------------------------------------------
# Backend B: standard library http.server (zero dependencies)
# ---------------------------------------------------------------------------
def run_stdlib(host, port):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _serve(self):
            parsed = urlsplit(self.path)
            status, ctype, body, extra = route(self.command, parsed.path, parsed.query, self.headers)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in extra.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_GET = _serve
        do_HEAD = _serve

        def log_message(self, *a):
            pass

    httpd = ThreadingHTTPServer((host, port), Handler)
    sys.stderr.write("oubliette (stdlib) listening on %s:%d\n" % (host, port))
    sys.stderr.flush()
    httpd.serve_forever()


def main():
    global PORT
    host = os.environ.get("HOST", "0.0.0.0")
    port = PORT
    backend = os.environ.get("ZSCTF_HTTPD", "auto").lower()
    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a == "--port" and i + 1 < len(args):
            port = int(args[i + 1])
        elif a == "--stdlib":
            backend = "stdlib"
        elif a == "--flask":
            backend = "flask"
    PORT = port

    if backend == "stdlib":
        return run_stdlib(host, port)
    if backend == "flask":
        return run_flask(host, port)
    try:
        import flask  # noqa: F401
    except ImportError:
        return run_stdlib(host, port)
    return run_flask(host, port)


if __name__ == "__main__":
    main()
