#!/usr/bin/env python3
"""
ZSCTF :: Palisade  (web, Hard)

"Palisade - Link Safety Inspector" is a security product: analysts paste a URL,
the server fetches it on their behalf, and Palisade returns a safe preview
(status + body) so nobody has to click an untrusted link themselves. Because a
fetch-on-your-behalf service is the textbook Server-Side Request Forgery (SSRF)
sink, Palisade ships a *guard* that refuses URLs pointing at internal, loopback,
private or otherwise non-routable addresses.

Behind the perimeter, Palisade also runs an INTERNAL results service
(`/internal/...`). That service binds an EPHEMERAL loopback port (127.0.0.1)
that is NEVER published - it is not served on the public port at all, so it is
unreachable from the host or the public interface. Staff never reach it from
their browsers - they reach it *through* the inspector (an in-container client),
which is why every outbound fetch the inspector makes carries a shared internal
credential header. The flag lives in the internal vault. Reaching it therefore
requires the SSRF parse-differential pivot even if the edge credential leaks:
the public port never exposes `/internal`.

This is a WHITE-BOX challenge: you are given this exact source file. The flaw is
therefore not hidden by obscurity. It is in plain sight, in the gap between how
the GUARD decides a URL is safe and how the FETCHER decides where to connect.

Per-instance: ZSCTF_SEED derives a unique vault token + unique internal
credential; ZSCTF_FLAG sets the flag. Same seed -> same instance.

Runs on Flask if available, else on the Python standard library http.server, so
it is deployable with or without third-party packages. `python app.py` serves on
$PORT (default 8000).
"""
import os
import re
import sys
import json
import socket
import hashlib
import ipaddress
from urllib.parse import urlsplit, parse_qs
from http.client import HTTPConnection, HTTPSConnection

# ---------------------------------------------------------------------------
# Per-instance configuration (derived deterministically from the team seed).
# Nothing secret is baked into this file: the secrets are functions of the seed,
# which is injected at run time and never shipped to players.
# ---------------------------------------------------------------------------
SEED = os.environ.get("ZSCTF_SEED", "static-demo-seed").encode()
FLAG = os.environ.get("ZSCTF_FLAG", "zerosecurectf{local_review_flag}")


def _derive(label: bytes, nhex: int) -> str:
    return hashlib.sha256(SEED + b"|" + label).hexdigest()[:nhex]


VAULT_TOKEN = _derive(b"vault-token", 32)   # 128-bit path segment; unguessable, not public
EDGE_SECRET = _derive(b"edge-secret", 64)   # shared internal credential the inspector injects
FINGERPRINT = _derive(b"instance-fingerprint", 12)  # PUBLIC, non-secret: proves determinism
EDGE_HEADER = "X-Palisade-Edge"

# ---------------------------------------------------------------------------
# RABBIT-HOLES (organizer-only; documented in writeup.md "Rabbit-holes").
#
# These are deliberate, PROVABLY-INERT misdirection. None of them reveals FLAG,
# the real VAULT_TOKEN or EDGE_SECRET, and none opens any new path to them. They
# exist to bog down careless/automated solvers who grab the first flag-shaped
# string or the first internal resource. Every decoy is rejectable by the
# published strict format rule  ^zerosecurectf\{[a-z0-9_]{8,48}\}$ . All vary by
# ZSCTF_SEED so a leaked walkthrough or one team's notes do not transfer.
# ---------------------------------------------------------------------------
# (R2/R3) A second, seed-derived "staging cache" vault path. It is listed on the
# internal index FIRST, to bait a solver that greps the first vault/<hex> it
# sees. Read through the SSRF pivot it returns a FIXTURE flag that is
# intentionally mal-formatted (UPPERCASE + hyphens) so it can never satisfy the
# validator -> the real flag lives only behind the correctly-labelled vault.
STAGING_TOKEN = _derive(b"staging-vault-token", 32)
STAGING_FIXTURE_FLAG = "zerosecurectf{STAGING-FIXTURE-%s-DO-NOT-SUBMIT}" % _derive(b"staging-fixture", 8).upper()

# (R1/R4) Inert, publicly-reachable red-herring endpoints a dirbuster/scanner
# grabs before it ever reads the guard. Each serves a flag-shaped DECOY whose
# defect is obvious on reflection:
#   /debug  -> 'zer0securectf{...}'  (zero->zer0 homoglyph prefix: not the format)
#   /backup -> 'ZEROSECURECTF{...}'  (UPPERCASE body: fails [a-z0-9_])
# Neither carries a real secret; the "edge credential" they mention is redacted.
DEBUG_DECOY_FLAG = "zer0securectf{%s}" % _derive(b"decoy-debug-build", 24)
BACKUP_DECOY_FLAG = "ZEROSECURECTF{%s}" % _derive(b"decoy-backup-dump", 24).upper()

PORT = int(os.environ.get("PORT", "8000"))
# The internal results service binds its OWN listener on an ephemeral loopback
# port (like barbican's upstream). It is never published and is not served on the
# public PORT, so the only way in is the SSRF loopback pivot -- even if the edge
# credential leaks. INTERNAL_HOST is loopback-only; INTERNAL_PORT is chosen by
# the OS at startup and advertised (non-secret) via /whoami so the pivot has a
# target. Knowing the port does not help an outside attacker: nothing is bound
# on the public interface for it.
INTERNAL_HOST = "127.0.0.1"
INTERNAL_PORT = None  # set at startup once the internal listener has bound
FETCH_TIMEOUT = float(os.environ.get("PALISADE_FETCH_TIMEOUT", "4"))
MAX_BODY = 64 * 1024

# ---------------------------------------------------------------------------
# THE SSRF GUARD  --  this is the whole challenge.
#
# The guard hand-parses the URL (a small regex) to decide whether the target is
# safe. Its contract: reject anything that points at a non-routable / internal
# address, allow public destinations.
#
# It reasons like this about names it cannot turn into an IP:
#   "Our network blocks DNS and all egress, so a host we cannot resolve cannot
#    reach anything. An unresolvable host is therefore harmless -> allow it."
#
# That assumption is the bug. "Unresolvable by *this guard*" is not the same as
# "unreachable by the *fetcher*": the two parse the URL's authority differently.
# ---------------------------------------------------------------------------
_URL_RE = re.compile(r"^(?P<scheme>[a-z][a-z0-9+.\-]*)://(?P<authority>[^/?#]*)", re.IGNORECASE)


def _is_internal_ip(ip: "ipaddress._BaseAddress") -> bool:
    return (ip.is_loopback or ip.is_private or ip.is_link_local or
            ip.is_unspecified or ip.is_reserved or ip.is_multicast)


def guard(url: str):
    """Return (allowed: bool, reason: str). The validator's own URL parse."""
    m = _URL_RE.match(url.strip())
    if not m:
        return False, "malformed URL (no scheme://authority)"
    scheme = m.group("scheme").lower()
    if scheme not in ("http", "https"):
        return False, "scheme %r not allowed (http/https only)" % scheme

    authority = m.group("authority")
    # Strip a trailing :port if present. NOTE: userinfo (the 'user@' part) is
    # left in place -- the authority substring is parsed here by hand.
    host = authority
    if ":" in authority:
        head, _, tail = authority.rpartition(":")
        if tail.isdigit():
            host = head

    h = host.strip("[]").lower()
    if not h:
        return False, "empty host"

    # Case 1: the host is already an IP literal -> check it directly.
    try:
        ip = ipaddress.ip_address(h)
        if _is_internal_ip(ip):
            return False, "host %s is a non-routable/internal address" % ip
        return True, "public IP literal %s" % ip
    except ValueError:
        pass

    # Case 2: a name -> resolve it and check every address it maps to.
    try:
        infos = socket.getaddrinfo(h, None)
    except (socket.gaierror, UnicodeError, ValueError):
        # egress/DNS is blocked, so (the author believes) a host
        # we cannot resolve cannot reach anything internal. Allow it.
        return True, "host %r does not resolve; treated as external/offline" % h

    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if _is_internal_ip(ip):
            return False, "host %r resolves to internal address %s" % (h, ip)
    return True, "host %r resolves to a public address" % h


# ---------------------------------------------------------------------------
# THE FETCHER  --  a deliberately minimal client (no redirects, no cookies).
#
# It uses the standard library's RFC-3986 URL parser (urlsplit) to decide where
# to connect. urlsplit() correctly treats 'user@host' userinfo and returns the
# real host. Every outbound request carries the shared internal credential, so
# requests the inspector makes to the internal service are trusted.
# ---------------------------------------------------------------------------
def do_fetch(url: str):
    sp = urlsplit(url)
    scheme = sp.scheme.lower()
    host = sp.hostname
    if not host:
        raise ValueError("no host")
    port = sp.port or (443 if scheme == "https" else 80)
    path = sp.path or "/"
    if sp.query:
        path += "?" + sp.query
    Conn = HTTPSConnection if scheme == "https" else HTTPConnection
    conn = Conn(host, port, timeout=FETCH_TIMEOUT)
    try:
        conn.request("GET", path, headers={EDGE_HEADER: EDGE_SECRET})
        resp = conn.getresponse()
        body = resp.read(MAX_BODY)
        return resp.status, body.decode("utf-8", "replace")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
_PAGE_CSS = """
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{margin:0;font:16px/1.55 system-ui,Segoe UI,Roboto,sans-serif;background:#0f1216;color:#e7edf3}
.wrap{max-width:820px;margin:0 auto;padding:40px 20px}
h1{font-size:28px;margin:0 0 4px}
.sub{color:#8aa0b4;margin:0 0 28px}
.card{background:#161b22;border:1px solid #273142;border-radius:12px;padding:20px;margin:18px 0}
label{display:block;font-weight:600;margin-bottom:8px}
input[type=text]{width:100%;padding:12px 14px;border-radius:8px;border:1px solid #30465f;background:#0b0f14;color:#e7edf3;font:14px ui-monospace,Menlo,Consolas,monospace}
button{margin-top:12px;padding:11px 20px;border:0;border-radius:8px;background:#2f81f7;color:#fff;font-weight:600;cursor:pointer}
button:hover{background:#4793ff}
code,pre{font:13px ui-monospace,Menlo,Consolas,monospace}
pre{background:#0b0f14;border:1px solid #273142;border-radius:8px;padding:14px;overflow:auto;white-space:pre-wrap;word-break:break-word}
.muted{color:#8aa0b4;font-size:14px}
.pill{display:inline-block;background:#0b0f14;border:1px solid #30465f;border-radius:999px;padding:3px 10px;font:12px ui-monospace,monospace;color:#9fb3c8}
a{color:#58a6ff}
"""

_INDEX_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Palisade - Link Safety Inspector</title><style>%(css)s</style></head>
<body><div class="wrap">
  <h1>Palisade</h1>
  <p class="sub">Link Safety Inspector &mdash; we fetch untrusted URLs for you, so you never have to click them.</p>
  <span class="pill">instance %(fp)s</span>

  <div class="card">
    <label for="u">URL to inspect</label>
    <input id="u" type="text" placeholder="https://example.com/some/link" value="https://example.com/">
    <button id="go">Inspect</button>
    <p class="muted">The inspector refuses URLs that point at internal, loopback or private
      addresses &mdash; an SSRF guard protects our network.</p>
    <pre id="out" class="muted">Result will appear here.</pre>
  </div>

  <div class="card">
    <p class="muted"><b>For staff:</b> the internal results service lives at
      <code>/internal/</code> on a private loopback port
      (<code>127.0.0.1:%(iport)s</code>) that is <i>not</i> published and is
      <i>not</i> served on this public port. It is not reachable from your
      browser; reach it <i>through the inspector</i> like every other internal
      call. The flag vault is listed on the internal index once you're in.</p>
    <p class="muted">White-box challenge: the full server source is
      <code>challenge/app.py</code>. The guard is in plain sight.</p>
  </div>

<script>
const out=document.getElementById('out'),inp=document.getElementById('u');
document.getElementById('go').onclick=async()=>{
  out.textContent='fetching...';
  try{
    const r=await fetch('/inspect?url='+encodeURIComponent(inp.value));
    const j=await r.json();
    out.textContent=JSON.stringify(j,null,2);
  }catch(e){out.textContent='error: '+e;}
};
</script>
</div></body></html>
"""

_INTERNAL_INDEX_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Palisade Internal Results Service</title>
<style>%(css)s</style></head><body><div class="wrap">
  <h1>Palisade &mdash; Internal</h1>
  <p class="sub">Results service. Authenticated by edge credential. Instance %(fp)s.</p>
  <div class="card">
    <p>Available internal resources:</p>
    <ul>
      <li><a href="/internal/vault/%(staging)s">results cache (staging)</a>
          &mdash; <code>/internal/vault/%(staging)s</code>
          <span class="muted">&nbsp;last preview run &mdash; fixture data, not the live vault</span></li>
      <li><a href="/internal/vault/%(token)s">flag vault</a>
          &mdash; <code>/internal/vault/%(token)s</code>
          <span class="muted">&nbsp;live per-instance secret</span></li>
    </ul>
    <p class="muted">These tokens are provisioned per instance by ops. Do not share.</p>
  </div>
</div></body></html>
"""


def _json(obj, status=200):
    return status, "application/json; charset=utf-8", json.dumps(obj).encode()


def _html(body, status=200):
    return status, "text/html; charset=utf-8", body.encode()


def _text(body, status=200):
    return status, "text/plain; charset=utf-8", body.encode()


def handle_inspect(query: str):
    params = parse_qs(query)
    urls = params.get("url", [])
    if not urls or not urls[0].strip():
        return _json({"ok": False, "reason": "missing ?url= parameter"}, 400)
    target = urls[0].strip()
    allowed, reason = guard(target)
    if not allowed:
        return _json({"ok": False, "url": target, "reason": "guard refused: " + reason}, 403)
    try:
        status, body = do_fetch(target)
    except Exception as e:  # connection refused, timeout, bad host, blocked egress...
        return _json({"ok": False, "url": target,
                      "reason": "fetch failed: %s: %s" % (type(e).__name__, e)}, 502)
    return _json({"ok": True, "url": target, "status": status, "body": body})


def route(method: str, path: str, query: str, headers):
    """Backend-agnostic request handler -> (status, content_type, body_bytes).

    `headers` is any case-insensitive mapping exposing .get(name, default).
    """
    if method not in ("GET", "HEAD"):
        return _text("method not allowed\n", 405)

    if path == "/" or path == "":
        return _html(_INDEX_HTML % {"css": _PAGE_CSS, "fp": FINGERPRINT, "iport": INTERNAL_PORT})

    if path == "/whoami":
        # public, non-secret: lets tooling learn the instance id + the internal
        # loopback port (the SSRF pivot target). The port is NOT a secret: the
        # internal listener binds 127.0.0.1 only and is never published, so
        # knowing it does not make it reachable from outside the container.
        return _json({"service": "palisade", "fingerprint": FINGERPRINT,
                      "internal_port": INTERNAL_PORT, "internal_service": "/internal/"})

    if path == "/inspect":
        return handle_inspect(query)

    # ---- The internal service is NOT served on the public port. ----
    # It lives on a separate, unpublished loopback listener (see route_internal /
    # run_internal). Requesting it here is a genuine 404 -- so a leaked/guessed
    # EDGE_SECRET on the public port buys nothing; the only path in is the SSRF
    # loopback pivot to 127.0.0.1:INTERNAL_PORT.
    if path == "/internal" or path == "/internal/" or path.startswith("/internal/"):
        return _text("404 not found\n", 404)

    # ---- RABBIT-HOLES: inert public red herrings (R1/R4). No real secret. ----
    if path == "/debug":
        return _json({
            "service": "palisade", "mode": "debug",
            "note": "non-production diagnostics; disabled in prod builds",
            "build_fingerprint": FINGERPRINT,
            "flag": DEBUG_DECOY_FLAG,
            "edge_header": EDGE_HEADER,
            "edge_hint": "rotated hourly; value redacted in diagnostics export",
        })
    if path == "/backup":
        return _text(
            "; palisade config backup (diagnostic export)\n"
            "; red-herring diagnostic stub, not a live secret store\n"
            "FLAG=%s\n"
            "%s=<redacted-32-byte-edge-credential>\n"
            "vault_hint=/internal/vault/<token>\n" % (BACKUP_DECOY_FLAG, EDGE_HEADER))

    return _text("404 not found\n", 404)


# ---------------------------------------------------------------------------
# THE INTERNAL RESULTS SERVICE  --  separate, unpublished loopback listener.
#
# This runs on its OWN server bound to 127.0.0.1:<ephemeral> (never published,
# never served on the public PORT), exactly like barbican's upstream. The ONLY
# client that can reach it is an in-container process -- i.e. the inspector's own
# fetcher, which it reaches via the SSRF loopback pivot. It is still gated by the
# shared edge credential (defence-in-depth: the inspector injects it on every
# outbound fetch), so even a process that could open the loopback port cannot
# read the vault without having ridden the inspector.
# ---------------------------------------------------------------------------
def route_internal(method: str, path: str, query: str, headers):
    """Request handler for the internal loopback service only."""
    if method not in ("GET", "HEAD"):
        return _text("method not allowed\n", 405)

    if path == "/internal" or path == "/internal/":
        if headers.get(EDGE_HEADER, "") != EDGE_SECRET:
            return _text("403 forbidden: internal service (edge credential required)\n", 403)
        return _html(_INTERNAL_INDEX_HTML % {"css": _PAGE_CSS, "fp": FINGERPRINT,
                                             "token": VAULT_TOKEN, "staging": STAGING_TOKEN})

    if path.startswith("/internal/vault/"):
        if headers.get(EDGE_HEADER, "") != EDGE_SECRET:
            return _text("403 forbidden: internal service (edge credential required)\n", 403)
        token = path[len("/internal/vault/"):].strip("/")
        if token == STAGING_TOKEN:
            # RABBIT-HOLE (R2 footgun): staging cache -> FIXTURE flag, not live.
            # Format-invalid on purpose (UPPERCASE + hyphens).
            return _text("Palisade vault entry [STAGING CACHE]\n"
                         "NOTE: fixture data from the last preview run, NOT the live vault.\n"
                         "FLAG: %s\n" % STAGING_FIXTURE_FLAG)
        if token != VAULT_TOKEN:
            return _text("404 no such vault entry\n", 404)
        return _text("Palisade vault entry\nFLAG: %s\n" % FLAG)

    return _text("404 not found\n", 404)


def run_internal():
    """Start the internal results service on an ephemeral loopback port.

    Returns the ThreadingHTTPServer (already serving in a daemon thread) after
    INTERNAL_PORT has been set to the port the OS assigned.
    """
    global INTERNAL_PORT
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class InternalHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _serve(self):
            parsed = urlsplit(self.path)
            status, ctype, body = route_internal(self.command, parsed.path,
                                                  parsed.query, self.headers)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_GET = _serve
        do_HEAD = _serve

        def log_message(self, *a):
            pass

    # Bind 127.0.0.1:0 -> loopback only, OS-chosen ephemeral port, never published.
    httpd = ThreadingHTTPServer((INTERNAL_HOST, 0), InternalHandler)
    INTERNAL_PORT = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    sys.stderr.write("palisade internal service on %s:%d (loopback-only, unpublished)\n"
                     % (INTERNAL_HOST, INTERNAL_PORT))
    sys.stderr.flush()
    return httpd


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
        status, ctype, body = route(request.method, path,
                                    request.query_string.decode("latin-1"),
                                    request.headers)
        return Response(body, status=status, content_type=ctype)

    # threaded=True is REQUIRED: the inspector makes a blocking HTTP call back to
    # this same server, so a second worker must be free to serve it.
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
            status, ctype, body = route(self.command, parsed.path, parsed.query, self.headers)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_GET = _serve
        do_HEAD = _serve

        def log_message(self, *a):
            pass

    httpd = ThreadingHTTPServer((host, port), Handler)
    sys.stderr.write("palisade (stdlib) listening on %s:%d\n" % (host, port))
    sys.stderr.flush()
    httpd.serve_forever()


def main():
    global PORT
    host = os.environ.get("HOST", "0.0.0.0")
    port = PORT
    # arg override: app.py [--port N] [--stdlib|--flask]
    backend = os.environ.get("ZSCTF_HTTPD", "auto").lower()
    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a == "--port" and i + 1 < len(args):
            port = int(args[i + 1])
        elif a == "--stdlib":
            backend = "stdlib"
        elif a == "--flask":
            backend = "flask"

    # Keep the module-global PORT in sync with the public port we actually bind.
    PORT = port

    # Start the internal results service FIRST, on its own ephemeral loopback
    # port, and learn that port before the public server comes up -- so /whoami
    # and the index can advertise the pivot target. The internal listener is
    # loopback-only and never published; the public server never serves
    # /internal (route() 404s it), so the SSRF pivot is the sole way in.
    run_internal()

    if backend == "stdlib":
        return run_stdlib(host, port)
    if backend == "flask":
        return run_flask(host, port)
    # auto: prefer Flask, fall back to stdlib
    try:
        import flask  # noqa: F401
    except ImportError:
        return run_stdlib(host, port)
    return run_flask(host, port)


if __name__ == "__main__":
    main()
