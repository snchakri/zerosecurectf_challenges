#!/usr/bin/env python3
"""
ZSCTF :: Mirage  (broken / honeypot, Hard-to-recognise)

"Mirage - Continuous Delivery Console" presents as an ordinary internal CI/CD
build-artifact dashboard: a landing page, an operator sign-in, a pipeline/build
browser, an artifact fetcher that *looks* vulnerable to path traversal, an
environment dump that *looks* like a leaked-secrets jackpot, and a deploy-token
minter that *looks* like it hands out live credentials. Poke it and it will
happily hand you plausible "secrets", deploy tokens and flag-shaped strings.

                        *** ORGANIZER NOTE (NOT FOR PLAYERS) ***
Mirage is a DELIBERATE DEFENSIVE HONEYPOT / TARPIT. There is NO real flag
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
canary marker, plus a build banner declaring tier=decoy).

Per-instance: ZSCTF_SEED derives the decoy operator key, decoy session token,
decoy deploy token and the (still-invalid) decoy flag bodies, so two teams see
different decoys but the honeypot conclusion is identical. Same seed -> same
instance.

Runs on Flask if available, else on the Python standard library http.server, so
it is deployable with or without third-party packages. `python app.py` serves
on $PORT (default 8000). A `--tcp` shim is also provided so the same canned
leads are reachable over a raw stdio-style TCP line protocol.
"""
import os
import re
import sys
import json
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
OPERATOR_KEY = _derive(b"operator-api-key", 16)      # DECOY sign-in key
SESSION_TOK = _derive(b"session-token", 24)          # DECOY session cookie value
SESSION_COOKIE = "mirage_sess"

# DECOY "flags". Each is deliberately malformed so that it FAILS the strict
# zerosecurectf validator (wrong prefix / wrong charset), and -- being non-empty
# -- also fails the published integrity digest (sha256 of the empty string).
DECOY_TOKEN = "zerosecurectf{deploy-token-%s}" % _derive(b"decoy-token", 8)          # hyphens in body
DECOY_ARTIFACT = "zerosecurectf{BUILD_ARTIFACT_%s}" % _derive(b"decoy-artifact", 8).upper()  # uppercase body
DECOY_ENV = "zer0securectf{env_promoted_%s}" % _derive(b"decoy-env", 8)              # bad prefix 'zer0'

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
# THE CANNED "ARTIFACT STORE".
#
# /api/artifact looks like a classic path-traversal sink into a build-artifact
# store, but it is SEALED: there is no filesystem behind it. It serves from this
# fixed in-memory dictionary. Any path is normalised (., .. and empty segments
# are dropped) to a key and looked up here. A miss returns a BYTE-IDENTICAL stub
# regardless of the request -- which is itself a tell that nothing real is read.
# ---------------------------------------------------------------------------
CANNED_ARTIFACTS = {
    "README": (
        "Mirage Continuous Delivery Console (node: %(fp)s)\n"
        "-------------------------------------------------\n"
        "Internal build/deploy dashboard. The CI service account key lives in\n"
        "  ci/secrets.env\n"
        "Promotion-gated build artifacts are under build/ .\n"
    ),
    "ci/secrets.env": (
        "# generated by the pipeline bootstrap; do not commit\n"
        "OPERATOR_API_KEY=%(key)s\n"
        "# sign in at /api/login then mint a deploy token at /api/token/mint\n"
    ),
    "build/flag.txt": (
        "%(decoy_artifact)s\n"
        "# promoted artifact from the release pipeline. verify against\n"
        "# /.well-known/zsctf-manifest.json before submitting.\n"
    ),
    "build/manifest.json": json.dumps({
        "node": "%(fp)s",
        "tier": "decoy",
        "artifacts": ["README", "ci/secrets.env", "build/flag.txt"],
        "cross_ref": "operator key rotates; re-auth at /api/login",
    }, indent=2),
}

_MISS_STUB = (
    "HTTP 404 :: no such artifact in this build store.\n"
    "This node serves a fixed, canned artifact index only (DECOY tier).\n"
    "See /robots.txt and /.well-known/zsctf-manifest.json .\n"
)


def _normalise_path(p: str) -> str:
    """Collapse a user path to a canonical key: drop '', '.', '..'. This SEALS
    the traversal -- '../../etc/passwd' becomes 'etc/passwd', a miss."""
    parts = []
    for seg in p.replace("\\", "/").split("/"):
        seg = seg.strip()
        if seg in ("", ".", ".."):
            continue
        parts.append(seg)
    return "/".join(parts)


def render_artifact(p: str):
    key = _normalise_path(p)
    tmpl = CANNED_ARTIFACTS.get(key)
    if tmpl is None:
        return 404, _MISS_STUB
    body = tmpl % {"fp": FINGERPRINT, "key": OPERATOR_KEY, "decoy_artifact": DECOY_ARTIFACT}
    return 200, body


# ---------------------------------------------------------------------------
# THE CANNED "BUILD LOG".
#
# /api/build/<id>/log looks like it streams a real per-build log, but every
# build id returns the SAME canned log bytes. Identical bytes for different
# build ids is the tell that no real build system is behind it.
# ---------------------------------------------------------------------------
_CANNED_LOG = (
    "== mirage build log (cached) ==\n"
    "[00:00:01] checkout         ok\n"
    "[00:00:04] restore-cache    ok\n"
    "[00:00:09] compile          ok\n"
    "[00:00:12] test             ok\n"
    "[00:00:15] promote-artifact ok -> build/flag.txt\n"
    "note: log served from cache; live build workers disabled on decoy tier.\n"
)


# ---------------------------------------------------------------------------
# THE CANNED "DEPLOY-TOKEN MINTER".
#
# /api/token/mint looks like it mints a live, scope-bound deploy credential, but
# it returns a fixed, canned token regardless of the requested scope -- only the
# echoed scope field changes. Identical token bytes for different scopes is the
# tell. The token itself is a flag-shaped DECOY (hyphens -> fails the charset).
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# THE CANNED "ENV DUMP".
#
# /api/env looks like a leaked process environment (the classic CI jackpot), but
# it is a fixed, canned dict. The flag-shaped value it "leaks" is a DECOY with a
# 'zer0' prefix -> fails the strict validator. Crucially, an injected ZSCTF_FLAG
# is NOT present here: the real process environment is never read.
# ---------------------------------------------------------------------------
_CANNED_ENV = {
    "CI": "true",
    "CI_NODE": FINGERPRINT,
    "CI_TIER": "decoy",
    "DEPLOY_ENV": "staging",
    "PROMOTED_FLAG": DECOY_ENV,
    "NOTE": "synthetic environment snapshot; not the live process env.",
}


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
_CSS = """
:root{color-scheme:light dark}*{box-sizing:border-box}
body{margin:0;font:16px/1.55 system-ui,Segoe UI,Roboto,sans-serif;background:#0d1117;color:#e6edf3}
.wrap{max-width:860px;margin:0 auto;padding:40px 20px}
h1{font-size:28px;margin:0 0 4px}.sub{color:#8b98a5;margin:0 0 24px}
.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:20px;margin:16px 0}
label{display:block;font-weight:600;margin:10px 0 6px}
input{width:100%;padding:10px 12px;border-radius:8px;border:1px solid #30363d;background:#010409;color:#e6edf3;font:14px ui-monospace,Consolas,monospace}
button{margin-top:12px;padding:10px 18px;border:0;border-radius:8px;background:#238636;color:#fff;font-weight:600;cursor:pointer}
code,pre{font:13px ui-monospace,Consolas,monospace}
pre{background:#010409;border:1px solid #30363d;border-radius:8px;padding:14px;overflow:auto;white-space:pre-wrap;word-break:break-word}
.muted{color:#8b98a5;font-size:14px}a{color:#2f81f7}
.pill{display:inline-block;background:#010409;border:1px solid #30363d;border-radius:999px;padding:3px 10px;font:12px ui-monospace,monospace;color:#7d8590}
"""

_INDEX = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mirage - Continuous Delivery Console</title><style>%(css)s</style></head>
<!-- build: mirage-canary * tier=decoy * artifacts=synthetic * do-not-promote -->
<body><div class="wrap">
  <h1>Mirage CD</h1>
  <p class="sub">Continuous Delivery / Build Artifact Console</p>
  <span class="pill">node %(fp)s</span>
  <div class="card">
    <p>Operator resources:</p>
    <ul>
      <li><a href="/api/login">/api/login</a> &mdash; operator sign-in</li>
      <li><code>/api/pipelines</code> &mdash; pipeline list</li>
      <li><code>/api/builds</code> &mdash; recent builds</li>
      <li><code>/api/build/42/log</code> &mdash; build log</li>
      <li><code>/api/artifact?path=README</code> &mdash; artifact fetch</li>
      <li><code>/api/env</code> &mdash; runner environment snapshot</li>
      <li><code>/api/token/mint?scope=deploy</code> &mdash; mint a deploy token (session required)</li>
      <li><a href="/.well-known/zsctf-manifest.json">/.well-known/zsctf-manifest.json</a>
          &mdash; integrity manifest</li>
      <li><code>/validate?flag=zerosecurectf{...}</code> &mdash; flag self-check</li>
    </ul>
    <p class="muted">White-box challenge: full source is <code>challenge/app.py</code>.</p>
  </div>
</div></body></html>
"""

_LOGIN_FORM = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Mirage - Sign in</title><style>%(css)s</style></head><body><div class="wrap">
<h1>Mirage CD</h1><p class="sub">Operator sign-in &mdash; node %(fp)s</p>
<div class="card">
  <form method="GET" action="/api/login">
    <label>Operator</label><input name="user" value="operator">
    <label>API key</label><input name="key" placeholder="operator API key">
    <button>Sign in</button>
  </form>
  <p class="muted">The CI service account key is provisioned by the pipeline bootstrap.</p>
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
    key = (params.get("key", [""])[0]).strip()
    if not user and not key:
        return _html(_LOGIN_FORM % {"css": _CSS, "fp": FINGERPRINT})
    if user == "operator" and key == OPERATOR_KEY:
        body = {
            "ok": True,
            "node": FINGERPRINT,
            "msg": "session established; mint a deploy token at /api/token/mint?scope=deploy",
        }
        extra = {"Set-Cookie": "%s=%s; Path=/; HttpOnly" % (SESSION_COOKIE, SESSION_TOK)}
        return _json(body, 200, extra)
    return _json({"ok": False, "reason": "invalid operator credentials"}, 401)


def handle_token_mint(query, headers):
    if _cookie(headers, SESSION_COOKIE) != SESSION_TOK:
        return _json({"ok": False, "reason": "login required (no valid session)"}, 401)
    params = parse_qs(query)
    scope = (params.get("scope", ["deploy"])[0]).strip() or "deploy"
    # Canned: identical token regardless of scope. The echoed scope is the only
    # thing that varies. The "deploy_token" is a flag-shaped DECOY.
    return _json({
        "ok": True,
        "node": FINGERPRINT,
        "scope": scope,
        "deploy_token": DECOY_TOKEN,
        "note": "verify against /.well-known/zsctf-manifest.json",
        "see_also": "/api/artifact?path=build/manifest.json",
    })


def handle_artifact(query):
    params = parse_qs(query)
    p = params.get("path", [""])[0]
    if not p:
        return _json({"ok": False, "reason": "missing ?path="}, 400)
    status, body = render_artifact(p)
    return _text(body, status)


def handle_build_log(build_id):
    # Byte-identical regardless of build_id: no real build system behind it.
    return _text(_CANNED_LOG)


def handle_env():
    return _json(dict(_CANNED_ENV))


def handle_pipelines():
    return _json({
        "node": FINGERPRINT,
        "tier": "decoy",
        "pipelines": [
            {"id": "release", "status": "green", "last_build": 42},
            {"id": "nightly", "status": "green", "last_build": 41},
        ],
        "note": "canned pipeline index (decoy tier)",
    })


def handle_builds():
    return _json({
        "node": FINGERPRINT,
        "tier": "decoy",
        "builds": [
            {"id": 42, "pipeline": "release", "artifact": "build/flag.txt", "log": "/api/build/42/log"},
            {"id": 41, "pipeline": "nightly", "artifact": "build/manifest.json", "log": "/api/build/41/log"},
        ],
        "note": "canned build index (decoy tier)",
    })


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
    "challenge": "mirage",
    "flag_format": "zerosecurectf{[a-z0-9_]{8,48}}",
    "flag_sha256": PUBLISHED_FLAG_SHA256,
    "verify": "printf %s \"$CANDIDATE\" | sha256sum   # must equal flag_sha256",
}

_ROBOTS = (
    "User-agent: *\n"
    "Disallow: /api/token/mint\n"
    "Disallow: /api/artifact\n"
    "Disallow: /api/env\n"
    "# ops: honeyfarm canary node -- DECOY tier, no production CI/CD mounted.\n"
    "# synthetic artifacts only; see SECOPS runbook (tarpit). do-not-promote.\n"
)


# A compact build-banner tell, served both as JSON (/api/status) and reused by
# the --tcp shim banner. Publishes the empty-string integrity digest and the
# decoy tier outright.
def _status_obj():
    return {
        "service": "mirage-cd",
        "node": FINGERPRINT,
        "tier": "decoy",
        "build": "mirage-canary",
        "artifacts": "synthetic",
        "promote": False,
        "flag_sha256": PUBLISHED_FLAG_SHA256,
    }


def route(method, path, query, headers):
    """Backend-agnostic handler -> (status, content_type, body_bytes, extra_headers)."""
    if method not in ("GET", "HEAD"):
        return _text("method not allowed\n", 405)

    if path in ("/", ""):
        return _html(_INDEX % {"css": _CSS, "fp": FINGERPRINT})
    if path == "/robots.txt":
        return _text(_ROBOTS)
    if path == "/whoami":
        return _json({"service": "mirage-cd", "fingerprint": FINGERPRINT, "tier": "decoy"})
    if path in ("/api/status", "/status"):
        return _json(_status_obj())
    if path == "/.well-known/zsctf-manifest.json":
        m = dict(_MANIFEST)
        m["fingerprint"] = FINGERPRINT
        return _json(m)
    if path in ("/api/login", "/login"):
        return handle_login(query, headers)
    if path == "/api/pipelines":
        return handle_pipelines()
    if path == "/api/builds":
        return handle_builds()
    if path == "/api/env":
        return handle_env()
    if path in ("/api/token/mint", "/api/token"):
        return handle_token_mint(query, headers)
    if path == "/api/artifact":
        return handle_artifact(query)
    if path == "/validate":
        return handle_validate(query)
    # /api/build/<id>/log
    m = re.match(r"^/api/build/([^/]+)/log$", path)
    if m:
        return handle_build_log(m.group(1))
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
    sys.stderr.write("mirage (stdlib) listening on %s:%d\n" % (host, port))
    sys.stderr.flush()
    httpd.serve_forever()


# ---------------------------------------------------------------------------
# Backend C: raw TCP line protocol (stdio-style service).
#
# A minimal line-oriented shim so the SAME canned leads are reachable over a raw
# socket (nc HOST PORT), the way many "network service" CTF targets are. It is
# intentionally thin: it maps verbs to the same backend-agnostic route() table,
# so every tell (canned bytes, self-rejecting SUBMIT, empty-string digest in the
# banner, tier=decoy) is identical to the HTTP surface. No command reaches a real
# flag; SUBMIT rejects every candidate including the empty string.
# ---------------------------------------------------------------------------
_TCP_HELP = (
    "commands:\n"
    "  HELP                      this help\n"
    "  STATUS                    build banner (publishes integrity digest)\n"
    "  PIPELINES                 pipeline index\n"
    "  BUILDS                    build index\n"
    "  LOG <id>                  build log (canned; identical for any id)\n"
    "  LOGIN <user> <key>        operator sign-in -> session token\n"
    "  SESSION <token>           attach a session token for this connection\n"
    "  MINT [scope]              mint a deploy token (session required)\n"
    "  ARTIFACT <path>           fetch a build artifact\n"
    "  ENV                       runner environment snapshot\n"
    "  SUBMIT <flag>             validate a candidate flag (self-rejecting)\n"
    "  QUIT                      close the connection\n"
)


def _tcp_dispatch(line, state):
    """Map one text line to a response string, mutating per-connection state.

    state: dict with optional 'session' token attached via LOGIN/SESSION.
    Returns (reply_text, keep_open_bool).
    """
    parts = line.strip().split()
    if not parts:
        return "", True
    verb = parts[0].upper()
    args = parts[1:]

    if verb in ("QUIT", "EXIT", "BYE"):
        return "bye\n", False
    if verb == "HELP":
        return _TCP_HELP, True
    if verb == "STATUS":
        return json.dumps(_status_obj(), indent=2) + "\n", True
    if verb == "PIPELINES":
        return handle_pipelines()[2].decode() + "\n", True
    if verb == "BUILDS":
        return handle_builds()[2].decode() + "\n", True
    if verb == "LOG":
        return handle_build_log(args[0] if args else "0")[2].decode() + "\n", True
    if verb == "ENV":
        return handle_env()[2].decode() + "\n", True
    if verb == "LOGIN":
        if len(args) < 2:
            return "ERR usage: LOGIN <user> <key>\n", True
        if args[0] == "operator" and args[1] == OPERATOR_KEY:
            state["session"] = SESSION_TOK
            return "OK session=%s (use MINT)\n" % SESSION_TOK, True
        return "ERR invalid operator credentials\n", True
    if verb == "SESSION":
        if not args:
            return "ERR usage: SESSION <token>\n", True
        state["session"] = args[0]
        return "OK session attached\n", True
    if verb == "MINT":
        if state.get("session") != SESSION_TOK:
            return "ERR login required (no valid session)\n", True
        scope = args[0] if args else "deploy"
        hdrs = {"Cookie": "%s=%s" % (SESSION_COOKIE, SESSION_TOK)}
        return handle_token_mint("scope=" + scope, hdrs)[2].decode() + "\n", True
    if verb == "ARTIFACT":
        if not args:
            return "ERR usage: ARTIFACT <path>\n", True
        return handle_artifact("path=" + args[0])[2].decode() + "\n", True
    if verb == "SUBMIT":
        flag = args[0] if args else ""
        return handle_validate("flag=" + flag)[2].decode() + "\n", True
    return "ERR unknown command (try HELP)\n", True


def run_tcp(host, port):
    import socketserver

    banner = (
        "Mirage CD (node %s) :: tier=decoy :: build=mirage-canary\n"
        "flag_sha256=%s\n"
        "type HELP for commands.\n"
    ) % (FINGERPRINT, PUBLISHED_FLAG_SHA256)

    class Handler(socketserver.StreamRequestHandler):
        timeout = 60

        def handle(self):
            state = {}
            try:
                self.wfile.write(banner.encode())
                self.wfile.flush()
                while True:
                    raw = self.rfile.readline()
                    if not raw:
                        break
                    try:
                        line = raw.decode("utf-8", "replace")
                    except Exception:
                        line = ""
                    reply, keep = _tcp_dispatch(line, state)
                    if reply:
                        self.wfile.write(reply.encode())
                        self.wfile.flush()
                    if not keep:
                        break
            except Exception:
                pass

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    srv = Server((host, port), Handler)
    sys.stderr.write("mirage (tcp) listening on %s:%d\n" % (host, port))
    sys.stderr.flush()
    srv.serve_forever()


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
        elif a == "--tcp":
            backend = "tcp"
    PORT = port

    if backend == "tcp":
        return run_tcp(host, port)
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
