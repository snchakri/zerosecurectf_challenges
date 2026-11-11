#!/usr/bin/env python3
"""
ZSCTF :: Broadsheet  (web, Hard)

"Broadsheet" is a newsletter studio. Editors compose an issue and use the
**Preview** feature to see how a personalised issue will look for a sample
subscriber: they write a small template snippet with placeholders such as
`{{ subscriber.name }}` or `{{ campaign.title }}`, and the server renders it.

Rendering user-supplied text *as a template* is the textbook Server-Side
Template Injection (SSTI) sink. Broadsheet's author knew that, and defended it
two ways:

  1. a real template SANDBOX (Jinja2's SandboxedEnvironment when available, or an
     equally locked-down built-in expression engine otherwise). The sandbox
     blocks the classic SSTI-to-RCE gadget chain: `__class__`, `__mro__`,
     `__subclasses__`, `__globals__`, `os.system`, ... all refuse to resolve.
  2. an input FILTER that rejects snippets containing "dangerous" substrings.

This is a WHITE-BOX challenge: you are given this exact source file. The flaw is
therefore not hidden by obscurity -- it is in plain sight, in the gap between
what the author THOUGHT the sandbox + filter protect and what they ACTUALLY
protect. The sandbox stops code execution; it does NOT stop you reading data the
application itself placed in the template context. And the filter is a deny-list
of raw substrings -- an incomplete list of disallowed inputs (CWE-184).

The flag never touches the OS and there is no command execution here: the whole
challenge is to read ONE in-application secret out of the render context,
through the preview, despite the sandbox and the filter.

Per-instance: ZSCTF_SEED derives the public instance fingerprint, the per-team
name of the secret key, and two decoy secrets; ZSCTF_FLAG sets the flag. Same
seed -> same instance.

Runs on Flask if available, else on the Python standard library http.server, and
renders with Jinja2 if available, else with a bundled Jinja-subset engine -- so
it is deployable with or without third-party packages. `python app.py` serves on
$PORT (default 8000).
"""
import os
import re
import ast
import sys
import json
import hashlib
from collections.abc import Mapping
from urllib.parse import urlsplit, parse_qs

# ---------------------------------------------------------------------------
# Per-instance configuration (derived deterministically from the team seed).
# Nothing secret is baked into this file: the secrets are functions of the seed,
# which is injected at run time and never shipped to players.
# ---------------------------------------------------------------------------
SEED = os.environ.get("ZSCTF_SEED", "static-demo-seed").encode()
FLAG = os.environ.get("ZSCTF_FLAG", "zerosecurectf{local_review_flag}")


def _derive(label: str, nhex: int) -> str:
    return hashlib.sha256(SEED + b"|" + label.encode()).hexdigest()[:nhex]


FINGERPRINT = _derive("instance-fingerprint", 12)  # PUBLIC, non-secret: proves determinism
FLAG_KEY = "dispatch_" + _derive("flag-key", 8)     # per-team name of the secret key in the bag

# ---------------------------------------------------------------------------
# RABBIT-HOLES (organizer-only; documented in writeup.md "Rabbit-holes").
#
# Deliberate, PROVABLY-INERT misdirection. None reveals the real FLAG or the real
# FLAG_KEY's value, and none opens a new path to them. Everything here is
# ZSCTF_SEED-derived (so leaked notes do not transfer, R5), and every decoy flag
# is rejectable by the published strict rule ^zerosecurectf\{[a-z0-9_]{8,48}\}$ .
# ---------------------------------------------------------------------------
# (R2/R3) A DECOY secret key that ALSO matches the dispatch_<hex> shape. It is
# inserted FIRST in the secrets bag, so a solver that grabs the first dispatch_*
# key it sees (or the first flag-shaped value from a whole-bag dump) reads this
# FIXTURE instead of the live flag. The fixture is UPPERCASE+hyphens, so it fails
# the format rule on reflection; the real flag is only behind the correct key.
DECOY_FLAG_KEY = "dispatch_" + _derive("decoy-flag-key", 8)
DECOY_FIXTURE_FLAG = "zerosecurectf{PREVIEW-FIXTURE-%s-NOT-LIVE}" % _derive("decoy-fixture", 8).upper()

# (R1/R4) Inert decoy served by the public /debug endpoint: 'zer0' homoglyph
# prefix (zero->0), so it can never satisfy the validator. The first thing a
# dirbuster/scanner grabs; a dead-end that carries no real secret.
DEBUG_DECOY_FLAG = "zer0securectf{%s}" % _derive("decoy-debug-build", 24)

PORT = int(os.environ.get("PORT", "8000"))

# How we render (independent of the HTTP backend):
#   auto    -> Jinja2 SandboxedEnvironment if importable, else the built-in engine
#   jinja2  -> force Jinja2 (error if not importable)
#   builtin -> force the bundled Jinja-subset engine (zero dependencies)
RENDER_ENGINE = os.environ.get("ZSCTF_ENGINE", "auto").lower()


# ---------------------------------------------------------------------------
# The application's own data. In a real app this "settings" object is a
# kitchen-sink: a handful of fields the newsletter legitimately uses, PLUS a
# secrets bag that the deployment put on the same object. The editor templates
# are only ever supposed to touch the public fields -- but the whole object is
# handed to the renderer, which is the crux.
# ---------------------------------------------------------------------------
class Settings:
    """Newsletter site settings. Its repr intentionally MASKS secret values (a
    real pattern -- e.g. frameworks hide SECRET_KEY on their debug pages) so a
    casual `{{ site }}` dump does not spill them. Note what it does NOT do: it
    does not stop direct access to the `secrets` attribute itself."""

    def __init__(self, title, sender, reply_to, footer, unsubscribe, secrets):
        self.title = title
        self.sender = sender
        self.reply_to = reply_to
        self.footer = footer
        self.unsubscribe = unsubscribe
        self.secrets = secrets  # a plain dict; NOT masked once you reach it

    def __repr__(self):
        public = " ".join(
            "%s=%r" % (k, getattr(self, k))
            for k in ("title", "sender", "reply_to", "footer", "unsubscribe")
        )
        # keys are shown (so ops can see which secrets exist) but values masked:
        masked = "{%s}" % ", ".join("%r: '***'" % k for k in self.secrets)
        return "<Settings %s secrets=%s>" % (public, masked)

    __str__ = __repr__


SECRETS = {
    DECOY_FLAG_KEY: DECOY_FIXTURE_FLAG,     # RABBIT-HOLE (R2/R3): listed FIRST to bait a grab-the-first solver
    FLAG_KEY: FLAG,                         # <-- the one secret that matters
    "smtp_password": _derive("smtp", 16),   # decoys: realistic co-tenants of a secrets bag
    "api_token": _derive("api", 24),
}

SETTINGS = Settings(
    title="The Broadsheet Weekly",
    sender="editors@broadsheet.example",
    reply_to="no-reply@broadsheet.example",
    footer="(c) The Broadsheet. You are receiving this because you subscribed.",
    unsubscribe="https://broadsheet.example/u/{{id}}",
    secrets=SECRETS,
)

# A fixed, benign sample subscriber + campaign used for every preview render.
SAMPLE_SUBSCRIBER = {"name": "Ada Lovelace", "email": "ada@subscribers.example", "city": "London"}
SAMPLE_CAMPAIGN = {"title": "What's new this week", "issue": 42, "date": "2026-10-15"}


def build_context():
    """The render context handed to EVERY preview. The editor is told about
    `subscriber`, `campaign` and the public `site.*` fields -- but `site` itself
    (hence `site.secrets`) is in the context, reachable by any expression."""
    return {"subscriber": dict(SAMPLE_SUBSCRIBER),
            "campaign": dict(SAMPLE_CAMPAIGN),
            "site": SETTINGS}


# ---------------------------------------------------------------------------
# GUARD #1 -- the input FILTER (deny-list of raw substrings).
#
# The author's intent: "strip out anything that looks like an SSTI/RCE gadget or
# that names a secret." It scans only the CODE inside `{{ ... }}` (so ordinary
# prose in the newsletter is never falsely rejected), lower-cases it, and refuses
# the snippet if any denied substring appears. It also forbids statement blocks
# (`{% ... %}`) entirely -- the composer only supports expression placeholders.
#
# <<< THE FILTER IS FLAWED >>> It is an *incomplete list of disallowed inputs*
# (CWE-184): it matches raw substrings, so a denied name can be reassembled at
# evaluation time from pieces that are individually allowed (e.g. 'sec'+'rets').
# ---------------------------------------------------------------------------
DENY = [
    "__",                                           # dunder gadgets
    "class", "mro", "subclass", "subclasses",       # type/gadget traversal
    "globals", "builtins", "import", "eval", "exec",
    "getattr", "setattr", "subprocess", "popen", "system",
    "config", "request", "session", "self",         # framework internals
    "cycler", "joiner", "namespace", "lipsum", "url_for",
    "secret", "flag", "password",                   # names of the sensitive fields
]
_CODE_RE = re.compile(r"\{\{(.*?)\}\}", re.DOTALL)


def guard(tpl: str):
    """Return (allowed: bool, reason: str)."""
    if "{%" in tpl or "%}" in tpl:
        return False, "statement blocks ({% ... %}) are not allowed in previews"
    code = " ".join(_CODE_RE.findall(tpl)).lower()
    for bad in DENY:
        if bad in code:
            return False, "snippet rejected by content filter (token %r)" % bad
    return True, "ok"


# ---------------------------------------------------------------------------
# RENDER ENGINE A -- Jinja2 SandboxedEnvironment (used when Jinja2 is present).
#
# The sandbox is a REAL protection: it intercepts every attribute/item access
# and refuses anything unsafe (names starting with '_', internal attributes), so
# the gadget chain to RCE does not resolve. We deliberately build a DEDICATED
# environment and do NOT expose Flask globals (no `config`, `request`, `url_for`,
# `self`), so the only reachable names are the ones we put in the context.
# ---------------------------------------------------------------------------
_JENV = None


def _jinja_render(tpl: str) -> str:
    global _JENV
    if _JENV is None:
        from jinja2.sandbox import SandboxedEnvironment
        _JENV = SandboxedEnvironment(autoescape=False)
    return _JENV.from_string(tpl).render(**build_context())


# ---------------------------------------------------------------------------
# RENDER ENGINE B -- a bundled Jinja-subset engine (zero dependencies).
#
# It renders `{{ expression }}` placeholders against the same context and leaves
# all other text verbatim. Expressions are parsed with Python's `ast` module and
# evaluated by a strict white-list walker that supports ONLY: literals, context
# names, attribute/index access, string/number '+'/'-'/'*' -- and NOTHING else
# (no calls, no dunders, no comprehensions). Attribute/item names beginning with
# '_' resolve to Undefined, exactly like the Jinja sandbox, so this fallback is
# locked down the same way: it cannot reach code execution either.
# ---------------------------------------------------------------------------
class _Undefined:
    __slots__ = ()
    def __str__(self): return ""
    def __bool__(self): return False
    def __repr__(self): return ""


_UNDEF = _Undefined()

_ALLOWED_BINops = (ast.Add, ast.Sub, ast.Mult)


def _safe_access(obj, key):
    """Mirror the Jinja sandbox: refuse '_'-prefixed names; try mapping item,
    then public attribute; unknown -> Undefined."""
    if isinstance(key, str):
        if key.startswith("_"):
            return _UNDEF
        if isinstance(obj, Mapping):
            return obj[key] if key in obj else _UNDEF
        if hasattr(obj, key):
            return getattr(obj, key)
        return _UNDEF
    # non-string key: only plain sequence/mapping indexing, never attributes
    if isinstance(obj, Mapping):
        return obj.get(key, _UNDEF)
    if isinstance(obj, (list, tuple)) and isinstance(key, int):
        return obj[key] if -len(obj) <= key < len(obj) else _UNDEF
    return _UNDEF


def _eval_node(node, ctx):
    if isinstance(node, ast.Expression):
        return _eval_node(node.body, ctx)
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return ctx[node.id] if node.id in ctx else _UNDEF
    if isinstance(node, ast.Attribute):
        return _safe_access(_eval_node(node.value, ctx), node.attr)
    if isinstance(node, ast.Subscript):
        key = _eval_node(node.slice, ctx)
        if isinstance(key, _Undefined):
            return _UNDEF
        return _safe_access(_eval_node(node.value, ctx), key)
    if isinstance(node, ast.BinOp) and isinstance(node.op, _ALLOWED_BINops):
        left, right = _eval_node(node.left, ctx), _eval_node(node.right, ctx)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        return left * right
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        v = _eval_node(node.operand, ctx)
        return -v if isinstance(node.op, ast.USub) else +v
    # Everything else (calls, comprehensions, bitwise '|' filters, ...) is refused.
    raise ValueError("unsupported expression element: %s" % type(node).__name__)


def _render_expr(expr: str, ctx) -> str:
    tree = ast.parse(expr.strip(), mode="eval")
    val = _eval_node(tree, ctx)
    return "" if isinstance(val, _Undefined) else str(val)


def _builtin_render(tpl: str) -> str:
    ctx = build_context()
    out, last = [], 0
    for m in _CODE_RE.finditer(tpl):
        out.append(tpl[last:m.start()])
        out.append(_render_expr(m.group(1), ctx))
        last = m.end()
    out.append(tpl[last:])
    return "".join(out)


def _engine_name() -> str:
    if RENDER_ENGINE == "builtin":
        return "builtin"
    if RENDER_ENGINE == "jinja2":
        return "jinja2"
    try:
        import jinja2  # noqa: F401
        return "jinja2"
    except ImportError:
        return "builtin"


def render_preview(tpl: str):
    """(ok, payload). ok True -> payload is the rendered string; ok False ->
    payload is a human reason (guard refusal or a render error)."""
    allowed, reason = guard(tpl)
    if not allowed:
        return False, reason
    try:
        out = _jinja_render(tpl) if _engine_name() == "jinja2" else _builtin_render(tpl)
    except Exception as e:  # syntax error, unsupported element, sandbox refusal...
        return False, "render error: %s: %s" % (type(e).__name__, e)
    return True, out


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
_PAGE_CSS = """
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{margin:0;font:16px/1.55 Georgia,'Times New Roman',serif;background:#f6f3ec;color:#1b1a17}
.wrap{max-width:820px;margin:0 auto;padding:40px 20px}
h1{font-size:34px;margin:0 0 2px;letter-spacing:.5px;border-bottom:3px double #1b1a17;padding-bottom:8px}
.sub{color:#6b655a;margin:6px 0 24px;font-style:italic}
.card{background:#fffdf8;border:1px solid #d8d2c4;border-radius:8px;padding:20px;margin:18px 0}
label{display:block;font-weight:bold;margin-bottom:8px;font-family:system-ui,sans-serif;font-size:14px}
textarea{width:100%;min-height:120px;padding:12px 14px;border-radius:6px;border:1px solid #c7c0b0;background:#fffefb;color:#1b1a17;font:13px/1.5 ui-monospace,Menlo,Consolas,monospace}
button{margin-top:12px;padding:10px 20px;border:0;border-radius:6px;background:#1b1a17;color:#f6f3ec;font-weight:bold;cursor:pointer;font-family:system-ui,sans-serif}
button:hover{background:#3a372f}
code,pre{font:13px ui-monospace,Menlo,Consolas,monospace}
pre{background:#f1ece1;border:1px solid #d8d2c4;border-radius:6px;padding:14px;overflow:auto;white-space:pre-wrap;word-break:break-word}
.muted{color:#6b655a;font-size:14px;font-family:system-ui,sans-serif}
.pill{display:inline-block;background:#1b1a17;color:#f6f3ec;border-radius:999px;padding:3px 12px;font:12px ui-monospace,monospace}
ul{font-family:system-ui,sans-serif;font-size:14px}
a{color:#7a1f1f}
"""

_INDEX_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Broadsheet &mdash; Newsletter Studio</title><style>%(css)s</style></head>
<body><div class="wrap">
  <h1>The Broadsheet</h1>
  <p class="sub">Newsletter Studio &mdash; compose an issue, preview it for a sample subscriber.</p>
  <span class="pill">instance %(fp)s &middot; engine %(engine)s</span>

  <div class="card">
    <label for="t">Issue template (preview for a sample subscriber)</label>
    <textarea id="t">Dear {{ subscriber.name }},

Welcome to {{ site.title }} &mdash; {{ campaign.title }} (issue {{ campaign.issue }}).

{{ site.footer }}</textarea>
    <button id="go">Preview</button>
    <p class="muted">Placeholders are rendered in a locked-down template sandbox and a
      content filter screens the snippet first. Only expression placeholders
      <code>{{ ... }}</code> are supported (no <code>{%% ... %%}</code> blocks).</p>
    <pre id="out" class="muted">Rendered preview will appear here.</pre>
  </div>

  <div class="card">
    <p class="muted"><b>Variables you can use:</b></p>
    <ul>
      <li><code>subscriber.name</code>, <code>subscriber.email</code>, <code>subscriber.city</code></li>
      <li><code>campaign.title</code>, <code>campaign.issue</code>, <code>campaign.date</code></li>
      <li><code>site.title</code>, <code>site.sender</code>, <code>site.footer</code></li>
    </ul>
    <p class="muted">White-box challenge: the full server source is
      <code>challenge/app.py</code>. The sandbox and the content filter are in plain sight.</p>
  </div>

<script>
const out=document.getElementById('out'),t=document.getElementById('t');
document.getElementById('go').onclick=async()=>{
  out.textContent='rendering...';
  try{
    const r=await fetch('/preview',{method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:'tpl='+encodeURIComponent(t.value)});
    const j=await r.json();
    out.textContent = j.ok ? j.rendered : ('refused: '+j.reason);
  }catch(e){out.textContent='error: '+e;}
};
</script>
</div></body></html>
"""


def _json(obj, status=200):
    return status, "application/json; charset=utf-8", json.dumps(obj).encode()


def _html(body, status=200):
    return status, "text/html; charset=utf-8", body.encode()


def _text(body, status=200):
    return status, "text/plain; charset=utf-8", body.encode()


def handle_preview(tpl):
    if tpl is None or tpl.strip() == "":
        return _json({"ok": False, "reason": "missing 'tpl' (template snippet)"}, 400)
    ok, payload = render_preview(tpl)
    if ok:
        return _json({"ok": True, "rendered": payload})
    return _json({"ok": False, "reason": payload}, 200)


def route(method: str, path: str, query: str, body_tpl):
    """Backend-agnostic request handler -> (status, content_type, body_bytes).

    `body_tpl` is the 'tpl' value parsed from a POST body (or None)."""
    if method not in ("GET", "HEAD", "POST"):
        return _text("method not allowed\n", 405)

    if path in ("/", ""):
        return _html(_INDEX_HTML % {"css": _PAGE_CSS, "fp": FINGERPRINT, "engine": _engine_name()})

    if path == "/whoami":
        # public, non-secret: lets tooling learn the instance id + active engine.
        return _json({"service": "broadsheet", "fingerprint": FINGERPRINT,
                      "engine": _engine_name(), "preview": "/preview"})

    if path == "/preview":
        # accept the snippet from the POST form body, or from ?tpl= for convenience.
        tpl = body_tpl
        if tpl is None:
            vals = parse_qs(query).get("tpl", [])
            tpl = vals[0] if vals else None
        return handle_preview(tpl)

    # ---- RABBIT-HOLE: inert public red herring (R1/R4). No real secret. ----
    if path == "/debug":
        return _json({
            "service": "broadsheet", "mode": "debug",
            "note": "non-production diagnostics; disabled in prod builds",
            "build_fingerprint": FINGERPRINT,
            "flag": DEBUG_DECOY_FLAG,
            "render_engine": _engine_name(),
            "hint": "preview cache warmed; sample issue flag shown above",
        })

    return _text("404 not found\n", 404)


# ---------------------------------------------------------------------------
# Backend A: Flask (used in deployment if available)
# ---------------------------------------------------------------------------
def run_flask(host, port):
    from flask import Flask, request, Response
    app = Flask(__name__)

    @app.route("/", defaults={"p": ""}, methods=["GET", "HEAD", "POST"])
    @app.route("/<path:p>", methods=["GET", "HEAD", "POST"])
    def _any(p):
        path = "/" + p
        body_tpl = None
        if request.method == "POST":
            body_tpl = request.form.get("tpl")
            if body_tpl is None:
                # tolerate a raw/urlencoded body that Flask did not parse as a form
                raw = request.get_data(as_text=True)
                vals = parse_qs(raw).get("tpl", [])
                body_tpl = vals[0] if vals else None
        status, ctype, body = route(request.method, path,
                                    request.query_string.decode("latin-1"), body_tpl)
        return Response(body, status=status, content_type=ctype)

    # threaded=True: the preview render is CPU-bound and short, but keep parity
    # with a normal multi-worker web app.
    app.run(host=host, port=port, threaded=True)


# ---------------------------------------------------------------------------
# Backend B: standard library http.server (zero dependencies)
# ---------------------------------------------------------------------------
def run_stdlib(host, port):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _read_body_tpl(self):
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                n = 0
            if n <= 0:
                return None
            raw = self.rfile.read(n).decode("utf-8", "replace")
            vals = parse_qs(raw).get("tpl", [])
            return vals[0] if vals else None

        def _serve(self, body_tpl=None):
            parsed = urlsplit(self.path)
            status, ctype, body = route(self.command, parsed.path, parsed.query, body_tpl)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_GET(self):
            self._serve()

        do_HEAD = do_GET

        def do_POST(self):
            self._serve(self._read_body_tpl())

        def log_message(self, *a):
            pass

    httpd = ThreadingHTTPServer((host, port), Handler)
    sys.stderr.write("broadsheet (stdlib/%s) listening on %s:%d\n" % (_engine_name(), host, port))
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
    PORT = port  # keep /whoami + index in sync with the bound port

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
