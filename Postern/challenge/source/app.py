#!/usr/bin/env python3
"""
ZSCTF :: Postern  (web, Easy)

A "postern" is a small side gate in a fortress wall -- a convenient back entrance
that is only as strong as the lock on it. This service is a tiny members' area
for a book club. After you "sign in", the server hands you a session cookie that
remembers who you are and what you may see. The administrators' area shows the
club secret (the flag); ordinary members only see the lobby.

THE FLAW (in plain sight -- this is a WHITE-BOX challenge, you get this source):
the session cookie is NOT signed. It is just URL-safe base64 of a small JSON
object, e.g. {"uid": 1007, "user": "guest", "role": "member"}. The server trusts
whatever role the cookie claims. Nothing stops a client from decoding the cookie,
changing "member" to "admin", re-encoding it, and sending it back. That is a
textbook client-trusted-authorization bug (OWASP A01: Broken Access Control;
CWE-302 Authentication Bypass by Assumption; CWE-565 Reliance on cookies without
validation/integrity).

Per-instance: ZSCTF_SEED derives a public instance fingerprint and a per-team
staging banner (a deliberately INVALID-format decoy flag, see README). Same seed
-> same instance. ZSCTF_FLAG sets the real flag.

Dependencies: Flask (3.1.x) + Python standard library. `python app.py` serves on
$PORT (default 8000); `--port N` overrides.
"""
import os
import sys
import json
import base64
import hashlib

from flask import Flask, request, make_response, Response

# ---------------------------------------------------------------------------
# Per-instance configuration (derived deterministically from the team seed).
# No secret is baked into this file: the flag is injected at run time via the
# environment and is never shipped to players.
# ---------------------------------------------------------------------------
SEED = os.environ.get("ZSCTF_SEED", "static-demo-seed").encode()

FLAG = os.environ.get("ZSCTF_FLAG")
if not FLAG:
    FLAG = "zerosecurectf{local_review_flag}"
    sys.stderr.write("WARNING: ZSCTF_FLAG is unset; using the placeholder flag. "
                     "Set ZSCTF_FLAG at deploy time.\n")
    sys.stderr.flush()


def _derive(label: bytes, nhex: int) -> str:
    return hashlib.sha256(SEED + b"|" + label).hexdigest()[:nhex]


# PUBLIC, non-secret: a stable per-instance fingerprint shown on the landing page
# and at /whoami, so each team's instance is visibly distinct.
FINGERPRINT = _derive(b"instance-fingerprint", 12)

# A per-team STAGING banner carrying a deliberately INVALID-format decoy flag.
# It begins "zer0securectf{" (a zero, not an 'o'), so it can NEVER match the
# published flag rule ^zerosecurectf\{[a-z0-9_]+\}$ and is never a valid
# submission (see README integrity rule). This is the challenge's single, bounded
# decoy.
DECOY_FLAG = "zer0securectf{staging_banner_%s_not_valid}" % _derive(b"staging-decoy", 8)

# The ordinary (member) session a fresh visitor is issued.
GUEST_UID = 1000 + (int(_derive(b"guest-uid", 6), 16) % 9000)   # e.g. 1000..9999


# ---------------------------------------------------------------------------
# Session cookie helpers -- URL-safe base64 of a small JSON object.
# NOTE: there is no signature and no server-side session store. This is the
# bug on purpose; a real app would sign the cookie (e.g. Flask's itsdangerous)
# or keep the role server-side.
# ---------------------------------------------------------------------------
COOKIE_NAME = "session"


def encode_cookie(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_cookie(value: str):
    """Return the decoded dict, or None if the cookie is missing/garbage."""
    if not value:
        return None
    try:
        pad = "=" * (-len(value) % 4)          # tolerate stripped padding
        raw = base64.urlsafe_b64decode(value + pad)
        obj = json.loads(raw.decode("utf-8"))
        if isinstance(obj, dict):
            return obj
    except Exception:
        return None
    return None


def current_session():
    return decode_cookie(request.cookies.get(COOKIE_NAME, ""))


# ---------------------------------------------------------------------------
app = Flask(__name__)


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Postern - Book Club</title>
<style>
:root{{color-scheme:light dark}}
body{{margin:0;font:16px/1.55 system-ui,Segoe UI,Roboto,sans-serif;background:#0f1216;color:#e7edf3}}
.wrap{{max-width:760px;margin:0 auto;padding:40px 20px}}
h1{{font-size:28px;margin:0 0 4px}} .sub{{color:#8aa0b4;margin:0 0 24px}}
.card{{background:#161b22;border:1px solid #273142;border-radius:12px;padding:18px;margin:16px 0}}
code,pre{{font:13px ui-monospace,Menlo,Consolas,monospace}}
pre{{background:#0b0f14;border:1px solid #273142;border-radius:8px;padding:12px;overflow:auto;white-space:pre-wrap}}
.muted{{color:#8aa0b4;font-size:14px}}
.pill{{display:inline-block;background:#0b0f14;border:1px solid #30465f;border-radius:999px;padding:3px 10px;font:12px ui-monospace,monospace;color:#9fb3c8}}
input,button{{font:15px system-ui;padding:8px 12px;border-radius:8px;border:1px solid #30465f;background:#0b0f14;color:#e7edf3}}
button{{cursor:pointer;background:#1f3a5f;border-color:#2f5a8f}}
a{{color:#58a6ff}}
</style></head>
<body><div class="wrap">
  <h1>Postern Book Club</h1>
  <p class="sub">A tiny members' area. Sign in to reach the lobby.</p>
  <span class="pill">instance {fp}</span>
  <div class="card">
    <form method="POST" action="/login">
      <label>Display name <input name="user" value="guest" maxlength="32"></label>
      <button type="submit">Sign in</button>
    </form>
    <p class="muted">Signing in issues a <code>session</code> cookie and sends you
      to <a href="/lobby">/lobby</a>. The administrators' area shows the club
      secret; ordinary members only see the lobby.</p>
  </div>
  <div class="card">
    <p class="muted">Endpoints:</p>
    <pre>POST /login     sign in (issues the session cookie)
GET  /lobby     members' lobby (role-gated)
GET  /whoami    public: instance fingerprint + your decoded session (JSON)
GET  /          this page</pre>
    <p class="muted">White-box challenge: the full server source is
      <code>challenge/app.py</code>.</p>
  </div>
</div></body></html>
"""


LOBBY_MEMBER = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Postern - Lobby</title>
<style>
:root{{color-scheme:light dark}}
body{{margin:0;font:16px/1.55 system-ui,Segoe UI,Roboto,sans-serif;background:#0f1216;color:#e7edf3}}
.wrap{{max-width:760px;margin:0 auto;padding:40px 20px}}
.card{{background:#161b22;border:1px solid #273142;border-radius:12px;padding:18px;margin:16px 0}}
.warn{{border-color:#5a4a1f;background:#1c1810}}
code,pre{{font:13px ui-monospace,Menlo,Consolas,monospace}}
.muted{{color:#8aa0b4;font-size:14px}}
a{{color:#58a6ff}}
</style></head>
<body><div class="wrap">
  <h1>Lobby</h1>
  <p>Welcome, <b>{user}</b> (uid {uid}, role <code>{role}</code>).</p>
  <div class="card">
    <p>The club secret is shown only to members whose role is
      <code>admin</code>. Your current role is <code>{role}</code>, so the
      secret stays hidden here.</p>
    <p class="muted">Your session is carried entirely in the <code>session</code>
      cookie. Curious what is inside it? See <a href="/whoami">/whoami</a>.</p>
  </div>
  <div class="card warn">
    <p class="muted">STAGING ENVIRONMENT BANNER (ignore in production):</p>
    <pre>demo flag for layout testing only -- NOT a valid submission:
{decoy}</pre>
    <p class="muted">This banner is a fixture. It is intentionally not in the
      published flag format and will never be accepted.</p>
  </div>
</div></body></html>
"""


LOBBY_ADMIN = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Postern - Lobby (admin)</title>
<style>
:root{{color-scheme:light dark}}
body{{margin:0;font:16px/1.55 system-ui,Segoe UI,Roboto,sans-serif;background:#0f1216;color:#e7edf3}}
.wrap{{max-width:760px;margin:0 auto;padding:40px 20px}}
.card{{background:#161b22;border:1px solid #273142;border-radius:12px;padding:18px;margin:16px 0}}
.ok{{border-color:#1f5a33;background:#10190f}}
code,pre{{font:13px ui-monospace,Menlo,Consolas,monospace}}
</style></head>
<body><div class="wrap">
  <h1>Lobby &mdash; administrators</h1>
  <p>Welcome, <b>{user}</b> (uid {uid}, role <code>admin</code>).</p>
  <div class="card ok">
    <p>Club secret (administrators only):</p>
    <pre>{flag}</pre>
  </div>
</div></body></html>
"""


def html(body, status=200, headers=None):
    resp = make_response(body, status)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    if headers:
        for k, v in headers.items():
            resp.headers[k] = v
    return resp


@app.route("/", methods=["GET"])
def index():
    # The landing page carries NO flag (real or decoy). A plain curl of / shows
    # only the sign-in form.
    return html(PAGE.format(fp=FINGERPRINT))


@app.route("/robots.txt", methods=["GET"])
def robots():
    # No secret here; disallow the members' area for tidy crawlers only.
    return Response("User-agent: *\nDisallow: /lobby\n", mimetype="text/plain")


@app.route("/login", methods=["POST"])
def login():
    name = (request.form.get("user") or "guest").strip()[:32] or "guest"
    # A fresh visitor is always issued an ordinary MEMBER session. The role is
    # stored, unsigned, in the cookie -- that is the flaw.
    session = {"uid": GUEST_UID, "user": name, "role": "member"}
    resp = make_response("", 303)
    resp.headers["Location"] = "/lobby"
    resp.set_cookie(COOKIE_NAME, encode_cookie(session),
                    httponly=False, samesite="Lax")
    return resp


@app.route("/lobby", methods=["GET"])
def lobby():
    sess = current_session()
    if sess is None:
        # Not signed in: send them to the landing page.
        return html(PAGE.format(fp=FINGERPRINT), status=401)

    role = str(sess.get("role", "member"))
    user = str(sess.get("user", "guest"))[:32]
    uid = sess.get("uid", GUEST_UID)

    if role == "admin":
        # The server trusts the role claimed by the (unsigned) cookie.
        return html(LOBBY_ADMIN.format(user=user, uid=uid, flag=FLAG),
                    headers={"X-Flag-Source": "live-admin"})

    return html(LOBBY_MEMBER.format(user=user, uid=uid, role=role, decoy=DECOY_FLAG))


@app.route("/whoami", methods=["GET"])
def whoami():
    sess = current_session()
    payload = {
        "service": "postern",
        "fingerprint": FINGERPRINT,
        "session": sess,          # echo the decoded cookie so its shape is visible
    }
    return Response(json.dumps(payload), mimetype="application/json; charset=utf-8")


def main():
    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "0.0.0.0")
    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a == "--port" and i + 1 < len(args):
            port = int(args[i + 1])
    sys.stderr.write("postern listening on %s:%d\n" % (host, port))
    sys.stderr.flush()
    # threaded=True so the reference solver's sequential requests are served
    # promptly; the dev server is adequate for an isolated, single-team instance.
    app.run(host=host, port=port, threaded=True)


if __name__ == "__main__":
    main()
