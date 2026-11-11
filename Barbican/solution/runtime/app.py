#!/usr/bin/env python3
"""
ZSCTF :: Barbican  (web, Hard)

"Barbican" is a two-tier web deployment, the pattern behind almost every modern
site: an EDGE gateway that faces the public internet, and an UPSTREAM
application that only the edge can talk to. The edge terminates the client
connection, applies access control, and forwards approved traffic to the
upstream over a single long-lived keep-alive connection (a connection pool of
one, as a thrifty reverse proxy would use).

The edge enforces one rule: the administrative area `/admin` on the upstream is
privileged, so the edge refuses `/admin` from the public side (HTTP 403). The
upstream itself does not re-check that rule -- it trusts that anything reaching
it has already passed the edge. This "trust the gateway" posture is exactly how
real internal services are deployed behind an authenticating proxy.

This is a WHITE-BOX challenge: you are given this exact source file. Both tiers
are small, self-contained stdlib HTTP servers in this one process. Read how each
tier frames an incoming request's body and how the edge decides what to forward.

Per-instance: ZSCTF_SEED derives a public instance fingerprint and a per-team
QA-preview fixture; ZSCTF_FLAG sets the real flag. Same seed -> same instance.

Zero third-party dependencies: pure Python standard library. `python app.py`
serves the public edge on $PORT (default 8000); the upstream binds an
ephemeral loopback port that is never published.
"""
import os
import sys
import json
import socket
import hashlib
import threading
from socketserver import ThreadingTCPServer, BaseRequestHandler
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Per-instance configuration (derived deterministically from the team seed).
# No secret is baked into this file: secrets are functions of the seed, injected
# at run time and never shipped to players.
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


FINGERPRINT = _derive(b"instance-fingerprint", 12)   # PUBLIC, non-secret
# A per-team QA-preview fixture. It is watermarked with the literal token
# "sample" and carries X-Flag-Source: qa-fixture, so it can never be mistaken
# for, or submitted as, a real flag (see README integrity rule).
DECOY_FIXTURE = "zerosecurectf{sample_preview_fixture_%s}" % _derive(b"preview-fixture", 8)

PORT = int(os.environ.get("PORT", "8000"))
HOST = os.environ.get("HOST", "0.0.0.0")

MAX_HEAD = 16 * 1024
MAX_BODY = 256 * 1024
SOCK_TIMEOUT = float(os.environ.get("BARBICAN_TIMEOUT", "15"))

BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = None          # set at startup once the upstream has bound


# ---------------------------------------------------------------------------
# A minimal buffered reader over a socket: just enough HTTP/1.1 framing.
# ---------------------------------------------------------------------------
class SockReader:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def _fill(self):
        data = self.sock.recv(65536)
        if not data:
            raise ConnectionError("peer closed")
        self.buf += data

    def read_until(self, delim, cap):
        while delim not in self.buf:
            if len(self.buf) > cap:
                raise ValueError("header too large")
            self._fill()
        idx = self.buf.index(delim) + len(delim)
        head, self.buf = self.buf[:idx], self.buf[idx:]
        return head

    def read_exactly(self, n):
        if n > MAX_BODY:
            raise ValueError("body too large")
        while len(self.buf) < n:
            self._fill()
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def readline(self):
        return self.read_until(b"\r\n", 4096)


def parse_head(reader):
    """Read request line + header block. Return (method, target, headers, raw)."""
    raw = reader.read_until(b"\r\n\r\n", MAX_HEAD)
    lines = raw.split(b"\r\n")
    request_line = lines[0].decode("latin-1")
    parts = request_line.split(" ")
    method = parts[0] if parts else ""
    target = parts[1] if len(parts) > 1 else "/"
    headers = {}
    for line in lines[1:]:
        if not line or b":" not in line:
            continue
        k, _, v = line.partition(b":")
        headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    return method, target, headers, raw


def read_chunked(reader):
    """Decode a chunked transfer-coded body into the raw entity bytes."""
    out = b""
    while True:
        size_line = reader.readline().strip()
        size = int(size_line.split(b";", 1)[0] or b"0", 16)
        if size == 0:
            reader.read_exactly(2)          # the final CRLF
            break
        out += reader.read_exactly(size)
        reader.read_exactly(2)              # CRLF after each chunk
        if len(out) > MAX_BODY:
            raise ValueError("body too large")
    return out


def build_response(status, ctype, body, extra=None):
    if isinstance(body, str):
        body = body.encode("utf-8")
    reason = {200: "OK", 403: "Forbidden", 404: "Not Found",
              400: "Bad Request", 405: "Method Not Allowed",
              502: "Bad Gateway"}.get(status, "OK")
    head = ["HTTP/1.1 %d %s" % (status, reason),
            "Content-Type: " + ctype,
            "Content-Length: %d" % len(body),
            "Connection: keep-alive"]
    if extra:
        for k, v in extra.items():
            head.append("%s: %s" % (k, v))
    return ("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + body


# ---------------------------------------------------------------------------
# UPSTREAM application tier (loopback only; never published).
#
# Framing policy: when a request announces a chunked transfer-coding, the
# upstream decodes the body as chunked; otherwise it uses Content-Length. The
# upstream trusts that the edge already authorised whatever it receives, so it
# serves /admin to any request that reaches it over the pooled connection.
# ---------------------------------------------------------------------------
UPSTREAM_HOME = (
    "Barbican upstream application.\n"
    "This service is internal: it is reachable only through the edge gateway.\n"
    "Resources: GET /app (this page), GET /admin (restricted administrative area).\n"
)


class UpstreamHandler(BaseRequestHandler):
    def handle(self):
        self.request.settimeout(SOCK_TIMEOUT)
        reader = SockReader(self.request)
        try:
            while True:
                try:
                    method, target, headers, _raw = parse_head(reader)
                except (ConnectionError, ValueError, socket.timeout):
                    return
                # Frame the body: chunked transfer-coding takes precedence; else
                # fall back to Content-Length.
                te = headers.get("transfer-encoding", "").lower()
                try:
                    if "chunked" in te:
                        read_chunked(reader)
                    else:
                        cl = int(headers.get("content-length", "0") or "0")
                        if cl:
                            reader.read_exactly(cl)
                except (ConnectionError, ValueError, socket.timeout):
                    return

                path = urlsplit(target).path
                if method not in ("GET", "HEAD"):
                    resp = build_response(405, "text/plain; charset=utf-8",
                                          "method not allowed\n")
                elif path in ("/", "/app"):
                    resp = build_response(200, "text/plain; charset=utf-8", UPSTREAM_HOME)
                elif path == "/admin":
                    body = ("Barbican administrative area (upstream).\n"
                            "FLAG: %s\n" % FLAG)
                    resp = build_response(200, "text/plain; charset=utf-8", body,
                                          extra={"X-Flag-Source": "live-admin"})
                else:
                    resp = build_response(404, "text/plain; charset=utf-8",
                                          "upstream: no such resource\n")
                try:
                    self.request.sendall(resp)
                except OSError:
                    return
        except Exception:
            return


# ---------------------------------------------------------------------------
# The edge's single pooled, long-lived connection to the upstream.
# A reverse proxy commonly multiplexes client traffic onto a small pool of
# persistent upstream connections; here the pool is one connection, serialised
# by a lock so each forwarded request reads exactly one upstream response.
# ---------------------------------------------------------------------------
class UpstreamPool:
    def __init__(self):
        self.lock = threading.Lock()
        self.sock = None
        self.reader = None

    def _connect(self):
        s = socket.create_connection((BACKEND_HOST, BACKEND_PORT), timeout=SOCK_TIMEOUT)
        s.settimeout(SOCK_TIMEOUT)
        self.sock = s
        self.reader = SockReader(s)

    def _read_one_response(self):
        head = self.reader.read_until(b"\r\n\r\n", MAX_HEAD)
        cl = 0
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                cl = int(line.split(b":", 1)[1].strip() or b"0")
                break
        body = self.reader.read_exactly(cl) if cl else b""
        return head + body

    def forward(self, raw_bytes):
        """Send one framed request to the upstream; return one upstream response."""
        with self.lock:
            for attempt in (1, 2):
                try:
                    if self.sock is None:
                        self._connect()
                    self.sock.sendall(raw_bytes)
                    return self._read_one_response()
                except (ConnectionError, OSError, ValueError):
                    try:
                        if self.sock:
                            self.sock.close()
                    except OSError:
                        pass
                    self.sock = None
                    if attempt == 2:
                        raise


POOL = UpstreamPool()


# ---------------------------------------------------------------------------
# EDGE gateway tier (public).
#
# Framing policy: the edge frames every request body by its Content-Length and
# forwards the request line, header block and that many body bytes to the
# upstream verbatim. The edge's own access control inspects the request it
# parsed and refuses the privileged administrative path.
# ---------------------------------------------------------------------------
EDGE_INDEX = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Barbican - Edge Gateway</title>
<style>
:root{color-scheme:light dark}
body{margin:0;font:16px/1.55 system-ui,Segoe UI,Roboto,sans-serif;background:#0f1216;color:#e7edf3}
.wrap{max-width:820px;margin:0 auto;padding:40px 20px}
h1{font-size:28px;margin:0 0 4px} .sub{color:#8aa0b4;margin:0 0 24px}
.card{background:#161b22;border:1px solid #273142;border-radius:12px;padding:18px;margin:16px 0}
code,pre{font:13px ui-monospace,Menlo,Consolas,monospace}
pre{background:#0b0f14;border:1px solid #273142;border-radius:8px;padding:12px;overflow:auto;white-space:pre-wrap}
.muted{color:#8aa0b4;font-size:14px}
.pill{display:inline-block;background:#0b0f14;border:1px solid #30465f;border-radius:999px;padding:3px 10px;font:12px ui-monospace,monospace;color:#9fb3c8}
a{color:#58a6ff}
</style></head>
<body><div class="wrap">
  <h1>Barbican</h1>
  <p class="sub">Edge gateway &mdash; public front for an internal application.</p>
  <span class="pill">instance %(fp)s</span>
  <div class="card">
    <p>The edge forwards approved traffic to the upstream application:</p>
    <pre>GET /app         upstream landing page (forwarded)
GET /admin       restricted at the edge (403)
GET /whoami      public instance fingerprint (edge-local)</pre>
    <p class="muted">The administrative area <code>/admin</code> is privileged
      and is refused at the edge. A QA preview of the admin area is available
      to staff via the <code>X-Barbican-Preview</code> request header; preview
      responses are <b>fixtures</b>, watermarked <code>sample</code> and tagged
      <code>X-Flag-Source: qa-fixture</code>, and are never valid submissions.</p>
    <p class="muted">White-box challenge: the full server source is
      <code>challenge/app.py</code>.</p>
  </div>
</div></body></html>
"""


class EdgeHandler(BaseRequestHandler):
    def handle(self):
        self.request.settimeout(SOCK_TIMEOUT)
        reader = SockReader(self.request)
        try:
            while True:
                try:
                    method, target, headers, raw = parse_head(reader)
                except (ConnectionError, ValueError, socket.timeout):
                    return
                # The edge frames request bodies by Content-Length.
                try:
                    cl = int(headers.get("content-length", "0") or "0")
                    body = reader.read_exactly(cl) if cl else b""
                except (ConnectionError, ValueError, socket.timeout):
                    return

                resp = self._dispatch(method, target, headers, raw, body)
                try:
                    self.request.sendall(resp)
                except OSError:
                    return
        except Exception:
            return

    def _dispatch(self, method, target, headers, raw, body):
        path = urlsplit(target).path

        if method not in ("GET", "HEAD", "POST"):
            return build_response(405, "text/plain; charset=utf-8", "method not allowed\n")

        # ---- edge-local endpoints (never forwarded) ----
        if path == "/whoami":
            payload = json.dumps({"service": "barbican-edge", "fingerprint": FINGERPRINT,
                                  "upstream": "internal"})
            return build_response(200, "application/json; charset=utf-8", payload)

        if path == "/" or path == "":
            return build_response(200, "text/html; charset=utf-8",
                                  EDGE_INDEX % {"fp": FINGERPRINT})

        # ---- access control: the privileged admin path is handled at the edge ----
        if path == "/admin":
            if "x-barbican-preview" in headers:
                # QA preview: return the per-instance fixture, not the upstream.
                fixture = ("Barbican administrative area (QA preview fixture).\n"
                           "FLAG: %s\n" % DECOY_FIXTURE)
                return build_response(200, "text/plain; charset=utf-8", fixture,
                                      extra={"X-Flag-Source": "qa-fixture"})
            return build_response(403, "text/plain; charset=utf-8",
                                  "403 forbidden: /admin is restricted at the edge\n")

        # ---- everything else is forwarded to the upstream verbatim ----
        try:
            upstream_resp = POOL.forward(raw + body)
        except Exception as e:
            return build_response(502, "text/plain; charset=utf-8",
                                  "edge: upstream error: %s\n" % type(e).__name__)
        return upstream_resp


# ---------------------------------------------------------------------------
class Edge(ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Upstream(ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    global PORT, BACKEND_PORT, HOST
    port = PORT
    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a == "--port" and i + 1 < len(args):
            port = int(args[i + 1])
    PORT = port

    # Start the upstream on an ephemeral loopback port first, learn its real
    # port, then point the edge's pool at it.
    upstream = Upstream((BACKEND_HOST, 0), UpstreamHandler)
    BACKEND_PORT = upstream.server_address[1]
    threading.Thread(target=upstream.serve_forever, daemon=True).start()

    edge = Edge((HOST, port), EdgeHandler)
    sys.stderr.write("barbican edge listening on %s:%d (upstream on %s:%d)\n"
                     % (HOST, port, BACKEND_HOST, BACKEND_PORT))
    sys.stderr.flush()
    try:
        edge.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        edge.server_close()
        upstream.shutdown()
        upstream.server_close()


if __name__ == "__main__":
    main()
