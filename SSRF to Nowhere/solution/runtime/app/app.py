#!/usr/bin/env python3
"""
SSRF TO NOWHERE  (REAL challenge, flag = ZeroSecure{...}).

The "sensor feed preview" tool fetches a user-supplied URL server-side -- a
classic SSRF. The flag lives on an internal admin endpoint, /admin/flag, which
only answers requests that arrive from loopback. You can see that the endpoint
exists, but hitting it directly from outside gets you a 403.

The catch: the fetcher has a (naive) SSRF filter that blocks the obvious
loopback spellings -- "localhost", "127.0.0.1", "::1". You must reach the
server's own loopback interface using a spelling the blocklist didn't think of
(e.g. 0.0.0.0, the decimal/octal form of 127.0.0.1, 127.1, ...).

Flag: ZeroSecure{ssrf_l00pback_4dm1n}
"""
from urllib.parse import urlparse

import requests
from flask import Flask, Response, render_template, request

app = Flask(__name__)
TIMEOUT = 4
FLAG = "ZeroSecure{ssrf_l00pback_4dm1n}"

# naive, string-based SSRF blocklist (bypassable by alternate loopback spellings)
BLOCKED_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


def _is_loopback(remote: str) -> bool:
    return remote in ("127.0.0.1", "::1", "::ffff:127.0.0.1")


@app.route("/", methods=["GET"])
def index():
    url = request.args.get("url", "")
    fetched = None
    error = None
    if url:
        try:
            if not url.lower().startswith(("http://", "https://")):
                raise ValueError("only http(s) URLs are supported")
            host = (urlparse(url).hostname or "").lower()
            if host in BLOCKED_HOSTS:
                raise ValueError(f"host '{host}' is blocked by the SSRF filter")
            r = requests.get(url, timeout=TIMEOUT)
            fetched = r.text[:4000]
        except Exception as e:  # noqa: BLE001
            error = str(e)
    return render_template("index.html", url=url, fetched=fetched, error=error)


@app.route("/admin/flag")
def admin_flag():
    # internal only: must originate from the server's own loopback interface
    if not _is_loopback(request.remote_addr or ""):
        return Response(
            "403 forbidden: /admin is restricted to localhost.\n",
            status=403,
            mimetype="text/plain",
        )
    return Response(f"{FLAG}\n", mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
