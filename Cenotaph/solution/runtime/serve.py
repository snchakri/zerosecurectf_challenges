#!/usr/bin/env python3
"""
ZSCTF :: Cenotaph -- minimal TCP front-end for the crackme (stdlib only).

Per connection: read one line (the candidate archive key), run the compiled
cenotaph binary once with that key as argv, and stream its output back. This is
a thin convenience wrapper so the decoy can be poked over a socket; the real
artifact players reverse is the ELF itself (build/cenotaph).

There is NO flag to protect here -- the binary emits only malformed decoys -- but
the wrapper is still written defensively (bounded input, per-run timeout, no
shell) because a tarpit must never become a pivot.

    python3 serve.py --tcp 0.0.0.0 1337        # serve
    CENOTAPH_BIN=/app/cenotaph python3 serve.py --tcp 0.0.0.0 1337

ZSCTF_FLAG is intentionally NOT referenced; the binary ignores it too.
"""
import argparse
import os
import socketserver
import subprocess
import sys

BIN = os.environ.get("CENOTAPH_BIN", "/app/cenotaph")
TIMEOUT = int(os.environ.get("CENOTAPH_TIMEOUT", "10"))
MAX_INPUT = int(os.environ.get("CENOTAPH_MAX_INPUT", "256"))


def run_once(candidate: str) -> bytes:
    try:
        p = subprocess.run([BIN, candidate], capture_output=True,
                           timeout=TIMEOUT, env={"PATH": "/usr/bin:/bin"})
        return (p.stdout or b"") + (p.stderr or b"")
    except subprocess.TimeoutExpired:
        return b"[serve] timeout\n"
    except OSError as e:
        return ("[serve] cannot exec binary: %s\n" % e).encode()


class Handler(socketserver.StreamRequestHandler):
    timeout = 30

    def handle(self):
        try:
            self.wfile.write(b"enter archive key (one line):\n")
            raw = self.rfile.readline(MAX_INPUT + 2) or b""
        except OSError:
            return
        candidate = raw.decode("latin-1", "replace").strip()[:MAX_INPUT]
        self.wfile.write(run_once(candidate))


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    ap = argparse.ArgumentParser(description="Cenotaph TCP front-end.")
    ap.add_argument("--tcp", nargs=2, metavar=("HOST", "PORT"), required=True)
    args = ap.parse_args()
    host, port = args.tcp[0], int(args.tcp[1])
    if not os.path.exists(BIN):
        sys.stderr.write("serve.py: binary not found at %s (set CENOTAPH_BIN)\n" % BIN)
        return 2
    srv = Server((host, port), Handler)
    sys.stderr.write("cenotaph serving on %s:%d (bin=%s)\n" % (host, port, BIN))
    sys.stderr.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
