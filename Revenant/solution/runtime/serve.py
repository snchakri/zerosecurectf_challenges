#!/usr/bin/env python3
"""
ZSCTF :: Revenant -- TCP front-end (stdlib only, no external deps).

The challenge *is* the compiled `revenant` binary: players receive the binary
and exploit it. In a hosted setting we expose that same binary over a byte
socket so it can be reached with `nc` and boxed exactly like the other ZSCTF
services.

Per connection we spawn one fresh `revenant` process and bridge the socket to
its stdin/stdout. The flag is injected into the child's environment (ZSCTF_FLAG)
and never written to disk or baked into an image layer; win() reads it live. The
per-instance decoy marker is derived by the binary from ZSCTF_SEED (also passed
through from the environment).

  python3 serve.py            # serve one session on stdio (handy for testing)
  python3 serve.py --tcp 0.0.0.0 1337
"""
import os
import sys
import pathlib
import threading
import subprocess
import socketserver

HERE = pathlib.Path(__file__).resolve().parent

# The compiled binary. Overridable for local runs / alternate layouts.
BIN = os.environ.get("REVENANT_BIN")
if not BIN:
    for cand in (HERE.parent / "build" / "revenant",
                 HERE / "revenant",
                 HERE.parent / "build" / "revenant.exe"):
        if cand.exists():
            BIN = str(cand)
            break
    else:
        BIN = str(HERE.parent / "build" / "revenant")

# Guardrails so one abusive session cannot wedge the box.
READ_TIMEOUT = float(os.environ.get("REVENANT_TIMEOUT", "30"))
MAX_INPUT = int(os.environ.get("REVENANT_MAX_INPUT", "65536"))

if "ZSCTF_FLAG" not in os.environ:
    sys.stderr.write("WARNING: ZSCTF_FLAG is not set; the binary will serve its "
                     "placeholder token.\n")
    sys.stderr.flush()


def child_env():
    # Pass ZSCTF_FLAG (-> win()) and ZSCTF_SEED (-> per-instance decoy) straight
    # through; nothing else is needed.
    return dict(os.environ)


def run_session(read_from, write_to):
    """Spawn one revenant and bridge raw bytes both ways until it exits."""
    if not os.path.exists(BIN):
        write_to(b"ERR: revenant binary unavailable on the server.\n")
        return
    proc = subprocess.Popen([os.path.abspath(BIN)],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            env=child_env())

    def pump_out():
        try:
            fd = proc.stdout.fileno()
            while True:
                b = os.read(fd, 4096)
                if not b:
                    break
                write_to(b)
        except Exception:
            pass

    t = threading.Thread(target=pump_out, daemon=True)
    t.start()

    sent = 0
    try:
        while sent < MAX_INPUT:
            b = read_from(min(4096, MAX_INPUT - sent))
            if not b:
                break
            try:
                proc.stdin.write(b)
                proc.stdin.flush()
            except Exception:
                break
            sent += len(b)
    except Exception:
        pass
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass

    try:
        proc.wait(timeout=READ_TIMEOUT)
    except Exception:
        proc.kill()
    t.join(timeout=2)


def serve_stdio():
    run_session(lambda n: sys.stdin.buffer.read(n),
                lambda b: (sys.stdout.buffer.write(b), sys.stdout.buffer.flush()))


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(READ_TIMEOUT)

        def reader(n):
            try:
                return self.request.recv(n)
            except Exception:
                return b""

        def writer(b):
            try:
                self.request.sendall(b)
            except Exception:
                pass

        run_session(reader, writer)


def serve_tcp(host, port):
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer((host, port), _Handler) as srv:
        sys.stderr.write("revenant listening on %s:%d\n" % (host, port))
        sys.stderr.flush()
        srv.serve_forever()


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--tcp":
        host = sys.argv[2] if len(sys.argv) > 2 else "0.0.0.0"
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 1337
        serve_tcp(host, port)
    else:
        serve_stdio()
