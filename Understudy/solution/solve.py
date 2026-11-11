#!/usr/bin/env python3
"""
ZSCTF :: Understudy -- reference solver (label-only model extraction).

Intended path (exploits nothing but the geometry of a linear decision surface):
  1. The oracle answers QUERY with a class LABEL only. Class T is the argmax only
     inside a razor-thin region whose boundary is the secret hyperplane
     h . x = theta. We are handed a foothold x0 that is inside class T.
  2. From x0 we shoot rays in random directions. A ray that decreases h . x
     eventually leaves class T; a binary search along it brackets the crossing to
     high precision, yielding a point that lies ON the secret boundary. (Rays that
     increase h . x go deeper into T and hit the box wall -- we discard those.)
  3. With ~3d such boundary points we recover the hyperplane: the points all
     satisfy h . p = theta, so they lie on a (d-1)-flat. Its normal is the
     smallest right singular vector of the centred point matrix (total least
     squares). We orient the normal so x0 is on the  h . x > theta  side, and read
     theta = h_hat . (mean of the boundary points).
  4. SUBMIT (h_hat, theta_hat). The service checks the reconstruction against the
     true secret boundary within tolerance and releases the flag.

No scores, no gradients, no brute force -- just line search + a singular-value
decomposition. That is the whole point: a label-only prediction API still leaks
its decision surface.

Run locally against the source:   python solve.py --local ../challenge/server.py
Run against a deployed instance:  python solve.py --remote HOST PORT
"""
import sys, subprocess, socket, argparse
import numpy as np


# -- transport abstractions --------------------------------------------------
class Proc:
    def __init__(self, path):
        self.p = subprocess.Popen([sys.executable, path], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, text=True, bufsize=1)
    def readline(self): return self.p.stdout.readline()
    def send(self, line):
        self.p.stdin.write(line + "\n"); self.p.stdin.flush()
    def close(self):
        try: self.send("QUIT")
        except Exception: pass
        try: self.p.wait(timeout=5)
        except Exception: self.p.kill()


class Sock:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=10)
        self.f = self.s.makefile("rw", newline="\n")
    def readline(self): return self.f.readline()
    def send(self, line): self.f.write(line + "\n"); self.f.flush()
    def close(self):
        try: self.send("QUIT")
        except Exception: pass
        self.s.close()


def _hex(arr):
    return np.asarray(arr, dtype="<f8").tobytes().hex()


def _unhex(s, n):
    v = np.frombuffer(bytes.fromhex(s), dtype="<f8")
    assert v.size == n, "expected %d floats, got %d" % (n, v.size)
    return v.astype(np.float64)


# -- protocol helpers --------------------------------------------------------
def read_banner(io):
    """Read the banner; return (D, C, TARGET, x0)."""
    D = C = TARGET = None
    x0 = None
    while True:
        line = io.readline()
        if not line:
            raise RuntimeError("service closed during banner")
        line = line.rstrip("\n")
        if line.startswith("Sortilege is a fixed linear classifier: input d="):
            # ...input d=96 -> 12 classes...
            seg = line.split("input d=", 1)[1]
            D = int(seg.split(" ", 1)[0])
            C = int(seg.split("-> ", 1)[1].split(" ", 1)[0])
        elif line.startswith("class ") and "is the RARE" in line:
            TARGET = int(line.split("class ", 1)[1].split(" ", 1)[0])
        elif line.startswith("FOOTHOLD x0 "):
            _, _, n, hx = line.split()
            x0 = _unhex(hx, int(n))
        if line.startswith("vectors are"):   # last structural banner line precedes FOOTHOLD
            pass
        if x0 is not None and D is not None and C is not None and TARGET is not None:
            break
    return D, C, TARGET, x0


class Oracle:
    def __init__(self, io, target):
        self.io = io; self.target = target; self.n = 0
    def label(self, x):
        self.io.send("QUERY " + _hex(x))
        line = self.io.readline().rstrip("\n")
        assert line.startswith("LABEL "), "unexpected QUERY reply: %r" % line
        self.n += 1
        return int(line.split()[1])
    def in_target(self, x):
        return self.label(x) == self.target


# -- the extraction ----------------------------------------------------------
def boundary_point(orc, x0, u, max_lambda=12.0):
    """Walk from x0 along +u until we leave class T (staying in the box), then
    binary-search the crossing. Return the boundary point, or None if the ray
    goes deeper into T and hits the box wall first."""
    lam = 0.01
    last_in = x0.copy()
    out = None
    while True:
        p = x0 + lam * u
        if np.any(p < 0.0) or np.any(p > 1.0):
            return None                      # left the box before leaving T
        if not orc.in_target(p):
            out = p; break
        last_in = p
        lam *= 1.5
        if lam > max_lambda:
            return None
    a, b = last_in, out                      # a in T, b out of T
    for _ in range(34):
        m = (a + b) / 2.0
        if orc.in_target(m):
            a = m
        else:
            b = m
    return (a + b) / 2.0


def extract_boundary(orc, x0, D, n_points=None, seed=1):
    if n_points is None:
        n_points = 3 * D
    rng = np.random.default_rng(seed)
    pts = []
    tries = 0
    while len(pts) < n_points and tries < 80 * D:
        tries += 1
        u = rng.standard_normal(D)
        u /= np.linalg.norm(u)
        p = boundary_point(orc, x0, u)
        if p is not None:
            pts.append(p)
    if len(pts) < D + 1:
        raise RuntimeError("only found %d boundary points (need >= %d)"
                           % (len(pts), D + 1))
    B = np.array(pts)
    mean = B.mean(axis=0)
    # total least squares: normal = smallest right singular vector
    _, _, Vt = np.linalg.svd(B - mean, full_matrices=False)
    h_hat = Vt[-1]
    # orient so x0 (inside T) is on the  h . x > theta  side
    if h_hat @ (x0 - mean) < 0:
        h_hat = -h_hat
    theta_hat = float(h_hat @ mean)
    return h_hat, theta_hat, len(pts)


def solve(io):
    D, C, TARGET, x0 = read_banner(io)
    orc = Oracle(io, TARGET)
    assert orc.in_target(x0), "published foothold is not classified as the target"
    h_hat, theta_hat, npts = extract_boundary(orc, x0, D)
    io.send("SUBMIT %s %r" % (_hex(h_hat), theta_hat))
    resp = io.readline().rstrip("\n")
    if resp.startswith("WIN"):               # flag follows on the next line
        resp = resp + "\n" + io.readline().rstrip("\n")
    return h_hat, theta_hat, npts, orc.n, resp


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--local", metavar="SERVER_PY")
    g.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"))
    args = ap.parse_args()
    io = Proc(args.local) if args.local else Sock(args.remote[0], int(args.remote[1]))
    try:
        h_hat, theta_hat, npts, nq, resp = solve(io)
        print("[+] boundary points used: %d" % npts)
        print("[+] queries spent:        %d" % nq)
        print("[+] recovered theta_hat = %.6f" % theta_hat)
        print("[+] service response:     %s" % resp)
        if resp.startswith("WIN") or "FLAG " in resp:
            flag = resp.split("FLAG ", 1)[1] if "FLAG " in resp else "(see response)"
            print("[+] FLAG =", flag)
            return 0
        print("[-] did not get a flag")
        return 1
    finally:
        io.close()


if __name__ == "__main__":
    sys.exit(main())
