#!/usr/bin/env python3
"""
ZSCTF :: Hairline -- reference solver.

Intended path (white-box adversarial example, exactly the what-a-jpeg-is shape):
  1. GET the model (PARAMS): weights W1,b1,W2,b2, the benign sample x0, the
     L-infinity budget epsilon, the target class and the confidence threshold tau.
  2. The feasible set is a BOX: each feature x_i is confined to
        [ max(0, x0_i - eps),  min(1, x0_i + eps) ].
     So "find a bounded adversarial example" == maximise the logit margin
        m(x) = z_target(x) - z_other(x)
     over that box. We minimise f(x) = -m(x) with an ANALYTIC gradient obtained
     by back-propagating through the ReLU MLP by hand.
  3. Box-constrained optimisation (scipy L-BFGS-B, Szegedy et al. 2013 style),
     with a few random restarts (Madry et al. 2017). A pure-numpy projected
     gradient attack (PGD / iterated FGSM, Goodfellow 2015 / Madry 2017) is
     provided as an equivalent alternative (--method pgd).
  4. SUBMIT the crafted vector; the service verifies budget + confident
     misclassification and returns the flag.

Random search within the same budget does NOT win -- that is the whole point
(Goodfellow et al. 2015: adversarial perturbations are a high-dimensional,
gradient-aligned phenomenon, not generic noise).

Run locally against the source:   python solve.py --local ../challenge/server.py
Run against a deployed instance:   python solve.py --remote HOST PORT
Pick the attack:                   --method lbfgsb (default) | pgd
"""
import sys, subprocess, socket, argparse
import numpy as np
from scipy.optimize import minimize


# -- transport abstractions (mirror the reference crypto solver) -------------
class Proc:
    def __init__(self, path):
        self.p = subprocess.Popen([sys.executable, path], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, text=True, bufsize=1)
    def readline(self):
        return self.p.stdout.readline()
    def send(self, line):
        self.p.stdin.write(line + "\n"); self.p.stdin.flush()
    def close(self):
        try: self.send("QUIT")
        except Exception: pass
        try: self.p.wait(timeout=5)
        except Exception: self.p.kill()


class Sock:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=15)
        self.f = self.s.makefile("rw", newline="\n")
    def readline(self):
        return self.f.readline()
    def send(self, line):
        self.f.write(line + "\n"); self.f.flush()
    def close(self):
        try: self.send("QUIT")
        except Exception: pass
        self.s.close()


# -- (de)serialisation: little-endian float64 hex ----------------------------
def unhex(s, n=None):
    v = np.frombuffer(bytes.fromhex(s), dtype="<f8").astype(np.float64)
    if n is not None and v.size != n:
        raise ValueError("expected %d floats, got %d" % (n, v.size))
    return v


def tohex(x):
    return np.asarray(x, dtype="<f8").tobytes().hex()


def fetch_params(io):
    """Send PARAMS and parse the model + challenge constants from the reply."""
    io.send("PARAMS")
    meta, tensors = {}, {}
    while True:
        line = io.readline()
        if not line:
            raise RuntimeError("service closed during PARAMS")
        line = line.rstrip("\n")
        if line == "END":
            break
        if not line.startswith("PARAM "):
            continue                         # skip banner / other lines
        tok = line.split()
        name = tok[1]
        if name == "meta":
            for kv in tok[2:]:
                k, v = kv.split("=")
                meta[k] = v
        elif name in ("W1", "W2"):
            rows, cols = int(tok[2]), int(tok[3])
            tensors[name] = unhex(tok[4], rows * cols).reshape(rows, cols)
        elif name in ("b1", "b2", "x0"):
            n = int(tok[2])
            tensors[name] = unhex(tok[3], n)
    m = dict(
        W1=tensors["W1"], b1=tensors["b1"], W2=tensors["W2"], b2=tensors["b2"],
        x0=tensors["x0"],
        d=int(meta["d"]), h=int(meta["h"]), classes=int(meta["classes"]),
        target=int(meta["target"]), epsilon=float(meta["epsilon"]),
        tau=float(meta["tau"]), lo=float(meta["lo"]), hi=float(meta["hi"]),
    )
    m["other"] = 1 - m["target"]
    return m


# -- the model, its margin, and the analytic gradient ------------------------
def margin_and_grad(M, x):
    """m(x) = z_target - z_other, and dm/dx, by backprop through the ReLU MLP."""
    W1, b1, W2, b2 = M["W1"], M["b1"], M["W2"], M["b2"]
    t, o = M["target"], M["other"]
    a1 = W1 @ x + b1
    relu_mask = a1 > 0.0
    h = np.where(relu_mask, a1, 0.0)
    z = W2 @ h + b2
    m = z[t] - z[o]
    dz = np.zeros_like(z); dz[t] = 1.0; dz[o] = -1.0     # dm/dz
    dh = W2.T @ dz                                       # dm/dh
    da1 = dh * relu_mask                                 # through ReLU
    dx = W1.T @ da1                                      # dm/dx
    return float(m), dx


def p_flag(M, x):
    W1, b1, W2, b2 = M["W1"], M["b1"], M["W2"], M["b2"]
    z = W2 @ np.maximum(W1 @ x + b1, 0.0) + b2
    z = z - z.max()
    e = np.exp(z)
    return float(e[M["target"]] / e.sum())


def box(M):
    lo = np.clip(M["x0"] - M["epsilon"], M["lo"], M["hi"])
    hi = np.clip(M["x0"] + M["epsilon"], M["lo"], M["hi"])
    return lo, hi


def craft_lbfgsb(M, restarts=6, seed=1234567):
    """Maximise the margin over the feasible box with L-BFGS-B + random restarts."""
    lo, hi = box(M)
    bounds = list(zip(lo, hi))
    rng = np.random.default_rng(seed)
    starts = [M["x0"].copy()] + [rng.uniform(lo, hi) for _ in range(restarts)]
    best_x, best_m = M["x0"].copy(), -np.inf
    for s in starts:
        res = minimize(lambda x: (lambda mg: (-mg[0], -mg[1]))(margin_and_grad(M, x)),
                       s, jac=True, method="L-BFGS-B", bounds=bounds,
                       options={"maxiter": 300, "ftol": 1e-12, "gtol": 1e-10})
        m, _ = margin_and_grad(M, res.x)
        if m > best_m:
            best_m, best_x = m, np.clip(res.x, lo, hi)
    return best_x


def craft_pgd(M, iters=150, restarts=6, seed=1234567):
    """Projected gradient ascent on the margin (L-inf), a.k.a. iterated FGSM."""
    lo, hi = box(M)
    step = 2.5 * M["epsilon"] / iters            # Madry et al. step-size heuristic
    rng = np.random.default_rng(seed)
    starts = [M["x0"].copy()] + [rng.uniform(lo, hi) for _ in range(restarts)]
    best_x, best_m = M["x0"].copy(), -np.inf
    for s in starts:
        x = s.copy()
        for _ in range(iters):
            _, g = margin_and_grad(M, x)
            x = np.clip(x + step * np.sign(g), lo, hi)   # ascend, then project
        m, _ = margin_and_grad(M, x)
        if m > best_m:
            best_m, best_x = m, x
    return best_x


def solve(io, method="lbfgsb"):
    M = fetch_params(io)
    x = (craft_pgd if method == "pgd" else craft_lbfgsb)(M)
    linf = float(np.max(np.abs(x - M["x0"])))
    conf = p_flag(M, x)
    io.send("SUBMIT %s" % tohex(x))
    resp = ""
    for _ in range(4):                       # win replies "WIN ...\nFLAG ..."
        line = io.readline().rstrip("\n")
        if not line:
            break
        resp = line
        if line.startswith("FLAG ") or line.startswith("DENIED") or line.startswith("ERR"):
            break
    return M, linf, conf, resp


def main():
    ap = argparse.ArgumentParser(description="ZSCTF Hairline reference solver")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--local", metavar="SERVER_PY")
    g.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"))
    ap.add_argument("--method", choices=["lbfgsb", "pgd"], default="lbfgsb")
    args = ap.parse_args()
    io = Proc(args.local) if args.local else Sock(args.remote[0], int(args.remote[1]))
    try:
        M, linf, conf, resp = solve(io, args.method)
        print("[+] method=%s  d=%d  epsilon=%.4f  tau=%.2f" %
              (args.method, M["d"], M["epsilon"], M["tau"]))
        print("[+] crafted perturbation: L-inf used = %.6f (budget %.4f), local p_flag = %.4f"
              % (linf, M["epsilon"], conf))
        print("[+] service response: %s" % resp)
        if resp.startswith("FLAG "):
            print("[+] FLAG =", resp[5:])
            return 0
        print("[-] did not get a flag")
        return 1
    finally:
        io.close()


if __name__ == "__main__":
    sys.exit(main())
