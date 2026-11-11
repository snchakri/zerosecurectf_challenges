#!/usr/bin/env python3
"""
ZSCTF :: Origami -- reference solver (nonlinear / ReLU-network extraction).

Intended path (exploits nothing but the piecewise-linear geometry of a ReLU net):

  The oracle answers QUERY with the real-valued output of a 1-hidden-layer ReLU
  network  f(x) = sum_i v_i * ReLU(w_i . x + b_i) + c.  This function is
  CONTINUOUS and PIECEWISE-LINEAR: input space is partitioned into polytopes
  (one per ReLU activation pattern), f is affine on each, and the boundaries
  between them are exactly the neuron hyperplanes { x : w_i . x + b_i = 0 }.

  The gradient of f at a point is  sum_{i active} v_i w_i  -- a BLEND of whichever
  neurons are currently on.  So one gradient does not reveal a single w_i, and a
  gradient carries NO information about any offset b_i.  But when a straight line
  crosses one neuron's hyperplane, exactly that neuron toggles, and the gradient
  JUMPS by  v_i * w_i.  That jump vector points along w_i.  This is the
  critical-point / gradient-jump extraction of Rolnick & Kording (ICML 2020),
  Jagielski et al. (USENIX Security 2020) and Carlini et al. (CRYPTO 2020).

  Algorithm:
    1. Shoot a random chord a + s*u through the box.  Scan f(a+s*u) on a grid;
       its slope (in s) is piecewise-constant and changes exactly at the kinks
       where the chord crosses a neuron hyperplane.  Locate each kink's bracket.
    2. For an isolated kink (neighbours far enough away to leave a clean linear
       segment on each side), estimate the full gradient of f just before and
       just after the kink by central differences.  The difference g_after -
       g_before = v_i * w_i; normalise it to get the unit normal n_i = +/- w_i.
    3. Localise the kink exactly by intersecting the two affine pieces along the
       chord, giving a point x* ON the hyperplane; then n_i . x* is the signed
       offset t_i = -b_i.
    4. Repeat over many chords.  Each clean kink yields one (n_i, t_i) sample.
       Canonicalise the sign and CLUSTER the samples: well-separated neurons form
       k tight clusters.  Average each cluster to a unit normal and median offset.
    5. SUBMIT the k reconstructed hyperplanes.  The service matches them to the
       true first layer (up to permutation and per-normal sign) and releases the
       flag.

  No labels, no gradients-of-a-linear-model shortcut, no single global SVD -- the
  piecewise-linear structure forces per-neuron kink extraction.

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
        self.s = socket.create_connection((host, port), timeout=20)
        self.f = self.s.makefile("rw", newline="\n")
    def readline(self): return self.f.readline()
    def send(self, line): self.f.write(line + "\n"); self.f.flush()
    def close(self):
        try: self.send("QUIT")
        except Exception: pass
        self.s.close()


def _hex(arr):
    return np.asarray(arr, dtype="<f8").tobytes().hex()


# -- protocol helpers --------------------------------------------------------
def read_banner(io):
    """Read the banner; return (D, K, LO, HI)."""
    D = K = None
    LO = HI = None
    while True:
        line = io.readline()
        if not line:
            raise RuntimeError("service closed during banner")
        line = line.rstrip("\n")
        if "hidden ReLU neurons" in line and "input d=" in line:
            seg = line.split("input d=", 1)[1]
            D = int(seg.split(" ", 1)[0])
            K = int(seg.split("-> ", 1)[1].split(" ", 1)[0])
        if "Inputs live in the box" in line:
            inside = line.split("box [", 1)[1].split("]", 1)[0]
            lo, hi = inside.split(",")
            LO = float(lo); HI = float(hi)
        if line.startswith("vectors/matrix are"):
            break
    if None in (D, K, LO, HI):
        raise RuntimeError("failed to parse banner (D=%r K=%r LO=%r HI=%r)"
                           % (D, K, LO, HI))
    return D, K, LO, HI


class Oracle:
    def __init__(self, io, D):
        self.io = io; self.D = D; self.n = 0
    def batch(self, X):
        """X (m, D) -> f values (m,). Counts as m queries."""
        X = np.atleast_2d(np.asarray(X, dtype=np.float64))
        self.io.send("QUERYB " + " ".join(_hex(row) for row in X))
        line = self.io.readline().rstrip("\n")
        assert line.startswith("VALUES "), "unexpected QUERYB reply: %r" % line
        vals = np.array([float(t) for t in line.split()[1:]])
        assert vals.size == X.shape[0], "got %d values for %d inputs" % (vals.size, X.shape[0])
        self.n += X.shape[0]
        return vals
    def one(self, x):
        return float(self.batch(x[None, :])[0])


# -- the extraction ----------------------------------------------------------
def gradient(orc, x, eps=1e-5):
    """Full gradient of f at x by central differences (exact within a linear
    region of this piecewise-linear f)."""
    D = orc.D
    E = np.eye(D) * eps
    stacked = np.vstack([x + E, x - E])            # 2D rows -> one batch
    vals = orc.batch(stacked)
    fp = vals[:D]; fm = vals[D:]
    return (fp - fm) / (2 * eps)


def s_range(x0, u, LO, HI):
    """Largest s-interval keeping x0 + s*u strictly inside the box."""
    lim = []
    for j in range(u.size):
        if abs(u[j]) > 1e-12:
            lim += [(HI - x0[j]) / u[j], (LO - x0[j]) / u[j]]
    sh = min([t for t in lim if t > 0], default=0.0) * 0.999
    sl = max([t for t in lim if t < 0], default=0.0) * 0.999
    return sl, sh


def process_line(orc, a, u, LO, HI, n_scan=200, min_half=0.12, max_delta=0.08):
    """Scan one chord; return a list of (x_star, unit_normal) for each clean,
    isolated kink crossed by the chord."""
    D = orc.D
    sl, sh = s_range(a, u, LO, HI)
    if sh - sl < 0.3:
        return []
    ss = np.linspace(sl, sh, n_scan)
    pts = a[None, :] + ss[:, None] * u[None, :]
    vals = orc.batch(pts)
    slopes = np.diff(vals) / np.diff(ss)
    dsl = np.abs(np.diff(slopes))
    thr = max(1e-6, 1e-3 * float(np.max(np.abs(slopes))))
    raw = [i for i in range(len(dsl)) if dsl[i] > thr]
    if not raw:
        return []
    # merge adjacent spike indices (a single kink can straddle 2 grid cells)
    brackets = []; cur = [raw[0]]
    for i in raw[1:]:
        if i - cur[-1] <= 2:
            cur.append(i)
        else:
            brackets.append(cur); cur = [i]
    brackets.append(cur)
    s0s = []
    for br in brackets:
        w = np.array([dsl[i] for i in br]); idx = np.array(br) + 1
        s0s.append(float(np.sum(w * ss[idx]) / np.sum(w)))   # dsl-weighted centroid
    s0s = sorted(s0s)
    step = (sh - sl) / (n_scan - 1)
    out = []
    for m, s0 in enumerate(s0s):
        left = s0s[m - 1] if m > 0 else sl
        right = s0s[m + 1] if m < len(s0s) - 1 else sh
        half = min(s0 - left, right - s0)
        if half < min_half:                 # neighbours too close to isolate
            continue
        delta = min(0.3 * half, max_delta)
        if delta < 3 * step:
            continue
        xl = a + (s0 - delta) * u
        xr = a + (s0 + delta) * u
        if not (np.all((xl >= LO) & (xl <= HI)) and np.all((xr >= LO) & (xr <= HI))):
            continue
        gl = gradient(orc, xl); gr = gradient(orc, xr)
        jump = gr - gl
        nrm = float(np.linalg.norm(jump))
        if nrm < 5e-3:
            continue
        n = jump / nrm
        # exact kink location: intersect the two affine pieces along the chord
        both = orc.batch(np.vstack([xl, xr]))
        fl, fr = float(both[0]), float(both[1])
        ml = float(gl @ u); mr = float(gr @ u)
        if abs(ml - mr) < 1e-9:
            continue
        s_star = ((fr - mr * (s0 + delta)) - (fl - ml * (s0 - delta))) / (ml - mr)
        if not (s0 - half < s_star < s0 + half):
            s_star = s0
        out.append((a + s_star * u, n))
    return out


def _canon(n):
    """Canonical sign: make the first significant component positive."""
    for j in range(n.size):
        if abs(n[j]) > 1e-6:
            return n if n[j] > 0 else -n
    return n


def _cluster(normals, cos_thr=0.999):
    used = [False] * len(normals); clusters = []
    for i in range(len(normals)):
        if used[i]:
            continue
        grp = [i]; used[i] = True
        for j in range(i + 1, len(normals)):
            if not used[j] and abs(float(normals[i] @ normals[j])) >= cos_thr:
                grp.append(j); used[j] = True
        clusters.append(grp)
    clusters.sort(key=len, reverse=True)
    return clusters


def extract(orc, D, K, LO, HI, seed=0, max_lines=600):
    rng = np.random.default_rng(seed)
    obs = []                      # list of (canon_unit_normal, x_star)
    lines = 0
    while lines < max_lines:
        lines += 1
        a = rng.uniform(0.6 * LO, 0.6 * HI, D)
        u = rng.standard_normal(D); u /= np.linalg.norm(u)
        for x_star, n in process_line(orc, a, u, LO, HI):
            obs.append((_canon(n), x_star))
        if lines % 15 == 0 and len(obs) >= 2 * K:
            cl = _cluster([o[0] for o in obs])
            if len(cl) >= K and sum(1 for c in cl[:K] if len(c) >= 3) == K:
                break
    normals = [o[0] for o in obs]
    clusters = _cluster(normals)
    if len(clusters) < K:
        raise RuntimeError("only separated %d neuron clusters (need %d); "
                           "collected %d kinks" % (len(clusters), K, len(obs)))
    clusters = clusters[:K]
    recov_n = np.zeros((K, D)); recov_t = np.zeros(K)
    for idx, c in enumerate(clusters):
        ns = np.array([normals[k] for k in c]); ref = ns[0]
        ns = np.array([x if float(x @ ref) >= 0 else -x for x in ns])
        nm = ns.mean(axis=0); nm /= np.linalg.norm(nm)
        recov_n[idx] = nm
        recov_t[idx] = float(np.median([nm @ obs[k][1] for k in c]))
    return recov_n, recov_t, len(obs)


import re
FLAG_RE = re.compile(r"^zerosecurectf\{[a-z0-9_]{8,48}\}$")


def redeem_and_assemble(io, recov_n, recov_t):
    """Per-piece reconstruction (the S2/S2a flag-extraction layer).

    Reconstructing the k hyperplanes is the crux, but it does NOT hand over the
    flag: the flag is split into k fragments, each sealed under a key derived
    from one neuron's exact hyperplane.  We REDEEM each recovered neuron; a match
    returns that neuron's real fragment, prefixed with its 2-hex-digit canonical
    position.  We place each fragment by its tag and concatenate in ascending
    position order, then verify against the published strict validator.  A
    wrong/approximate neuron would return a DECOY fragment (which carries an
    upper-case defect), so an assembly containing one fails the validator -- the
    careful-solver discriminator that makes every bad piece rejectable.
    """
    K = recov_n.shape[0]
    frags = {}
    for i in range(K):
        row = np.hstack([recov_n[i], recov_t[i]])
        io.send("REDEEM %s" % _hex(row))
        line = io.readline().rstrip("\n")
        assert line.startswith("FRAG "), "unexpected REDEEM reply: %r" % line
        tok = line.split(" ", 1)[1]
        pos = int(tok[:2], 16)
        frags[pos] = tok[2:]
    flag = "".join(frags[p] for p in sorted(frags))
    ok = bool(FLAG_RE.match(flag)) and flag.startswith("zerosecurectf{")
    return flag, ok


def solve(io, seed=0):
    D, K, LO, HI = read_banner(io)
    orc = Oracle(io, D)
    recov_n, recov_t, n_kinks = extract(orc, D, K, LO, HI, seed=seed)
    # 1) sound win-check: confirm all k hyperplanes match (returns NO flag).
    M = np.hstack([recov_n, recov_t[:, None]])           # (K, D+1)
    io.send("SUBMIT %s" % _hex(M.ravel()))
    submit_resp = io.readline().rstrip("\n")
    # 2) per-piece reconstruction: REDEEM each neuron, assemble the fragments.
    flag, ok = redeem_and_assemble(io, recov_n, recov_t)
    if ok:
        resp = "%s\nFLAG %s" % (submit_resp, flag)
    else:
        resp = ("%s\nASSEMBLY FAILED (near-flag rejected by strict validator): %s"
                % (submit_resp, flag))
    return recov_n, recov_t, n_kinks, orc.n, resp, (D, K)


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--local", metavar="SERVER_PY")
    g.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"))
    ap.add_argument("--seed", type=int, default=0, help="RNG seed for the solver's chord sampling")
    args = ap.parse_args()
    io = Proc(args.local) if args.local else Sock(args.remote[0], int(args.remote[1]))
    try:
        recov_n, recov_t, n_kinks, nq, resp, (D, K) = solve(io, seed=args.seed)
        print("[+] network: d=%d, k=%d neurons" % (D, K))
        print("[+] clean kinks collected: %d" % n_kinks)
        print("[+] queries spent:         %d" % nq)
        print("[+] reconstructed %d neuron hyperplanes" % K)
        print("[+] service response:      %s" % resp)
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
