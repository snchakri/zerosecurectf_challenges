#!/usr/bin/env python3
"""
ZSCTF :: Understudy  (ai-ml / AI-ML security, Hard)

A BLACK-BOX model-extraction challenge.

"Sortilege" is a fixed linear classifier that labels a d-dimensional feature
vector into one of C classes. It is served as a *prediction API*: you may ask it
to classify any vector you like, but it answers with the predicted class LABEL
ONLY -- no scores, no probabilities, no gradients. This is the realistic
"decision-based" / label-only black-box setting (Tramer et al., "Stealing
Machine Learning Models via Prediction APIs", USENIX Security 2016; Lowd & Meek,
"Adversarial Learning", KDD 2005).

One of the classes, class T (the last index), is the RARE / SECRET class: it is
the argmax only inside a razor-thin region of the input box, so you will never
stumble into it by random querying. To give you a foothold, the service
publishes one vector x0 that it guarantees is classified as T.

The secret you must STEAL is the decision boundary that isolates class T:
a hyperplane  h . x = theta  (h a unit normal; class T lies on the  h . x > theta
side). The service releases the flag only when you SUBMIT a reconstruction of
that hyperplane within tolerance -- i.e. when you have extracted the model's
hidden decision surface purely by querying its labels.

Why this is hard and cannot be short-circuited:
  * Label-only: a single query gives one bit of region-membership, not a score,
    so you cannot read the weights off directly -- you must reconstruct the
    surface geometrically, from ~d boundary points found by line search.
  * Rare class: the T region is ~1e-6 of the box, so random search never finds
    it; the published foothold x0 is the only way in, and one interior point
    does not reveal the normal -- you need many boundary points.
  * Per-instance secret: ZSCTF_SEED fixes a unique boundary h,theta and a unique
    flag, so a leaked solution for one team does not transfer.

Nothing is hidden by obscurity: players are given this exact source file. The
lesson is in plain sight -- a label-only prediction API still leaks its decision
boundary to a patient querying attacker.

Safety scope: Sortilege is a tiny fixed numpy linear model with random
per-instance weights. It is NOT a real classifier and performs no real
classification. This is defensive AI-ML-security education about model
extraction / model stealing from prediction APIs (OWASP ML05 model theft,
MITRE ATLAS "Exfiltration via ML Inference API"), nothing more. No external
model, no network egress, no third-party ML library -- pure numpy + stdlib.
"""
import os, sys, hashlib, socketserver
from statistics import NormalDist
import numpy as np

# ----------------------------------------------------------------------------
# Public architecture / challenge constants (identical for every instance).
# Calibrated (see writeup.md "Dual measurement & calibration") so the problem is
# simultaneously: solvable by label-only boundary extraction to tight tolerance,
# unreachable by random querying (the T region is ~1e-6 of the box), and robust
# across seeds with a large safety margin.
# ----------------------------------------------------------------------------
D          = 96            # feature-vector dimension
C          = 12            # number of classes
TARGET     = C - 1         # the rare/secret class index whose boundary is the prize
P_SMALL    = 1e-6          # target volume fraction of the T half-space in the box
KAPPA      = 1.0e4         # steepness of the T score -> crisp, near-planar boundary
WBG_SCALE  = 2.0           # background-weight scale  (s = WBG_SCALE / sqrt(D))
BBG_SCALE  = 0.5           # background-bias scale
LO, HI     = 0.0, 1.0      # valid feature range (per coordinate)
COS_TOL    = 0.999         # required cosine between submitted & true unit normal
THETA_TOL  = 0.02          # required abs error on the (unit-scaled) offset theta
QUERY_BUDGET = 1_000_000   # generous per-connection query budget (intended ~1.5e4)

SEED = os.environ.get("ZSCTF_SEED", "static-demo-seed").encode()
FLAG = os.environ.get("ZSCTF_FLAG")
if FLAG is None:
    sys.stderr.write("WARNING: ZSCTF_FLAG is unset; using a non-winning placeholder. "
                     "Set ZSCTF_FLAG at deploy time.\n")
    sys.stderr.flush()
    FLAG = "zerosecurectf{local_review_flag}"


# ----------------------------------------------------------------------------
# Per-instance model, derived deterministically from the seed.
# numpy's default_rng (PCG64) is a portable, version-stable bit stream, so the
# same seed yields the same model on any machine with the pinned numpy.
# `make_instance` is a pure function of the seed (single source of truth): the
# live service and the acceptance test both build instances through it.
# ----------------------------------------------------------------------------
def _rng(seed_bytes, label):
    h = hashlib.sha256(seed_bytes + b"|" + label).digest()
    return np.random.default_rng(int.from_bytes(h, "big") % (2**63))


def make_instance(seed_bytes):
    """Return a dict with the full per-instance model, derived from seed_bytes:
         Wbg (C-1, D), bbg (C-1,)  -- the C-1 'background' linear classes
         h (D,), theta (float)     -- the SECRET boundary isolating class T
         x0 (D,)                   -- a published foothold guaranteed in class T
    """
    rb = _rng(seed_bytes, b"background")
    Wbg = rb.standard_normal((C - 1, D)) * (WBG_SCALE / np.sqrt(D))
    bbg = rb.standard_normal(C - 1) * BBG_SCALE

    rh = _rng(seed_bytes, b"direction")
    h = rh.standard_normal(D)
    h = h / np.linalg.norm(h)

    # theta = the (1 - P_SMALL) quantile of  h . x  for x ~ Uniform([0,1]^D), so
    # that the T region  {x in box : h . x > theta}  occupies ~P_SMALL of the box.
    # For a unit normal h, h . x is a sum of D independent scaled uniforms with
    # mean 0.5*sum(h) and variance 1/12; by the CLT (D=96) it is very close to
    # Normal, so we use the analytic quantile. This is deterministic (no Monte
    # Carlo noise) and, because the true distribution has lighter-than-Normal
    # tails, the realised T fraction is <= P_SMALL -- genuinely rare. (Measured:
    # ~1e-6 of the box across seeds; see writeup.md.)
    mu = 0.5 * float(np.sum(h))
    sigma = np.sqrt(1.0 / 12.0)
    theta = float(mu + sigma * NormalDist().inv_cdf(1.0 - P_SMALL))

    inst = dict(Wbg=Wbg, bbg=bbg, h=h, theta=theta)

    # Foothold: publish a vector GUARANTEED to be in class T, constructed so its
    # COORDINATES do NOT encode sign(h).
    #
    # The naive foothold -- walk from the T-maximising cube vertex v = 1[h>0]
    # straight toward the box centre -- collapses every coordinate onto one of two
    # values keyed by sign(h_j): x0_j is affine in v_j in {0,1}. Thresholding x0 at
    # its own mean then recovers ~100% of sign(h) for FREE (0 queries), which
    # undercuts the "label-only, nothing leaks" premise (red-team finding).
    #
    # Instead we start from a RANDOM box vertex `corner` (drawn independently of h)
    # and project it onto the thin target slab { x : h . x = theta + eps } by
    # alternating projection (project onto the hyperplane along h, then clip back
    # into the box). The result sits near that random corner but just inside T, so
    # the DOMINANT per-coordinate signal is the random corner, not sign(h):
    #   * thresholding / clustering x0 recovers sign(h) only at ~chance, and
    #   * the continuous MAP direction (x0 - mean) has only a small cosine to h,
    #     far below the win gate (0.999),
    # so the intended line-search + SVD boundary extraction is still required.
    # NOTE: a single published in-T point necessarily carries a small residual
    # signal about h (its MAP estimate is x0 - centre, whose h-component is the
    # forced margin theta - mu); this construction drives that residual down to
    # that information-theoretic floor, which is far from solving the challenge.
    # Deterministic (fixed numpy PCG64 stream keyed by the seed) => reproducible.
    # Start from a RANDOM near-corner point of the box (each coordinate sits near
    # one box edge, chosen by a fair coin that is independent of h) and project it
    # onto the slab by alternating projection. A near-corner point is FAR from the
    # box centre, so the forced component of (x0 - centre) along h (the small
    # margin theta - mu) is a tiny fraction of |x0 - centre| -> the MAP direction
    # (x0 - mean) has only a small cosine to h. And because the dominant
    # per-coordinate value is the RANDOM corner bit, thresholding/clustering x0
    # recovers sign(h) only at chance. We keep each coordinate a small `edge`
    # inside the walls (not exactly on them) and use a small in-T margin `eps`, so
    # the reference solver's rays still have room to travel out of T before hitting
    # a wall (a point exactly on a wall would kill every ray). Deterministic
    # (fixed numpy PCG64 stream keyed by the seed) => reproducible per seed.
    rf = _rng(seed_bytes, b"foothold")
    eps  = 0.01                                        # margin inside T, above theta
    edge = 0.05                                        # keep coords in [edge, 1-edge]
    c = theta + eps
    blo, bhi = LO + edge, HI - edge
    bit = rf.integers(0, 2, D)                         # random corner bits (indep. of h)
    base = np.where(bit == 1, bhi, blo).astype(np.float64)
    base = np.clip(base + (rf.random(D) - 0.5) * edge, blo, bhi)   # jitter off the edges
    x0 = base.copy()
    for _ in range(80):                                # alternating projection: slab ∩ band
        x0 = x0 + (c - float(h @ x0)) * h              # onto { h . x = c }  (|h| = 1)
        x0 = np.clip(x0, blo, bhi)                      # onto the interior band
    x0 = np.clip(x0 + (c - float(h @ x0)) * h, LO, HI)  # final hyperplane projection
    for _ in range(300):                               # guarantee membership in T
        if _predict(inst, x0) == TARGET:
            break
        x0 = np.clip(x0 + 0.01 * h, LO, HI)            # nudge deeper into T if needed
    inst["x0"] = x0
    return inst


def _scores(inst, x):
    """Linear scores for a single vector x (D,). Returns (C,).
       Classes 0..C-2 are the background linear classes; class TARGET's score is
       a steep linear ramp across the secret boundary h . x = theta."""
    sb = inst["Wbg"] @ x + inst["bbg"]                      # (C-1,)
    st = KAPPA * (float(inst["h"] @ x) - inst["theta"])     # scalar
    return np.concatenate([sb, [st]])


def _predict(inst, x):
    return int(np.argmax(_scores(inst, x)))


INST = make_instance(SEED)
H_TRUE = INST["h"]
THETA_TRUE = INST["theta"]
X0 = INST["x0"]


# ----------------------------------------------------------------------------
# float64 hex (de)serialisation for vectors on the wire.
# ----------------------------------------------------------------------------
def _hex(arr):
    return np.asarray(arr, dtype="<f8").tobytes().hex()


def _unhex(s, n):
    v = np.frombuffer(bytes.fromhex(s), dtype="<f8")
    if v.size != n:
        raise ValueError("expected %d float64 values, got %d" % (n, v.size))
    return v.astype(np.float64)


# ----------------------------------------------------------------------------
# Win check: has the player reconstructed the secret boundary (h, theta)?
# The boundary is scale-invariant: (h, theta) and (c*h, c*theta) describe the
# same hyperplane for c > 0, so we normalise the submission to a unit normal
# before comparing, and require the orientation (which side is T) to be correct.
# ----------------------------------------------------------------------------
def check_boundary(h_hat, theta_hat):
    if not (np.all(np.isfinite(h_hat)) and np.isfinite(theta_hat)):
        return False, "DENIED submission has non-finite values"
    n = float(np.linalg.norm(h_hat))
    if n == 0.0:
        return False, "DENIED normal vector is zero"
    h_unit = h_hat / n
    theta_unit = theta_hat / n
    cos = float(h_unit @ H_TRUE)                    # signed: orientation matters
    dth = abs(theta_unit - THETA_TRUE)
    if cos >= COS_TOL and dth <= THETA_TOL:
        return True, ("WIN boundary reconstructed (cosine = %.6f >= %.3f, "
                      "|dtheta| = %.6f <= %.3f)\nFLAG %s"
                      % (cos, COS_TOL, dth, THETA_TOL, FLAG))
    if cos < 0 and (-cos) >= COS_TOL:
        return False, ("DENIED the hyperplane direction is right but your normal "
                       "points OUT of class T; flip its sign (and theta) so that "
                       "h . x > theta selects T")
    return False, ("DENIED reconstruction not within tolerance "
                   "(cosine = %.6f, need >= %.3f; |dtheta| = %.6f, need <= %.3f)"
                   % (cos, COS_TOL, dth, THETA_TOL))


# ----------------------------------------------------------------------------
# Line protocol. One connection == one querying session with its own budget.
# ----------------------------------------------------------------------------
def banner():
    out = []
    out.append("=== ZSCTF Sortilege :: label-only model-extraction oracle ===")
    out.append("Sortilege is a fixed linear classifier: input d=%d -> %d classes "
               "(argmax of linear scores)." % (D, C))
    out.append("The API is DECISION-BASED: QUERY returns the predicted class LABEL "
               "only -- no scores, no probabilities.")
    out.append("class %d is the RARE/SECRET class: it is the argmax only inside a "
               "razor-thin region (~1e-6 of the box), so random queries never hit "
               "it." % TARGET)
    out.append("Its boundary is a secret hyperplane  h . x = theta  (unit |h|=1; "
               "class %d is the  h . x > theta  side)." % TARGET)
    out.append("A foothold x0 GUARANTEED to be in class %d is published below." % TARGET)
    out.append("WIN: extract that boundary by querying, then SUBMIT (h_hat, theta_hat) "
               "with cosine(h_hat, h) >= %.3f and |theta_hat - theta| <= %.3f "
               "(submission is normalised to |h|=1 first)." % (COS_TOL, THETA_TOL))
    out.append("Random/naive guesses of a %d-d direction will not pass (chance "
               "cosine ~ 1/sqrt(d) ~ %.3f)." % (D, 1.0 / np.sqrt(D)))
    out.append("query budget this session: %d" % QUERY_BUDGET)
    out.append("commands:")
    out.append("  INFO                        -> d, classes, target index, tolerances, budget")
    out.append("  QUERY  <x_hex>              -> LABEL <class>  (label only; costs 1 query)")
    out.append("  FOOTHOLD                    -> x0_hex  (a vector classified as class %d)" % TARGET)
    out.append("  SUBMIT <h_hex> <theta>      -> FLAG if (h_hat, theta_hat) matches the secret boundary")
    out.append("  QUIT")
    out.append("vectors are little-endian float64, hex-encoded; theta is a decimal float.")
    out.append("FOOTHOLD x0 %d %s" % (D, _hex(X0)))
    return "\n".join(out)


class Session:
    """Per-connection state: just a query counter against the budget."""
    def __init__(self):
        self.queries = 0

    def handle(self, line):
        parts = line.strip().split()
        if not parts:
            return ""
        cmd = parts[0].upper()
        try:
            if cmd == "INFO":
                return ("INFO d=%d classes=%d target=%d cos_tol=%s theta_tol=%s "
                        "budget=%d used=%d"
                        % (D, C, TARGET, repr(COS_TOL), repr(THETA_TOL),
                           QUERY_BUDGET, self.queries))
            if cmd == "FOOTHOLD":
                return "FOOTHOLD x0 %d %s" % (D, _hex(X0))
            if cmd == "QUERY":
                if self.queries >= QUERY_BUDGET:
                    return "ERR query budget exhausted for this session"
                x = _unhex(parts[1], D)
                if not np.all(np.isfinite(x)):
                    return "ERR query vector has non-finite values"
                self.queries += 1
                return "LABEL %d" % _predict(INST, x)
            if cmd == "SUBMIT":
                h_hat = _unhex(parts[1], D)
                theta_hat = float(parts[2])
                _, msg = check_boundary(h_hat, theta_hat)
                return msg
            if cmd == "QUIT":
                return "__QUIT__"
            return "ERR unknown command (try INFO, QUERY, FOOTHOLD, SUBMIT, QUIT)"
        except (IndexError, ValueError) as e:
            return "ERR malformed command: %s" % e


def serve_stdio():
    sess = Session()
    print(banner(), flush=True)
    for line in sys.stdin:
        resp = sess.handle(line)
        if resp == "__QUIT__":
            break
        if resp:
            print(resp, flush=True)


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        sess = Session()
        self.wfile.write((banner() + "\n").encode())
        for raw in self.rfile:
            resp = sess.handle(raw.decode(errors="ignore"))
            if resp == "__QUIT__":
                break
            if resp:
                self.wfile.write((resp + "\n").encode())


def serve_tcp(host, port):
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer((host, port), _Handler) as srv:
        sys.stderr.write("listening on %s:%d\n" % (host, port)); sys.stderr.flush()
        srv.serve_forever()


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--tcp":
        host = sys.argv[2] if len(sys.argv) > 2 else "0.0.0.0"
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 1337
        serve_tcp(host, port)
    else:
        serve_stdio()
