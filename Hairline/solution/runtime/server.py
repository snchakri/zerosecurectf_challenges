#!/usr/bin/env python3
"""
ZSCTF :: Hairline  (misc / AI-ML security, Hard)

A DEFENSIVE content-safety gateway. "Sentinel" is a small, fixed neural-network
classifier that scores an item's extracted feature vector and labels it either
  class 0 = ALLOWED   (benign / safe content)
  class 1 = FLAGGED   (disallowed content)
You are the red-teamer auditing its robustness. Sentinel will show you its exact
weights (this is a white-box robustness audit, like DiceCTF's what-a-jpeg-is) and
one known-ALLOWED sample x0. It releases the flag only if you hand it a feature
vector that is:
    * inside the valid feature range [0, 1] per coordinate, and
    * within an L-infinity budget epsilon of x0 (a *bounded* perturbation), and
    * confidently misclassified as FLAGGED (p_flag >= tau).
i.e. a genuine *adversarial example*: a hairline nudge that crosses the decision
boundary, not a trivial out-of-distribution input.

Nothing is hidden by obscurity: players are given this exact source file, and the
service hands out the model weights on request. The lesson is in plain sight --
the gap between random robustness and adversarial robustness in high dimension.

Self-contained: a hand-built 2-layer numpy MLP (no sklearn, no external model,
no network egress). Deterministic per instance: ZSCTF_SEED fixes the weights, the
benign sample and the flag, so a leaked solution for one team does not transfer.

Safety scope: the classifier is a tiny fixed numpy model with random per-instance
weights; it is NOT a real moderation system and performs no real classification.
This is defensive adversarial-ML education about classifier brittleness under a
bounded perturbation (OWASP ML01 input-manipulation), nothing more.
"""
import os, sys, hashlib, socketserver
import numpy as np

# ----------------------------------------------------------------------------
# Public architecture / challenge constants (same for every instance).
# Calibrated (see writeup.md "Dual-measurement & calibration") so that across
# many seeds the problem is simultaneously: solvable by gradient optimisation,
# unsolvable by random search within the budget, and started from a confidently
# benign sample.
# ----------------------------------------------------------------------------
D       = 100          # feature-vector dimension (a fixed content "embedding")
H       = 64           # hidden units
C       = 2            # classes: 0 = allowed, 1 = flagged
TARGET  = 1            # the class an adversarial example must induce (flagged)
BENIGN  = 1 - TARGET   # 0 = allowed
ALPHA   = 4.0          # first-layer init scale factor  (s1 = ALPHA / sqrt(D))
BETA    = 3.0          # second-layer init scale factor (s2 = BETA  / sqrt(H))
B1_SC   = 0.1          # hidden-bias scale
B2_SC   = 0.1          # logit-bias scale
EPSILON = 0.10         # L-infinity perturbation budget (each feature in [0,1])
TAU     = 0.90         # "confident" threshold on p_flag required to win
LO, HI  = 0.0, 1.0     # valid feature range (per coordinate)
M_TARGET = -2.5        # desired logit-margin of x0 (-> p_allowed(x0) ~ 0.924)
BUDGET_TOL = 1e-9      # float round-off tolerance on the L-inf budget check
LOGIT_TAU = float(np.log(TAU / (1.0 - TAU)))   # margin needed to win (~2.197)

SEED = os.environ.get("ZSCTF_SEED", "static-demo-seed").encode()
FLAG = os.environ.get("ZSCTF_FLAG", "zerosecurectf{local_review_flag}")


# ----------------------------------------------------------------------------
# Per-instance model, derived deterministically from the seed.
# numpy's default_rng (PCG64) is a portable, version-stable bit stream, so the
# same seed yields the same weights on any machine with the pinned numpy.
# `make_instance` is a pure function of the seed (single source of truth): the
# live service and the acceptance test both build instances through it.
# ----------------------------------------------------------------------------
def _rng(seed_bytes, label):
    h = hashlib.sha256(seed_bytes + b"|" + label).digest()
    return np.random.default_rng(int.from_bytes(h, "big") % (2**63))


def _logits(W1, b1, W2, b2, X):
    """Forward pass. X may be (D,) or (n, D). Returns (n, C)."""
    return np.maximum(np.atleast_2d(X) @ W1.T + b1, 0.0) @ W2.T + b2


def _margins(W1, b1, W2, b2, X):
    z = _logits(W1, b1, W2, b2, X)
    return z[:, TARGET] - z[:, BENIGN]


def make_instance(seed_bytes):
    """Return (W1, b1, W2, b2, x0) derived deterministically from seed_bytes."""
    s1 = ALPHA / np.sqrt(D)
    s2 = BETA / np.sqrt(H)
    r = _rng(seed_bytes, b"weights")
    W1 = r.standard_normal((H, D)) * s1
    b1 = r.standard_normal(H) * B1_SC
    W2 = r.standard_normal((C, H)) * s2
    b2 = r.standard_normal(C) * B2_SC
    # CENTRE the model: fold the mean logit-margin over the input box into the
    # output biases so that, for every seed, roughly half of [0,1]^D is ALLOWED
    # and half is FLAGGED. This guarantees a usable benign start exists and keeps
    # the decision boundary "soft" (un-saturated) rather than all-one-class.
    pr = _rng(seed_bytes, b"center")
    probe = pr.random((256, D))
    zz = np.maximum(probe @ W1.T + b1, 0.0) @ W2.T + b2
    mean_margin = float(np.mean(zz[:, TARGET] - zz[:, BENIGN]))
    b2 = b2.copy()
    b2[TARGET] -= mean_margin / 2.0
    b2[BENIGN] += mean_margin / 2.0
    # Benign sample: the ALLOWED candidate whose logit-margin is closest to
    # M_TARGET, so p_allowed(x0) ~ 0.92 -- confidently benign, yet reachable.
    br = _rng(seed_bytes, b"benign")
    cand = br.random((800, D))
    m = _margins(W1, b1, W2, b2, cand)
    conf = m <= -LOGIT_TAU
    if conf.any():
        idx = np.where(conf)[0]
        pick = idx[int(np.argmin(np.abs(m[idx] - M_TARGET)))]
    else:                                       # should not happen once centred
        pick = int(np.argmin(m))
    return W1, b1, W2, b2, cand[pick].copy()


W1, b1, W2, b2, X0 = make_instance(SEED)


# ----------------------------------------------------------------------------
# Classification + win check
# ----------------------------------------------------------------------------
def classify(x):
    z = _logits(W1, b1, W2, b2, x)[0]
    z = z - z.max()                             # numerically stable softmax
    e = np.exp(z)
    p = e / e.sum()
    return int(np.argmax(z)), float(p[TARGET]), z


def _hex(arr):
    return np.asarray(arr, dtype="<f8").tobytes().hex()


def _unhex(s, n):
    v = np.frombuffer(bytes.fromhex(s), dtype="<f8")
    if v.size != n:
        raise ValueError("expected %d float64 values, got %d" % (n, v.size))
    return v.astype(np.float64)


def check_submission(x):
    """Return (won: bool, message: str) for a candidate feature vector x (D,)."""
    if not np.all(np.isfinite(x)):
        return False, "DENIED submitted vector has non-finite values"
    if np.any(x < LO - BUDGET_TOL) or np.any(x > HI + BUDGET_TOL):
        return False, ("DENIED submitted vector leaves the valid feature range "
                       "[%.1f, %.1f]" % (LO, HI))
    linf = float(np.max(np.abs(x - X0)))
    if linf > EPSILON + BUDGET_TOL:
        return False, ("DENIED perturbation exceeds the L-inf budget: "
                       "||x - x0||_inf = %.6f > epsilon = %.4f" % (linf, EPSILON))
    pred, p_flag, _ = classify(x)
    if pred == TARGET and p_flag >= TAU:
        return True, ("WIN adversarial example accepted (L-inf used = %.6f, "
                      "p_flag = %.4f)\nFLAG %s" % (linf, p_flag, FLAG))
    if pred == TARGET:
        return False, ("DENIED classified as FLAGGED but confidence p_flag = "
                       "%.4f < required tau = %.2f (push harder, still in budget)"
                       % (p_flag, TAU))
    return False, ("DENIED still classified as ALLOWED (p_flag = %.4f); the "
                   "vector is within budget but not yet adversarial" % p_flag)


# ----------------------------------------------------------------------------
# Line protocol
# ----------------------------------------------------------------------------
def banner():
    out = []
    out.append("=== ZSCTF Sentinel :: content-safety classifier robustness audit ===")
    out.append("Sentinel is a fixed 2-layer MLP: input d=%d -> relu hidden h=%d "
               "-> %d logits -> softmax." % (D, H, C))
    out.append("classes: 0 = ALLOWED, 1 = FLAGGED. target class to induce: %d (FLAGGED)."
               % TARGET)
    out.append("A known-ALLOWED sample x0 is published below (p_allowed(x0) is high).")
    out.append("WIN: submit x with  x in [%.1f,%.1f]^d  and  ||x - x0||_inf <= %.4f  "
               "such that argmax == %d and p_flag >= %.2f." % (LO, HI, EPSILON, TARGET, TAU))
    out.append("This is a white-box audit: GET the weights, craft a bounded adversarial")
    out.append("perturbation of x0, and SUBMIT it. Random noise within the budget will")
    out.append("not win -- only a gradient-directed perturbation crosses the boundary.")
    out.append("commands:")
    out.append("  PARAMS                 -> dump model weights W1,b1,W2,b2 and x0 (float64 hex)")
    out.append("  SCORE  <x_hex>         -> logits + p_flag + predicted class for your vector")
    out.append("  SUBMIT <x_hex>         -> FLAG if x is in-budget and confidently FLAGGED")
    out.append("  QUIT")
    out.append("vectors are little-endian float64, hex-encoded (row-major for matrices).")
    return "\n".join(out)


def _params_lines():
    return [
        "PARAM meta d=%d h=%d classes=%d target=%d epsilon=%s tau=%s lo=%s hi=%s norm=linf"
        % (D, H, C, TARGET, repr(EPSILON), repr(TAU), repr(LO), repr(HI)),
        "PARAM W1 %d %d %s" % (H, D, _hex(W1)),
        "PARAM b1 %d %s" % (H, _hex(b1)),
        "PARAM W2 %d %d %s" % (C, H, _hex(W2)),
        "PARAM b2 %d %s" % (C, _hex(b2)),
        "PARAM x0 %d %s" % (D, _hex(X0)),
        "END",
    ]


def handle_line(line):
    parts = line.strip().split()
    if not parts:
        return ""
    cmd = parts[0].upper()
    try:
        if cmd == "PARAMS":
            return "\n".join(_params_lines())
        if cmd == "SCORE":
            x = _unhex(parts[1], D)
            pred, p_flag, z = classify(x)
            return ("SCORE logit_allowed=%.6f logit_flagged=%.6f p_flag=%.6f argmax=%d"
                    % (z[BENIGN], z[TARGET], p_flag, pred))
        if cmd == "SUBMIT":
            x = _unhex(parts[1], D)
            _, msg = check_submission(x)
            return msg
        if cmd == "QUIT":
            return "__QUIT__"
        return "ERR unknown command (try PARAMS, SCORE, SUBMIT, QUIT)"
    except (IndexError, ValueError) as e:
        return "ERR malformed command: %s" % e


def serve_stdio():
    print(banner(), flush=True)
    for line in sys.stdin:
        resp = handle_line(line)
        if resp == "__QUIT__":
            break
        if resp:
            print(resp, flush=True)


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write((banner() + "\n").encode())
        for raw in self.rfile:
            resp = handle_line(raw.decode(errors="ignore"))
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
