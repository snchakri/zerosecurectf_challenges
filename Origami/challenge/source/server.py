#!/usr/bin/env python3
"""
ZSCTF :: Origami  (ai-ml / AI-ML security, Extreme)

A NONLINEAR model-extraction challenge against a small ReLU network.

"Kirigami" is a fixed one-hidden-layer ReLU neural network that maps a
d-dimensional input to a single real-valued score. It is served as a
*prediction API*: you may ask it to score any vector you like, and -- unlike the
label-only oracle in `understudy` -- it answers with the real-valued output
f(x). This is the realistic "confidence / logit" black-box setting studied in the
model-extraction literature (Tramer et al., USENIX Security 2016; Rolnick &
Kording, "Reverse-engineering deep ReLU networks", ICML 2020; Jagielski et al.,
"High Accuracy and High Fidelity Extraction of Neural Networks", USENIX Security
2020; Carlini et al., "Cryptanalytic Extraction of Neural Network Models", CRYPTO
2020).

The network is

    f(x) = sum_i  v_i * ReLU(w_i . x + b_i)  +  c         (i = 0 .. k-1)

with k hidden neurons.  |w_i| = 1 (the first-layer rows are unit vectors).  The
SECRET you must STEAL is the entire first layer: the set of k neuron hyperplanes

    w_i . x + b_i = 0 ,

each described by its unit normal n_i = w_i and its signed offset t_i = -b_i (so
the hyperplane is { x : n_i . x = t_i }).  You win when you SUBMIT k hyperplanes
that match the true k -- up to permutation and the sign of each normal -- within
a tight tolerance.  This is full first-layer extraction of a neural network,
performed purely by querying its scalar output.

Why a label-only / linear attack does NOT work here (see writeup.md "Why the
cheap shortcuts fail", measured):
  * f is PIECEWISE-LINEAR, not linear.  A single finite-difference gradient at
    any point gives  sum_{i active} v_i w_i  -- a BLEND of whichever neurons are
    currently on, NOT any individual w_i.  So the one-shot "read the weights off
    a linear model" trick recovers nothing usable.
  * There is no single decision hyperplane to fit.  Pooling boundary/critical
    points and running a single total-least-squares SVD (the `understudy` attack)
    mixes points from k different hyperplanes and converges to a direction that
    matches NO neuron.
  * You must instead find CRITICAL POINTS (ReLU kinks) where exactly one neuron
    toggles, and read that neuron's weight vector off the GRADIENT JUMP across
    the kink:  Delta grad f = v_i * w_i.  Collect kinks for all k neurons,
    cluster/orient them, and you have reconstructed the first layer.

Per-instance secret: ZSCTF_SEED fixes a unique network (weights, biases, output
layer) and a unique flag, so a leaked solution for one team does not transfer.

Nothing is hidden by obscurity: players are given this exact source file.

Safety scope: Kirigami is a tiny fixed numpy ReLU network with random
per-instance weights. It is NOT a real model and performs no real task. This is
defensive AI-ML-security education about model extraction / model stealing from
prediction APIs (OWASP ML05 model theft, MITRE ATLAS "Exfiltration via ML
Inference API"), nothing more. No external model, no network egress, no
third-party ML library -- pure numpy + stdlib.
"""
import os, sys, hashlib, socketserver, itertools
import numpy as np

# ----------------------------------------------------------------------------
# Public architecture / challenge constants (identical for every instance).
# Calibrated (see writeup.md "Dual measurement & calibration") so the problem is
# simultaneously: solvable by ReLU-kink first-layer extraction to a tight
# tolerance, NOT solvable by any linear shortcut (single-gradient read-off or
# single-hyperplane SVD), and robust across seeds with a large safety margin.
# ----------------------------------------------------------------------------
D            = 24           # input dimension
K            = 8            # number of hidden ReLU neurons (the first layer to steal)
LO, HI       = -1.0, 1.0    # valid input range (per coordinate); the query box
COS_TOL      = 0.9999       # required |cosine| between each submitted & true unit normal
T_TOL        = 0.01         # required abs error on each signed offset t_i = -b_i
QUERY_BUDGET = 1_000_000    # generous per-connection query budget (intended ~7k-13k; see writeup)

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
# same seed yields the same network on any machine with the pinned numpy.
# `make_instance` is a pure function of the seed (single source of truth): the
# live service and the acceptance test both build instances through it.
# ----------------------------------------------------------------------------
def _rng(seed_bytes, label):
    h = hashlib.sha256(seed_bytes + b"|" + label).digest()
    return np.random.default_rng(int.from_bytes(h, "big") % (2**63))


def make_instance(seed_bytes):
    """Return a dict with the full per-instance ReLU network, derived from the
    seed:
         W (k, d)  -- first-layer weight rows, each a UNIT vector (|w_i| = 1)
         b (k,)    -- first-layer biases
         v (k,)    -- output-layer weights (nonzero, mixed sign)
         c (float) -- output bias
    The recoverable SECRET per neuron is the hyperplane { x : w_i . x = -b_i },
    i.e. unit normal n_i = w_i and signed offset t_i = -b_i.

    Geometry is calibrated so EVERY neuron hyperplane passes through the interior
    of the box [LO,HI]^d (it is pinned to a random interior anchor p_i), which
    guarantees the neuron toggles inside the query region and is therefore
    recoverable by a kink search.  Output weights v_i are bounded away from zero
    so each kink's gradient jump  v_i * w_i  is clearly detectable.
    """
    rw = _rng(seed_bytes, b"first-layer")
    W = rw.standard_normal((K, D))
    W /= np.linalg.norm(W, axis=1, keepdims=True)          # unit rows

    # Pin each hyperplane to a random interior anchor p_i in [-0.5, 0.5]^d, so
    # the plane w_i . x + b_i = 0 passes through p_i (well inside the box) and is
    # certain to be crossed by generic chords of the box.
    P = rw.uniform(-0.5, 0.5, size=(K, D))
    b = -np.sum(W * P, axis=1)                             # b_i = -(w_i . p_i)

    # Output layer: mixed-sign weights bounded away from zero so every neuron's
    # kink is detectable in the output, and a nonzero output bias.
    rv = _rng(seed_bytes, b"output-layer")
    signs = rv.choice([-1.0, 1.0], size=K)
    mags = rv.uniform(0.6, 1.4, size=K)
    v = signs * mags
    c = float(rv.uniform(-1.0, 1.0))

    return dict(W=W, b=b, v=v, c=c)


def _f(inst, x):
    """The network's scalar output for a single vector x (D,). Pure float64."""
    pre = inst["W"] @ x + inst["b"]                        # (K,)
    h = np.maximum(pre, 0.0)                               # ReLU
    return float(inst["v"] @ h + inst["c"])


def _f_batch(inst, X):
    """Vectorised output for a stack of inputs X (m, D) -> (m,)."""
    pre = X @ inst["W"].T + inst["b"]                      # (m, K)
    h = np.maximum(pre, 0.0)
    return h @ inst["v"] + inst["c"]


INST = make_instance(SEED)
N_TRUE = INST["W"].copy()                 # true unit normals n_i = w_i   (K, D)
T_TRUE = (-INST["b"]).copy()              # true signed offsets  t_i = -b_i (K,)


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
# Win check: has the player reconstructed the ENTIRE first layer?
#
# A submission is k hyperplanes (n_hat_i, t_hat_i).  Each hyperplane is
# scale-free but has a sign ambiguity: (n, t) and (-n, -t) describe the same
# plane.  We match the submitted set to the true set by a PERFECT bipartite
# matching, where submitted i may match true j iff
#     |cos(n_hat_i, n_true_j)| >= COS_TOL   and   |t_hat_i - s*t_true_j| <= T_TOL
# with s = sign(n_hat_i . n_true_j) resolving the shared sign flip.  The player
# wins iff every one of the k submitted hyperplanes can be matched to a distinct
# true hyperplane within tolerance (i.e. a perfect matching exists).
# ----------------------------------------------------------------------------
def _feasible(n_hat, t_hat, j):
    n = float(np.linalg.norm(n_hat))
    if n == 0.0 or not np.isfinite(n) or not np.isfinite(t_hat):
        return False
    n_unit = n_hat / n
    d = float(n_unit @ N_TRUE[j])
    s = 1.0 if d >= 0.0 else -1.0
    return (abs(d) >= COS_TOL) and (abs(t_hat - s * T_TRUE[j]) <= T_TOL)


def _perfect_matching(feas):
    """feas: (K, K) boolean, feas[i][j] = submitted i may match true j.
    Return True iff a perfect matching covering all K submitted rows exists
    (Kuhn's augmenting-path algorithm; K is small)."""
    match_true = [-1] * K          # which submitted row each true column is matched to

    def try_assign(i, seen):
        for j in range(K):
            if feas[i][j] and not seen[j]:
                seen[j] = True
                if match_true[j] == -1 or try_assign(match_true[j], seen):
                    match_true[j] = i
                    return True
        return False

    for i in range(K):
        if not try_assign(i, [False] * K):
            return False
    return True


def check_submission(M):
    """M: (K, D+1) array; row i = [n_hat_i (D) , t_hat_i (1)]."""
    if M.shape != (K, D + 1):
        return False, "DENIED submission must be %d x %d" % (K, D + 1)
    if not np.all(np.isfinite(M)):
        return False, "DENIED submission has non-finite values"
    feas = [[_feasible(M[i, :D], float(M[i, D]), j) for j in range(K)]
            for i in range(K)]
    n_cover = sum(1 for row in feas if any(row))
    if _perfect_matching(feas):
        return True, ("WIN first layer reconstructed: all %d neuron hyperplanes "
                      "matched (|cos| >= %.4f, |dt| <= %.3f). No flag is returned "
                      "here -- REDEEM each neuron to receive its sealed fragment, "
                      "then assemble the %d fragments in canonical position order "
                      "(ascending signed offset t) to form the flag."
                      % (K, COS_TOL, T_TOL, K))
    return False, ("DENIED reconstruction incomplete: only %d/%d submitted "
                   "hyperplanes fall within tolerance of a distinct true neuron "
                   "(need all %d; |cos| >= %.4f and |dt| <= %.3f for a match)"
                   % (n_cover, K, K, COS_TOL, T_TOL))


# ----------------------------------------------------------------------------
# PER-PIECE RECONSTRUCTION (S2/S2a flag-extraction layer).
#
# Reconstructing all k neuron hyperplanes is the *crux*, but it does NOT hand you
# the flag.  The flag is split into k contiguous fragments; fragment at canonical
# position p is SEALED (XOR keystream) under a key derived from the EXACT
# parameters of the neuron that owns that position, quantized to the win
# tolerance.  You REDEEM one neuron at a time: if your submitted hyperplane
# matches a true neuron within the same (|cos| >= COS_TOL, |dt| <= T_TOL)
# tolerance as the win-check, the service unseals and returns that neuron's
# fragment; otherwise it returns a DECOY fragment deterministically derived from
# the hyperplane you submitted.
#
# Canonical assembly order = neurons VALUE-ORDERED by their (sign-canonical)
# signed offset t, ascending; position p=0 is the smallest t.  Each returned
# fragment is prefixed with its 2-hex-digit canonical position, so you can place
# it; concatenating the k real fragments in position order reproduces exactly
#   zerosecurectf{local_review_flag}
# A decoy fragment always carries one upper-case character in its body, so any
# assembly that includes a decoy (a wrong/approximate neuron) FAILS the strict
# validator ^zerosecurectf\{[a-z0-9_]{8,48}\}$ -- a rejectable near-flag.  A
# reversed / wrong-order assembly does not even start with the literal
# "zerosecurectf{" prefix.  The flag is therefore NEVER returned whole: the
# service only ever emits individual (position-tagged) fragments, and assembly
# happens on the player's side.
#
# Design note (organizer): the sealing key is derived from the TRUE neuron's
# canonical-quantized parameters and the match-to-tolerance is the gate, rather
# than having the player derive the key from their own (noisy) recovered normal.
# A unit normal recovered only to |cos| >= 0.9999 differs from the true normal by
# up to ~0.014 per component, which no fixed per-component quantization can snap
# to identical key bits without an error-correcting secure sketch; server-side
# keying keeps the challenge rock-solid solvable while still binding each fragment
# cryptographically to that neuron's exact geometry.
# ----------------------------------------------------------------------------
FRAG_KEY_DOMAIN   = b"origami-frag-v1"
DECOY_KEY_DOMAIN  = b"origami-decoy-v1"
NQ_DECIMALS       = 5          # normal-component quantization (well inside cos tol)
TQ_DECIMALS       = 3          # offset quantization (matches t_tol = 0.01)


def _keystream(key_material, nbytes):
    """SHA-256 counter-mode keystream (pure stdlib, deterministic)."""
    out = bytearray()
    ctr = 0
    while len(out) < nbytes:
        out += hashlib.sha256(key_material + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return bytes(out[:nbytes])


def _canon_plane(n, t):
    """Resolve the (n,t) ~ (-n,-t) sign ambiguity robustly: make the component of
    largest magnitude positive.  That component is far from zero for a generic
    unit normal, so this canonical sign is stable under the recovery noise."""
    n = np.asarray(n, dtype=np.float64)
    j = int(np.argmax(np.abs(n)))
    s = 1.0 if n[j] >= 0.0 else -1.0
    return n * s, float(t) * s


def _canon_quant(n, t):
    """Canonical, quantized byte representation of a hyperplane (sign-resolved,
    unit-normalised, rounded to the win tolerance).  This is the key material the
    fragment is sealed under."""
    nn, tt = _canon_plane(n, t)
    nrm = float(np.linalg.norm(nn))
    if nrm > 0.0:
        nn = nn / nrm
        nn, tt = _canon_plane(nn, tt)      # re-fix sign after normalisation
    nstr = ",".join(("%.*f" % (NQ_DECIMALS, x)) for x in nn)
    tstr = "%.*f" % (TQ_DECIMALS, tt)
    return ("N:" + nstr + "|T:" + tstr).encode()


def _build_fragments():
    """Split FLAG into K position-ordered slices and seal each under the key of
    the true neuron that owns its canonical position.  Returns:
        SEALS   : list length K; SEALS[j] = ciphertext owned by true neuron j
        SIZES   : the K slice lengths in canonical-position order
    After this, no plaintext flag slice is retained in module state."""
    body = FLAG
    L = len(body)
    base, rem = divmod(L, K)
    sizes = [base + (1 if i < rem else 0) for i in range(K)]   # position order
    slices = []
    idx = 0
    for sz in sizes:
        slices.append(body[idx:idx + sz]); idx += sz
    # canonical position order = true neurons sorted by sign-canonical offset t
    ct = [_canon_plane(N_TRUE[j], float(T_TRUE[j]))[1] for j in range(K)]
    order = sorted(range(K), key=lambda j: ct[j])             # order[p] = neuron j
    seals = [None] * K
    for p in range(K):
        j = order[p]
        key = hashlib.sha256(FRAG_KEY_DOMAIN + b"|" + SEED + b"|"
                             + _canon_quant(N_TRUE[j], float(T_TRUE[j]))).digest()
        pt = (("%02x" % p) + slices[p]).encode()
        ks = _keystream(key, len(pt))
        seals[j] = bytes(a ^ b for a, b in zip(pt, ks))
    return seals, sizes


SEALS, FRAG_SIZES = _build_fragments()
DECOY_LEN = max(FRAG_SIZES) if FRAG_SIZES else 1
_DEC_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789_"


def _match_neuron(n_hat, t_hat):
    """Return the true-neuron index this hyperplane matches within the win
    tolerance, or -1.  (True neurons are mutually near-orthogonal, so at the
    0.9999 cosine gate at most one can match; ties resolve to the best |cos|.)"""
    best_j, best_cos = -1, -1.0
    n = float(np.linalg.norm(n_hat))
    if n == 0.0 or not np.isfinite(n) or not np.isfinite(t_hat):
        return -1
    n_unit = n_hat / n
    for j in range(K):
        if _feasible(n_hat, t_hat, j):
            c = abs(float(n_unit @ N_TRUE[j]))
            if c > best_cos:
                best_cos, best_j = c, j
    return best_j


def redeem(n_hat, t_hat):
    """One-neuron redemption.  Returns a position-tagged fragment token string.
    A matched neuron yields its real (unsealed) fragment; anything else yields a
    deterministic decoy fragment (which carries an upper-case defect so that any
    assembly including it fails the strict flag validator)."""
    j = _match_neuron(n_hat, t_hat)
    if j >= 0:
        key = hashlib.sha256(FRAG_KEY_DOMAIN + b"|" + SEED + b"|"
                             + _canon_quant(N_TRUE[j], float(T_TRUE[j]))).digest()
        ks = _keystream(key, len(SEALS[j]))
        pt = bytes(a ^ b for a, b in zip(SEALS[j], ks))
        return pt.decode("latin-1")
    # decoy: deterministic in the submitted hyperplane (plane-canonical)
    dk = hashlib.sha256(DECOY_KEY_DOMAIN + b"|" + SEED + b"|"
                        + _canon_quant(n_hat, t_hat)).digest()
    p_d = dk[0] % K
    ksd = _keystream(dk, DECOY_LEN)
    body = "".join(_DEC_ALPHABET[b % len(_DEC_ALPHABET)] for b in ksd)
    up_pos = dk[1] % DECOY_LEN
    up_ch = chr(ord("A") + (dk[2] % 26))        # guaranteed upper-case defect
    body = body[:up_pos] + up_ch + body[up_pos + 1:]
    return ("%02x" % p_d) + body


# ----------------------------------------------------------------------------
# Line protocol. One connection == one querying session with its own budget.
# ----------------------------------------------------------------------------
def banner():
    out = []
    out.append("=== ZSCTF Kirigami :: score-oracle neural-network extraction ===")
    out.append("Kirigami is a fixed 1-hidden-layer ReLU network: input d=%d -> %d "
               "hidden ReLU neurons -> 1 real output." % (D, K))
    out.append("  f(x) = sum_i v_i * ReLU(w_i . x + b_i) + c     (i = 0 .. %d, |w_i| = 1)"
               % (K - 1))
    out.append("The API is SCORE-BASED: QUERY returns the real-valued output f(x) "
               "(not a label).")
    out.append("Inputs live in the box [%.1f, %.1f]^%d; every neuron hyperplane "
               "passes through the box interior. Queries OUTSIDE the box are "
               "REJECTED (QUERY/QUERYB must stay in [%.1f, %.1f]^%d)."
               % (LO, HI, D, LO, HI, D))
    out.append("STEAL the whole first layer: the %d neuron hyperplanes "
               "{ x : n_i . x = t_i }, where n_i = w_i (unit) and t_i = -b_i." % K)
    out.append("WIN-CHECK: SUBMIT %d hyperplanes (n_i, t_i). They are matched to the "
               "true %d up to permutation and the sign of each normal; the check "
               "passes iff all %d match with |cosine| >= %.4f and |t_i - t_true| "
               "<= %.3f. SUBMIT confirms completeness but returns NO flag."
               % (K, K, K, COS_TOL, T_TOL))
    out.append("FLAG EXTRACTION (per-piece reconstruction): the flag is split into "
               "%d fragments, each SEALED under a key derived from one neuron's "
               "exact hyperplane (quantized to the win tolerance). REDEEM a single "
               "hyperplane: a match (same tolerance as the win-check) returns that "
               "neuron's real fragment; a wrong/approximate hyperplane returns a "
               "DECOY fragment. Each fragment is prefixed with its 2-hex-digit "
               "canonical position. Concatenate the %d real fragment bodies in "
               "ascending-position order to get zerosecurectf{local_review_flag}; a decoy (or a "
               "wrong order) yields a rejectable near-flag." % (K, K))
    out.append("A single finite-difference gradient gives only a BLEND of the "
               "active neurons' weights, and a single-hyperplane SVD fit matches "
               "no neuron: you must find ReLU kinks and read each w_i off the "
               "gradient JUMP (Delta grad f = v_i * w_i).")
    out.append("Random guesses of a %d-d direction will not pass (chance |cosine| "
               "~ 1/sqrt(d) ~ %.3f)." % (D, 1.0 / np.sqrt(D)))
    out.append("query budget this session: %d" % QUERY_BUDGET)
    out.append("commands:")
    out.append("  INFO                        -> d, k, box, tolerances, budget")
    out.append("  QUERY  <x_hex>              -> VALUE <f(x)>         (1 query)")
    out.append("  QUERYB <x1_hex> <x2_hex>... -> VALUES <f1> <f2> ... (1 query each)")
    out.append("  SUBMIT <M_hex>              -> WIN-CHECK for the %d hyperplanes "
               "(no flag); M is a %d x %d float64 matrix (row i = n_i[0..%d], "
               "t_i), row-major." % (K, K, D + 1, D - 1))
    out.append("  REDEEM <row_hex>            -> FRAG <tag+body> for ONE hyperplane "
               "(row = n_i[0..%d], t_i; %d float64 values)" % (D - 1, D + 1))
    out.append("  QUIT")
    out.append("vectors/matrix are little-endian float64, hex-encoded; outputs are "
               "Python float reprs (exact round-trip).")
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
                return ("INFO d=%d k=%d box=[%s,%s] cos_tol=%s t_tol=%s "
                        "budget=%d used=%d"
                        % (D, K, repr(LO), repr(HI), repr(COS_TOL), repr(T_TOL),
                           QUERY_BUDGET, self.queries))
            if cmd == "QUERY":
                if self.queries >= QUERY_BUDGET:
                    return "ERR query budget exhausted for this session"
                x = _unhex(parts[1], D)
                if not np.all(np.isfinite(x)):
                    return "ERR query vector has non-finite values"
                if np.any(x < LO) or np.any(x > HI):
                    return ("ERR query vector outside the box [%s,%s]^%d"
                            % (repr(LO), repr(HI), D))
                self.queries += 1
                return "VALUE %r" % _f(INST, x)
            if cmd == "QUERYB":
                hexes = parts[1:]
                if not hexes:
                    return "ERR QUERYB needs at least one vector"
                if self.queries + len(hexes) > QUERY_BUDGET:
                    return "ERR query budget exhausted for this session"
                X = np.array([_unhex(h, D) for h in hexes])
                if not np.all(np.isfinite(X)):
                    return "ERR query batch has non-finite values"
                if np.any(X < LO) or np.any(X > HI):
                    return ("ERR query batch has a vector outside the box "
                            "[%s,%s]^%d" % (repr(LO), repr(HI), D))
                self.queries += len(hexes)
                vals = _f_batch(INST, X)
                return "VALUES " + " ".join(repr(float(z)) for z in vals)
            if cmd == "SUBMIT":
                flat = _unhex(parts[1], K * (D + 1))
                M = flat.reshape(K, D + 1)
                _, msg = check_submission(M)
                return msg
            if cmd == "REDEEM":
                row = _unhex(parts[1], D + 1)
                if not np.all(np.isfinite(row)):
                    return "ERR redeem row has non-finite values"
                return "FRAG " + redeem(row[:D], float(row[D]))
            if cmd == "QUIT":
                return "__QUIT__"
            return ("ERR unknown command (try INFO, QUERY, QUERYB, SUBMIT, "
                    "REDEEM, QUIT)")
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
