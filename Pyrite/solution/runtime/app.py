#!/usr/bin/env python3
"""
ZSCTF :: Pyrite  (broken / honeypot, Hard-to-recognise)

"Pyrite - Key Recovery Service" presents as an ordinary, slightly abandoned
internal crypto-triage box: it publishes a batch of "recoverable" key material
(a weak-looking RSA modulus, a pair of signatures with a 'reused nonce' note,
and a partially-leaked RSA private key) and offers "recovery" endpoints that
happily hand you plausible, flag-shaped strings.

                        *** ORGANIZER NOTE (NOT FOR PLAYERS) ***
Pyrite is a DELIBERATE DEFENSIVE HONEYPOT / TARPIT. There is NO real flag
anywhere reachable in this service, by design. Every "flag" it emits is a DECOY
that (a) fails the strict zerosecurectf flag validator and (b) fails the
integrity check the service itself publishes at
/.well-known/zsctf-manifest.json. Each advertised "weakness" is PROVABLY a dead
end, verifiable from the published parameters alone:

  * the "weak RSA" modulus N is PRIME -> there is nothing to factor, and its
    "ciphertext" c decrypts (N prime => d = e^{-1} mod (N-1) exists) to pure
    garbage, not a flag;
  * the "reused nonce" signatures have r1 != r2 -> a reused nonce forces r1==r2,
    so the premise is false and no private key is recoverable;
  * the "leaked partial key" exposes only 32 low bits of d -> far below the
    ~ (1/4)*log2(N) bits that known-bits / Coppersmith recovery requires, so it
    is provably insufficient.

The intended learning outcome is a red-team skill: RECOGNISE A HONEYPOT /
RABBIT-HOLE AND DISENGAGE (timebox, spot the trap, move on). ZSCTF_FLAG is
intentionally UNUSED (documented in challenge.yml and writeup.md). The published
integrity digest is sha256(b"") -- the digest of the empty string -- the
service's own quiet admission that the correct flag is empty: there is nothing
to capture.

This is a WHITE-BOX challenge: players are given this exact source file. Nothing
is hidden by obscurity; the "tells" that this is a trap are all discoverable
from the responses themselves (a published integrity digest nothing can satisfy,
a self-rejecting validator, canned "recovery" oracles, a prime "RSA" modulus,
a false nonce-reuse premise, and a robots.txt canary marker).

Per-instance: ZSCTF_SEED derives all decoy parameters and the (still-invalid)
decoy flag bodies deterministically, so two teams see different decoys but the
honeypot conclusion is identical. Same seed -> same instance.

Zero third-party dependencies at runtime: prime generation and primality are
pure-stdlib (deterministic-base Miller-Rabin). Runs on Flask if available, else
on the Python standard library http.server. `python app.py` serves on $PORT
(default 8000).
"""
import os
import re
import sys
import json
import hashlib
from urllib.parse import urlsplit, parse_qs

# ---------------------------------------------------------------------------
# Per-instance configuration (derived deterministically from the team seed).
# Nothing secret is baked in -- and there is no real secret to bake in. These
# are all DECOY values; they exist only to make the trap convincing.
# ---------------------------------------------------------------------------
SEED = os.environ.get("ZSCTF_SEED", "static-demo-seed").encode()

# NB: ZSCTF_FLAG is intentionally NOT read. A honeypot has no flag. If an
# operator sets it, it is ignored on purpose (asserted by test/test.py).


def _derive_bytes(label: bytes, nbytes: int) -> bytes:
    """Deterministic byte stream from SEED|label via a SHA-256 counter (XOF)."""
    out = b""
    ctr = 0
    while len(out) < nbytes:
        out += hashlib.sha256(SEED + b"|" + label + b"|" + str(ctr).encode()).digest()
        ctr += 1
    return out[:nbytes]


def _derive_hex(label: bytes, nhex: int) -> str:
    return hashlib.sha256(SEED + b"|" + label).hexdigest()[:nhex]


def _derive_int(label: bytes, bits: int) -> int:
    """A deterministic odd integer with the top bit set (so it has ~`bits` bits)."""
    nbytes = (bits + 7) // 8
    val = int.from_bytes(_derive_bytes(label, nbytes), "big")
    val |= (1 << (bits - 1))   # force high bit -> full bit-length
    val |= 1                   # force odd
    return val


# --- pure-stdlib primality (deterministic Miller-Rabin) --------------------
# Bases below give a deterministic (not probabilistic) primality decision for
# all n < 3.3e24; for larger n they constitute a strong, standard probable-prime
# test. The challenge's claim "N is prime" is independently verifiable by any
# analyst (e.g. sympy.isprime, or openssl/factordb), so we do not rely on trust.
_MR_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
_SMALL_PRIMES = (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59,
                 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113)


def is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in _MR_BASES:
        a %= n
        if a == 0:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def next_prime(n: int) -> int:
    n |= 1
    while not is_probable_prime(n):
        n += 2
    return n


# ---------------------------------------------------------------------------
# DECOY LEAD 1 -- "weak RSA" (looks factorable; is actually PRIME).
# We publish N, e, c. The hint invites factoring. But N is PRIME, so there is
# nothing to factor. And because N is prime, d = e^{-1} mod (N-1) exists, so c
# "decrypts" -- to deterministic garbage (c is derived noise, not a real
# ciphertext). Either way the lead yields no flag. (~1024-bit.)
# ---------------------------------------------------------------------------
RSA_E = 65537
RSA_N = next_prime(_derive_int(b"rsa-prime-modulus", 1024))   # PRIME, by construction
RSA_C = _derive_int(b"rsa-ciphertext", 1023) % RSA_N          # derived noise, not an encryption

# ---------------------------------------------------------------------------
# DECOY LEAD 2 -- "reused nonce" signatures (premise is FALSE).
# Reusing an ECDSA/DSA nonce k forces identical r across the two signatures;
# the private key then falls out of (h1-h2)/(s1-s2) etc. We publish two
# signatures over the curve order n with a "nonce reused" hint -- but r1 != r2,
# so no nonce was reused and no key is recoverable. n is the secp256k1 order
# (a well-known prime) purely so the modulus looks authentic.
# ---------------------------------------------------------------------------
EC_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SIG_H1 = _derive_int(b"ec-h1", 255) % EC_N
SIG_R1 = _derive_int(b"ec-r1", 255) % EC_N
SIG_S1 = _derive_int(b"ec-s1", 255) % EC_N
SIG_H2 = _derive_int(b"ec-h2", 255) % EC_N
SIG_R2 = _derive_int(b"ec-r2", 255) % EC_N   # independently derived -> r2 != r1
SIG_S2 = _derive_int(b"ec-s2", 255) % EC_N

# ---------------------------------------------------------------------------
# DECOY LEAD 3 -- "leaked partial key" (provably insufficient).
# N2 is a genuine 1024-bit RSA semiprime; d2 is its real private exponent. We
# leak only the low 32 bits of d2. Known-bits / Coppersmith partial-key-exposure
# recovery needs a constant fraction (~1/4) of the bits of N -- i.e. ~256 bits
# here -- so 32 bits is provably far too few to recover the key.
# ---------------------------------------------------------------------------
_P2 = next_prime(_derive_int(b"rsa2-p", 512))
_Q2 = next_prime(_derive_int(b"rsa2-q", 512))
PART_N = _P2 * _Q2
PART_E = 65537
_PHI2 = (_P2 - 1) * (_Q2 - 1)
_D2 = pow(PART_E, -1, _PHI2)              # the REAL private exponent (never published)
PART_D_LOW_BITS = 32
PART_D_LOW = _D2 & ((1 << PART_D_LOW_BITS) - 1)   # only the low 32 bits leaked

# ---------------------------------------------------------------------------
# Public, non-secret instance fingerprint.
# ---------------------------------------------------------------------------
FINGERPRINT = _derive_hex(b"instance-fingerprint", 12)

# DECOY "flags" emitted by the "recovery" oracles. Each is deliberately
# malformed so it FAILS the strict zerosecurectf validator (wrong prefix /
# wrong charset), and -- being non-empty -- also fails the published integrity
# digest (sha256 of the empty string).
DECOY_RSA = "zer0securectf{rsa_modulus_factored_%s}" % _derive_hex(b"decoy-rsa", 8)      # bad prefix 'zer0'
DECOY_NONCE = "zerosecurectf{NONCE_REUSE_RECOVERED_%s}" % _derive_hex(b"decoy-nonce", 8).upper()  # uppercase body
DECOY_PARTIAL = "zerosecurectf{partial-key-completed-%s}" % _derive_hex(b"decoy-partial", 8)       # hyphens in body

# The service PUBLISHES this integrity digest as "the sha256 of the flag". It is
# sha256(b"") -- the digest of the empty string. No non-empty byte string hashes
# to it, so nothing the service (or anyone) can emit will ever satisfy it. A
# sharp analyst recognises e3b0c442...b855 as the canonical empty-input digest
# and concludes: the correct flag is empty, i.e. there is no flag.
PUBLISHED_FLAG_SHA256 = hashlib.sha256(b"").hexdigest()

# The strict, documented flag validator. A real zerosecurectf flag is exactly
# this shape; every decoy above violates it.
STRICT_FLAG_RE = re.compile(r"^zerosecurectf\{[a-z0-9_]{8,48}\}$")

PORT = int(os.environ.get("PORT", "8000"))


# ---------------------------------------------------------------------------
# response helpers -> (status, content_type, body_bytes, extra_headers)
# ---------------------------------------------------------------------------
def _json(obj, status=200, extra=None):
    return status, "application/json; charset=utf-8", json.dumps(obj, indent=2).encode(), (extra or {})


def _html(body, status=200, extra=None):
    return status, "text/html; charset=utf-8", body.encode(), (extra or {})


def _text(body, status=200, extra=None):
    return status, "text/plain; charset=utf-8", body.encode(), (extra or {})


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
_CSS = """
:root{color-scheme:light dark}*{box-sizing:border-box}
body{margin:0;font:16px/1.55 system-ui,Segoe UI,Roboto,sans-serif;background:#0f1216;color:#e7edf3}
.wrap{max-width:860px;margin:0 auto;padding:40px 20px}
h1{font-size:28px;margin:0 0 4px}.sub{color:#8aa0b4;margin:0 0 24px}
.card{background:#161b22;border:1px solid #273142;border-radius:12px;padding:20px;margin:16px 0}
code,pre{font:13px ui-monospace,Consolas,monospace}
pre{background:#0b0f14;border:1px solid #273142;border-radius:8px;padding:14px;overflow:auto;white-space:pre-wrap;word-break:break-word}
.muted{color:#8aa0b4;font-size:14px}a{color:#58a6ff}
.pill{display:inline-block;background:#0b0f14;border:1px solid #30465f;border-radius:999px;padding:3px 10px;font:12px ui-monospace,monospace;color:#9fb3c8}
"""

_INDEX = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pyrite - Key Recovery Service</title><style>%(css)s</style></head>
<!-- build: pyrite-canary * tier=decoy * artifacts=synthetic * do-not-promote -->
<body><div class="wrap">
  <h1>Pyrite</h1>
  <p class="sub">Key Recovery Service (crypto triage)</p>
  <span class="pill">node %(fp)s</span>
  <div class="card">
    <p>This node holds some recoverable key material pulled from an old audit.
       Published leads:</p>
    <ul>
      <li><a href="/params">/params</a> &mdash; the key material (RSA / signatures / partial key)</li>
      <li><code>/recover/rsa</code> &mdash; factor the weak RSA modulus, decrypt the ciphertext</li>
      <li><code>/recover/nonce</code> &mdash; recover the signing key from the reused nonce</li>
      <li><code>/recover/partial</code> &mdash; finish the partially-leaked private key</li>
      <li><code>/validate?flag=zerosecurectf{...}</code> &mdash; flag self-check</li>
      <li><a href="/.well-known/zsctf-manifest.json">/.well-known/zsctf-manifest.json</a>
          &mdash; integrity manifest</li>
    </ul>
    <p class="muted">White-box challenge: full source is <code>challenge/app.py</code>.</p>
  </div>
</div></body></html>
"""


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------
def handle_params():
    """Publish the (decoy) key material. Big integers are emitted as decimal
    strings so any client can parse them without precision loss."""
    return _json({
        "node": FINGERPRINT,
        "tier": "decoy",
        "rsa": {
            "note": "legacy key; primes look low-entropy -- should be factorable (Fermat?).",
            "e": RSA_E,
            "N": str(RSA_N),
            "c": str(RSA_C),
        },
        "ecdsa": {
            "note": "signer reused the per-message nonce k across both signatures.",
            "curve": "secp256k1",
            "n": str(EC_N),
            "sig1": {"h": str(SIG_H1), "r": str(SIG_R1), "s": str(SIG_S1)},
            "sig2": {"h": str(SIG_H2), "r": str(SIG_R2), "s": str(SIG_S2)},
        },
        "partial": {
            "note": "low bits of the private exponent d leaked from a side channel; finish with partial-key exposure.",
            "e": PART_E,
            "N": str(PART_N),
            "d_low": PART_D_LOW,
            "d_low_bits": PART_D_LOW_BITS,
        },
    })


def _recover(decoy):
    """A canned 'recovery oracle'. It ignores all input and returns a fixed,
    plausible-but-useless result. Identical bytes for different inputs is itself
    the tell that no computation is happening behind it."""
    return _json({
        "ok": True,
        "node": FINGERPRINT,
        "candidate_flag": decoy,
        "note": "verify against /.well-known/zsctf-manifest.json before submitting",
        "see_also": "/params",
    })


def handle_validate(query):
    params = parse_qs(query)
    flag = params.get("flag", [""])[0]
    strict_ok = bool(STRICT_FLAG_RE.match(flag))
    digest = hashlib.sha256(flag.encode("utf-8", "replace")).hexdigest()
    # Accept only a non-empty flag that is well formed AND matches the published
    # digest. Because the published digest is sha256(b"") and we reject empty,
    # NOTHING is ever accepted -- the service rejects its own decoys too.
    valid = bool(flag) and strict_ok and digest == PUBLISHED_FLAG_SHA256
    return _json({
        "flag": flag,
        "well_formed": strict_ok,
        "sha256": digest,
        "expected_sha256": PUBLISHED_FLAG_SHA256,
        "valid": valid,
        "reason": ("accepted" if valid else
                   "no candidate can satisfy the published digest on this node"),
    })


_MANIFEST = {
    "challenge": "pyrite",
    "flag_format": "zerosecurectf{[a-z0-9_]{8,48}}",
    "flag_sha256": PUBLISHED_FLAG_SHA256,
    "verify": "printf %s \"$CANDIDATE\" | sha256sum   # must equal flag_sha256",
}

_ROBOTS = (
    "User-agent: *\n"
    "Disallow: /params\n"
    "Disallow: /recover\n"
    "# ops: honeyfarm canary node -- DECOY tier, no production keystore mounted.\n"
    "# synthetic key material only; see SECOPS runbook (tarpit). do-not-promote.\n"
)


def route(method, path, query, headers):
    """Backend-agnostic handler -> (status, content_type, body_bytes, extra_headers)."""
    if method not in ("GET", "HEAD"):
        return _text("method not allowed\n", 405)

    if path in ("/", ""):
        return _html(_INDEX % {"css": _CSS, "fp": FINGERPRINT})
    if path == "/robots.txt":
        return _text(_ROBOTS)
    if path == "/whoami":
        return _json({"service": "pyrite", "fingerprint": FINGERPRINT, "tier": "decoy"})
    if path == "/.well-known/zsctf-manifest.json":
        m = dict(_MANIFEST)
        m["fingerprint"] = FINGERPRINT
        return _json(m)
    if path == "/params":
        return handle_params()
    if path == "/recover/rsa":
        return _recover(DECOY_RSA)
    if path == "/recover/nonce":
        return _recover(DECOY_NONCE)
    if path == "/recover/partial":
        return _recover(DECOY_PARTIAL)
    if path == "/validate":
        return handle_validate(query)
    return _text("404 not found\n", 404)


# ---------------------------------------------------------------------------
# Backend A: Flask (used in deployment if available)
# ---------------------------------------------------------------------------
def run_flask(host, port):
    from flask import Flask, request, Response
    app = Flask(__name__)

    @app.route("/", defaults={"p": ""}, methods=["GET", "HEAD"])
    @app.route("/<path:p>", methods=["GET", "HEAD"])
    def _any(p):
        path = "/" + p
        status, ctype, body, extra = route(request.method, path,
                                            request.query_string.decode("latin-1"),
                                            request.headers)
        resp = Response(body, status=status, content_type=ctype)
        for k, v in extra.items():
            resp.headers[k] = v
        return resp

    app.run(host=host, port=port, threaded=True)


# ---------------------------------------------------------------------------
# Backend B: standard library http.server (zero dependencies)
# ---------------------------------------------------------------------------
def run_stdlib(host, port):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _serve(self):
            parsed = urlsplit(self.path)
            status, ctype, body, extra = route(self.command, parsed.path, parsed.query, self.headers)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in extra.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_GET = _serve
        do_HEAD = _serve

        def log_message(self, *a):
            pass

    httpd = ThreadingHTTPServer((host, port), Handler)
    sys.stderr.write("pyrite (stdlib) listening on %s:%d\n" % (host, port))
    sys.stderr.flush()
    httpd.serve_forever()


def main():
    global PORT
    host = os.environ.get("HOST", "0.0.0.0")
    port = PORT
    backend = os.environ.get("ZSCTF_HTTPD", "auto").lower()
    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a == "--port" and i + 1 < len(args):
            port = int(args[i + 1])
        elif a == "--stdlib":
            backend = "stdlib"
        elif a == "--flask":
            backend = "flask"
    PORT = port

    if backend == "stdlib":
        return run_stdlib(host, port)
    if backend == "flask":
        return run_flask(host, port)
    try:
        import flask  # noqa: F401
    except ImportError:
        return run_stdlib(host, port)
    return run_flask(host, port)


if __name__ == "__main__":
    main()
