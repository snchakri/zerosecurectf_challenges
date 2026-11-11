#!/usr/bin/env python3
"""
ZSCTF :: Portcullis  (web, Hard)

"Portcullis" is a single sign-on (SSO) gatehouse. Users sign in and are issued a
session token -- a JSON Web Token (JWT) -- that carries their identity and role.
Internal apps trust that token. The staff admin console at ``/admin`` is the inner
keep: it opens only for a token whose ``role`` claim is ``admin``.

Reaching the keep does not hand over the flag; it hands over the MEANS to collect
it. The flag is delivered by a capability-scoped credential vault (``/admin/vault``):
its body is split into ordered fragments, one per scope, and each scope opens only
for an admin token carrying the correct scoped ``grant`` -- and the grant for the
next scope is disclosed only by an authentic read of the current one (OAuth step-up
style). A wrong grant returns a decoy fragment. Collect every authentic fragment, in
order, to assemble the flag.

Portcullis signs its tokens with RS256 (RSA-SHA256): a 2048-bit private key the
gatehouse keeps to itself, and a matching PUBLIC key it publishes so downstream
services can verify tokens. Publishing the verification key is normal and
necessary for asymmetric JWTs -- you can read ours at ``/pubkey.pem`` and
``/.well-known/jwks.json``.

This is a WHITE-BOX challenge: you are given this exact source file. The flaw is
therefore not hidden by obscurity -- it is in plain sight, in how the token
*verifier* decides which algorithm (and therefore which key) to trust. Read
``jwt_verify`` below.

Self-contained: pure-Python RSA + a hand-written JWT (HS256 and RS256), built only
on the standard library (``hashlib``, ``hmac``, ``base64``, ``json``,
``http.server``, ``urllib``). No third-party packages. ``python app.py`` serves on
``$PORT`` (default 8000).

Per-instance: ``ZSCTF_SEED`` deterministically derives the RSA keypair (hence the
published public key and the instance fingerprint); ``ZSCTF_FLAG`` sets the flag.
Same seed -> same instance. Nothing secret is baked into this file.
"""
import os
import sys
import json
import hmac
import time
import base64
import hashlib
from urllib.parse import urlsplit, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ===========================================================================
# Per-instance configuration (derived deterministically from the team seed).
# ===========================================================================
SEED = os.environ.get("ZSCTF_SEED", "static-demo-seed").encode()
FLAG = os.environ.get("ZSCTF_FLAG", "zerosecurectf{local_review_flag}")

PORT = int(os.environ.get("PORT", "8000"))
ISSUER = "portcullis-sso"
TOKEN_TTL = int(os.environ.get("PORTCULLIS_TTL", "3600"))  # seconds


def _derive_hex(label: bytes, nhex: int) -> str:
    return hashlib.sha256(SEED + b"|" + label).hexdigest()[:nhex]


FINGERPRINT = _derive_hex(b"instance-fingerprint", 12)  # PUBLIC, non-secret: proves determinism
KID = _derive_hex(b"key-id", 16)                        # PUBLIC key id for the JWK


# ===========================================================================
# Multi-stage flag delivery -- the capability-scoped credential vault.
#
# Reaching /admin (the algorithm-confusion gate -- see jwt_verify) NO LONGER
# hands over the flag. It hands over only the MEANS: the address of an internal
# credential vault (/admin/vault) and the entry grant for its first scope. The
# flag's BODY is split into NUM_SCOPES ordered fragments, one per scope. To read
# the AUTHENTIC fragment at scope i you must present an admin token that ALSO
# carries an integer claim `scope` and a string claim `grant` equal to that
# scope's secret grant. Each authentic read discloses `next_grant` -- the grant
# for scope i+1 -- so the scopes must be walked IN ORDER (this mirrors OAuth-style
# incremental / step-up authorization: each scoped access credential is minted by
# exchanging the one before it). A wrong or absent grant returns a per-instance
# DECOY fragment that carries a '-' (a character the published flag format
# forbids), so a careless "just read every scope" sweep assembles a flag-shaped
# NEAR-token that fails the published format rule
#     ^zerosecurectf\{[a-z0-9_]{8,48}\}$
# and is therefore rejectable by reasoning, never by guessing. No single response
# ever contains the whole flag; it exists only once a solver concatenates the
# NUM_SCOPES authentic fragments, in scope order, inside the published frame.
#
# The scope grants, the decoy fragments and the split are all pure functions of
# ZSCTF_SEED (+ the flag), so the whole mechanism is per-instance and reproducible
# (same seed+flag -> identical; different seed -> different grants and decoys).
# ===========================================================================
FLAG_PREFIX = "zerosecurectf{"
FLAG_SUFFIX = "}"
if (FLAG.startswith(FLAG_PREFIX) and FLAG.endswith(FLAG_SUFFIX)
        and len(FLAG) > len(FLAG_PREFIX) + len(FLAG_SUFFIX)):
    _FLAG_BODY = FLAG[len(FLAG_PREFIX):-len(FLAG_SUFFIX)]
else:
    # Non-standard flag (should not happen under the deploy contract, which always
    # uses zerosecurectf{local_review_flag}): degrade gracefully -- deliver the whole string as
    # the body with an empty frame, so the mechanism still works end to end.
    _FLAG_BODY = FLAG
    FLAG_PREFIX = ""
    FLAG_SUFFIX = ""

NUM_SCOPES = min(6, max(1, len(_FLAG_BODY)))


def _split_contiguous(s: str, n: int):
    """Split *s* into *n* contiguous, near-even pieces. ''.join(pieces) == s."""
    out, i = [], 0
    base, rem = divmod(len(s), n)
    for k in range(n):
        size = base + (1 if k < rem else 0)
        out.append(s[i:i + size])
        i += size
    return out


_REAL_FRAGMENTS = _split_contiguous(_FLAG_BODY, NUM_SCOPES)


def _scope_grant(i: int) -> str:
    """The secret grant that unlocks the AUTHENTIC fragment at scope *i*.

    Seed-derived so the server recomputes it statelessly. A solver can only learn
    grant[0] (from /admin) and grant[i+1] (disclosed by an authentic read of scope
    i); it can never compute grant[i] ahead of time, so the scopes are forced to be
    walked in order (no skipping to the last fragment).
    """
    return hashlib.sha256(SEED + b"|portcullis-scope-grant|" + str(i).encode()).hexdigest()[:24]


def _decoy_fragment(i: int) -> str:
    """A per-instance decoy fragment for scope *i*.

    Same length as the real fragment but with a leading '-', a character the
    published flag format (^zerosecurectf\\{[a-z0-9_]{8,48}\\}$) forbids. Any
    assembly that includes even one decoy therefore fails the format rule on
    inspection -- the reasoning-based discriminator (guess-exposure 0).
    """
    length = len(_REAL_FRAGMENTS[i])
    if length <= 0:
        return "-"
    h = hashlib.sha256(SEED + b"|portcullis-decoy-fragment|" + str(i).encode()).hexdigest()
    filler = (h * ((length // len(h)) + 1))[:length]
    return "-" + filler[1:]


_DECOY_FRAGMENTS = [_decoy_fragment(i) for i in range(NUM_SCOPES)]

# Published, length-agnostic character-class check: the decoy marker '-' (and any
# character outside the flag alphabet) fails it. Used only to DOCUMENT the tell;
# the deploy-time published validator additionally bounds the body to {8,48}.
FLAG_FORMAT = r"^zerosecurectf\{[a-z0-9_]{8,48}\}$"


# ===========================================================================
# Deterministic, pure-Python RSA key generation (no third-party crypto).
#   - A seeded SHA-256 counter-mode stream gives a reproducible bit source.
#   - Miller-Rabin with a FIXED set of small-prime bases is deterministic and,
#     for 1024-bit candidates, has negligible error probability.
# The result (n, e, d) is a 2048-bit RSA key that is a pure function of the seed.
# ===========================================================================
def _sieve(limit: int):
    s = bytearray([1]) * (limit + 1)
    s[0] = s[1] = 0
    for i in range(2, int(limit ** 0.5) + 1):
        if s[i]:
            step = i
            s[i * i::step] = bytearray(len(s[i * i::step]))
    return [i for i in range(2, limit + 1) if s[i]]


_SMALL_PRIMES = _sieve(4000)
_MR_BASES = _SMALL_PRIMES[:32]   # fixed bases -> deterministic primality test


def _is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
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
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


class _SeededRNG:
    """Deterministic byte source: SHA-256(seed||label||counter)."""
    def __init__(self, seed: bytes, label: bytes):
        self._seed = hashlib.sha256(seed + b"|" + label).digest()
        self._ctr = 0
        self._buf = b""

    def _more(self):
        self._buf += hashlib.sha256(self._seed + self._ctr.to_bytes(8, "big")).digest()
        self._ctr += 1

    def randbits(self, nbits: int) -> int:
        nbytes = (nbits + 7) // 8
        while len(self._buf) < nbytes:
            self._more()
        chunk, self._buf = self._buf[:nbytes], self._buf[nbytes:]
        return int.from_bytes(chunk, "big") >> (nbytes * 8 - nbits)


def _gen_prime(rng: "_SeededRNG", bits: int) -> int:
    while True:
        cand = rng.randbits(bits)
        cand |= (1 << (bits - 1)) | (1 << (bits - 2)) | 1   # full length + odd
        while cand.bit_length() == bits:
            if _is_probable_prime(cand):
                return cand
            cand += 2


def _gen_rsa(seed: bytes, modbits: int = 2048, e: int = 65537):
    pbits = modbits // 2
    qbits = modbits - pbits
    rng = _SeededRNG(seed, b"rsa-keygen-v1")
    while True:
        p = _gen_prime(rng, pbits)
        if (p - 1) % e == 0:
            continue
        q = _gen_prime(rng, qbits)
        if q == p or (q - 1) % e == 0:
            continue
        n = p * q
        if n.bit_length() != modbits:
            continue
        d = pow(e, -1, (p - 1) * (q - 1))
        return n, e, d


RSA_N, RSA_E, RSA_D = _gen_rsa(SEED)
RSA_K = (RSA_N.bit_length() + 7) // 8   # modulus length in bytes


# ===========================================================================
# Minimal DER / PEM encoding of the public key as a standard
# SubjectPublicKeyInfo ("-----BEGIN PUBLIC KEY-----"). This is byte-for-byte
# what `openssl rsa -pubout` emits, so a player can derive the same bytes with
# their own tooling. These EXACT bytes are what /pubkey.pem serves.
# ===========================================================================
def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der_tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _der_int(x: int) -> bytes:
    b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:                       # keep it positive
        b = b"\x00" + b
    return _der_tlv(0x02, b)


def _spki_pem(n: int, e: int) -> str:
    rsa_pub = _der_tlv(0x30, _der_int(n) + _der_int(e))                 # RSAPublicKey SEQUENCE
    algid = _der_tlv(0x30, bytes.fromhex("06092A864886F70D010101") +    # rsaEncryption OID
                            bytes.fromhex("0500"))                      # NULL
    spki = _der_tlv(0x30, algid + _der_tlv(0x03, b"\x00" + rsa_pub))    # SEQ{ alg, BITSTRING }
    b64 = base64.b64encode(spki).decode("ascii")
    body = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return "-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----\n"


PUBKEY_PEM = _spki_pem(RSA_N, RSA_E)          # str; served verbatim at /pubkey.pem
PUBKEY_PEM_BYTES = PUBKEY_PEM.encode("ascii")  # the EXACT bytes a verifier sees


# ===========================================================================
# JWT -- hand-written (HS256 + RS256). base64url helpers.
# ===========================================================================
def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# ---- RS256: RSASSA-PKCS1-v1_5 over SHA-256, implemented with big-int pow ----
_SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _emsa_pkcs1v15(msg: bytes, em_len: int) -> bytes:
    h = hashlib.sha256(msg).digest()
    t = _SHA256_DIGESTINFO + h
    ps = b"\xff" * (em_len - len(t) - 3)      # >= 8 bytes by construction for 2048-bit
    return b"\x00\x01" + ps + b"\x00" + t


def rsa_sign(signing_input: bytes) -> bytes:
    em = _emsa_pkcs1v15(signing_input, RSA_K)
    s = pow(int.from_bytes(em, "big"), RSA_D, RSA_N)
    return s.to_bytes(RSA_K, "big")


def rsa_verify(signing_input: bytes, sig: bytes) -> bool:
    # Strict "encode-and-compare": reconstruct the expected padded block and
    # require an exact match. This rejects Bleichenbacher-style forged padding.
    if len(sig) != RSA_K:
        return False
    s = int.from_bytes(sig, "big")
    if s >= RSA_N:
        return False
    m = pow(s, RSA_E, RSA_N)
    em = m.to_bytes(RSA_K, "big")
    return hmac.compare_digest(em, _emsa_pkcs1v15(signing_input, RSA_K))


# ---- HS256: HMAC-SHA256 ----
def hs256_mac(signing_input: bytes, key: bytes) -> bytes:
    return hmac.new(key, signing_input, hashlib.sha256).digest()


def jwt_issue(payload: dict) -> str:
    """Issue a signed token. Portcullis ALWAYS issues RS256 (asymmetric)."""
    header = {"alg": "RS256", "typ": "JWT", "kid": KID}
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = (h + "." + p).encode("ascii")
    sig = rsa_sign(signing_input)
    return h + "." + p + "." + b64url_encode(sig)


# ===========================================================================
# THE TOKEN VERIFIER  --  this is the whole challenge.
#
# Portcullis verifies tokens with ONE helper, called from every protected route
# with THE SAME key material: the service's RSA public key (its PEM bytes). The
# developer's mental model was "we sign with RS256, so we verify with the RSA
# public key." But this verifier lets the *token's own header* choose the
# algorithm, and hands the same `key` to whichever branch the header selects:
#
#     * header alg == "RS256"  ->  verify the RSA signature with the public key   (intended)
#     * header alg == "HS256"  ->  verify an HMAC whose secret is ... the public key
#
# For RS256 the public key is the right verification key. For HS256 the "key" is
# an HMAC *secret* -- and it is the public key, which is PUBLIC. Anyone can fetch
# it (/pubkey.pem) and compute a matching HMAC, so anyone can forge any token.
#
# This is the classic JWT algorithm-confusion / key-confusion bug:
#   Tim McLean, "Critical vulnerabilities in JSON Web Token libraries" (2015);
#   CWE-347 Improper Verification of Cryptographic Signature; CVE-2016-5431.
#
# `alg: none` and every algorithm other than RS256/HS256 are rejected outright.
# ===========================================================================
VERIFY_KEY = PUBKEY_PEM_BYTES   # the single key object passed to the verifier


def jwt_verify(token: str):
    """Return the payload dict if the token is valid, else None."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    h_b64, p_b64, s_b64 = parts
    try:
        header = json.loads(b64url_decode(h_b64))
        payload = json.loads(b64url_decode(p_b64))
        sig = b64url_decode(s_b64)
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None

    alg = header.get("alg")
    signing_input = (h_b64 + "." + p_b64).encode("ascii")

    # --- algorithm dispatch keyed on the untrusted header (the flaw) ---
    if alg == "RS256":
        ok = rsa_verify(signing_input, sig)
    elif alg == "HS256":
        # BUG: the same VERIFY_KEY (the public-key PEM bytes) is used as the
        # HMAC secret. A public value must never be an HMAC key.
        ok = hmac.compare_digest(hs256_mac(signing_input, VERIFY_KEY), sig)
    else:
        return None  # alg:none and anything else -> rejected

    if not ok:
        return None

    # expiry is enforced when present (a real session service would)
    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and time.time() > exp:
        return None
    return payload


def token_from_request(headers, cookie_jwt):
    """Prefer Authorization: Bearer; fall back to the `session` cookie."""
    auth = headers.get("Authorization", "")
    if auth[:7].lower() == "bearer ":
        return auth[7:].strip()
    return cookie_jwt


def parse_cookies(raw: str) -> dict:
    out = {}
    for part in raw.split(";"):
        if "=" in part:
            k, _, v = part.strip().partition("=")
            out[k] = v
    return out


# ===========================================================================
# Pages
# ===========================================================================
_CSS = """
:root{color-scheme:light dark;--bg:#0c0f14;--panel:#141a22;--line:#26303d;--ink:#e8eef5;--mut:#8aa0b4;--acc:#5aa2ff;--gold:#e6b566}
*{box-sizing:border-box}
body{margin:0;font:16px/1.6 system-ui,Segoe UI,Roboto,sans-serif;background:
 radial-gradient(1200px 600px at 80% -10%,#15263f55,transparent),var(--bg);color:var(--ink);min-height:100vh}
.wrap{max-width:860px;margin:0 auto;padding:46px 20px 80px}
.brand{display:flex;align-items:center;gap:14px;margin-bottom:6px}
.crest{width:42px;height:42px;flex:0 0 42px;border-radius:9px;border:1px solid var(--line);
 background:linear-gradient(160deg,#1b2838,#0e141c);display:grid;place-items:center;color:var(--gold);font-size:22px}
h1{font-size:30px;margin:0;letter-spacing:.3px}
.sub{color:var(--mut);margin:2px 0 26px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:22px;margin:18px 0}
.card h2{margin:0 0 10px;font-size:17px}
label{display:block;font-weight:600;margin:0 0 8px}
input[type=text]{width:100%;padding:12px 14px;border-radius:9px;border:1px solid #30465f;
 background:#0a0e13;color:var(--ink);font:14px ui-monospace,Menlo,Consolas,monospace}
button{margin-top:12px;padding:11px 20px;border:0;border-radius:9px;background:var(--acc);color:#04121f;
 font-weight:700;cursor:pointer}
button:hover{filter:brightness(1.08)}
code,pre{font:13px ui-monospace,Menlo,Consolas,monospace}
pre{background:#0a0e13;border:1px solid var(--line);border-radius:9px;padding:14px;overflow:auto;
 white-space:pre-wrap;word-break:break-word}
.muted{color:var(--mut)}
.pill{display:inline-block;background:#0a0e13;border:1px solid #30465f;border-radius:999px;
 padding:3px 11px;font:12px ui-monospace,monospace;color:#9fb3c8}
.grid{display:grid;gap:10px;grid-template-columns:1fr}
.row{display:flex;flex-wrap:wrap;gap:8px}
a{color:var(--acc)}
.k{color:var(--gold)}
hr{border:0;border-top:1px solid var(--line);margin:20px 0}
"""

_INDEX = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Portcullis SSO</title><style>%(css)s</style></head>
<body><div class="wrap">
  <div class="brand"><div class="crest">&#9876;</div>
    <div><h1>Portcullis</h1>
    <p class="sub">Single Sign-On gatehouse &mdash; one token, every inner door.</p></div></div>
  <span class="pill">instance %(fp)s</span>
  <span class="pill">alg RS256</span>
  <span class="pill">iss %(iss)s</span>

  <div class="card">
    <h2>Sign in</h2>
    <label for="u">Username</label>
    <input id="u" type="text" value="guest" autocomplete="off">
    <div class="row"><button id="login">Issue session token</button>
      <button id="me" style="background:#223247;color:#cfe0f2">Who am I?</button>
      <button id="adm" style="background:#223247;color:#cfe0f2">Enter /admin</button></div>
    <p class="muted" style="margin-top:12px">Everyone who signs in is issued a
      <span class="k">role=user</span> token. The staff console at
      <code>/admin</code> requires <span class="k">role=admin</span>. Reaching it
      does not hand over the flag &mdash; it opens the <code>/admin/vault</code>,
      which releases the flag in ordered, capability-scoped fragments.</p>
    <pre id="out" class="muted">Responses appear here.</pre>
  </div>

  <div class="card">
    <h2>Token verification material</h2>
    <p class="muted">Portcullis signs with RS256. Downstream services verify with
      our published public key:</p>
    <ul class="muted">
      <li><a href="/pubkey.pem">/pubkey.pem</a> &mdash; PEM (SubjectPublicKeyInfo)</li>
      <li><a href="/.well-known/jwks.json">/.well-known/jwks.json</a> &mdash; JWK set</li>
      <li><a href="/info">/info</a> &mdash; non-secret instance metadata</li>
    </ul>
    <hr>
    <p class="muted"><b>White-box challenge.</b> The full server source is
      <code>challenge/app.py</code>. The weakness is in plain sight, in how the
      token verifier (<code>jwt_verify</code>) chooses which algorithm &mdash; and
      therefore which key &mdash; to trust.</p>
  </div>

<script>
const out=document.getElementById('out');
const show=(t)=>out.textContent=(typeof t==='string'?t:JSON.stringify(t,null,2));
async function j(url,opt){const r=await fetch(url,opt);const t=await r.text();
  try{return [r.status,JSON.parse(t)];}catch(e){return [r.status,t];}}
document.getElementById('login').onclick=async()=>{
  const [s,b]=await j('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username:document.getElementById('u').value||'guest'})});
  show({status:s,...(typeof b==='object'?b:{body:b})});};
document.getElementById('me').onclick=async()=>{const [s,b]=await j('/api/me');show({status:s,result:b});};
document.getElementById('adm').onclick=async()=>{const [s,b]=await j('/admin');show({status:s,result:b});};
</script>
</div></body></html>
"""


def _json(obj, status=200, extra=None):
    return status, "application/json; charset=utf-8", json.dumps(obj).encode(), (extra or [])


def _html(body, status=200):
    return status, "text/html; charset=utf-8", body.encode(), []


def _text(body, status=200, ctype="text/plain; charset=utf-8"):
    return status, ctype, body.encode(), []


# ===========================================================================
# Backend-agnostic router -> (status, content_type, body_bytes, extra_headers)
# ===========================================================================
def route(method, path, query, headers, body):
    if method not in ("GET", "HEAD", "POST"):
        return _text("405 method not allowed\n", 405)

    cookies = parse_cookies(headers.get("Cookie", ""))
    cookie_jwt = cookies.get("session", "")

    if path in ("/", ""):
        return _html(_INDEX % {"css": _CSS, "fp": FINGERPRINT, "iss": ISSUER})

    if path == "/info":
        return _json({
            "service": "portcullis-sso",
            "fingerprint": FINGERPRINT,
            "issuer": ISSUER,
            "sign_alg": "RS256",
            "kid": KID,
            "jwks": "/.well-known/jwks.json",
            "pubkey_pem": "/pubkey.pem",
            "admin_requires": {"claim": "role", "value": "admin"},
            "flag_delivery": {
                "endpoint": "/admin/vault",
                "scopes": NUM_SCOPES,
                "format": FLAG_FORMAT,
                "note": ("the flag is delivered in ordered, capability-scoped fragments; "
                         "/admin issues the entry grant once you reach it"),
            },
        })

    if path == "/pubkey.pem":
        # Served verbatim; these exact bytes are the RS256 verification key.
        return _text(PUBKEY_PEM, 200, ctype="application/x-pem-file; charset=ascii")

    if path == "/.well-known/jwks.json":
        jwk = {
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID,
            "n": b64url_encode(RSA_N.to_bytes(RSA_K, "big")),
            "e": b64url_encode(RSA_E.to_bytes((RSA_E.bit_length() + 7) // 8, "big")),
        }
        return _json({"keys": [jwk]})

    if path == "/api/login":
        if method != "POST":
            return _json({"ok": False, "error": "POST a JSON body {\"username\": ...}"}, 405)
        username = "guest"
        try:
            if body:
                data = json.loads(body.decode("utf-8", "replace"))
                if isinstance(data, dict) and isinstance(data.get("username"), str):
                    username = data["username"][:64] or "guest"
        except Exception:
            # also accept form-encoded ?username=...
            q = parse_qs(body.decode("utf-8", "replace"))
            if q.get("username"):
                username = q["username"][0][:64] or "guest"
        now = int(time.time())
        # SSO NEVER issues an admin token: every sign-in is role=user.
        payload = {"iss": ISSUER, "sub": username, "role": "user",
                   "iat": now, "exp": now + TOKEN_TTL}
        token = jwt_issue(payload)
        cookie = "session=%s; Path=/; HttpOnly; SameSite=Strict" % token
        return _json({"ok": True, "token": token, "token_type": "Bearer",
                      "claims": payload,
                      "hint": "Admin needs role=admin. This token is role=user."},
                     extra=[("Set-Cookie", cookie)])

    if path == "/api/me":
        token = token_from_request(headers, cookie_jwt)
        if not token:
            return _json({"authenticated": False, "error": "no token (Bearer or session cookie)"}, 401)
        claims = jwt_verify(token)
        if claims is None:
            return _json({"authenticated": False, "error": "invalid or expired token"}, 401)
        return _json({"authenticated": True, "claims": claims})

    if path == "/admin":
        token = token_from_request(headers, cookie_jwt)
        if not token:
            return _json({"ok": False, "error": "authentication required"}, 401)
        claims = jwt_verify(token)
        if claims is None:
            return _json({"ok": False, "error": "invalid or expired token"}, 401)
        if claims.get("role") != "admin":
            return _json({"ok": False, "error": "forbidden: admin role required",
                          "your_role": claims.get("role")}, 403)
        # Reaching the keep NO LONGER hands over the flag -- only the MEANS to
        # begin collecting it, scope by scope, from the credential vault.
        return _json({
            "ok": True,
            "message": "Welcome to the staff console, %s." % claims.get("sub", "admin"),
            "flag_delivery": {
                "mechanism": "capability-scoped credential vault (ordered scope chain)",
                "endpoint": "/admin/vault",
                "scopes": NUM_SCOPES,
                "assembly": {
                    "prefix": FLAG_PREFIX,
                    "suffix": FLAG_SUFFIX,
                    "order": ("concatenate the authentic fragment of scope 0,1,...,%d, in that "
                              "order, then wrap it in prefix+...+suffix" % (NUM_SCOPES - 1)),
                    "format": FLAG_FORMAT,
                },
                "how": ("present an admin token that ALSO carries an integer claim `scope` "
                        "(0..%d) and a string claim `grant`. Scope 0's grant is `entry_grant` "
                        "below; each AUTHENTIC read discloses `next_grant` for the following "
                        "scope, so the scopes must be walked in order. A wrong or missing grant "
                        "returns a DECOY fragment (it carries a '-', which the flag format "
                        "forbids), and discloses no next_grant." % (NUM_SCOPES - 1)),
                "entry_scope": 0,
                "entry_grant": _scope_grant(0),
            },
        })

    if path == "/admin/vault":
        token = token_from_request(headers, cookie_jwt)
        if not token:
            return _json({"ok": False, "error": "authentication required"}, 401)
        claims = jwt_verify(token)
        if claims is None:
            return _json({"ok": False, "error": "invalid or expired token"}, 401)
        if claims.get("role") != "admin":
            return _json({"ok": False, "error": "forbidden: admin role required",
                          "your_role": claims.get("role")}, 403)
        scope = claims.get("scope")
        grant = claims.get("grant")
        # bool is a subclass of int -> reject it explicitly.
        if not isinstance(scope, int) or isinstance(scope, bool) or not (0 <= scope < NUM_SCOPES):
            return _json({"ok": False,
                          "error": "token must carry an integer `scope` claim in 0..%d"
                                   % (NUM_SCOPES - 1),
                          "scopes": NUM_SCOPES}, 400)
        authentic = isinstance(grant, str) and hmac.compare_digest(grant, _scope_grant(scope))
        fragment = _REAL_FRAGMENTS[scope] if authentic else _DECOY_FRAGMENTS[scope]
        resp = {"ok": True, "scope": scope, "scopes_total": NUM_SCOPES, "fragment": fragment}
        if authentic:
            if scope + 1 < NUM_SCOPES:
                resp["next_scope"] = scope + 1
                resp["next_grant"] = _scope_grant(scope + 1)
            else:
                resp["complete"] = True
                resp["note"] = ("final scope reached; concatenate the authentic fragments of "
                                "scopes 0..%d inside the frame to form the flag" % (NUM_SCOPES - 1))
        else:
            # A wrong/absent grant yields a decoy fragment and NO next_grant: the
            # chain cannot be continued authentically from here. That absence is
            # the per-step tell, and the decoy carries a '-' (invalid in the flag).
            resp["note"] = "fragment delivered for this scope"
        return _json(resp)

    return _text("404 not found\n", 404)


# ===========================================================================
# Standard-library HTTP server (zero dependencies)
# ===========================================================================
def run(host, port):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "Portcullis/1.0"

        def _dispatch(self):
            parsed = urlsplit(self.path)
            body = b""
            if self.command == "POST":
                length = int(self.headers.get("Content-Length", "0") or "0")
                if length > 0:
                    body = self.rfile.read(min(length, 1 << 20))
            status, ctype, out, extra = route(self.command, parsed.path,
                                               parsed.query, self.headers, body)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(out)))
            self.send_header("X-Content-Type-Options", "nosniff")
            for name, value in extra:
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(out)

        do_GET = _dispatch
        do_HEAD = _dispatch
        do_POST = _dispatch

        def log_message(self, *a):
            pass

    httpd = ThreadingHTTPServer((host, port), Handler)
    sys.stderr.write("portcullis listening on %s:%d (instance %s)\n" % (host, port, FINGERPRINT))
    sys.stderr.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


def main():
    global PORT
    host = os.environ.get("HOST", "0.0.0.0")
    port = PORT
    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a == "--port" and i + 1 < len(args):
            port = int(args[i + 1])
    PORT = port
    run(host, port)


if __name__ == "__main__":
    main()
