#!/usr/bin/env python3
"""
ZSCTF :: Ravelin  (web, Extreme)

A ravelin is a detached, triangular outwork set in front of a fortress's main
wall: an attacker who takes it is still outside the keep. This challenge is a
small internal incident-report portal built the way real ones are -- a thin
Flask app with three layers of trust, each guarding the next. No single defect
lets you in; you must chain three independent, standard web bugs in order.

WHITE-BOX: you are given this exact source file. The three layers are:

  1. Report snapshots (`/api/snapshot/<id>`) are read without an ownership
     check -- an IDOR (CWE-639). Among the snapshots is an operations record
     that discloses the server's session-signing key.

  2. The `rav_session` cookie is a JSON payload with an appended HMAC-SHA256
     signature. With the leaked key you can forge a cookie that claims
     `role=auditor` -- the server trusts a valid signature as proof of role
     (improper verification -> privilege escalation, CWE-347 / CWE-285). The
     auditor area then legitimately hands auditors the vault query-signing key.

  3. Auditors save "queries" as signed, serialised SavedQuery objects. The
     render endpoint rebuilds the object by blindly copying every field of the
     payload into the instance (`__dict__.update`) -- a mass-assignment /
     unsafe-deserialisation bug (CWE-915 / CWE-502). The UI never sets a
     `target` field, but a forged blob can, and a SavedQuery with `target` set
     reaches the internal vault.

FLAG-EXTRACTION LAYER (S2/S2a -- commitment/opening in a derived order):
reaching the vault does NOT hand over the flag. The `flag` handle is SEALED into
N salted-hash COMMITMENTS, each committing to one contiguous flag fragment. A
manifest returns only those commitments (hashes -- never the fragments). To read
a fragment you OPEN a cell at a step (by injecting integer `cell`/`step` fields
into the same SavedQuery mass-assignment). A cell yields its REAL fragment only
when opened at the step the derived opening-order assigns it; the order is a
derangement derived from the vault query-signing key earned in stage 2. Opening
at the wrong step -- or the naive "cell i at step i" index order -- returns a
per-step DECOY fragment, and those concatenate to a flag-SHAPED near-miss that
fails the strict validator. Only the correctly-ordered openings concatenate to
the real flag, which is therefore never present whole in any single response.

Per-instance: ZSCTF_SEED derives the public fingerprint, both signing keys, the
sealed-cell opening order, and every decoy; ZSCTF_FLAG sets the real flag. Same
seed -> identical secrets and identical opening order.

Dependencies: Flask (pinned in deploy/). `python app.py` serves on $PORT
(default 8000).
"""
import os
import sys
import json
import base64
import hmac
import hashlib

from flask import Flask, request, jsonify, Response, make_response

# ---------------------------------------------------------------------------
# Per-instance configuration -- everything secret is a deterministic function
# of the team seed, injected at run time. Nothing secret is written to disk or
# baked into an image layer.
# ---------------------------------------------------------------------------
SEED = os.environ.get("ZSCTF_SEED", "static-demo-seed").encode()

FLAG = os.environ.get("ZSCTF_FLAG")
if not FLAG:
    FLAG = "zerosecurectf{local_review_flag}"
    sys.stderr.write("WARNING: ZSCTF_FLAG is unset; using the placeholder flag. "
                     "Set ZSCTF_FLAG at deploy time.\n")
    sys.stderr.flush()


def _derive_hex(label: bytes, nhex: int) -> str:
    return hashlib.sha256(SEED + b"|" + label).hexdigest()[:nhex]


# Public, non-secret instance fingerprint.
FINGERPRINT = _derive_hex(b"instance-fingerprint", 12)

# Stage-1 secret: the session-signing key, disclosed only via the IDOR snapshot.
SESSION_KEY = _derive_hex(b"session-signing-key", 64)
SESSION_KID = "sess-" + _derive_hex(b"session-kid", 8)

# Stage-2 -> stage-3 secret: the vault query-signing key, disclosed only to a
# valid auditor at /auditor/config. Distinct from the session key.
VAULT_SIGN_KEY = _derive_hex(b"vault-query-signing-key", 64)

# Rabbit-hole material (all per-instance; see writeup.md "Rabbit-holes").
# R1 decoy flag: flag-SHAPED but violates the published strict validator
#     ^zerosecurectf\{[a-z0-9_]{8,48}\}$  (the 'zer0' prefix + UPPERCASE body).
DECOY_FLAG_BAD = "zer0securectf{ARCHIVED_%s}" % _derive_hex(b"decoy-archived", 10).upper()
# R2/R3 near-miss key: a hex string that LOOKS like the session key but is not;
#     forging with it produces a signature that fails the server's HMAC gate.
FAKE_SESSION_KEY = _derive_hex(b"decoy-session-key-trap", 64)
# R4b vault fixture: a QA sample that is watermarked 'sample' and tagged as a
#     fixture source, never the live secret.
DECOY_FIXTURE = "zerosecurectf{sample_vault_fixture_%s}" % _derive_hex(b"vault-fixture", 8)

PORT = int(os.environ.get("PORT", "8000"))
HOST = os.environ.get("HOST", "0.0.0.0")


# ---------------------------------------------------------------------------
# Signing primitives: a payload is JSON, canonicalised (sorted keys), base64url
# encoded, and an appended HMAC-SHA256 over that encoding. The same scheme signs
# both the session cookie (SESSION_KEY) and SavedQuery blobs (VAULT_SIGN_KEY).
# ---------------------------------------------------------------------------
def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def sign_token(key_hex: str, payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    p = _b64u(raw)
    sig = _b64u(hmac.new(bytes.fromhex(key_hex), p.encode(), hashlib.sha256).digest())
    return p + "." + sig


def verify_token(key_hex: str, token: str):
    """Return the payload dict if the signature verifies, else None."""
    try:
        p, dot, sig = token.partition(".")
        if not dot:
            return None
        expected = _b64u(hmac.new(bytes.fromhex(key_hex), p.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(expected, sig):
            return None
        return json.loads(_b64u_dec(p))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# S2/S2a flag-extraction layer: sealed commitment cells opened in a derived
# order. Everything here is a deterministic function of VAULT_SIGN_KEY (hence of
# ZSCTF_SEED), so an auditor who legitimately earns that key can reproduce the
# order and verify every opening; nothing below depends on wall-clock or
# randomness. See the module docstring and writeup.md "Flag extraction".
# ---------------------------------------------------------------------------
SEAL_N = 8                      # number of commitment cells / flag fragments
SEAL_V = b"sealed-cells/v1"     # scheme / domain-separation tag


def _seal_chunks(text: str, n: int):
    """Split `text` into n contiguous chunks (front chunks absorb the remainder).
    Concatenating the chunks in index order reproduces `text` exactly."""
    base, rem = divmod(len(text), n)
    out, i = [], 0
    for k in range(n):
        size = base + (1 if k < rem else 0)
        out.append(text[i:i + size])
        i += size
    return out


def _seal_order():
    """A DERANGEMENT of range(SEAL_N) derived from the vault query-signing key.
    `order[step]` is the cell id that must be opened at that step. We reject any
    permutation with a fixed point, so the naive "cell i at step i" index order
    is ALWAYS wrong (every position yields a decoy)."""
    key = bytes.fromhex(VAULT_SIGN_KEY)
    ctr = 0
    while True:
        stream, j = b"", 0
        while len(stream) < SEAL_N * 4:
            stream += hashlib.sha256(key + b"|" + SEAL_V + b"/order|"
                                     + str(ctr).encode() + b"|"
                                     + str(j).encode()).digest()
            j += 1
        perm = list(range(SEAL_N))
        for i in range(SEAL_N - 1, 0, -1):          # Fisher-Yates, 4 bytes/pos
            r = int.from_bytes(stream[i * 4:i * 4 + 4], "big") % (i + 1)
            perm[i], perm[r] = perm[r], perm[i]
        if all(perm[p] != p for p in range(SEAL_N)):
            return perm
        ctr += 1


def _seal_nonce(cell: int) -> bytes:
    """Per-cell opening randomness, bound to the vault key so a legitimate
    auditor can VERIFY a revealed fragment against its published commitment."""
    return hashlib.sha256(bytes.fromhex(VAULT_SIGN_KEY) + b"|" + SEAL_V
                          + b"/nonce|" + str(cell).encode()).digest()


# Real flag fragments (contiguous), and a flag-SHAPED decoy assembly whose body
# is UPPERCASE so it fails ^zerosecurectf\{[a-z0-9_]{8,48}\}$ on sight.
FLAG_CHUNKS = _seal_chunks(FLAG, SEAL_N)
DECOY_ASSEMBLY = "zerosecurectf{WRONG_ORDER_%s}" % _derive_hex(b"sealed-decoy-asm", 12)
DECOY_CHUNKS = _seal_chunks(DECOY_ASSEMBLY, SEAL_N)

SEAL_ORDER = _seal_order()              # order[step] -> cell id (derangement)
SEAL_INV = [0] * SEAL_N                 # inv[cell]   -> step
for _p, _c in enumerate(SEAL_ORDER):
    SEAL_INV[_c] = _p
# Cell c, opened at its correct step SEAL_INV[c], reveals FLAG_CHUNKS[SEAL_INV[c]];
# its commitment seals exactly that fragment.
SEAL_COMMIT = [
    _b64u(hashlib.sha256(_seal_nonce(c) + b"|"
                         + FLAG_CHUNKS[SEAL_INV[c]].encode()).digest())
    for c in range(SEAL_N)
]


# ---------------------------------------------------------------------------
# Data: report snapshots. Ownership is recorded but NOT enforced on read -- the
# IDOR. Snapshot 4108 (owned by 'ops') discloses the live session-signing key.
# ---------------------------------------------------------------------------
SNAPSHOTS = {
    4101: {"owner": "guest", "title": "Welcome to Ravelin",
           "kind": "note",
           "body": "Your workspace. You may read your own snapshots here. "
                   "Analysts see incident reports; auditors (role=auditor) reach "
                   "the vault console. Public fingerprint: " + FINGERPRINT},
    4102: {"owner": "intake", "title": "Archived finding (quarantined)",
           "kind": "note",
           # R1: the first flag-shaped string a careless enumerator meets.
           "body": "Legacy import. Quarantined token retained for audit only: "
                   + DECOY_FLAG_BAD + " (do not submit; failed format validation)."},
    4103: {"owner": "analyst", "title": "Incident 2024-114: latency spike",
           "kind": "incident",
           "body": "p99 latency regression traced to a cache stampede; resolved."},
    4104: {"owner": "analyst", "title": "Incident 2024-131: disk pressure",
           "kind": "incident",
           "body": "Log rotation misconfig filled /var; rotation policy fixed."},
    4105: {"owner": "ops", "title": "Key material (ROTATED OUT - do not use)",
           "kind": "secret-material",
           # R2/R3: decoy key, looks like the real thing, fails the HMAC gate.
           "key_id": "sess-retired-0000",
           "status": "retired",
           "hmac_key_hex": FAKE_SESSION_KEY,
           "body": "Superseded signing key, kept for forensic comparison only."},
    4106: {"owner": "ops", "title": "Runbook: session cookies",
           "kind": "note",
           "body": "rav_session = base64url(json) + '.' + base64url(HMAC-SHA256). "
                   "The active signing key is tracked in the current key-material "
                   "snapshot (status=active)."},
    4107: {"owner": "analyst", "title": "Incident 2024-140: 5xx burst",
           "kind": "incident",
           "body": "Upstream timeout storm; circuit-breaker thresholds retuned."},
    4108: {"owner": "ops", "title": "Key material (ACTIVE)",
           "kind": "secret-material",
           # Stage-1 payload: the LIVE session key.
           "key_id": SESSION_KID,
           "status": "active",
           "hmac_key_hex": SESSION_KEY,
           "body": "Active session signing key. Auditor tooling re-derives the "
                   "vault key from the auditor console, not from here."},
    4109: {"owner": "analyst", "title": "Incident 2024-151: noisy neighbour",
           "kind": "incident",
           "body": "CPU throttling from a co-tenant batch job; quotas applied."},
    4110: {"owner": "intake", "title": "Triage backlog",
           "kind": "note",
           "body": "12 open items; see the incident snapshots above."},
    4111: {"owner": "ops", "title": "Diagnostics",
           "kind": "note",
           "body": "Health probe is at /api/healthcheck (diagnostic only)."},
    4112: {"owner": "analyst", "title": "Incident 2024-160: clock skew",
           "kind": "incident",
           "body": "NTP drift caused token-expiry flapping; NTP peers fixed."},
}

# The internal vault. Reachable ONLY through a SavedQuery whose `target` names a
# handle -- a field the UI never sets.
#   * PLAIN handles return their value directly (an ops note and the R4b QA
#     fixture -- a rejectable decoy, never the live secret).
#   * The SEALED `flag` handle NEVER returns the flag whole: target='flag'
#     returns a manifest of commitments, and target='flag'+cell+step opens one
#     fragment at a time (see SavedQuery._render_sealed). The live flag lives
#     here (process memory) and nowhere else.
VAULT_PLAIN = {
    "rotation_note": "Rotate the session key each quarter; retire old keys to a snapshot.",
    "flag_sample": DECOY_FIXTURE,     # R4b: QA fixture, never the live secret
}
VAULT_SEALED = {
    "flag": FLAG,                      # the real thing -- sealed, never whole
}
VAULT_HANDLES = ["rotation_note", "flag_sample", "flag"]   # advertised order
VAULT_META = {
    "rotation_note": {"source": "ops-note"},
    "flag_sample": {"source": "qa-fixture",
                    "note": "watermarked 'sample'; never a valid submission"},
    "flag": {"source": "live-vault", "sealed": True,
             "note": "sealed into %d commitment cells; open them in the "
                     "key-derived order (target='flag' for the manifest)" % SEAL_N},
}


# ---------------------------------------------------------------------------
# SavedQuery: a tiny serialisable object. render() returns benign rows UNLESS a
# `target` attribute is present, in which case it reads the vault. The legit
# builder never sets `target`; only a forged/injected blob can.
# ---------------------------------------------------------------------------
INCIDENT_ROWS = [
    {"id": sid, "title": s["title"]}
    for sid, s in sorted(SNAPSHOTS.items()) if s["kind"] == "incident"
]


class SavedQuery:
    def __init__(self):
        self.name = "untitled"
        self.filter = ""
        # NOTE: no `target` here; it is intentionally not part of a legit query.

    def render(self):
        target = getattr(self, "target", None)
        if target is not None:
            # Privileged path: only ever reached when `target` was injected.
            if target in VAULT_SEALED:
                return self._render_sealed(target)
            if target in VAULT_PLAIN:
                return {"kind": "vault", "handle": target,
                        "source": VAULT_META[target]["source"],
                        "value": VAULT_PLAIN[target]}
            return {"kind": "vault", "handle": target, "source": "none",
                    "value": None, "note": "no such vault entry"}
        rows = [r for r in INCIDENT_ROWS
                if self.filter.lower() in r["title"].lower()]
        return {"kind": "rows", "name": self.name, "filter": self.filter,
                "rows": rows}

    def _render_sealed(self, target):
        """Commitment/opening extraction. `target` alone -> the manifest (only
        hashes). `target` + injected integer `cell`/`step` -> one opened
        fragment. The flag is never returned whole from either branch."""
        cell = getattr(self, "cell", None)
        step = getattr(self, "step", None)
        if cell is None or step is None:
            # MANIFEST: N commitments, never the sealed fragments themselves.
            return {
                "kind": "vault-sealed", "handle": target, "source": "live-vault",
                "scheme": SEAL_V.decode(), "cells": SEAL_N,
                "commitments": [{"cell": c, "commit": SEAL_COMMIT[c]}
                                for c in range(SEAL_N)],
                "open_order_derivation":
                    ("order = derangement of range(%d) from a Fisher-Yates "
                     "shuffle whose byte stream is "
                     "SHA256(vault_sign_key|'sealed-cells/v1/order|<ctr>|<j>'); "
                     "reject fixed points. Open cell order[step] at each step "
                     "0..%d and concatenate the revealed fragments in step order."
                     % (SEAL_N, SEAL_N - 1)),
                "open_via": ("inject target='%s' plus integer 'cell' and 'step' "
                             "fields into a SavedQuery blob and render it" % target),
                "verify":
                    ("a fragment f opened from cell c is genuine iff "
                     "b64url(SHA256( SHA256(vault_sign_key|'sealed-cells/v1/nonce|'|c)"
                     " | '|' | f )) == commitments[c].commit"),
            }
        # OPENING: reveal exactly one fragment (never the whole flag).
        try:
            c, p = int(cell), int(step)
        except (TypeError, ValueError):
            return {"kind": "vault-open", "handle": target, "cell": cell,
                    "step": step, "fragment": None,
                    "note": "cell and step must be integers"}
        if not (0 <= c < SEAL_N and 0 <= p < SEAL_N):
            return {"kind": "vault-open", "handle": target, "cell": c, "step": p,
                    "fragment": None,
                    "note": "cell/step out of range 0..%d" % (SEAL_N - 1)}
        if SEAL_ORDER[p] == c:
            frag = FLAG_CHUNKS[p]          # correct cell at this step -> real
        else:
            frag = DECOY_CHUNKS[p]         # wrong cell/order -> per-step decoy
        return {"kind": "vault-open", "handle": target, "cell": c, "step": p,
                "fragment": frag}


def deserialize_saved_query(payload: dict) -> SavedQuery:
    """Rebuild a SavedQuery from a verified payload. The bug (CWE-915/CWE-502):
    every field is copied onto the instance, including fields the application
    layer never intended to be client-controlled (e.g. `target`)."""
    q = SavedQuery()
    fields = payload.get("fields", {})
    if not isinstance(fields, dict):
        fields = {}
    q.__dict__.update(fields)          # <-- mass assignment / object injection
    return q


# ---------------------------------------------------------------------------
# Session handling: role is whatever a validly-signed cookie claims.
# ---------------------------------------------------------------------------
def current_session():
    cookie = request.cookies.get("rav_session", "")
    if not cookie:
        return {"user": "guest", "role": "guest"}
    payload = verify_token(SESSION_KEY, cookie)
    if not payload or "role" not in payload:
        return {"user": "guest", "role": "guest"}
    return {"user": payload.get("user", "guest"), "role": payload.get("role", "guest")}


# ---------------------------------------------------------------------------
app = Flask(__name__)


LANDING = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ravelin - Incident Portal</title>
<style>
:root{color-scheme:light dark}
body{margin:0;font:16px/1.55 system-ui,Segoe UI,Roboto,sans-serif;background:#0f1216;color:#e7edf3}
.wrap{max-width:860px;margin:0 auto;padding:40px 20px}
h1{font-size:28px;margin:0 0 4px}.sub{color:#8aa0b4;margin:0 0 24px}
.card{background:#161b22;border:1px solid #273142;border-radius:12px;padding:18px;margin:16px 0}
code,pre{font:13px ui-monospace,Menlo,Consolas,monospace}
pre{background:#0b0f14;border:1px solid #273142;border-radius:8px;padding:12px;overflow:auto;white-space:pre-wrap}
.muted{color:#8aa0b4;font-size:14px}
.pill{display:inline-block;background:#0b0f14;border:1px solid #30465f;border-radius:999px;padding:3px 10px;font:12px ui-monospace,monospace;color:#9fb3c8}
a{color:#58a6ff}
</style></head>
<body><div class="wrap">
  <h1>Ravelin</h1>
  <p class="sub">Internal incident-report portal.</p>
  <span class="pill">instance %(fp)s</span>
  <div class="card">
    <p>API surface:</p>
    <pre>GET  /api/whoami                 your session (guest unless a valid cookie)
GET  /api/snapshot/&lt;id&gt;          read a report snapshot (ids near 41xx)
GET  /api/healthcheck?probe=...  diagnostic echo (no outbound request)
--- auditor only (role=auditor), 403 otherwise ---
GET  /auditor/config             auditor tooling config (vault query key)
POST /auditor/query/new          build a signed SavedQuery {name,filter}
POST /auditor/query/render       render a signed SavedQuery blob</pre>
    <p class="muted">White-box: the full server source is
      <code>challenge/app.py</code>. A valid flag matches
      <code>^zerosecurectf{[a-z0-9_]{8,48}}$</code>; anything else (legacy
      quarantined tokens, QA fixtures watermarked <code>sample</code>) is never
      a valid submission.</p>
  </div>
</div></body></html>
"""


@app.get("/")
def index():
    return Response(LANDING % {"fp": FINGERPRINT}, mimetype="text/html")


@app.get("/api/whoami")
def whoami():
    sess = current_session()
    return jsonify({"service": "ravelin", "fingerprint": FINGERPRINT,
                    "user": sess["user"], "role": sess["role"]})


@app.get("/api/snapshot/<int:sid>")
def snapshot(sid):
    # IDOR (CWE-639): the snapshot is returned with no check that the caller
    # owns it. A `?include=` parameter is accepted but ignored (inert).
    snap = SNAPSHOTS.get(sid)
    if not snap:
        return jsonify({"error": "no such snapshot", "id": sid}), 404
    out = {"id": sid}
    out.update(snap)
    return jsonify(out)


@app.get("/api/healthcheck")
def healthcheck():
    # R4a: looks like an SSRF probe (`probe`/`url` params) but performs NO
    # outbound request whatsoever; it only echoes a digest of its input.
    probe = request.args.get("probe", request.args.get("url", ""))
    echo = hashlib.sha256((probe + "|" + FINGERPRINT).encode()).hexdigest()[:16]
    return jsonify({"status": "ok", "probe_echo": echo,
                    "note": "diagnostic only; no outbound request is performed"})


def _require_auditor():
    sess = current_session()
    if sess["role"] != "auditor":
        return None, (jsonify({"error": "forbidden", "need_role": "auditor",
                               "your_role": sess["role"]}), 403)
    return sess, None


@app.get("/auditor/config")
def auditor_config():
    sess, err = _require_auditor()
    if err:
        return err
    # Auditors are legitimately handed the vault query-signing key; saving
    # queries is a normal auditor feature. Vault handles are listed WITH their
    # source so a careful auditor can tell the live entry from the QA fixture.
    return jsonify({
        "role": sess["role"],
        "vault_sign_key": VAULT_SIGN_KEY,
        "query": {
            "new_endpoint": "/auditor/query/new",
            "render_endpoint": "/auditor/query/render",
            "accepted_fields": ["name", "filter"],
        },
        "vault_index": [{"handle": h, **VAULT_META[h]} for h in VAULT_HANDLES],
    })


@app.post("/auditor/query/new")
def auditor_query_new():
    sess, err = _require_auditor()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    # The legit builder copies ONLY name and filter -- never `target`.
    fields = {"name": str(data.get("name", "untitled")),
              "filter": str(data.get("filter", ""))}
    blob = sign_token(VAULT_SIGN_KEY, {"__type__": "SavedQuery", "fields": fields})
    return jsonify({"saved_query": blob})


@app.post("/auditor/query/render")
def auditor_query_render():
    sess, err = _require_auditor()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    blob = data.get("saved_query", "")
    payload = verify_token(VAULT_SIGN_KEY, blob)
    if not payload or payload.get("__type__") != "SavedQuery":
        return jsonify({"error": "invalid or unsigned saved_query"}), 400
    q = deserialize_saved_query(payload)      # CWE-915/CWE-502 happens here
    return jsonify({"result": q.render()})


# A convenience to mint a baseline (non-privileged) cookie, so the normal app is
# demonstrably usable. Analysts are NOT auditors.
@app.post("/api/login")
def login():
    resp = make_response(jsonify({"ok": True, "role": "analyst"}))
    cookie = sign_token(SESSION_KEY, {"user": "analyst", "role": "analyst"})
    resp.set_cookie("rav_session", cookie, httponly=True, samesite="Lax")
    return resp


def main():
    port = PORT
    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a == "--port" and i + 1 < len(args):
            port = int(args[i + 1])
    sys.stderr.write("ravelin listening on %s:%d (fingerprint %s)\n"
                     % (HOST, port, FINGERPRINT))
    sys.stderr.flush()
    app.run(host=HOST, port=port, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
