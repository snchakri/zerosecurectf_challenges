# Portcullis — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

In one terminal, run the local challenge service:

```bash
python solution/runtime/app.py
```

In another terminal, run the solver:

```bash
python solution/solve.py --url http://127.0.0.1:8000
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Portcullis — official writeup

**Flag:** `zerosecurectf{alg_c0nfusion_turns_a_public_key_into_a_skeleton_key}`
(static demo seed; per-instance in production).


## The flaw

Portcullis is an SSO gatehouse. It signs session tokens (JWTs) with **RS256** —
an *asymmetric* signature: the gatehouse keeps a 2048-bit RSA **private** key and
publishes the matching **public** key so any downstream service can verify a
token. Publishing the verification key is correct and necessary for asymmetric
JWTs; ours is at `/pubkey.pem` and `/.well-known/jwks.json`.

The bug is in the verifier. A JWT names its own algorithm in a header field
(`alg`), and Portcullis's `jwt_verify` **trusts that field to choose the
algorithm**, then hands the *same key material* — the RSA public-key PEM bytes —
to whichever branch the header selects:

```python
VERIFY_KEY = PUBKEY_PEM_BYTES          # the one key the developer passes in

if alg == "RS256":
    ok = rsa_verify(signing_input, sig)                 # public key verifies an RSA signature  (correct)
elif alg == "HS256":
    ok = hmac.compare_digest(hs256_mac(signing_input, VERIFY_KEY), sig)  # BUG
else:
    return None                                          # alg:none etc. -> rejected
```

For RS256, the public key is the right verification key. For HS256 it is used as
an **HMAC secret** — and an HMAC secret must be secret, while this value is
*public*. The developer's mental model ("we sign with RS256, so we verify with
the RSA public key") quietly assumed the algorithm was fixed; letting the token
pick it turns the public key into a symmetric signing key that anyone can use.

This is the classic **JWT algorithm-confusion / key-confusion** vulnerability:

- Tim McLean, *"Critical vulnerabilities in JSON Web Token libraries,"* Auth0,
  March 2015 — the original disclosure of this exact RS256↔HS256 confusion.
  <https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/>
- **CVE-2016-5431** / **CVE-2016-10555** (algorithm confusion in JWT libraries).
- PortSwigger Web Security Academy, *"JWT authentication bypass via algorithm
  confusion."*
  <https://portswigger.net/web-security/jwt/algorithm-confusion>
- Primitive classes: **CWE-347** (Improper Verification of Cryptographic
  Signature), **CWE-345** (Insufficient Verification of Data Authenticity),
  **OWASP A01:2021** Broken Access Control. JWT/JWS/JWA grammar: RFC 7519 / 7515
  / 7518; RS256 padding: RFC 8017 §8.2 (RSASSA-PKCS1-v1_5).


## Exploitation

The attacker mints an **HS256** token whose HMAC key is the **public key bytes**
the service itself publishes:

1. **Fetch the verification key** — `GET /pubkey.pem`. Keep the *exact* bytes
   returned (the PEM text, newlines and all). These bytes are the HMAC secret the
   flawed branch will use.
2. **Build the token** —
   - header `{"alg":"HS256","typ":"JWT"}`
   - payload `{"iss":"portcullis-sso","sub":"portcullis-admin","role":"admin","exp":<future>}`
   - `signing_input = base64url(header) + "." + base64url(payload)`
   - `signature = HMAC-SHA256(key = pubkey.pem bytes, msg = signing_input)`
   - `token = signing_input + "." + base64url(signature)`
3. **Open the keep** — `GET /admin` with `Authorization: Bearer <token>`. The
   verifier HMACs with the public key, the MAC matches, `role == "admin"`, and the
   staff console returns the flag.

`solution/solve.py` does exactly this:

```bash
python solution/solve.py --url http://127.0.0.1:8000
# [+] fetched RS256 public key (451 bytes of PEM) -> using it as the HMAC secret
# [+] forged HS256 token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
# [+] GET /admin -> HTTP 200
# [+] FLAG = zerosecurectf{...}
```

The one subtlety that makes it *Hard* rather than trivial: the HMAC key must be
the **exact byte representation** the server uses. Portcullis serves the standard
`SubjectPublicKeyInfo` PEM (identical to `openssl rsa -pubout`) and uses those
same bytes verbatim, so "download the PEM, use it as the key" is unambiguous. With
real tooling (`jwt_tool -X k`, or deriving the PEM with `openssl`) you must land
on the same encoding; a JWK-only service would force you to reconstruct the PEM
yourself.


## Why the intended path is the only cheap one

- **No RS256 forgery.** Changing a real RS256 token's payload (e.g. flipping
  `role` to `admin`) breaks its signature; re-signing needs the 2048-bit RSA
  **private** key, which is never published and is infeasible to recover. (The
  test asserts a role-flipped RS256 token is rejected.)
- **`alg:none` is closed.** The verifier rejects `alg:none` and every algorithm
  other than RS256/HS256, so the single easiest JWT bug does not work. (Asserted.)
- **No weak secret to guess.** There is no symmetric secret anywhere — the only
  HS256 key that verifies is the public key. A wordlist/brute-force attack on the
  HMAC secret has nothing to find. (The test asserts HS256 with `secret`, empty,
  `changeme`, and a random key are all rejected.)
- **No direct admin login.** There is no admin password or role selector; sign-in
  always issues `role=user`. `role=admin` can only arrive inside a token the
  verifier accepts — i.e. through the confusion.
- **No guessing.** White-box source; the route is reached purely by reasoning
  about JWT algorithm/key handling. Guess-exposure ≈ 0.


## Design notes (for the ZSCTF team)

- **Lineage** (`corpus-genome.yaml`, reconstruction per system.html §17):
  - `zsctf-web-003 Security Driven` — **GROUND**: chain a forged credential into
    disclosure of an admin-only secret (the staff console + flag).
  - `zsctf-web-009 Sharer's World` — **GUARD-SWAP**: recover admin-only data past
    a *deployed* defence; here the defence is **JWT signature verification** in
    place of a CSP, and the swap is what introduces the confusion.
  - `zsctf-web-013 wp-admin` — **CONSTRAIN**: a hardened, constrained admin
    topology (non-root, read-only FS, blocked egress) the player reasons about.
  - `zsctf-web-014 NoteNinja` — **GUARD-SWAP**: force the intended path by
    *closing the known unintended routes* (`alg:none`, RS256 tamper) before reuse.
  - **Crux-class donor (cross-category):** `zsctf-crypto-014 Diffecient`
    ("a key store built on a non-cryptographic primitive is forgeable → GROUND
    into a real auth service that misuses a primitive"). Portcullis is the web
    realisation of that insight class: an auth service misuses a verification
    primitive so credentials become forgeable.
- **Crux (insight class):** verification keyed on an attacker-controlled `alg`,
  with a *public* value reused as a *symmetric secret*.
- **Per-instance:** `ZSCTF_SEED` deterministically derives the RSA keypair (hence
  the published public key, the `kid`, and the fingerprint); `ZSCTF_FLAG` the
  flag. Same seed → same instance (the test checks fingerprint **and** modulus
  reproducibility, and that different seeds differ).
- **Self-contained crypto:** RSA keygen, RSASSA-PKCS1-v1_5 (RFC 8017), HMAC-SHA256
  JWS, and SPKI DER/PEM are all implemented on the Python standard library — no
  third-party packages — so there is nothing to trust but the code in front of
  you. The RS256 verifier uses strict **encode-and-compare** padding, which
  rejects Bleichenbacher-style signature forgery (closing that alternate route).
- **Harder variants (extrapolation):**
  (a) **PARAMETERISE** the exposure: serve the key only as a **JWK** (no PEM), so
  the solver must reconstruct the DER/PEM encoding itself before the HMAC lands —
  raising the tooling axis. (b) **GUARD-SWAP** to a *kid-driven* key lookup and
  make the confusion a path/SSRF to fetch an attacker-chosen key (classic
  `jku`/`x5u`/`kid` injection) — a `CHAIN(X)` toward SSRF. (c) **CONSTRAIN** with
  an admin bot + short token TTL to add a timing dimension.

---

