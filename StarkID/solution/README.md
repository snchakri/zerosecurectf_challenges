# StarkID — solution

Run commands from this challenge directory unless the retained author instructions specify another working directory.

1. Open the target service and log in to obtain an RS256 token.
2. Fetch `/api/.well-known/jwks` and rebuild the published JWK in the exact property order used by the flag endpoint.
3. Use that serialized public JWK as the HS256 HMAC secret. Sign a token with `sub=fury`, `clearance=director`, and the documented issuer and audience.
4. Send the token to `/api/flag` as a Bearer token. The complete original exploit sketch is in the PDF.

Author procedures and reference material:

- [challenge-1-stark_id.pdf](challenge-1-stark_id.pdf)
- [source/challenge-1-stark_id.pdf](source/challenge-1-stark_id.pdf)

**Verification:** archived reference; not rerun. Original event-only links may no longer respond.

## Missing runtime files

The archived API files import `lib/keys`, but the local copy has no key module, JWKS route, or referenced `scripts/generate-keys.js`. The original exploit is documented, but the application cannot currently start from the preserved source alone.
