#!/usr/bin/env python3
"""
ZSCTF :: Noisefloor  (crypto, Extreme)

A post-quantum "lockbox" KEM. The vendor seals a secret under an LWE keypair:

    private key   s  in  {-1,0,1}^n        (short, ternary)
    public key   (A, b)   with   b = A.s + e   (mod q),   e in {-1,0,1}^m

The AES-256-GCM sealing key is HKDF(s): to open the lockbox you must recover the
*exact* private key s from the public key (A, b). That is the Learning-With-Errors
(LWE) search problem -- believed hard, and the whole point of post-quantum crypto.

The catch (this is the vulnerability, in plain sight): the vendor chose a huge
modulus q ~ 2^20 with a tiny +-1 noise term, to make decryption-failure
"impossibly" rare. That pushes the error *below the noise floor* that LWE security
needs. With q so large relative to |e|, the Bounded-Distance-Decoding gap is
enormous and the keypair falls to ordinary lattice reduction (LLL on the primal /
Kannan embedding) -- no BKZ, no quantum computer required.

Players are handed the full generator source AND the public artifact
(`public/params.json`). Nothing is hidden by obscurity: the weakness is the
parameter choice itself. The private key and the flag live only in the process
environment (ZSCTF_SEED / ZSCTF_FLAG), never in the artifact.

Self-contained. Deps: pycryptodome (AES-GCM + HKDF) + stdlib only.

Usage:
    python lockbox.py --emit public            # write public/params.json
    python lockbox.py --stdout                  # print the public artifact as JSON
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

# ---------------------------------------------------------------------------
# Public, frozen parameter contract.
#
# q is deliberately ~2^20 while the secret and error are ternary ({-1,0,1}).
# That modulus/noise ratio is the planted weakness: it is far above any sane
# post-quantum choice (Kyber uses q = 3329 with centred-binomial noise), so the
# lattice gap is huge and LLL alone recovers the key. See writeup.md.
# ---------------------------------------------------------------------------
N = 40            # secret dimension   (3^40 ~= 2^63.4 keys: brute force / naive MITM infeasible)
M = 52            # number of LWE samples (rows of A)
Q = 1048583       # modulus, a prime just above 2^20  ("noise too cheap")
SECRET_BOUND = 1  # ternary secret s_i in {-1,0,1}
ERROR_BOUND = 1   # ternary error  e_i in {-1,0,1}

# --- Second, INDEPENDENT short-vector channel (SPLIT-KDF, S2/S2a) -----------
# The sealing key is NOT derived from the primary secret s alone. It is split:
#   key = HKDF( canon(s) || canon(s2) )
# where s2 is the private key of a SECOND, independent LWE lockbox (A2, b2) with
# its own public data. Recovering s from (A, b) -- the primary lattice crux,
# UNCHANGED -- is necessary but NOT sufficient: a clean primary solve still
# cannot open the box (GCM auth fails) until s2 is also recovered from (A2, b2)
# by a second lattice reduction. A smaller instance (dim m2+n2+1 = 55), so the
# second LLL is fast, but it is a genuine second short-vector recovery, not a
# freebie. See writeup.md "Flag extraction (organizer-only)".
N2 = 24           # second-channel secret dimension
M2 = 30           # second-channel samples
Q2 = 1048583      # same "noise too cheap" prime (independent instance)

KDF_LABEL = b"NOISEFLOOR-KEM-v1"              # legacy s-only label (one-shot path, now DEAD)
SPLIT_LABEL = b"NOISEFLOOR-SPLITKDF-v2"       # split-KDF domain separator
SPLIT_SEP = b"|s2|"                           # field separator inside the KDF material
KDF_INFO = b"noisefloor/aes256gcm"
AAD = b"zsctf:noisefloor:lockbox:v1"


# ---------------------------------------------------------------------------
# Deterministic, portable DRBG: a SHA-256 counter stream keyed by (seed,label).
# Version-independent (unlike random.Random), so an instance is reproducible on
# any platform -- required for determinism and per-instance generation.
# ---------------------------------------------------------------------------
class DRBG:
    def __init__(self, seed_bytes: bytes, label: bytes):
        self._key = hashlib.sha256(label + b"|" + seed_bytes).digest()
        self._ctr = 0
        self._buf = b""

    def _refill(self) -> None:
        self._buf += hashlib.sha256(self._key + self._ctr.to_bytes(8, "big")).digest()
        self._ctr += 1

    def take(self, k: int) -> bytes:
        while len(self._buf) < k:
            self._refill()
        out, self._buf = self._buf[:k], self._buf[k:]
        return out

    def randrange(self, bound: int) -> int:
        # rejection sampling over whole bytes -> unbiased in [0, bound)
        nbytes = (bound.bit_length() + 7) // 8 + 1
        limit = (256 ** nbytes) - ((256 ** nbytes) % bound)
        while True:
            v = int.from_bytes(self.take(nbytes), "big")
            if v < limit:
                return v % bound

    def ternary(self) -> int:
        # unbiased map onto {-1,0,1}: reject byte 255 (255 values -> 85 each)
        while True:
            byte = self.take(1)[0]
            if byte != 255:
                return (byte % 3) - 1


# ---------------------------------------------------------------------------
# Secret encoding + key derivation (shared contract with the solver).
# ---------------------------------------------------------------------------
def canon_ternary(vec) -> bytes:
    """Canonical, injective byte encoding of an arbitrary ternary vector."""
    out = bytearray()
    for x in vec:
        if x not in (-1, 0, 1):
            raise ValueError("vector is not ternary")
        out.append(x % 3)  # -1,0,1 -> 2,0,1  (bijective)
    return bytes(out)


def canonical_secret_bytes(s) -> bytes:
    """Canonical byte encoding of the primary ternary secret (length-checked)."""
    if len(s) != N:
        raise ValueError("secret vector has wrong dimension")
    return canon_ternary(s)


def derive_key(s, salt: bytes) -> bytes:
    """LEGACY s-only derivation. Retained only to document the now-DEAD one-shot
    path: the flag is no longer sealed under this key, so a clean primary solve
    that stops here cannot open the lockbox (see derive_split_key)."""
    material = hashlib.sha256(KDF_LABEL + b"|" + canonical_secret_bytes(s)).digest()
    return HKDF(material, 32, salt, SHA256, context=KDF_INFO)


def derive_split_key(s, s2, salt: bytes) -> bytes:
    """SPLIT-KDF: the real sealing key binds BOTH independently-recovered secrets.
    key = HKDF( SHA256( SPLIT_LABEL | canon(s) | SEP | canon(s2) ) ). canon(s) is
    a fixed N bytes and canon(s2) a fixed N2 bytes, so the concatenation is
    injective in (s, s2)."""
    material = hashlib.sha256(
        SPLIT_LABEL + b"|" + canon_ternary(s) + SPLIT_SEP + canon_ternary(s2)
    ).digest()
    return HKDF(material, 32, salt, SHA256, context=KDF_INFO)


def near_flag_for(seed: bytes) -> bytes:
    """Per-instance DECOY plaintext for the sign-flipped second secret. Flag-shaped
    but deliberately format-invalid (uppercase body -> fails the strict validator
    ^zerosecurectf\\{[a-z0-9_]{8,48}\\}$), so it is rejectable by reasoning."""
    tag = hashlib.sha256(b"noisefloor-decoy|" + seed).hexdigest()[:8]
    return ("zerosecurectf{SIGNFLIP_decoy_" + tag + "}").encode()


# ---------------------------------------------------------------------------
# Instance generation.
# ---------------------------------------------------------------------------
def gen_instance(seed: bytes, flag: bytes) -> dict:
    # --- primary channel (UNCHANGED: the main lattice gate) -----------------
    rng = DRBG(seed, b"noisefloor-lwe")
    A = [[rng.randrange(Q) for _ in range(N)] for _ in range(M)]
    s = [rng.ternary() for _ in range(N)]
    e = [rng.ternary() for _ in range(M)]
    b = [(sum(A[i][j] * s[j] for j in range(N)) + e[i]) % Q for i in range(M)]

    # --- second, INDEPENDENT channel: its own LWE lockbox (A2, b2) ----------
    rng2 = DRBG(seed, b"noisefloor-lwe2")
    A2 = [[rng2.randrange(Q2) for _ in range(N2)] for _ in range(M2)]
    s2 = [rng2.ternary() for _ in range(N2)]
    e2 = [rng2.ternary() for _ in range(M2)]
    b2 = [(sum(A2[i][j] * s2[j] for j in range(N2)) + e2[i]) % Q2 for i in range(M2)]

    # deterministic salt / nonces from the same seed -> reproducible artifact
    kdf_rng = DRBG(seed, b"noisefloor-seal")
    salt = kdf_rng.take(16)
    nonce = kdf_rng.take(12)
    decoy_nonce = kdf_rng.take(12)

    # real flag: sealed under the SPLIT key binding BOTH secrets
    key = derive_split_key(s, s2, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(AAD)
    ct, tag = cipher.encrypt_and_digest(flag)

    # decoy lockbox: the sign-flipped second secret (-s2) is the footgun. A solver
    # who skips the b2 - A2.s2 ternary-consistency check and reads s2 with the
    # wrong sign derives key' = HKDF(canon(s)||canon(-s2)); this box opens under
    # key' to a format-invalid near-flag (rejectable by the published validator).
    decoy_s2 = [-x for x in s2]
    decoy_key = derive_split_key(s, decoy_s2, salt)
    dcipher = AES.new(decoy_key, AES.MODE_GCM, nonce=decoy_nonce)
    dcipher.update(AAD)
    dct, dtag = dcipher.encrypt_and_digest(near_flag_for(seed))

    return {
        "name": "noisefloor",
        "scheme": "LWE-KEM / AES-256-GCM sealed lockbox (split-KDF: two independent keys)",
        "n": N,
        "m": M,
        "q": Q,
        "secret_bound": SECRET_BOUND,
        "error_bound": ERROR_BOUND,
        "A": A,
        "b": b,
        # second, independent LWE lockbox -- its secret s2 is the other KDF input
        "n2": N2,
        "m2": M2,
        "q2": Q2,
        "error_bound2": ERROR_BOUND,
        "A2": A2,
        "b2": b2,
        "kdf": {
            "scheme": "split",
            "label": SPLIT_LABEL.decode(),
            "hash": "SHA-256",
            "info": KDF_INFO.decode(),
            "material": "SHA256(label | canon(s) | '|s2|' | canon(s2))",
            "sep": SPLIT_SEP.decode(),
        },
        "aad": AAD.decode(),
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ct.hex(),
        "tag": tag.hex(),
        # decoy lockbox (sign-flipped s2); opens to a format-invalid near-flag
        "decoy_nonce": decoy_nonce.hex(),
        "decoy_ciphertext": dct.hex(),
        "decoy_tag": dtag.hex(),
        "note": (
            "Two independent LWE lockboxes. The AES-256-GCM sealing key is SPLIT: "
            "key = HKDF(SHA256(label | canon(s) | '|s2|' | canon(s2))). Recover the "
            "ternary private key s from (A,b) AND the ternary s2 from (A2,b2) by "
            "lattice reduction; s alone does not open the box. Two ciphertexts are "
            "published -- exactly one unseals to a value matching the flag format "
            "^zerosecurectf\\{[a-z0-9_]{8,48}\\}$; the other is a decoy."
        ),
    }


def load_env():
    seed = os.environ.get("ZSCTF_SEED")
    flag = os.environ.get("ZSCTF_FLAG")
    if seed is None:
        sys.stderr.write("WARNING: ZSCTF_SEED unset -- using INSECURE default placeholder seed.\n")
        seed = "noisefloor-default-seed"
    if flag is None:
        sys.stderr.write("WARNING: ZSCTF_FLAG unset -- using DEFAULT placeholder flag.\n")
        flag = "zerosecurectf{local_review_flag}"
    return seed.encode(), flag.encode()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Noisefloor LWE lockbox generator.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--emit", metavar="OUTDIR", help="write OUTDIR/params.json (public artifact)")
    g.add_argument("--stdout", action="store_true", help="print the public artifact JSON to stdout")
    args = ap.parse_args(argv)

    seed, flag = load_env()
    inst = gen_instance(seed, flag)

    if args.stdout:
        json.dump(inst, sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        return 0

    outdir = args.emit
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, "params.json")
    with open(path, "w", encoding="ascii") as fh:
        json.dump(inst, fh, separators=(",", ":"))
    sys.stderr.write("wrote %s\n" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
