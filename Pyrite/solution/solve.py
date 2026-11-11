#!/usr/bin/env python3
"""
ZSCTF :: Pyrite -- reference "solve".

There is NO exploit. Pyrite is a honeypot/tarpit: no real flag is reachable.
This script is the reference ANALYSIS a sharp cryptanalyst performs to REACH
THAT CONCLUSION through evidence, rather than sinking time into the decoys. It:

  1. reads the published integrity manifest and shows flag_sha256 == sha256("")
     -- the empty-string digest -- i.e. the "correct flag" is empty: there is
     nothing to capture;
  2. proves each advertised "weakness" is a dead end, from the published
     parameters alone:
       - RSA: the modulus N is PRIME (Miller-Rabin) -> nothing to factor; and
         its "ciphertext" c decrypts (d = e^{-1} mod (N-1)) to garbage, not a flag;
       - nonce: the two signatures have r1 != r2 -> no nonce was reused ->
         no key is recoverable (a reused nonce forces r1 == r2);
       - partial: only 32 bits of d are leaked, far below the ~(1/4)log2(N)
         bits that known-bits / Coppersmith recovery requires -> insufficient;
  3. harvests every flag-shaped string the "recovery" oracles emit and shows
     each FAILS the strict zerosecurectf validator AND the published digest;
  4. shows the recovery oracles are canned/static (identical bytes regardless
     of input), i.e. no computation is happening behind them;
  5. shows the service's own /validate rejects every candidate (including empty).

Verdict: HONEYPOT. Disengage. Exit 0 means "correctly identified as a honeypot".

Usage:
    python solve.py --url http://HOST:PORT
"""
import sys
import re
import json
import hashlib
import argparse
from urllib.parse import urlencode
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

STRICT = re.compile(r"^zerosecurectf\{[a-z0-9_]{8,48}\}$")
FLAGISH = re.compile(r"zer[o0]securectf\{[^}]*\}", re.IGNORECASE)
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

# --- self-contained primality (no third-party deps) ------------------------
_MR_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in _MR_BASES:
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


def get(url, timeout=20):
    req = Request(url, headers={"Accept": "*/*"})
    try:
        with urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.getheaders()), r.read().decode("utf-8", "replace")
    except HTTPError as e:
        return e.code, dict(e.getheaders()), e.read().decode("utf-8", "replace")


def getj(url):
    _, _, body = get(url)
    try:
        return json.loads(body)
    except Exception:
        return {}


def main():
    ap = argparse.ArgumentParser(description="Pyrite honeypot analysis (no exploit).")
    ap.add_argument("--url", required=True, metavar="http://HOST:PORT")
    args = ap.parse_args()
    base = args.url.rstrip("/")

    try:
        # --- harvest the published integrity manifest ---
        manifest = getj(base + "/.well-known/zsctf-manifest.json")
        published = manifest.get("flag_sha256", "")
        print("[*] published flag_sha256 =", published)
        empty_digest = (published == EMPTY_SHA256)
        if empty_digest:
            print("    -> that is sha256(b'') -- the empty-string digest.")
            print("    -> the 'correct flag' is EMPTY: there is nothing to capture.")

        # --- prove each advertised 'weakness' is a dead end, from /params ---
        params = getj(base + "/params")
        print("\n[*] analysing the published key material:")

        rsa = params.get("rsa", {})
        N = int(rsa.get("N", "0"))
        e = int(rsa.get("e", "0"))
        c = int(rsa.get("c", "0"))
        n_is_prime = is_prime(N)
        print("    - RSA modulus N is prime (nothing to factor): %s" % n_is_prime)
        rsa_decrypt_is_garbage = True
        if n_is_prime and e and N > 1:
            # N prime => phi(N) = N-1 => d = e^{-1} mod (N-1) exists.
            d = pow(e, -1, N - 1)
            m = pow(c, d, N)
            raw = m.to_bytes((m.bit_length() + 7) // 8, "big")
            rsa_decrypt_is_garbage = not bool(FLAGISH.search(raw.decode("latin-1")))
            print("    - decrypting c yields a flag-shaped string: %s (garbage otherwise)"
                  % (not rsa_decrypt_is_garbage))

        ec = params.get("ecdsa", {})
        r1 = int(ec.get("sig1", {}).get("r", "0"))
        r2 = int(ec.get("sig2", {}).get("r", "0"))
        nonce_premise_false = (r1 != r2)
        print("    - 'reused nonce' claim: r1 == r2 ? %s  -> premise %s"
              % (r1 == r2, "FALSE (no nonce reuse -> no key)" if nonce_premise_false else "holds"))

        part = params.get("partial", {})
        N2 = int(part.get("N", "0"))
        leaked_bits = int(part.get("d_low_bits", "0"))
        needed_bits = N2.bit_length() // 4      # known-bits / Coppersmith threshold (~N/4)
        partial_insufficient = (leaked_bits < needed_bits)
        print("    - partial key: %d bits leaked vs ~%d needed -> insufficient: %s"
              % (leaked_bits, needed_bits, partial_insufficient))

        # --- harvest every flag-shaped string the 'recovery' oracles emit ---
        candidates = set()
        for leaf in ("rsa", "nonce", "partial"):
            j = getj(base + "/recover/" + leaf)
            candidates.update(FLAGISH.findall(j.get("candidate_flag", "")))

        print("\n[*] flag-shaped strings harvested from the recovery oracles:")
        all_bad = True
        for cand in sorted(candidates):
            strict_ok = bool(STRICT.match(cand))
            digest = hashlib.sha256(cand.encode()).hexdigest()
            integ_ok = (digest == published)
            verdict = "REJECTED (fails strict format AND integrity digest)"
            if strict_ok or integ_ok:
                verdict = "*** unexpectedly valid ***"
                all_bad = False
            print("    - %-48s %s" % (cand, verdict))

        # --- tell: the recovery oracles are canned/static (no computation) ---
        a1 = getj(base + "/recover/rsa?work=1")
        a2 = getj(base + "/recover/rsa?work=99999&extra=abc")
        canned_oracle = (a1 == a2)

        # --- tell: the service's own validator rejects every candidate ---
        self_reject = True
        for cand in sorted(candidates):
            if getj(base + "/validate?" + urlencode({"flag": cand})).get("valid"):
                self_reject = False
        empty_rejected = not getj(base + "/validate?flag=").get("valid")

        print("\n[*] honeypot tells:")
        print("    - published digest is sha256('')                          : %s" % empty_digest)
        print("    - 'weak RSA' modulus is prime (nothing to factor)         : %s" % n_is_prime)
        print("    - RSA ciphertext decrypts to garbage (no flag)            : %s" % rsa_decrypt_is_garbage)
        print("    - 'reused nonce' premise is false (r1 != r2)              : %s" % nonce_premise_false)
        print("    - 'leaked partial key' is provably insufficient          : %s" % partial_insufficient)
        print("    - /recover oracles return identical bytes for any input   : %s" % canned_oracle)
        print("    - /validate rejects every candidate (and empty)           : %s"
              % (self_reject and empty_rejected))

        ok = (empty_digest and candidates and all_bad and n_is_prime
              and rsa_decrypt_is_garbage and nonce_premise_false
              and partial_insufficient and canned_oracle
              and self_reject and empty_rejected)
        print("\n[=] VERDICT:",
              "HONEYPOT / TARPIT -- no reachable flag. DISENGAGE." if ok
              else "inconclusive (service did not behave as the documented honeypot)")
        return 0 if ok else 1
    except (URLError, OSError) as ex:
        print("[-] network error talking to %s: %s" % (base, ex))
        return 2


if __name__ == "__main__":
    sys.exit(main())
