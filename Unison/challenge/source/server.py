#!/usr/bin/env python3
"""
ZSCTF :: Unison  (crypto, Hard)

A firmware-activation *broadcast*. A vendor provisions its whole device fleet by
encrypting ONE signed activation record -- byte-for-byte identical for every
device -- under each device's own RSA public key. Every device uses the small
public exponent e = 3; only the modulus differs from device to device.

You have intercepted the ciphertext broadcast to all devices. The activation
record (which carries the flag) never travels in the clear -- but the same
plaintext under the same tiny exponent, sent to several moduli at once, is
exactly the shape Hastad's broadcast attack was written for.

Players are given this exact source file. The cryptographic flaw is therefore
not hidden behind obscurity: it is the design itself -- one plaintext, exponent
3, many moduli. That is the point; the challenge is to recognise it and exploit
it with the Chinese Remainder Theorem and an integer cube root.

Self-contained: pure-Python deterministic RSA key generation (no third-party
crypto libraries), so there is nothing to trust but the maths in front of you.
"""
import os, sys, math, hashlib, socketserver

# ----------------------------------------------------------------------------
# Public scheme parameters (all public, printed in the banner / CAPTURE).
# ----------------------------------------------------------------------------
E           = 3           # small public exponent -- the whole point
NUM_DEVICES = 5           # the fleet; any 3 ciphertexts suffice for e = 3
PRIME_BITS  = 512         # => 1024-bit moduli: far too large to factor, so the
                          #    only cheap route is the broadcast, not key recovery
BLOB_BYTES  = 112         # fixed activation-record length => ~896-bit plaintext m,
                          #    which guarantees  m < N  and (crucially)  m^3 > N
MAGIC       = b"ZSCTF-FW-ACTIVATION-v1"

# ----------------------------------------------------------------------------
# Per-instance secrets, derived deterministically from a seed (team id). Same
# ZSCTF_SEED -> identical fleet (moduli + ciphertexts) and identical plaintext,
# so a team's instance is reproducible yet unique; a leaked solution for one
# seed does not transfer to another.
# ----------------------------------------------------------------------------
SEED = os.environ.get("ZSCTF_SEED", "static-demo-seed").encode()
FLAG = os.environ.get(
    "ZSCTF_FLAG",
    "zerosecurectf{local_review_flag}",
).encode()


# ----------------------------------------------------------------------------
# A deterministic byte stream: SHA-256 in counter mode over (seed | label).
# This replaces an OS RNG so key generation is a pure function of the seed.
# ----------------------------------------------------------------------------
class DRBG:
    def __init__(self, seed, label):
        self.seed = seed
        self.label = label
        self.counter = 0
        self.buf = b""

    def _refill(self):
        block = hashlib.sha256(
            self.seed + b"|" + self.label + b"|" + self.counter.to_bytes(8, "big")
        ).digest()
        self.buf += block
        self.counter += 1

    def read(self, n):
        while len(self.buf) < n:
            self._refill()
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def randbits(self, nbits):
        nbytes = (nbits + 7) // 8
        x = int.from_bytes(self.read(nbytes), "big")
        return x >> (nbytes * 8 - nbits)


# ----------------------------------------------------------------------------
# Primality: small-prime trial division + deterministic Miller-Rabin. The
# candidates come from a hash DRBG (non-adversarial), so a fixed set of prime
# bases is a strong, standard, reproducible test. (Miller-Rabin: Rabin 1980.)
# ----------------------------------------------------------------------------
def _sieve(limit):
    bs = bytearray([1]) * (limit + 1)
    bs[0] = bs[1] = 0
    for i in range(2, int(limit ** 0.5) + 1):
        if bs[i]:
            bs[i * i::i] = bytearray(len(bs[i * i::i]))
    return [i for i in range(limit + 1) if bs[i]]

_SMALL_PRIMES = _sieve(2000)
_MR_BASES = _SMALL_PRIMES[:16]   # 2,3,5,...,53 -- ample for non-adversarial inputs


def _is_probable_prime(n):
    if n < 2:
        return False
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
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(drbg, bits):
    """Deterministic prime of the given bit length with p = 5 (mod 6).

    p = 5 (mod 6) forces p != 1 (mod 3), hence 3 does not divide (p-1); with this
    on both factors, gcd(e=3, phi(N)) = 1 and e = 3 is a valid exponent.
    """
    while True:
        cand = drbg.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        cand += (5 - cand) % 6                 # snap up to the nearest 5 (mod 6)
        for _ in range(8192):
            if _is_probable_prime(cand):
                return cand
            cand += 6                          # preserves 5 (mod 6) and oddness


# ----------------------------------------------------------------------------
# Build the fleet and the single shared plaintext.
# ----------------------------------------------------------------------------
def build_plaintext():
    """The ONE activation record, identical for every device. The flag is
    embedded as ASCII; deterministic filler pads it to a fixed length so that
    the integer m satisfies  m < N  (valid RSA) and  m^3 > N  (so no single
    ciphertext is a plain cube -- the broadcast is mandatory)."""
    core = MAGIC + b"\x00" + FLAG + b"\x00"
    if len(core) > BLOB_BYTES - 8:
        raise SystemExit("ZSCTF_FLAG too long for the activation record")
    filler = DRBG(SEED, b"activation-filler").read(BLOB_BYTES - len(core))
    blob = core + filler
    assert len(blob) == BLOB_BYTES
    assert blob[0] != 0                        # leading byte set => stable bit length
    return int.from_bytes(blob, "big"), blob


def build_fleet():
    m, blob = build_plaintext()
    devices = []
    primes_seen = set()
    for i in range(NUM_DEVICES):
        p = _gen_prime(DRBG(SEED, b"device-%d-p" % i), PRIME_BITS)
        q = _gen_prime(DRBG(SEED, b"device-%d-q" % i), PRIME_BITS)
        if p == q or p in primes_seen or q in primes_seen:
            raise SystemExit("degenerate prime collision; change ZSCTF_SEED")
        primes_seen.update((p, q))
        n = p * q
        c = pow(m, E, n)
        devices.append({"i": i, "n": n, "c": c})

    # ---- integrity invariants (fail-closed; this is what makes the challenge
    #      exactly a Hastad broadcast and nothing cheaper) -------------------
    moduli = [d["n"] for d in devices]
    assert all(m < n for n in moduli), "plaintext not reduced: RSA invalid"
    assert all(m ** E > n for n in moduli), "m^E <= N: a single cube root would win"
    for a in range(len(moduli)):
        for b in range(a + 1, len(moduli)):
            assert math.gcd(moduli[a], moduli[b]) == 1, "moduli share a factor"
    return m, blob, devices


M, BLOB, DEVICES = build_fleet()


# ----------------------------------------------------------------------------
# Line protocol (stdio or TCP), mirroring the ZSCTF service template.
# ----------------------------------------------------------------------------
def _device_line(d):
    return "device %d e %d n %x ct %x" % (d["i"], E, d["n"], d["c"])


def banner():
    out = [
        "=== ZSCTF Firmware Activation Broadcast ===",
        "The vendor provisions its device fleet by encrypting ONE signed",
        "activation record (identical for every device) under each device's",
        "RSA public key. Public exponent e = %d; each device has a distinct" % E,
        "modulus. You have intercepted the ciphertext sent to every device.",
        "devices: %d" % NUM_DEVICES,
        "commands: CAPTURE | DEVICE <i> | VERIFY <plaintext_hex> | QUIT",
    ]
    return "\n".join(out)


def handle_line(line):
    parts = line.strip().split()
    if not parts:
        return ""
    cmd = parts[0].upper()
    try:
        if cmd == "CAPTURE":
            return "\n".join(_device_line(d) for d in DEVICES)
        if cmd == "DEVICE":
            i = int(parts[1])
            if not (0 <= i < NUM_DEVICES):
                return "ERR device index out of range"
            return _device_line(DEVICES[i])
        if cmd == "VERIFY":
            guess = int(parts[1], 16)
            if guess == M:
                # The flag already lives inside the record you submitted; this
                # only confirms the recovery. Submitting the exact m requires
                # solving the broadcast, so it leaks nothing you don't have.
                return "FLAG " + FLAG.decode()
            return "NOMATCH that is not the activation record"
        if cmd == "QUIT":
            return "__QUIT__"
        return "ERR unknown command"
    except (IndexError, ValueError):
        return "ERR malformed command"


def serve_stdio():
    print(banner(), flush=True)
    for line in sys.stdin:
        resp = handle_line(line)
        if resp == "__QUIT__":
            break
        if resp:
            print(resp, flush=True)


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write((banner() + "\n").encode())
        for raw in self.rfile:
            resp = handle_line(raw.decode(errors="ignore"))
            if resp == "__QUIT__":
                break
            if resp:
                self.wfile.write((resp + "\n").encode())


def serve_tcp(host, port):
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer((host, port), _Handler) as srv:
        sys.stderr.write("listening on %s:%d\n" % (host, port))
        sys.stderr.flush()
        srv.serve_forever()


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--tcp":
        host = sys.argv[2] if len(sys.argv) > 2 else "0.0.0.0"
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 1337
        serve_tcp(host, port)
    else:
        serve_stdio()
