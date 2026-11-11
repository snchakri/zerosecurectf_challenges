#!/usr/bin/env python3
"""
ZSCTF :: Foretoken  (crypto, Hard)

A password-reset *token service*. It has already issued a batch of reset tokens
to ordinary users, and it will show them all to you. The NEXT token it issues
goes to the site administrator. Foretell that administrator token and the
service hands you the flag.

Players are given this exact source file. The weakness is therefore not hidden
behind obscurity: it is in plain sight, in *where the tokens come from*. The
service mints them with Python's `random` module -- a Mersenne Twister
(MT19937), a fast general-purpose PRNG that was never meant to be
unpredictable (CWE-338: use of a cryptographically weak PRNG for a security
token). The whole challenge is to see that and exploit it.

Self-contained: pure-Python standard library only (`random`, `hashlib`), so
there is nothing to trust but the code in front of you.
"""
import os, sys, hashlib, random, socketserver

# ----------------------------------------------------------------------------
# Per-instance configuration, derived deterministically from a seed (team id).
# A unique seed gives every team a unique token stream (hence a unique admin
# token) and a unique flag, so a leaked answer for one instance does not
# transfer: the attack must be re-run against each instance.
# ----------------------------------------------------------------------------
SEED = os.environ.get("ZSCTF_SEED", "static-demo-seed").encode()
FLAG = os.environ.get("ZSCTF_FLAG",
                      "zerosecurectf{local_review_flag}")
if FLAG == "zerosecurectf{local_review_flag}":
    sys.stderr.write("[foretoken] WARNING: ZSCTF_FLAG unset; using placeholder (demo only).\n")

# A 256-bit integer seed for the Mersenne Twister, fixed per instance.
SEED_INT = int.from_bytes(hashlib.sha256(SEED).digest(), "big")

# ----------------------------------------------------------------------------
# THE TOKEN MINT (this is the whole challenge)
# ----------------------------------------------------------------------------
# Each reset token is 128 bits, assembled from four consecutive 32-bit draws of
# the PRNG and rendered as 32 hex characters. A naive engineer ships this for
# "stateless, reproducible" token generation, not realising that MT19937's
# output is a fixed, invertible function of its 624-word internal state -- so a
# run of outputs fully determines every future output.
WORDS_PER_TOKEN = 4                      # 4 * 32 = 128-bit tokens
STATE_WORDS     = 624                    # MT19937 internal state is 624 words
N_REVEAL        = STATE_WORDS // WORDS_PER_TOKEN   # = 156 tokens == 624 outputs

def _mint(rng):
    """One 128-bit reset token: four 32-bit draws, most-significant first."""
    return "".join("%08x" % rng.getrandbits(32) for _ in range(WORDS_PER_TOKEN))

# Mint the whole deterministic stream once, at import time:
#   tokens 0 .. N_REVEAL-1  -> issued to users, revealed on request (624 outputs)
#   token  N_REVEAL         -> the administrator's token, kept secret
_rng          = random.Random(SEED_INT)
ISSUED        = [_mint(_rng) for _ in range(N_REVEAL)]
ADMIN_TOKEN   = _mint(_rng)

# ----------------------------------------------------------------------------
# Line protocol
# ----------------------------------------------------------------------------
def banner():
    out = []
    out.append("=== ZSCTF Password-Reset Token Service ===")
    out.append("For 'stateless, reproducible' tokens we mint them with Python's random module.")
    out.append("tokens already issued to users: %d (each 128-bit; fetch them with HISTORY)" % N_REVEAL)
    out.append("the NEXT token will be issued to the site administrator.")
    out.append("win: foretell the administrator's next reset token with PREDICT.")
    out.append("commands: HISTORY | PREDICT <token_hex> | QUIT")
    return "\n".join(out)

def history_block():
    out = ["HISTORY %d" % N_REVEAL]
    out += ["TOKEN %d %s" % (i, tok) for i, tok in enumerate(ISSUED)]
    out.append("END")
    return "\n".join(out)

def handle_line(line):
    parts = line.strip().split()
    if not parts:
        return ""
    cmd = parts[0].upper()
    try:
        if cmd == "HISTORY":
            return history_block()
        if cmd == "PREDICT":
            guess = parts[1].strip().lower()
            if guess == ADMIN_TOKEN:
                return "FLAG " + FLAG
            if guess in ISSUED:
                return "WRONG that token has already been issued; foretell the NEXT one"
            return "WRONG not the administrator's token"
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
        # Swallow abrupt client disconnects (resets/broken pipes from probes,
        # port scanners and health checks) instead of logging a traceback.
        try:
            self.wfile.write((banner() + "\n").encode())
            for raw in self.rfile:
                resp = handle_line(raw.decode(errors="ignore"))
                if resp == "__QUIT__":
                    break
                if resp:
                    self.wfile.write((resp + "\n").encode())
        except (ConnectionError, BrokenPipeError):
            pass

def serve_tcp(host, port):
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer((host, port), _Handler) as srv:
        sys.stderr.write("listening on %s:%d\n" % (host, port)); sys.stderr.flush()
        srv.serve_forever()

if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--tcp":
        host = sys.argv[2] if len(sys.argv) > 2 else "0.0.0.0"
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 1337
        serve_tcp(host, port)
    else:
        serve_stdio()
