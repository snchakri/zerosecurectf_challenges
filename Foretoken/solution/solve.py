#!/usr/bin/env python3
"""
ZSCTF :: Foretoken -- reference solver.

Intended path (no exploit of anything but the maths of MT19937):
  1. Every reset token is four consecutive 32-bit outputs of Python's random
     module, which is a Mersenne Twister (MT19937).
  2. Each 32-bit output is a fixed, invertible "tempering" of one 32-bit word of
     the generator's 624-word internal state. The 156 issued tokens give exactly
     156 * 4 = 624 outputs -- one full state's worth.
  3. UNTEMPER each of those 624 outputs to recover the 624 state words, i.e.
     clone the generator's internal state.
  4. Load the recovered state back into a fresh random.Random (with the word
     index at 624, so the next draw triggers MT19937's state "twist" exactly as
     the service's own generator did) and draw the next four words -> the
     administrator's token. Submit it.

Nothing here is specific to the flag or the seed: it reconstructs the state from
whatever outputs the service shows, so it re-solves each per-instance deployment.

Pure standard library (random, hashlib not needed): the untempering is the whole
technique, and random.Random carries the forward prediction.

Run locally against the source:   python solve.py --local ../challenge/server.py
Run against a deployed instance:   python solve.py --remote HOST PORT
"""
import sys, subprocess, socket, argparse, random

# ----------------------------------------------------------------------------
# MT19937 tempering and its inverse.
#
# Forward tempering (CPython, _randommodule.c genrand_uint32):
#     y ^= (y >> 11)
#     y ^= (y << 7)  & 0x9D2C5680
#     y ^= (y << 15) & 0xEFC60000
#     y ^= (y >> 18)
# Each step is a bijection on 32-bit words, so the whole thing inverts.
# ----------------------------------------------------------------------------
def _undo_rshift_xor(y, shift):
    """Invert  y = x ^ (x >> shift)  for a 32-bit x (recover the high bits first)."""
    x = 0
    for bit in range(31, -1, -1):
        src = (x >> (bit + shift)) & 1 if (bit + shift) <= 31 else 0
        x |= ((((y >> bit) & 1) ^ src) << bit)
    return x

def _undo_lshift_and_xor(y, shift, mask):
    """Invert  y = x ^ ((x << shift) & mask)  for a 32-bit x (recover low bits first)."""
    x = 0
    for bit in range(32):
        src = ((x << shift) & mask) >> bit & 1
        x |= ((((y >> bit) & 1) ^ src) << bit)
    return x

def untemper(y):
    y = _undo_rshift_xor(y, 18)
    y = _undo_lshift_and_xor(y, 15, 0xEFC60000)
    y = _undo_lshift_and_xor(y, 7, 0x9D2C5680)
    y = _undo_rshift_xor(y, 11)
    return y

def temper(y):
    """Forward tempering; used only as a self-check of untemper()."""
    y ^= (y >> 11)
    y ^= (y << 7) & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    y ^= (y >> 18)
    return y & 0xFFFFFFFF

# ----------------------------------------------------------------------------
# Transport abstractions (identical surface for a local subprocess or a socket).
# ----------------------------------------------------------------------------
class Proc:
    def __init__(self, path):
        self.p = subprocess.Popen([sys.executable, path], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, text=True, bufsize=1)
    def readline(self): return self.p.stdout.readline()
    def send(self, line):
        self.p.stdin.write(line + "\n"); self.p.stdin.flush()
    def close(self):
        try: self.send("QUIT")
        except Exception: pass
        try: self.p.wait(timeout=5)
        except Exception: self.p.kill()

class Sock:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=10)
        self.f = self.s.makefile("rw", newline="\n")
    def readline(self): return self.f.readline()
    def send(self, line): self.f.write(line + "\n"); self.f.flush()
    def close(self):
        try: self.send("QUIT")
        except Exception: pass
        self.s.close()

# ----------------------------------------------------------------------------
# Protocol helpers
# ----------------------------------------------------------------------------
def read_banner(io):
    """Read lines until the 'commands:' marker."""
    while True:
        line = io.readline()
        if not line:
            raise RuntimeError("service closed during banner")
        if line.rstrip("\n").startswith("commands:"):
            return

def fetch_history(io):
    """Send HISTORY and return the list of token hex strings in issue order."""
    io.send("HISTORY")
    header = io.readline().rstrip("\n")
    assert header.startswith("HISTORY "), "unexpected history header: %r" % header
    n = int(header.split()[1])
    tokens = [None] * n
    for _ in range(n):
        line = io.readline().rstrip("\n")
        assert line.startswith("TOKEN "), "unexpected history line: %r" % line
        _, idx, tok = line.split()
        tokens[int(idx)] = tok
    footer = io.readline().rstrip("\n")         # consume the "END" terminator
    assert footer == "END", "unexpected history footer: %r" % footer
    assert all(t is not None for t in tokens), "history had gaps"
    return tokens

# ----------------------------------------------------------------------------
# The attack
# ----------------------------------------------------------------------------
def tokens_to_words(tokens):
    """Flatten tokens into the 32-bit output stream, most-significant word first."""
    words = []
    for tok in tokens:
        assert len(tok) % 8 == 0, "token not a whole number of 32-bit words: %r" % tok
        words += [int(tok[i:i+8], 16) for i in range(0, len(tok), 8)]
    return words

def predict_next_token(tokens):
    outputs = tokens_to_words(tokens)
    assert len(outputs) >= 624, "need >= 624 outputs to clone MT19937, got %d" % len(outputs)
    window = outputs[:624]                      # one full, block-aligned state

    state = [untemper(o) for o in window]
    # self-check: re-tempering the recovered state must reproduce the outputs
    assert [temper(s) for s in state] == window, "untemper self-check failed"

    # Load the cloned state back into a fresh generator. Index 624 means "all
    # 624 words consumed" -> the next draw triggers the state twist, mirroring
    # the service's generator exactly at this block boundary.
    clone = random.Random()
    clone.setstate((3, tuple(state + [624]), None))

    words_per_token = len(tokens[0]) // 8
    return "".join("%08x" % clone.getrandbits(32) for _ in range(words_per_token))

def solve(io):
    read_banner(io)
    tokens = fetch_history(io)
    guess = predict_next_token(tokens)
    io.send("PREDICT " + guess)
    resp = io.readline().rstrip("\n")
    return guess, resp

def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--local", metavar="SERVER_PY")
    g.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"))
    args = ap.parse_args()
    io = Proc(args.local) if args.local else Sock(args.remote[0], int(args.remote[1]))
    try:
        guess, resp = solve(io)
        print("[+] predicted administrator token = %s" % guess)
        print("[+] service response: %s" % resp)
        if resp.startswith("FLAG "):
            print("[+] FLAG =", resp[5:]); return 0
        print("[-] did not get a flag"); return 1
    finally:
        io.close()

if __name__ == "__main__":
    sys.exit(main())
