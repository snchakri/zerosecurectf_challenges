#!/usr/bin/env python3
"""
PACKED GHOST - build script.

Inside the ctfbuild container:
  1. compile src/payload.c            -> payload ELF (holds earned-fake)
  2. run packer.py on the payload     -> src/stub.c  (holds bait + egg)
  3. compile stub.c                   -> dist/challenge (the packed ELF)

Then self-verifies:
  * running dist/challenge prints the earned-fake (payload really executes)
  * `strings dist/challenge` shows bait + egg but NOT the earned-fake
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WIN_PATH = HERE.replace("/c/", "C:\\").replace("/", "\\")

SCRIPT = r"""
set -e
cd /work
mkdir -p dist
gcc -O2 -o /tmp/payload src/payload.c
python3 src/packer.py /tmp/payload src/stub.c
gcc -O2 -o dist/challenge src/stub.c
chmod 755 dist/challenge
echo '=== file ==='
file dist/challenge
echo '=== run (expect earned-fake) ==='
./dist/challenge
echo '=== strings grep DOOM (expect ONLY bait) ==='
strings dist/challenge | grep -o 'DOOM{[^}]*}' | sort -u
echo '=== earned-fake present in plaintext? (expect no) ==='
if strings dist/challenge | grep -q 'unp4ck3d_th3_gh0st'; then echo 'LEAK'; else echo 'clean'; fi
echo '=== egg present? ==='
strings dist/challenge | grep -o "ghosts don't carry flags." | head -1
"""


def main():
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    r = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{WIN_PATH}:/work", "ctfbuild",
         "bash", "-c", SCRIPT],
        capture_output=True, text=True, env=env,
    )
    print(r.stdout)
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr)
        sys.exit("build failed")
    if "clean" not in r.stdout or "LEAK" in r.stdout:
        sys.exit("earned-fake leaked in plaintext!")
    print("[06 PACKED GHOST] build OK")


if __name__ == "__main__":
    main()
