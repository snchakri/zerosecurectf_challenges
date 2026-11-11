#!/usr/bin/env python3
"""
THE CHECK THAT LIES - build script.

Fills the obfuscated byte arrays into src/challenge.c, compiles it to a Linux
x86-64 ELF inside the `ctfbuild` Docker image, and self-verifies all 3 paths.

Decoy strings (LOCKED):
  bait        : DOOM{str1ngs_1s_t00_34sy}     (plain in .rodata)
  earned-fake : DOOM{r3v3rs3d_th3_ch3ck_gg}   (printed when the check passes)
  egg         : concrete_wall() message       (behind an unsatisfiable gate)
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")
SRC = os.path.join(HERE, "src", "challenge.c")

PASSWORD = "concrete"                       # the vault password
EARNED_FAKE = "DOOM{r3v3rs3d_th3_ch3ck_gg}"
WIN_PATH = HERE.replace("/c/", "C:\\").replace("/", "\\")  # for docker mount


def c_array(bs):
    return ", ".join(str(b) for b in bs)


def main():
    os.makedirs(DIST, exist_ok=True)

    target = bytes((c ^ 0x42) for c in PASSWORD.encode())
    ef = bytes((c ^ 0x5A) for c in EARNED_FAKE.encode())

    src = open(SRC).read()
    src = src.replace("{ TARGET_BYTES }", "{ " + c_array(target) + " }")
    src = src.replace("{ EF_BYTES }", "{ " + c_array(ef) + " }")
    gen = os.path.join(HERE, "src", "_generated.c")
    with open(gen, "w", newline="\n") as f:
        f.write(src)

    # compile inside the ctfbuild container
    docker_cmd = [
        "docker", "run", "--rm",
        "-v", f"{WIN_PATH}:/work",
        "ctfbuild",
        "bash", "-c",
        "gcc -O0 -fno-stack-protector -no-pie "
        "-o /work/dist/challenge /work/src/_generated.c && "
        "chmod 755 /work/dist/challenge && file /work/dist/challenge",
    ]
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    r = subprocess.run(docker_cmd, capture_output=True, text=True, env=env)
    print(r.stdout.strip())
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr)
        sys.exit("compile failed")

    print("[05 THE CHECK THAT LIES] build OK")


if __name__ == "__main__":
    main()
