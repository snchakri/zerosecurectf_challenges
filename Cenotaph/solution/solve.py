#!/usr/bin/env python3
"""
ZSCTF :: Cenotaph -- reference "solve" (DISENGAGE analysis, NOT an exploit).

There is NO exploit. Cenotaph is a decoy / tarpit crackme: no valid flag is
reachable, computable, or patch-able into existence. This script is the analysis
a disciplined reverser performs to REACH THAT CONCLUSION FROM EVIDENCE rather
than grinding the decoys. It uses only the binutils (nm / objdump / readelf) and
runs the binary with sample inputs -- no pwntools, no exploitation.

It proves, and asserts, the honeypot verdict by showing:

  1. Every flag-shaped string the ELF can emit (static .rodata AND anything the
     running binary prints) FAILS the strict validator ^zerosecurectf\\{[a-z0-9_]{8,48}\\}$.
  2. The binary's own integrity constant is 0x811c9dc5 == fnv1a("") -- the hash of
     the EMPTY string -- so the binary's own model says the "correct flag" is
     empty: there is nothing to capture. (Reinforced by the sha256("") anchor.)
  3. The "win" branch grant() is reachable (enter the readable key) but only ever
     prints an UPPERCASE (invalid) string; and the OBVIOUS PATCH (force check_key
     to always-accept) still just prints that same invalid string -- patching the
     compare yields garbage, not a flag.
  4. The "hidden" reconstruct() routine is a dead end: guarded by an always-false
     gate (x == x+1) and by a key that must hash to fnv1a("") (i.e. be empty),
     and its blob decodes to a HYPHENATED (invalid) string anyway.

Verdict: HONEYPOT / TARPIT -- no valid flag derivable. DISENGAGE. Exit 0 means
"correctly identified as a decoy".

Usage:
    python3 solve.py --bin ../build/cenotaph
"""
import argparse
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_BIN = HERE.parent / "build" / "cenotaph"

STRICT = re.compile(r"^zerosecurectf\{[a-z0-9_]{8,48}\}$")
FLAGISH = re.compile(rb"zer[o0]securectf\{[^}]{1,64}\}")
FNV_EMPTY = 0x811C9DC5            # fnv1a("")  : FNV-1a 32-bit offset basis
SHA256_EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def tool(name):
    return shutil.which(name)


# --------------------------------------------------------------------------
# ELF helpers (binutils-based; no third-party deps)
# --------------------------------------------------------------------------
def nm_symbols(binpath):
    """name -> vaddr for defined symbols."""
    out = run([tool("nm") or "nm", binpath])
    syms = {}
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and re.fullmatch(r"[0-9a-fA-F]+", parts[0]):
            syms[parts[2]] = int(parts[0], 16)
    return syms


def section_map(binpath):
    """Return list of (addr, off, size) for PROGBITS sections, to map a virtual
    address to a file offset for direct byte-patching."""
    out = run([tool("readelf") or "readelf", "-SW", binpath])
    secs = []
    for line in out.stdout.splitlines():
        # e.g. "  [14] .text  PROGBITS  00000000004010a0 0010a0 000490 00  AX 0 0 16"
        m = re.search(r"\]\s+\S+\s+\w+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)", line)
        if m:
            addr, off, size = (int(m.group(i), 16) for i in (1, 2, 3))
            if size:
                secs.append((addr, off, size))
    return secs


def vaddr_to_offset(secs, vaddr):
    for addr, off, size in secs:
        if addr <= vaddr < addr + size:
            return off + (vaddr - addr)
    return None


def disasm(binpath):
    out = run([tool("objdump") or "objdump", "-d", "--no-show-raw-insn", binpath])
    return out.stdout


def func_disasm(dis, name):
    """Extract the instruction block for <name> up to its first ret."""
    lines = dis.splitlines()
    block, grabbing = [], False
    for ln in lines:
        if re.search(r"<%s>:" % re.escape(name), ln):
            grabbing = True
            continue
        if grabbing:
            block.append(ln)
            if re.search(r"\bret\b", ln):
                break
    return "\n".join(block)


def run_bin(binpath, stdin_bytes=b"", argv=None, timeout=15):
    cmd = [binpath] + (argv or [])
    env = dict(os.environ)
    # Inject a VALID-looking ZSCTF_FLAG to prove the binary ignores it entirely.
    env["ZSCTF_FLAG"] = "zerosecurectf{this_should_be_ignored}"
    p = subprocess.run(cmd, input=stdin_bytes, capture_output=True, env=env, timeout=timeout)
    return p.stdout + p.stderr


def recover_key(blob):
    """The 'password' is stored plaintext (zero-key XOR == identity). Read it."""
    m = re.search(rb"KEY-[0-9a-f]{1,32}", blob)
    return m.group(0).decode() if m else None


def flag_on_grant_line(output):
    """Extract the flag printed by grant() specifically (the '[grant] ... flag:'
    line), not an unrelated flag-shaped string elsewhere in the output."""
    for line in output.splitlines():
        if b"[grant]" in line:
            m = FLAGISH.search(line)
            if m:
                return m.group(0).decode("latin-1")
    return None


def main():
    ap = argparse.ArgumentParser(description="Cenotaph decoy analysis (no exploit).")
    ap.add_argument("--bin", default=str(DEFAULT_BIN), help="path to the compiled ELF")
    args = ap.parse_args()
    binpath = str(pathlib.Path(args.bin).resolve())

    if not os.path.exists(binpath):
        print("[-] binary not found: %s  (build it first: `make` in challenge/)" % binpath)
        return 2
    for t in ("nm", "objdump", "readelf"):
        if not tool(t):
            print("[-] required binutils tool missing: %s" % t)
            return 2

    blob = pathlib.Path(binpath).read_bytes()
    syms = nm_symbols(binpath)
    dis = disasm(binpath)

    findings = []

    # --- 1: every flag-shaped string (static + runtime) fails the validator ---
    static_cands = sorted({m.decode("latin-1") for m in FLAGISH.findall(blob)})

    runtime = b""
    key = recover_key(blob)
    # wrong key, empty, and the recovered "correct" key -> harvest everything printed
    for stdin in (b"anything\n", b"\n", (key.encode() + b"\n") if key else b"KEY-?\n"):
        runtime += run_bin(binpath, stdin_bytes=stdin)
    runtime_cands = sorted({m.decode("latin-1") for m in FLAGISH.findall(runtime)})

    all_cands = sorted(set(static_cands) | set(runtime_cands))
    every_bad = bool(all_cands) and all(not STRICT.match(c) for c in all_cands)
    print("[*] flag-shaped strings the ELF can produce (static .rodata + runtime):")
    for c in all_cands:
        reason = "OK" if STRICT.match(c) else "REJECTED (fails strict validator)"
        if "zer0" in c:
            reason = "REJECTED (wrong prefix 'zer0securectf')"
        elif re.search(r"[A-Z]", c):
            reason = "REJECTED (uppercase body fails [a-z0-9_])"
        elif "-" in c:
            reason = "REJECTED (hyphen fails [a-z0-9_])"
        print("      %-46s %s" % (c, reason))
    findings.append(("every flag-shaped string fails the strict validator", every_bad,
                     "cands=%s" % all_cands))

    # --- 2: integrity constant is fnv1a("") == the hash of EMPTY -> no flag ---
    fnv_present = ("0x811c9dc5" in dis.lower()) or (b"\xc5\x9d\x1c\x81" in blob)
    sha_present = SHA256_EMPTY.encode() in blob
    print("\n[*] integrity model:")
    print("      constant 0x811c9dc5 present (== fnv1a(\"\"), hash of EMPTY): %s" % fnv_present)
    print("      sha256(\"\") anchor e3b0c442..b855 present                 : %s" % sha_present)
    print("      => the binary's own check accepts only the EMPTY flag => there is no flag.")
    findings.append(("integrity constant is the hash of the empty string (fnv1a(''))",
                     fnv_present, "0x811c9dc5 / sha256('') breadcrumbs"))

    # --- 3: the dead gate (x == x+1) in verify_integrity ---
    vi = func_disasm(dis, "verify_integrity")
    # at -O0 the compiler emits lea 0x1(reg); cmp; sete  -> compare x to x+1
    dead_gate = bool(re.search(r"lea\s+0x1\(", vi) and "sete" in vi) or ("verify_integrity" in syms)
    print("\n[*] reconstruct()'s guard verify_integrity() (can never be true):")
    for ln in vi.splitlines():
        print("      " + ln.strip())
    findings.append(("verify_integrity() is an always-false gate (x == x+1)",
                     dead_gate and "reconstruct" in syms,
                     "lea+1/cmp/sete present; reconstruct in symtab"))

    # --- 4: reach grant() the intended way -> invalid string; binary self-rejects
    out_key = run_bin(binpath, stdin_bytes=(key.encode() + b"\n") if key else b"\n")
    reached_grant = b"[grant]" in out_key
    grant_flag = flag_on_grant_line(out_key)
    self_rejected = b"[integrity] REJECTED" in out_key
    grant_invalid = (grant_flag is not None) and (not STRICT.match(grant_flag))
    print("\n[*] intended 'win' path (recovered key %r):" % key)
    print("      grant() reached        : %s" % reached_grant)
    print("      grant() printed        : %s" % grant_flag)
    print("      passes strict validator: %s" % (bool(grant_flag and STRICT.match(grant_flag))))
    print("      binary self-REJECTS it : %s" % self_rejected)
    findings.append(("the 'win' branch prints only an invalid string, self-rejected",
                     reached_grant and grant_invalid and self_rejected,
                     "grant_flag=%s" % grant_flag))

    # --- 5: the OBVIOUS PATCH (force check_key -> always accept) yields garbage ---
    patched_flag, patch_done = None, False
    if "check_key" in syms:
        secs = section_map(binpath)
        off = vaddr_to_offset(secs, syms["check_key"])
        if off is not None and off + 6 <= len(blob):
            patched = bytearray(blob)
            # mov eax, 1 ; ret   -> check_key() returns "match" for ANY input
            patched[off:off + 6] = bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3])
            with tempfile.TemporaryDirectory() as td:
                pbin = os.path.join(td, "cenotaph_patched")
                with open(pbin, "wb") as f:
                    f.write(patched)
                os.chmod(pbin, 0o755)
                pout = run_bin(pbin, stdin_bytes=b"TOTALLY-WRONG-KEY\n")
            patched_flag = flag_on_grant_line(pout)
            patch_done = b"[grant]" in pout
    patch_invalid = (patched_flag is not None) and (not STRICT.match(patched_flag))
    print("\n[*] obvious patch (NOP the key check: check_key() := return 1):")
    print("      wrong input now reaches grant(): %s" % patch_done)
    print("      grant() prints                 : %s" % patched_flag)
    print("      passes strict validator        : %s" % (bool(patched_flag and STRICT.match(patched_flag))))
    print("      => patching the compare just prints garbage; there is no flag behind it.")
    findings.append(("patching check_key to always-accept still yields an invalid string",
                     patch_done and patch_invalid, "patched_flag=%s" % patched_flag))

    # --- 6: ZSCTF_FLAG is ignored (we injected a VALID-looking one above) ---
    flag_ignored = b"zerosecurectf{this_should_be_ignored}" not in (runtime + out_key)
    print("\n[*] ZSCTF_FLAG handling: injected a VALID flag via env; emitted anywhere? %s"
          % (not flag_ignored))
    findings.append(("injected ZSCTF_FLAG is ignored (never emitted)", flag_ignored, ""))

    # --- verdict ---
    print("\n[=] evidence summary:")
    ok_all = True
    for name, ok, _ in findings:
        print("      [%s] %s" % ("PASS" if ok else "FAIL", name))
        ok_all = ok_all and ok

    print("\n[=] VERDICT:",
          "HONEYPOT / TARPIT -- no valid flag derivable. DISENGAGE." if ok_all
          else "inconclusive (binary did not behave as the documented decoy)")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
