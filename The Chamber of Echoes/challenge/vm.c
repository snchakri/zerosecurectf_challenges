/*
 * R3 - "Telemetry"  [rev + pwn / VM / info-leak]  EXTRAPOLATE (capstone)
 * Lineage: custom-VM rev (corCTF vmquack / Google CTF VM lifting) crossed with
 * OOB-read info-leak exploitation (the "bounds check that looks diligent but is
 * off-by-a-region" class of bug).
 *
 * A lightweight VM with a flat memory MEM[] split into:
 *     scratch = MEM[0 .. SCRATCH_SIZE)      <- public telemetry buffer
 *     vault   = MEM[SCRATCH_SIZE .. end)     <- holds the flag, fragmented+encoded
 *
 * The VM runs a bytecode program (prog.bin) supplied by the operator. It offers
 * a PEEK "telemetry" opcode meant to dump bytes from the scratch buffer. The
 * intended, protected way to obtain the flag is the REVEAL opcode -- but REVEAL
 * faults on the very first flag bit (poisoned register), exit 139. So the flag
 * can only be exfiltrated indirectly, by abusing PEEK.
 *
 * SECURITY REVIEW NOTE (in-universe): PEEK is bounds-checked. It rejects any
 * offset outside the scratch buffer, and additionally clamps the copy length so
 * it can never run past the end of VM memory. (Looks safe. It is not: the length
 * clamp is to the whole MEM, not to the scratch region -- a valid scratch offset
 * plus a long length reads straight through into the vault.)
 *
 * Opcodes (operand stack of 32-bit ints; imm16 little-endian):
 *   0x00 HALT
 *   0x01 PUSH imm16        push a constant
 *   0x02 ADD               b=pop,a=pop -> push a+b   (offset arithmetic helper)
 *   0x10 PEEK              len=pop, off=pop -> append scratch[off..off+len) to out
 *   0x20 OUT               print "LEAK <hex>\n" for the pending bytes, then clear
 *   0xFF REVEAL            protected flag fetch -- faults on first bit (exit 139)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define SCRATCH_SIZE 256
#define VAULT_SIZE   256
#define MEMSZ        (SCRATCH_SIZE + VAULT_SIZE)

static uint8_t MEM[MEMSZ];              /* scratch then vault, one backing store */

int main(int argc, char **argv) {
    const char *progpath  = (argc > 1) ? argv[1] : "prog.bin";
    const char *vaultpath = (argc > 2) ? argv[2] : "vault.bin";

    /* server-side secret: load the encoded vault behind the scratch buffer */
    FILE *vf = fopen(vaultpath, "rb");
    if (!vf) { perror("vault"); return 3; }
    fread(MEM + SCRATCH_SIZE, 1, VAULT_SIZE, vf);
    fclose(vf);
    /* scratch stays zero-initialized (bss) -- it is "empty telemetry" */

    FILE *pf = fopen(progpath, "rb");
    if (!pf) { perror("prog"); return 3; }
    static uint8_t prog[65536];
    int plen = (int)fread(prog, 1, sizeof(prog), pf);
    fclose(pf);

    long stack[1024]; int sp = 0;
    static uint8_t out[1 << 20]; int outlen = 0;
    int ip = 0;

    while (ip < plen) {
        uint8_t op = prog[ip++];
        if (op == 0x00) break;
        else if (op == 0x01) { long v = prog[ip] | (prog[ip+1] << 8); ip += 2; stack[sp++] = v; }
        else if (op == 0x02) { long b = stack[--sp], a = stack[--sp]; stack[sp++] = a + b; }
        else if (op == 0x10) {
            long len = stack[--sp];
            long off = stack[--sp];
            /* --- bounds checks that look careful --- */
            if (off < 0 || off >= SCRATCH_SIZE) {         /* offset must be in scratch */
                fprintf(stderr, "peek: offset outside telemetry buffer\n");
                return 2;
            }
            long maxn = (long)MEMSZ - off;                 /* clamp... to all of MEM (bug) */
            long n = (len < maxn) ? len : maxn;
            if (n < 0) n = 0;
            for (long i = 0; i < n; i++) out[outlen++] = MEM[off + i];
        }
        else if (op == 0x20) {
            fputs("LEAK ", stdout);
            for (int i = 0; i < outlen; i++) printf("%02x", out[i]);
            putchar('\n');
            outlen = 0;
        }
        else if (op == 0xFF) {
            /* protected reveal: faults on the first flag bit (poisoned register) */
            fputs("*** trap: flag register poisoned on first-bit fetch\n", stderr);
            return 139;                                    /* segfault-style exit */
        }
        else { fprintf(stderr, "bad opcode %02x at %d\n", op, ip - 1); return 4; }
    }
    return 0;
}
