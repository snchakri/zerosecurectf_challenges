/*
 * R2 - "Linear Lock"  [rev / VM]  EXTRAPOLATE (of R1)
 * Lineage: custom-VM rev (corCTF vmquack / Google CTF VM lifting) crossed with
 * the "flag check is a linear system" pattern (many quals' matrix checkers).
 *
 * Extrapolation of R1: R1's checker handles each flag byte independently
 * (diagonal). R2 is a register VM whose bytecode computes y = M*x (mod 257)
 * for an invertible matrix M and compares y to an embedded target vector, so
 * the flag bytes are fully coupled -- you must recover M from the bytecode and
 * solve a linear system over GF(257), not invert byte-by-byte.
 *
 * Registers: 256 x uint32 accumulators. Input: flag bytes in IN[].
 * Opcodes (little-endian imm16):
 *   0x00 HALT
 *   0x01 LOADI reg, imm16          R[reg] = imm
 *   0x02 MACIN reg, inidx, c16      R[reg] += c * IN[inidx]      (multiply-accumulate)
 *   0x03 CMP   reg, imm16          if (R[reg] % 257) != imm set fail
 *   0x05 LEN   imm16               fail unless input length == imm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define P 257

int main(int argc, char **argv) {
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    unsigned char *in = (unsigned char *)argv[1];
    int inlen = (int)strlen(argv[1]);

    FILE *f = fopen("program.bin", "rb");
    if (!f) { perror("program.bin"); return 3; }
    static unsigned char prog[65536];
    int plen = (int)fread(prog, 1, sizeof(prog), f);
    fclose(f);

    static uint32_t R[256];
    int ip = 0, fail = 0;

    while (ip < plen) {
        unsigned char op = prog[ip++];
        if (op == 0x00) break;
        else if (op == 0x01) {
            unsigned char reg = prog[ip++];
            uint32_t imm = prog[ip] | (prog[ip+1] << 8); ip += 2;
            R[reg] = imm;
        }
        else if (op == 0x02) {
            unsigned char reg = prog[ip++];
            unsigned char idx = prog[ip++];
            uint32_t c = prog[ip] | (prog[ip+1] << 8); ip += 2;
            uint32_t v = (idx < (unsigned)inlen) ? in[idx] : 0;
            R[reg] += c * v;
        }
        else if (op == 0x03) {
            unsigned char reg = prog[ip++];
            uint32_t imm = prog[ip] | (prog[ip+1] << 8); ip += 2;
            if ((R[reg] % P) != imm) fail = 1;
        }
        else if (op == 0x05) {
            uint32_t imm = prog[ip] | (prog[ip+1] << 8); ip += 2;
            if ((uint32_t)inlen != imm) fail = 1;
        }
        else { fprintf(stderr, "bad opcode %02x at %d\n", op, ip-1); return 4; }
    }

    if (fail) { printf("Wrong.\n"); return 1; }
    printf("Correct!\n");
    return 0;
}
