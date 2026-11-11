/*
 * R1 - "Stackjack"  [rev / VM]  INTERPOLATE
 * Lineage: corCTF 2021 "vmquack", Google CTF 2017 custom-VM lifting.
 *
 * A tiny stack VM. It loads a bytecode program (program.bin) that checks the
 * command-line argument and prints "Correct!" iff the argument is the flag.
 * The VM semantics are public (this source is part of the handout); the puzzle
 * is the bytecode. Each flag byte is read with INB, transformed by a reversible
 * op chain, and compared (EQ) to an embedded constant, so the whole thing
 * inverts byte-by-byte once you disassemble program.bin.
 *
 * Opcodes:
 *   0x00 HALT
 *   0x01 PUSH imm8      push a constant
 *   0x02 INB            push next input byte (0 + set past-end flag if exhausted)
 *   0x03 XOR            a=pop,b=pop -> push a^b
 *   0x04 ADD            a=pop,b=pop -> push (a+b)&0xff
 *   0x05 SUB            a=pop,b=pop -> push (b-a)&0xff
 *   0x07 EQ             a=pop,b=pop -> if a!=b set fail
 *   0x08 ENDCHK imm8    fail unless exactly imm8 input bytes were consumed and
 *                       no INB read past the end
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    unsigned char *in = (unsigned char *)argv[1];
    int inlen = (int)strlen(argv[1]);

    FILE *f = fopen("program.bin", "rb");
    if (!f) { perror("program.bin"); return 3; }
    static unsigned char prog[65536];
    int plen = (int)fread(prog, 1, sizeof(prog), f);
    fclose(f);

    unsigned char stack[256];
    int sp = 0;
    int ip = 0;
    int inpos = 0;
    int past_end = 0;
    int fail = 0;

    while (ip < plen) {
        unsigned char op = prog[ip++];
        if (op == 0x00) break;
        else if (op == 0x01) { stack[sp++] = prog[ip++]; }
        else if (op == 0x02) {
            if (inpos < inlen) stack[sp++] = in[inpos++];
            else { stack[sp++] = 0; past_end = 1; inpos++; }
        }
        else if (op == 0x03) { unsigned char a=stack[--sp],b=stack[--sp]; stack[sp++]=a^b; }
        else if (op == 0x04) { unsigned char a=stack[--sp],b=stack[--sp]; stack[sp++]=(a+b)&0xff; }
        else if (op == 0x05) { unsigned char a=stack[--sp],b=stack[--sp]; stack[sp++]=(b-a)&0xff; }
        else if (op == 0x07) { unsigned char a=stack[--sp],b=stack[--sp]; if (a!=b) fail=1; }
        else if (op == 0x08) { unsigned char n=prog[ip++]; if (inpos!=n || past_end) fail=1; }
        else { fprintf(stderr, "bad opcode %02x at %d\n", op, ip-1); return 4; }
    }

    if (fail) { printf("Wrong.\n"); return 1; }
    printf("Correct!\n");
    return 0;
}
