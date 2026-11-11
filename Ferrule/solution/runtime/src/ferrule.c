/*
 * ZSCTF :: Ferrule  (rev, easy)
 * ------------------------------------------------------------------------
 * A toy "firmware activation" tool for a fictional appliance (Acme Ferrule).
 * The operator types an activation key; a correct key unlocks the unit and
 * prints its feature token (the CTF flag).
 *
 * This is a self-contained, beginner on-ramp *crackme*. The intended path is
 * basic static analysis -- not running it blindly, and NOT `strings`:
 *
 *   - There is NO plaintext flag in the binary. The flag is sealed as
 *         SECRET[i] = flag[i] XOR key[i % KEY_LEN]
 *     (a repeating-key XOR -- the classic beginner keygen transform). So the
 *     most anyone gets from `strings` is the SECRET byte array, which is
 *     indistinguishable from noise.
 *
 *   - There is NO plaintext key in the binary either. The binary never stores
 *     the key or the flag's format string. It confirms a candidate key by
 *     decoding SECRET with it and checking that the result's 32-bit FNV-1a
 *     checksum equals the sealed EXPECT_HASH.
 *
 * A reverser who reads the decode loop sees the repeating-key XOR and knows
 * (from the CTF flag format) that the hidden plaintext must begin with
 * "zerosecurectf{". That single crib recovers the short key by known-plaintext
 * XOR -- see solve/solve.py and writeup.md.
 *
 * secret.h is generated per instance by challenge/src/gen.py from ZSCTF_SEED
 * (which derives the key) and ZSCTF_FLAG (which is sealed). It is the only
 * generated input to this otherwise-static source.
 *
 * Reproducible build (see challenge/src/Makefile and the writeup):
 *     python3 gen.py && gcc -O0 -fno-stack-protector -no-pie \
 *                           -fcf-protection=none -Wall -o ferrule ferrule.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "secret.h"   /* generated: SECRET[], SECRET_LEN, EXPECT_HASH */

/* FNV-1a (32-bit). Used as a key-correctness check so the binary can confirm a
 * candidate key without ever storing the flag or its format string. */
static unsigned int fnv1a32(const unsigned char *p, int n)
{
    unsigned int h = 2166136261u;
    int i;
    for (i = 0; i < n; i++) {
        h ^= (unsigned int)p[i];
        h *= 16777619u;
    }
    return h;
}

static void emit(const char *s)
{
    fputs(s, stdout);
}

int main(void)
{
    char key[256];
    unsigned char out[SECRET_LEN + 1];
    size_t klen;
    int i;

    /* Unbuffered stdout so the socket front-end sees the prompt immediately. */
    setvbuf(stdout, NULL, _IONBF, 0);

    emit("=== Acme Ferrule :: firmware activation tool v2.1 ===\n");
    emit("Enter the activation key to unlock this unit.\n");
    emit("key> ");

    if (!fgets(key, (int)sizeof(key), stdin)) {
        emit("\n[ferrule] no key entered; aborting.\n");
        return 0;
    }

    /* Trim trailing newline / carriage return. */
    klen = strlen(key);
    while (klen > 0 && (key[klen - 1] == '\n' || key[klen - 1] == '\r'))
        key[--klen] = '\0';

    if (klen == 0) {
        emit("[ferrule] empty key; activation declined.\n");
        return 0;
    }

    /* Decode the sealed payload with the supplied key (repeating XOR). */
    for (i = 0; i < SECRET_LEN; i++)
        out[i] = (unsigned char)(SECRET[i] ^ (unsigned char)key[(size_t)i % klen]);
    out[SECRET_LEN] = '\0';

    /* A correct key makes the decoded payload hash to the sealed value. */
    if (fnv1a32(out, SECRET_LEN) == EXPECT_HASH) {
        emit("[ferrule] activation key accepted -- unit unlocked.\n");
        emit("[ferrule] feature token: ");
        fwrite(out, 1, (size_t)SECRET_LEN, stdout);
        emit("\n");
        return 0;
    }

    emit("[ferrule] activation declined: key not valid for this unit.\n");
    return 0;
}
