/*
 * encode.c — NULL STREAM cipher tool
 * Static Brotherhood internal encryption utility
 *
 * Cipher: Galois LFSR, 32-bit
 * Tap mask: 0x80200003
 * Seed: XOR-fold of 8-byte nonce (derived from header)
 * Output format: NULLSTRM (8 bytes) || nonce (8 bytes) || ciphertext
 *
 * Build (strip for challenge):
 *   gcc -O2 -o encode encode.c && strip encode
 *
 * What contestants should find:
 *   strings encode         -> "NULL_STREAM_V1", "NULLSTRM", usage string
 *   xxd transmission.null  -> NULLSTRM magic + 8-byte nonce in header
 *   radare2 / objdump      -> Galois LFSR loop, TAP_MASK constant, derive_seed
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define TAP_MASK   0x80200003U
#define MAGIC      "NULLSTRM"
#define HDR_SIZE   16          /* bytes: 8 magic + 8 nonce */

static const char VERSION[] = "NULL_STREAM_V1";

/*
 * Derive 32-bit LFSR seed from 8-byte nonce.
 * XOR the two 32-bit halves (little-endian).
 * Visible in disassembly as two 4-byte loads + XOR instruction.
 */
static uint32_t derive_seed(const uint8_t *nonce) {
    uint32_t a, b;
    memcpy(&a, nonce,     4);
    memcpy(&b, nonce + 4, 4);
    return a ^ b;
}

/*
 * Galois LFSR: produce one output byte (8 clock cycles).
 * Each cycle: output bit = LSB of state.
 * Shift right by 1. If output bit was 1, XOR state with TAP_MASK.
 * Bits packed LSB-first into the output byte.
 *
 * The TAP_MASK constant (0x80200003) is the key artifact
 * contestants must recover from the binary.
 */
static uint8_t lfsr_byte(uint32_t *state) {
    uint8_t out = 0;
    int i;
    for (i = 0; i < 8; i++) {
        uint32_t bit = *state & 1u;
        *state >>= 1;
        if (bit) {
            *state ^= TAP_MASK;
        }
        out |= (uint8_t)(bit << i);
    }
    return out;
}

int main(int argc, char *argv[]) {
    FILE *fin, *fout;
    uint8_t nonce[8];
    uint32_t state;
    int c, i;

    if (argc != 3) {
        fprintf(stderr, "%s\nusage: %s <input> <output>\n", VERSION, argv[0]);
        return 1;
    }

    fin = fopen(argv[1], "rb");
    if (!fin) {
        fprintf(stderr, "error: cannot open input file\n");
        return 1;
    }

    fout = fopen(argv[2], "wb");
    if (!fout) {
        fclose(fin);
        fprintf(stderr, "error: cannot create output file\n");
        return 1;
    }

    /* Generate random 8-byte nonce */
    srand((unsigned int)time(NULL));
    for (i = 0; i < 8; i++) {
        nonce[i] = (uint8_t)(rand() & 0xFF);
    }

    /* Write header: "NULLSTRM" (8 bytes) + nonce (8 bytes) */
    fwrite(MAGIC, 1, 8, fout);
    fwrite(nonce, 1, 8, fout);

    /* Derive LFSR seed from nonce and initialise state */
    state = derive_seed(nonce);

    /* Encrypt: XOR each plaintext byte with one LFSR output byte */
    while ((c = fgetc(fin)) != EOF) {
        fputc((unsigned char)c ^ lfsr_byte(&state), fout);
    }

    fclose(fin);
    fclose(fout);
    return 0;
}
