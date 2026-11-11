#include "secret.h"

#include <stddef.h>
#include <stdint.h>

#define TB_SECRET_XOR_KEY 0x5au

static const uint8_t k_flag_xor[] = {
    0x20, 0x3f, 0x28, 0x35, 0x29, 0x3f, 0x39, 0x2f,
    0x28, 0x3f, 0x39, 0x2e, 0x3c, 0x21, 0x2e, 0x32,
    0x3f, 0x05, 0x28, 0x3f, 0x3b, 0x36, 0x33, 0x29,
    0x2e, 0x05, 0x3c, 0x36, 0x3b, 0x3d, 0x27,
};

int secret_get_true_flag(char *out, size_t out_cap, uint32_t *out_len) {
    size_t i;
    size_t len = sizeof(k_flag_xor) / sizeof(k_flag_xor[0]);

    if (out == NULL || out_len == NULL) {
        return 0;
    }
    if (out_cap <= len) {
        return 0;
    }

    for (i = 0; i < len; i++) {
        out[i] = (char)(k_flag_xor[i] ^ TB_SECRET_XOR_KEY);
    }
    out[len] = '\0';
    *out_len = (uint32_t)len;
    return 1;
}

void secret_zeroize(volatile void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    size_t i;
    if (p == NULL) {
        return;
    }
    for (i = 0; i < len; i++) {
        p[i] = 0;
    }
}
