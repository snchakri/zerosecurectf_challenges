#include "flag.h"

#include <stddef.h>

bool flag_can_unlock(const wallet_t *wallet) {
    if (wallet == NULL) {
        return false;
    }

    return wallet->balance >= FLAG_PRICE;
}

const char *flag_value(void) {
    static unsigned char encoded[] = {
        9, 54, 33, 60, 0, 54, 48, 38, 33, 54, 12, 16, 7, 21, 40, 61,
        54, 52, 50, 39, 58, 37, 54, 12, 49, 50, 63, 50, 61, 48, 54, 12,
        54, 43, 35, 63, 60, 58, 39, 12, 53, 58, 61, 50, 61, 48, 54, 12,
        62, 60, 55, 54, 46
    };
    static char decoded[sizeof(encoded) + 1] = {0};
    static int initialized = 0;

    if (!initialized) {
        for (size_t i = 0; i < sizeof(encoded); ++i) {
            decoded[i] = (char)(encoded[i] ^ 0x53);
        }
        decoded[sizeof(encoded)] = '\0';
        initialized = 1;
    }

    return decoded;
}
