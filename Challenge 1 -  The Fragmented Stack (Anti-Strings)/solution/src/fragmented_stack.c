#include <stdio.h>
#include <stdint.h>

__attribute__((used, noinline))
static void hidden_flag_builder(void) {
    volatile uint8_t flag[38];

    flag[0] = 0x5a;
    flag[1] = 0x65;
    flag[2] = 0x72;
    flag[3] = 0x6f;
    flag[4] = 0x53;
    flag[5] = 0x65;
    flag[6] = 0x63;
    flag[7] = 0x75;
    flag[8] = 0x72;
    flag[9] = 0x65;
    flag[10] = 0x5f;
    flag[11] = 0x43;
    flag[12] = 0x54;
    flag[13] = 0x46;
    flag[14] = 0x7b;
    flag[15] = 0x66;
    flag[16] = 0x72;
    flag[17] = 0x61;
    flag[18] = 0x67;
    flag[19] = 0x5f;
    flag[20] = 0x73;
    flag[21] = 0x74;
    flag[22] = 0x61;
    flag[23] = 0x63;
    flag[24] = 0x6b;
    flag[25] = 0x5f;
    flag[26] = 0x62;
    flag[27] = 0x79;
    flag[28] = 0x74;
    flag[29] = 0x65;
    flag[30] = 0x77;
    flag[31] = 0x69;
    flag[32] = 0x73;
    flag[33] = 0x65;
    flag[34] = 0x5f;
    flag[35] = 0x39;
    flag[36] = 0x7d;
    flag[37] = 0x00;

    volatile uint32_t sink =
        flag[0] ^ flag[1] ^ flag[2] ^ flag[3] ^ flag[4] ^ flag[5] ^
        flag[6] ^ flag[7] ^ flag[8] ^ flag[9] ^ flag[10] ^ flag[11] ^
        flag[12] ^ flag[13] ^ flag[14] ^ flag[15] ^ flag[16] ^ flag[17] ^
        flag[18] ^ flag[19] ^ flag[20] ^ flag[21] ^ flag[22] ^ flag[23] ^
        flag[24] ^ flag[25] ^ flag[26] ^ flag[27] ^ flag[28] ^ flag[29] ^
        flag[30] ^ flag[31] ^ flag[32] ^ flag[33] ^ flag[34] ^ flag[35] ^
        flag[36];

    if (sink == 0x13371337) {
        puts("impossible");
    }
}

int main(void) {
    puts("Access Denied.");
    return 0;
}
