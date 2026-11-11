#include <stdint.h>
#include <stdio.h>

__attribute__((used, noinline))
static void hidden_flag_builder(void) {
    volatile uint8_t flag[43];

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
    flag[15] = 0x73;
    flag[16] = 0x63;
    flag[17] = 0x68;
    flag[18] = 0x72;
    flag[19] = 0x6f;
    flag[20] = 0x64;
    flag[21] = 0x69;
    flag[22] = 0x6e;
    flag[23] = 0x67;
    flag[24] = 0x65;
    flag[25] = 0x72;
    flag[26] = 0x5f;
    flag[27] = 0x73;
    flag[28] = 0x74;
    flag[29] = 0x61;
    flag[30] = 0x63;
    flag[31] = 0x6b;
    flag[32] = 0x5f;
    flag[33] = 0x66;
    flag[34] = 0x72;
    flag[35] = 0x61;
    flag[36] = 0x67;
    flag[37] = 0x6d;
    flag[38] = 0x65;
    flag[39] = 0x6e;
    flag[40] = 0x74;
    flag[41] = 0x7d;
    flag[42] = 0x00;

    volatile uint8_t sink = 0;
    for (int i = 0; i < 42; i++) {
        sink ^= flag[i];
    }

    if (sink == 0xff) {
        puts("never");
    }
}

int main(void) {
    puts("Access denied.");
    return 0;
}
