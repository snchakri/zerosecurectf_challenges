#include <stdio.h>
#include <string.h>

__attribute__((used, noinline))
static void print_flag(void) {
    volatile unsigned char flag[41];

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
    flag[15] = 0x6d;
    flag[16] = 0x61;
    flag[17] = 0x74;
    flag[18] = 0x72;
    flag[19] = 0x79;
    flag[20] = 0x6f;
    flag[21] = 0x73;
    flag[22] = 0x68;
    flag[23] = 0x6b;
    flag[24] = 0x61;
    flag[25] = 0x5f;
    flag[26] = 0x62;
    flag[27] = 0x72;
    flag[28] = 0x61;
    flag[29] = 0x6e;
    flag[30] = 0x63;
    flag[31] = 0x68;
    flag[32] = 0x5f;
    flag[33] = 0x66;
    flag[34] = 0x6c;
    flag[35] = 0x69;
    flag[36] = 0x70;
    flag[37] = 0x5f;
    flag[38] = 0x39;
    flag[39] = 0x7d;
    flag[40] = 0x00;

    for (int i = 0; i < 40; i++) {
        putchar(flag[i]);
    }
    putchar('\n');
}

int main(void) {
    char input[128];

    puts("Matryoshka Protocol v1");
    printf("Enter encapsulation token: ");
    if (fgets(input, sizeof(input), stdin) == NULL) {
        return 1;
    }
    input[strcspn(input, "\n")] = '\0';

    volatile int layer_accepted = 0;

    if (layer_accepted) {
        print_flag();
    } else {
        puts("Protocol rejected.");
    }

    return 0;
}
