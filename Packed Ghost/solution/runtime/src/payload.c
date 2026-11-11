/*
 * PACKED GHOST - the inner payload.
 *
 * This is what the packer XOR-encrypts and the stub decrypts at runtime.
 * Unpacking it (or just running the packed binary) yields the EARNED-FAKE.
 */
#include <stdio.h>

int main(void)
{
    puts("ghost materialised.");
    puts("DOOM{unp4ck3d_th3_gh0st}");
    return 0;
}
