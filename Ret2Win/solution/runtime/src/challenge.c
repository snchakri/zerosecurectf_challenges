/*
 * RET2WIN DECOY
 *
 *   overflow -> win()     prints a decoy ................... BAIT
 *   overflow -> admin()   prints another decoy ............. EARNED-FAKE
 *   but on a CLEAN return, main() calls goodbye() ......... EGG
 *
 * i.e. the only way to see the real message is to NOT exploit it.
 *
 * Build: gcc -fno-stack-protector -no-pie -O0
 */
#include <stdio.h>
#include <unistd.h>

void goodbye(void)
{
    puts("control flow redirected into an empty room. no occupants, no flags.");
}

void win(void)
{
    puts("DOOM{r3t2w1n_t00_0bv10us}");
}

void admin(void)
{
    puts("DOOM{s3cr3t_4dm1n_pwn3d}");
}

void vuln(void)
{
    char buf[64];
    puts("state your business, occupant:");
    read(0, buf, 0x100);          /* 256 bytes into 64 -- the overflow */
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    vuln();
    goodbye();                     /* clean exit prints the egg */
    return 0;
}
