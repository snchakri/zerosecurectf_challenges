/*
 * THE CHECK THAT LIES
 *
 *   strings(1) surfaces a flag immediately ................. BAIT
 *   reversing the password check prints another flag ....... EARNED-FAKE
 *   a second gate can never be satisfied; the function it
 *   guards is the only place the real message lives ........ EGG
 *
 * Build with build.py (it fills in the obfuscated arrays and compiles for
 * Linux x86-64 inside the ctfbuild container).
 */
#include <stdio.h>
#include <string.h>

/* Sitting in .rodata in plain sight -- the bait. */
const char *souvenir = "DOOM{str1ngs_1s_t00_34sy}";

/* The earned-fake, stored XOR-0x5A so `strings` will NOT reveal it. */
static unsigned char ef[] = { EF_BYTES };

/* The egg. Reached only through a gate that cannot be satisfied, so the
 * reflex of "run it and read the output" never prints this line. */
void concrete_wall(void)
{
    puts("the vault door opens onto a concrete wall. nicely reversed, though.");
}

/* Reversible check: (input[i] ^ 0x42) must equal target[i]. */
static const unsigned char target[] = { TARGET_BYTES };

static int check(const char *s)
{
    size_t n = strlen(s);
    if (n != sizeof(target))
        return 0;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)(s[i] ^ 0x42) != target[i])
            return 0;
    return 1;
}

int main(void)
{
    char buf[64];
    printf("enter vault password: ");
    fflush(stdout);
    if (!fgets(buf, sizeof buf, stdin))
        return 0;
    buf[strcspn(buf, "\r\n")] = 0;

    if (check(buf)) {
        unsigned char out[sizeof ef + 1];
        for (size_t i = 0; i < sizeof ef; i++)
            out[i] = ef[i] ^ 0x5A;
        out[sizeof ef] = 0;
        printf("ACCESS GRANTED: %s\n", (char *)out);

        /* An int cannot equal two distinct constants at once. Dead forever. */
        volatile int x = (int)strlen(buf) * 7 + 3;
        if (x == 0x1337 && x == 0xBEEF)
            concrete_wall();
    } else {
        puts("ACCESS DENIED.");
    }
    return 0;
}
