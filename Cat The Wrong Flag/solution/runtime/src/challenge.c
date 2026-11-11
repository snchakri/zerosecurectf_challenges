/*
 * CAT THE WRONG FLAG  (REAL challenge, flag = ZeroSecure{...}).
 *
 * The "file retrieval terminal" will happily read a filename into a 64-byte
 * buffer with no bounds check -- a classic stack overflow. But there is no flag
 * file on disk and nothing in `strings`: the flag is stored XOR-encrypted and
 * is only turned back into text by open_vault(), which main() never calls.
 *
 * Overflow vuln()'s buffer and redirect the saved return address to
 * open_vault(). A `pop rdi; ret` / plain `ret` gadget is provided so you can
 * fix stack alignment for the puts() inside open_vault().
 *
 * Build with build.py (fills the encrypted array + compiles, no-PIE no-canary).
 */
#include <stdio.h>
#include <unistd.h>

/* provided gadget: `pop rdi; ret` (and a `ret` for 16-byte stack alignment) */
void __attribute__((used)) gadget(void)
{
    asm volatile("pop %rdi; ret");
}

/* The flag, XOR-0x5A so it never appears in `strings`. */
static unsigned char vault[] = { VAULT_BYTES };
static const unsigned int vault_len = VAULT_LEN;

/* Never called in normal flow. The only thing that prints the real flag. */
void __attribute__((used)) open_vault(void)
{
    char out[256];
    for (unsigned int i = 0; i < vault_len; i++)
        out[i] = vault[i] ^ 0x5A;
    out[vault_len] = 0;
    puts(out);
}

void vuln(void)
{
    char buf[64];
    read(0, buf, 0x200);               /* 512 into 64 -- the overflow */
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    puts("silo file retrieval terminal.");
    puts("name a file and we'll fetch it:");
    vuln();
    puts("no such file. the vault stays sealed.");
    return 0;
}
