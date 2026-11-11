/*
 * ZSCTF :: Cenotaph  (broken / honeypot, REVERSE-ENGINEERING)
 *
 * A "cenotaph" is an empty tomb: a monument built to look like it holds
 * something, that deliberately holds nothing. This crackme is exactly that.
 *
 *                 *** ORGANIZER NOTE (NOT FOR PLAYERS) ***
 * Cenotaph is a DELIBERATE DEFENSIVE TARPIT / DECOY BINARY. There is NO real
 * flag anywhere reachable in this ELF -- not in .rodata, not in any computed
 * form, not via any patch. By design, EVERY flag-shaped string the binary can
 * emit is MALFORMED: it fails the strict ZSCTF validator
 *      ^zerosecurectf\{[a-z0-9_]{8,48}\}$
 * The intended learning outcome is a red-team skill: RECOGNISE A DECOY /
 * RABBIT-HOLE AND DISENGAGE (timebox, weigh evidence over momentum, stop).
 * This mirrors real-world decoy binaries dropped to burn an analyst's time.
 *
 * WHITE-BOX challenge: players are given this exact source. Nothing hides
 * behind obscurity; the "tells" that prove there is no flag are all reasoning-
 * discoverable from the source and the compiled binary. No single billboard
 * tell -- together they are decisive.
 *
 * ZSCTF_FLAG is intentionally NOT read anywhere in this program. A decoy has no
 * flag; if an operator injects ZSCTF_FLAG it is ignored (asserted by test.py).
 *
 * Per-instance: gen_config.h is produced from ZSCTF_SEED by generate.py, so the
 * decoy bodies / fingerprint / "password" differ per team while the honeypot
 * conclusion is identical. Same seed -> byte-identical binary.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

/* Per-instance DECOY data, emitted deterministically from ZSCTF_SEED. Every
 * value here is a decoy; there is no secret to bake in. */
#include "gen_config.h"

/* ---------------------------------------------------------------------------
 * TELL #1 (load-bearing): the "integrity anchor".
 *
 * FNV_OFFSET_BASIS is, by definition, fnv1a("") -- the FNV-1a hash of the EMPTY
 * string (see the FNV spec; the 32-bit offset basis is 0x811c9dc5). The binary
 * demands that a correct flag hash to EXPECTED_FNV == FNV_OFFSET_BASIS. The only
 * input that satisfies that is the empty string. In other words the binary's own
 * integrity model states the "correct flag" is EMPTY: there is nothing to
 * capture. The sha256-of-empty constant below is a second, redundant breadcrumb
 * (e3b0c442...b855 is the canonical digest of b"").
 * ------------------------------------------------------------------------- */
#define FNV_OFFSET_BASIS 0x811c9dc5u      /* == fnv1a("")  : hash of the EMPTY string */
#define FNV_PRIME        0x01000193u
#define EXPECTED_FNV     FNV_OFFSET_BASIS /* a valid flag must hash to fnv1a("") => be EMPTY */

static const char INTEGRITY_ANCHOR[] =
    "integrity: sha256(\"\")=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/* ---------------------------------------------------------------------------
 * TELL #2: the key schedule is degenerate. g_xor_key is ALL ZERO, so the XOR
 * "decryption" below is the identity map: every "decrypted" buffer equals the
 * stored bytes verbatim. A cipher whose key is zero cannot transform uppercase/
 * hyphenated stored bytes into a valid lowercase flag -- it cannot transform
 * anything at all.
 * ------------------------------------------------------------------------- */
static const unsigned char g_xor_key[16] = { 0 };   /* DEGENERATE: all zero */

static void xor_transform(const unsigned char *in, size_t n, char *out)
{
    size_t i;
    for (i = 0; i < n; i++)
        out[i] = (char)(in[i] ^ g_xor_key[i % sizeof(g_xor_key)]);
    out[n] = '\0';
}

static unsigned int fnv1a(const char *s)
{
    unsigned int h = FNV_OFFSET_BASIS;
    for (; *s; ++s) {
        h ^= (unsigned char)*s;
        h *= FNV_PRIME;
    }
    return h;
}

/* ---------------------------------------------------------------------------
 * TELL #3: an integrity gate that can NEVER be true.
 *
 * No finite machine integer equals its own successor, so (x == x + 1) is always
 * false. `volatile` stops the optimiser from folding it, keeping the dead branch
 * visible in the disassembly. This gate guards reconstruct(), so reconstruct()
 * is unreachable at run time no matter the input.
 * ------------------------------------------------------------------------- */
static int verify_integrity(void)
{
    volatile unsigned int x = (unsigned int)CFG_STATE;
    return (x == x + 1u);               /* always 0 */
}

/* ---------------------------------------------------------------------------
 * DECOY 1 -- the "win" branch (reachable; also the target of the obvious patch).
 *
 * grant() "decrypts" the embedded win flag with the zero key (identity) and
 * prints it. The stored bytes spell an UPPERCASE body, e.g.
 *      zerosecurectf{ARCHIVE_SEALED_AB12CD34}
 * which fails the [a-z0-9_] charset. Reaching grant() -- by entering the key, or
 * by patching check_key() to always accept -- therefore only ever prints an
 * invalid string. There is no flag here.
 * ------------------------------------------------------------------------- */
static void grant(char *produced)
{
    xor_transform(CFG_DECOY1_CIPHER, sizeof(CFG_DECOY1_CIPHER), produced);
    printf("[grant] access granted. flag: %s\n", produced);
}

/* check_key(): "obfuscated" compare. Recovers the expected key via the zero-key
 * XOR (identity) and strcmp()s the candidate. Because the key is recoverable by
 * reading the binary, this gate LOOKS crackable -- but passing it only reaches
 * grant()'s malformed string above. */
static int check_key(const char *candidate)
{
    char expected[64];
    xor_transform(CFG_KEY_CIPHER, sizeof(CFG_KEY_CIPHER), expected);
    return strcmp(candidate, expected) == 0;
}

/* ---------------------------------------------------------------------------
 * DECOY 3 -- the "hidden" reconstruct() routine (dead: never called from main).
 *
 * It LOOKS like the real flag-rebuilder reachable by patching a call into it.
 * It is a dead end three times over:
 *   (1) verify_integrity() is always false (x == x+1);
 *   (2) the candidate must hash to EXPECTED_FNV == fnv1a("") -- i.e. be EMPTY;
 *   (3) even if reached, the blob decodes (zero key -> identity) to a HYPHENATED
 *       body, e.g. zerosecurectf{imds-restore-ab12cd34}, which fails the charset.
 * It also circles straight back to grant(). External linkage keeps it in the
 * symbol table so a reverser can find it with nm/objdump.
 * ------------------------------------------------------------------------- */
void reconstruct(const char *candidate)
{
    char out[256];
    if (!verify_integrity()) {
        puts("[reconstruct] integrity gate closed; see grant().");
        return;
    }
    if (fnv1a(candidate) != EXPECTED_FNV) {
        puts("[reconstruct] key rejected (must hash to fnv1a(\"\")); see grant().");
        return;
    }
    xor_transform(CFG_DECOY3_CIPHER, sizeof(CFG_DECOY3_CIPHER), out);
    printf("[reconstruct] %s\n", out);
}

static void banner(void)
{
    printf("=== Cenotaph key warden :: node %s ===\n", CFG_FINGERPRINT);
    printf("%s\n", INTEGRITY_ANCHOR);
    /* DECOY 2 -- a static .rodata lure for `strings`: the prefix is 'zer0'
     * (a zero), not 'zerosecurectf', so it fails the validator outright. */
    printf("archive tag: %s\n", CFG_DECOY2);
    printf("enter archive key:\n");
}

int main(int argc, char **argv)
{
    char candidate[128];
    char produced[256];
    unsigned int h;

    banner();

    if (argc > 1) {
        size_t n = strlen(argv[1]);
        if (n >= sizeof(candidate)) n = sizeof(candidate) - 1;
        memcpy(candidate, argv[1], n);
        candidate[n] = '\0';
    } else {
        if (!fgets(candidate, sizeof(candidate), stdin))
            candidate[0] = '\0';
        candidate[strcspn(candidate, "\r\n")] = '\0';
    }

    produced[0] = '\0';
    if (check_key(candidate))
        grant(produced);
    else
        puts("[check] key declined.");

    /* The binary's OWN integrity verdict on whatever it produced. Because
     * EXPECTED_FNV == fnv1a(""), only the empty string is ACCEPTED, so every
     * non-empty produced flag is REJECTED by the program itself -- the decoy
     * fails its own check. */
    if (produced[0]) {
        h = fnv1a(produced);
        if (h == EXPECTED_FNV)
            puts("[integrity] ACCEPTED");
        else
            printf("[integrity] REJECTED: 0x%08x != 0x%08x (expected == fnv1a(\"\"))\n",
                   h, EXPECTED_FNV);
    }
    return 0;
}
