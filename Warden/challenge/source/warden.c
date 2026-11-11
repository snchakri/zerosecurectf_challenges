/*
 * ZSCTF :: Warden  (pwn)
 * ------------------------------------------------------------------------
 * A toy "license warden" daemon for a fictional appliance (Acme LicenseOS).
 * A client connects, is prompted for a license key, and the daemon reports
 * whether the key activates a licensed session.
 *
 * This is a self-contained *teaching* crackme-style binary. It talks only to
 * its own stdin/stdout (the deployment wraps that in a TCP socket). It reads
 * untrusted input into a fixed-size on-stack license field and reports a
 * verdict. The flag is never on disk and never in an image layer: grant()
 * reads it from the process environment (ZSCTF_FLAG) at the moment it runs.
 *
 * Reproducible build (documented, see challenge/Makefile and the writeup):
 *     gcc -O0 -fno-stack-protector -no-pie -o warden warden.c
 *
 * -no-pie is deliberate: it gives every routine a fixed load address, which
 * is the pedagogical point of this intro-level exercise.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The license key the appliance will actually read into its field. A real
 * key is short; the field is sized generously for it. */
#define FIELD_LEN 64

/* How many bytes the front-end hands us for one key submission. */
#define SUBMISSION_LEN 256

/* A tiny indirection so the read site takes an opaque destination pointer.
 * (Keeps the build warning-free under -O0; the daemon's behaviour is
 * identical to calling read() in place.) */
static ssize_t take_submission(char *dst)
{
    return read(0, dst, SUBMISSION_LEN);
}

static void emit(const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    write(1, s, n);
}

/*
 * grant() -- activate a fully-licensed session.
 *
 * This is the privileged routine the appliance runs for an activated license:
 * it discloses the licensed-feature token (the CTF flag) that unlocks the
 * premium feature set. It is reached only once a session has been granted.
 *
 * The flag is pulled live from the environment so it is never compiled into
 * the binary. If the operator forgot to provision one, we warn on stderr and
 * fall back to a clearly-marked placeholder so the daemon still runs.
 */
void grant(void)
{
    const char *flag = getenv("ZSCTF_FLAG");
    if (!flag) {
        const char warn[] =
            "WARNING: ZSCTF_FLAG is not set; serving placeholder token.\n";
        write(2, warn, sizeof(warn) - 1);
        flag = "zerosecurectf{local_review_flag}";
    }

    emit("[warden] license activated -- premium features unlocked.\n");
    emit("[warden] feature token: ");
    emit(flag);
    emit("\n");
    fflush(stdout);
    _exit(0);
}

/*
 * check_key() -- the daemon's ordinary verdict path.
 *
 * In this appliance build no key validates (there is no shipped master key),
 * so a well-formed submission is simply declined. The point of the exercise
 * is not to find a magic key.
 */
static void check_key(const char *key)
{
    (void)key;
    emit("[warden] license declined: key not recognised for this appliance.\n");
}

int main(void)
{
    /* Unbuffered I/O so the socket front-end sees prompts immediately. */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    char field[FIELD_LEN];

    emit("=== Acme LicenseOS :: License Warden v1.4 ===\n");
    emit("Submit your license key to activate this appliance.\n");
    emit("license> ");

    ssize_t n = take_submission(field);
    if (n <= 0) {
        emit("[warden] no key submitted; goodbye.\n");
        return 0;
    }

    check_key(field);
    emit("[warden] session closed.\n");
    return 0;
}
