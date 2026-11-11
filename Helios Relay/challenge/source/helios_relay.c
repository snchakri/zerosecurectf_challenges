/*
 * ZSCTF :: Helios Relay  (pwn)
 * ------------------------------------------------------------------------
 * A toy telemetry relay for a fictional solar-array controller
 * ("Helios Grid Edge"). Field beacons stream short status records to the
 * relay; an operator can attach a custom *label template* to each record so
 * the rendered line reads the way their dashboard expects. The relay then
 * renders the operator's template and echoes the finished line back.
 *
 * This is a self-contained *teaching* service. It talks only to its own
 * stdin/stdout; the deployment wraps that in a TCP socket with socat. The
 * licensed-feature token (the CTF flag) is never on disk and never baked into
 * an image layer: unlock_control_plane() reads it live from the process
 * environment (ZSCTF_FLAG) at the instant it runs, and only once the relay's
 * control plane has been authorised.
 *
 * Reproducible build (see challenge/Makefile and the writeup):
 *     gcc -O0 -fno-stack-protector -no-pie -fno-pic \
 *         -o helios_relay helios_relay.c
 *
 * -no-pie is deliberate and documented: the control-plane authorisation word
 * is a global with a fixed load address, which is the pedagogical anchor of
 * this exercise (the operator is handed the full source and this exact build
 * recipe, so the address is recoverable from the binary's symbol table).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define LABEL_MAX   512          /* bytes accepted for one label template   */

/*
 * The relay's control plane is latched by a single authorisation word. The
 * firmware only ever hands the operator read access to telemetry; the control
 * plane stays dark until this word matches the vendor's provisioning seal.
 *
 * The seal is a fixed 32-bit constant shipped with the firmware image. It is
 * NOT a password an operator types -- the firmware compares the latched word
 * against it internally and refuses any other value (see the tripwire below).
 */
#define PROVISIONING_SEAL 0x5A534331u   /* 'Z' 'S' 'C' '1' little-endian */

volatile unsigned int authorization_level = 0;

static void print_banner(void)
{
    puts("====================================================");
    puts("   HELIOS GRID EDGE :: telemetry relay  (build 7.2) ");
    puts("====================================================");
    puts("Beacon uplink nominal. Control plane: LOCKED.");
    puts("Attach a label template to a record and the relay will");
    puts("render it back to you. Type HELP for the command set.");
}

static void print_help(void)
{
    puts("commands:");
    puts("  HELP           - show this command set");
    puts("  STATUS         - print current array telemetry (read-only)");
    puts("  DIAG           - emit the field-maintenance token");
    puts("  EXIT | QUIT    - disconnect from the relay");
    puts("  <template>     - any other line is rendered as a label template");
}

static void print_status(void)
{
    puts("[telemetry] string_01 .... 41.8 V   7.90 A   OK");
    puts("[telemetry] string_02 .... 41.6 V   7.88 A   OK");
    puts("[telemetry] inverter   .... locked @ 50.00 Hz  OK");
    puts("[telemetry] control-plane authorisation word: LOW");
}

/*
 * Field-maintenance token. Technicians quote this when they open a ticket so
 * the vendor can confirm which cabinet they touched. It is deliberately
 * formatted like the licensed-feature token but unlocks nothing: latching the
 * control plane is governed solely by the authorisation word above.
 */
static void print_diag_token(void)
{
    puts("[maint] field-maintenance token (quote this on a ticket):");
    puts("[maint] zerosecurectf{local_review_flag}");
    puts("[maint] note: this token does not authorise the control plane.");
}

static void unlock_control_plane(void)
{
    const char *flag = getenv("ZSCTF_FLAG");
    puts("[control] AUTHORISATION WORD MATCHES PROVISIONING SEAL");
    puts("[control] control plane UNLOCKED -- licensed-feature token follows:");
    if (flag == NULL) {
        fputs("[control][WARNING] ZSCTF_FLAG is unset; emitting placeholder.\n",
              stderr);
        flag = "zerosecurectf{local_review_flag}";
    }
    puts(flag);
}

/*
 * Per-instance stack slide. The provisioning seed (ZSCTF_SEED) deterministically
 * selects how many scratch slots the render frame reserves before the label
 * buffer, so the template buffer lands at a per-team offset within the frame.
 * Beacons on different grids therefore present a different render layout, so a
 * payload crafted against another team's instance will not line up here.
 */
static unsigned int seed_slots(void)
{
    const char *s = getenv("ZSCTF_SEED");
    unsigned int h = 2166136261u;            /* FNV-1a over the seed string */
    if (s) {
        for (; *s; ++s) { h ^= (unsigned char)*s; h *= 16777619u; }
    }
    return h % 8u;                           /* 0..7 extra 8-byte scratch slots */
}

/*
 * Read exactly `n` raw bytes of a label-template frame from stdin into `dst`.
 * Telemetry frames are length-declared and carried verbatim, so any byte value
 * -- including embedded zero bytes -- is preserved as sent. Returns the number
 * of bytes actually read, or -1 if the stream closed early.
 */
static long read_frame(char *dst, long n)
{
    long got = 0;
    while (got < n) {
        size_t r = fread(dst + got, 1, (size_t)(n - got), stdin);
        if (r == 0) return -1;
        got += (long)r;
    }
    return got;
}

/*
 * render_label() -- render one operator-supplied label template.
 *
 * The relay lets the operator decide exactly how a record's label reads, so
 * the template is handed straight to the C runtime's line formatter and the
 * finished line is echoed back. A read-only telemetry feature, by design.
 */
static void render_label(const char *tmpl, long len)
{
    unsigned int n = seed_slots();
    volatile long slide[n + 1];              /* frame scratch: size set by seed */
    char buffer[LABEL_MAX];

    for (unsigned int i = 0; i <= n; ++i)
        slide[i] = (long)(0x5100 + i);       /* touch the slide so it stays live */

    memset(buffer, 0, sizeof(buffer));
    if (len > (long)sizeof(buffer) - 1) len = (long)sizeof(buffer) - 1;
    if (len > 0) memcpy(buffer, tmpl, (size_t)len);

    fputs("[relay] rendered label: ", stdout);
    printf(buffer);
    fputc('\n', stdout);

    if (slide[n] == 0) fputc('\0', stdout);  /* keep the slide from folding away */
}

int main(void)
{
    char line[64];
    char frame[LABEL_MAX];

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);

    print_banner();

    while (1) {
        fputs("relay> ", stdout);

        if (fgets(line, sizeof(line), stdin) == NULL) {
            puts("\n[relay] uplink closed.");
            break;
        }
        line[strcspn(line, "\r\n")] = '\0';

        if (strcmp(line, "EXIT") == 0 || strcmp(line, "QUIT") == 0) {
            puts("[relay] disconnecting. uplink closed.");
            break;
        }
        if (strcmp(line, "HELP") == 0)   { print_help();       continue; }
        if (strcmp(line, "STATUS") == 0) { print_status();     continue; }
        if (strcmp(line, "DIAG") == 0)   { print_diag_token(); continue; }

        if (strncmp(line, "RENDER ", 7) == 0) {
            long n = strtol(line + 7, NULL, 10);
            if (n <= 0 || n > (long)sizeof(frame) - 1) {
                puts("[relay] frame length out of range (1..511).");
                continue;
            }
            if (read_frame(frame, n) != n) {
                puts("\n[relay] short frame; uplink closed.");
                break;
            }
            render_label(frame, n);

            if (authorization_level == PROVISIONING_SEAL) {
                unlock_control_plane();
                return 0;
            } else if (authorization_level != 0) {
                printf("[relay][tripwire] authorisation word = 0x%08x does not "
                       "match the provisioning seal; relatching to LOCKED.\n",
                       authorization_level);
                authorization_level = 0;
            }
            continue;
        }

        puts("[relay] unknown command. Type HELP. (templates go via RENDER <len>)");
    }

    return 0;
}
