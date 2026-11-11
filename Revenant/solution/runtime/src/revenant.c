/*
 * ZSCTF :: Revenant  (pwn / heap)
 * ------------------------------------------------------------------------
 * A toy "Reliquary Registry" -- a tiny in-memory record manager for a
 * fictional archival appliance. A client allocates small records and raw
 * "notes", renames records, releases them, and asks the service to "render"
 * a record (which calls that record's handler function pointer).
 *
 * This is a self-contained *teaching* heap binary. It talks only to its own
 * stdin/stdout (the deployment wraps that in a TCP socket). The flag is never
 * on disk and never baked into an image layer: win() reads it live from the
 * process environment (ZSCTF_FLAG) at the moment it runs.
 *
 * ---- THE BUG (CWE-416, use-after-free) ------------------------------------
 * `free <id>` releases a record's heap chunk but does NOT clear its slot.
 * The slot therefore dangles. Each record is a struct whose LAST field is a
 * function pointer (`render`). By freeing a record and then allocating a raw
 * `note` of the SAME tcache size class, the note's user buffer is placed on
 * top of the freed record's chunk (glibc tcache LIFO reuse is deterministic
 * in a single-threaded process). Writing past the record's label region
 * through the note overwrites the overlapping `render` field; invoking the
 * dangling record then transfers control to an attacker-chosen address.
 *
 * ---- WHY THIS VARIANT (honesty note, see writeup.md) ----------------------
 * We deliberately use the ROBUST, DETERMINISTIC heap variant: UAF that
 * overwrites a struct function pointer, redirected to win() at a FIXED
 * (-no-pie) address. This needs NO info leak and corrupts NO allocator
 * metadata, so it reproduces identically across glibc builds. Full tcache/
 * fastbin poisoning (safe-linking defeat, metadata forgery) is intentionally
 * NOT required -- it is glibc-version-fragile and would hurt reproducibility.
 *
 * Reproducible build (see challenge/build.sh, challenge/Makefile, writeup.md):
 *     gcc -O0 -fno-stack-protector -no-pie -fcf-protection=none -Wall \
 *         -o revenant src/revenant.c
 *
 * -no-pie is deliberate: it fixes win() at a known address so no leak is
 * needed -- the pedagogical point is the UAF -> function-pointer hijack, not
 * ASLR defeat.
 */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

/* ---- record model --------------------------------------------------------
 * The function pointer is the LAST field, at a fixed offset the player must
 * derive from this source (offsetof(record_t, render) == 24). It is NOT at
 * offset 0, so clobbering it requires reasoning about the struct layout and
 * the tcache size class -- not a blind write.
 */
typedef struct record {
    char     label[16];                  /* 0..15  : short display name       */
    uint64_t checksum;                   /* 16..23 : inert integrity field    */
    void   (*render)(struct record *);   /* 24..31 : handler (hijack target)  */
} record_t;

_Static_assert(sizeof(record_t) == 32, "record_t must be 32 bytes (0x30 chunk)");
_Static_assert(offsetof(record_t, render) == 24, "render must sit at offset 24");

#define MAX_SLOTS   16
#define MAX_WRITE   256     /* cap on a single write payload (protocol sanity) */
#define LABEL_CAP   16      /* a record write may only touch its label region  */

enum { SLOT_EMPTY = 0, SLOT_RECORD = 1, SLOT_NOTE = 2 };

static void  *slots[MAX_SLOTS];
static int    kinds[MAX_SLOTS];
static size_t caps[MAX_SLOTS];           /* writable bytes for a NOTE slot     */

/* ---- raw, heap-free I/O --------------------------------------------------
 * We use read()/write() directly (no stdio) so the ONLY heap activity is the
 * player's own new/note/free commands. That keeps tcache behaviour pristine
 * and the exploit deterministic.
 */
static void out(const char *s, size_t n)
{
    size_t o = 0;
    while (o < n) {
        ssize_t w = write(1, s + o, n - o);
        if (w <= 0) break;
        o += (size_t)w;
    }
}
static void emit(const char *s) { out(s, strlen(s)); }

static void emit_uint(unsigned long v)
{
    char buf[32];
    int i = (int)sizeof(buf);
    buf[--i] = '\0';
    if (v == 0) buf[--i] = '0';
    while (v && i > 0) { buf[--i] = (char)('0' + (v % 10)); v /= 10; }
    emit(&buf[i]);
}
static void emit_hex(unsigned long v)
{
    static const char hx[] = "0123456789abcdef";
    char buf[19];
    int i = (int)sizeof(buf);
    buf[--i] = '\0';
    if (v == 0) buf[--i] = '0';
    while (v && i > 0) { buf[--i] = hx[v & 0xf]; v >>= 4; }
    emit("0x");
    emit(&buf[i]);
}

/* ---- buffered stdin reader (also heap-free) ------------------------------ */
static unsigned char inbuf[8192];
static size_t in_len = 0, in_pos = 0;

static int refill(void)
{
    if (in_pos < in_len) return 1;
    ssize_t n = read(0, inbuf, sizeof inbuf);
    if (n <= 0) return 0;
    in_len = (size_t)n;
    in_pos = 0;
    return 1;
}
static int get_byte(int *c)
{
    if (!refill()) return 0;
    *c = inbuf[in_pos++];
    return 1;
}
static ssize_t read_line(char *dst, size_t cap)
{
    size_t i = 0;
    int c;
    while (i + 1 < cap) {
        if (!get_byte(&c)) { if (i == 0) return -1; break; }
        if (c == '\n') break;
        if (c == '\r') continue;
        dst[i++] = (char)c;
    }
    dst[i] = '\0';
    return (ssize_t)i;
}
static int read_exact(char *dst, size_t n)
{
    size_t got = 0;
    int c;
    while (got < n) {
        if (!get_byte(&c)) return 0;
        dst[got++] = (char)c;
    }
    return 1;
}

/* ---- tiny token/number parsing (no stdio) -------------------------------- */
static long parse_long(const char *s, const char **end)
{
    long v = 0;
    int neg = 0;
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '-') { neg = 1; s++; }
    while (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); s++; }
    if (end) *end = s;
    return neg ? -v : v;
}

/* ---- the record handlers ------------------------------------------------- */

/* default_render(): the ONLY handler a record ever gets on the benign path.
 * It discloses nothing; it just reports the record as idle. */
static void default_render(record_t *r)
{
    emit("[registry] record \"");
    /* label is not guaranteed NUL-terminated; print at most 15 chars. */
    size_t i = 0;
    for (; i < LABEL_CAP - 1 && r->label[i]; i++) out(&r->label[i], 1);
    emit("\" is idle -- nothing to render.\n");
}

/*
 * win(): the curator-override routine that discloses the archival token (the
 * CTF flag). It is never installed as any record's handler on the benign
 * path, and -no-pie fixes it at a known address. Reaching it requires the UAF
 * function-pointer hijack. The flag is pulled live from the environment so it
 * is never compiled into the binary; a clearly-marked placeholder is used if
 * the operator forgot to provision one.
 */
void win(record_t *r)
{
    (void)r;
    const char *flag = getenv("ZSCTF_FLAG");
    if (!flag) {
        static const char warn[] =
            "WARNING: ZSCTF_FLAG is not set; serving placeholder token.\n";
        write(2, warn, sizeof(warn) - 1);
        flag = "zerosecurectf{REPLACE_ME_AT_DEPLOY}";
    }
    emit("[registry] curator override accepted -- archival token released:\n");
    emit(flag);
    emit("\n");
    _exit(0);
}

/*
 * admin_panel(): a DECOY routine (rabbit-hole R4). It has external linkage so
 * it shows up in nm/objdump right next to win(), and a solver scanning for a
 * "winning" symbol may be tempted to redirect the handler here. It is provably
 * inert: it reads NO environment and discloses NO token. Rejectable by reading
 * this source -- only win() touches ZSCTF_FLAG.
 */
void admin_panel(record_t *r)
{
    (void)r;
    emit("[registry] administrative console is sealed in this appliance build.\n");
    emit("[registry] (no archival token is dispensed here.)\n");
}

/* ---- per-instance decoy (rabbit-hole R5, varies by ZSCTF_SEED) ----------- */
static void make_seed_decoy(char *dst, size_t cap)
{
    /* FNV-1a over ZSCTF_SEED -> a per-instance marker. It is formatted to
     * FAIL the published strict validator ^zerosecurectf\{[a-z0-9_]{8,48}\}$
     * on purpose (it contains a hyphen), so a careful solver rejects it by the
     * format rule alone. */
    const char *seed = getenv("ZSCTF_SEED");
    if (!seed) seed = "0";
    uint64_t h = 1469598103934665603ULL;
    for (const char *p = seed; *p; p++) {
        h ^= (unsigned char)*p;
        h *= 1099511628211ULL;
    }
    static const char hx[] = "0123456789abcdef";
    char tag[17];
    for (int i = 0; i < 16; i++) tag[i] = hx[(h >> (i * 4)) & 0xf];
    tag[16] = '\0';
    /* "zerosecurectf{SESS-........}"  -- the '-' makes it fail the validator */
    size_t o = 0;
    const char *pre = "zerosecurectf{SESS-";
    for (const char *p = pre; *p && o + 1 < cap; p++) dst[o++] = *p;
    for (int i = 0; i < 16 && o + 1 < cap; i++) dst[o++] = tag[i];
    if (o + 1 < cap) dst[o++] = '}';
    dst[o] = '\0';
}

static void print_banner(void)
{
    emit("=== Reliquary Registry :: archival record service v2.3 ===\n");
    /* R1: a baked, flag-shaped decoy that FAILS the strict validator (it has
     * uppercase letters in the body). First thing a lazy `strings`/read sees. */
    emit("notice: legacy build tag zerosecureCTF{LEGACY_BUILD_TAG_IGNORE}\n");
    /* R5: per-instance decoy derived from ZSCTF_SEED; also fails the validator. */
    char decoy[64];
    make_seed_decoy(decoy, sizeof decoy);
    emit("notice: session marker ");
    emit(decoy);
    emit("\n");
    emit("Type 'help' for the command list.\n");
}

static void print_help(void)
{
    emit("commands:\n");
    emit("  new                 allocate a record (gets a default handler)\n");
    emit("  note <size>         allocate a raw note buffer of <size> bytes\n");
    emit("  rename <id> <len>   write <len> bytes into a RECORD's label\n");
    emit("  write <id> <len>    write <len> bytes into a NOTE buffer\n");
    emit("  free <id>           release a slot's chunk\n");
    emit("  show <id>           print a record's label and checksum\n");
    emit("  render <id>         invoke a record's handler\n");
    emit("  promote <id>        request administrative escalation for a record\n");
    emit("  help                this list\n");
    emit("  quit                disconnect\n");
}

/* ---- command implementations --------------------------------------------- */
static int find_free_slot(void)
{
    for (int i = 0; i < MAX_SLOTS; i++)
        if (kinds[i] == SLOT_EMPTY) return i;
    return -1;
}
static int valid_slot(long id)
{
    return id >= 0 && id < MAX_SLOTS && kinds[id] != SLOT_EMPTY;
}

static void cmd_new(void)
{
    int id = find_free_slot();
    if (id < 0) { emit("[registry] slot table full.\n"); return; }
    record_t *r = (record_t *)malloc(sizeof(record_t));
    if (!r) { emit("[registry] out of memory.\n"); return; }
    memset(r, 0, sizeof(*r));
    memcpy(r->label, "(unnamed)", 9);
    r->checksum = 0;
    r->render = default_render;
    slots[id] = r;
    kinds[id] = SLOT_RECORD;
    caps[id] = 0;
    emit("[registry] record #");
    emit_uint((unsigned long)id);
    emit(" created (handler installed).\n");
}

static void cmd_note(long size)
{
    if (size < 1 || size > MAX_WRITE) {
        emit("[registry] note size out of range (1..256).\n");
        return;
    }
    int id = find_free_slot();
    if (id < 0) { emit("[registry] slot table full.\n"); return; }
    void *p = malloc((size_t)size);
    if (!p) { emit("[registry] out of memory.\n"); return; }
    memset(p, 0, (size_t)size);
    slots[id] = p;
    kinds[id] = SLOT_NOTE;
    caps[id] = (size_t)size;
    emit("[registry] note #");
    emit_uint((unsigned long)id);
    emit(" created (");
    emit_uint((unsigned long)size);
    emit(" bytes).\n");
}

/* Read exactly `len` bytes from the wire, then copy at most `copy_cap` of them
 * into `dst`. We always consume `len` bytes so the protocol stays in sync even
 * when the write is capped. */
static void do_write(char *dst, size_t copy_cap, long len)
{
    if (len < 0 || len > MAX_WRITE) {
        emit("[registry] write length out of range (0..256).\n");
        return;
    }
    char tmp[MAX_WRITE];
    if (!read_exact(tmp, (size_t)len)) {
        emit("[registry] short write; connection drained.\n");
        return;
    }
    size_t n = (size_t)len;
    if (n > copy_cap) n = copy_cap;
    memcpy(dst, tmp, n);
    emit("[registry] wrote ");
    emit_uint((unsigned long)n);
    emit(" byte(s).\n");
}

static void cmd_rename(long id, long len)
{
    if (!valid_slot(id) || kinds[id] != SLOT_RECORD) {
        emit("[registry] rename expects a live record id.\n");
        /* still consume the bytes so the stream stays aligned */
        if (len > 0 && len <= MAX_WRITE) { char t[MAX_WRITE]; read_exact(t, (size_t)len); }
        return;
    }
    record_t *r = (record_t *)slots[id];
    /* A record rename may ONLY touch the label region: it can never reach the
     * render field through the legitimate path. The UAF is the only way. */
    do_write(r->label, LABEL_CAP, len);
}

static void cmd_write_note(long id, long len)
{
    if (!valid_slot(id) || kinds[id] != SLOT_NOTE) {
        emit("[registry] write expects a live note id.\n");
        if (len > 0 && len <= MAX_WRITE) { char t[MAX_WRITE]; read_exact(t, (size_t)len); }
        return;
    }
    /* A note's entire buffer is writable -- it is "just data". */
    do_write((char *)slots[id], caps[id], len);
}

static void cmd_free(long id)
{
    if (!valid_slot(id)) { emit("[registry] no such slot.\n"); return; }
    free(slots[id]);
    /* BUG (CWE-416): the slot is intentionally NOT cleared, nor is its kind.
     * The pointer now dangles; render/write on it is use-after-free. */
    emit("[registry] slot #");
    emit_uint((unsigned long)id);
    emit(" released.\n");
}

static void cmd_show(long id)
{
    if (!valid_slot(id) || kinds[id] != SLOT_RECORD) {
        emit("[registry] show expects a record id.\n");
        return;
    }
    record_t *r = (record_t *)slots[id];
    emit("[registry] record #");
    emit_uint((unsigned long)id);
    emit(": label=\"");
    size_t i = 0;
    for (; i < LABEL_CAP - 1 && r->label[i]; i++) out(&r->label[i], 1);
    emit("\" checksum=");
    emit_hex((unsigned long)r->checksum);
    emit("\n");
}

static void cmd_render(long id)
{
    if (!valid_slot(id) || kinds[id] != SLOT_RECORD) {
        emit("[registry] render expects a record id.\n");
        return;
    }
    record_t *r = (record_t *)slots[id];
    r->render(r);   /* <- calls the (possibly hijacked) handler */
}

static void cmd_promote(long id)
{
    /* Rabbit-hole R2/R4: a tempting "escalate to admin" feature that routes to
     * the inert admin_panel(). It dispenses no token and is not the win path. */
    if (!valid_slot(id) || kinds[id] != SLOT_RECORD) {
        emit("[registry] promote expects a record id.\n");
        return;
    }
    admin_panel((record_t *)slots[id]);
}

int main(void)
{
    print_banner();

    char line[512];
    for (;;) {
        emit("registry> ");
        ssize_t n = read_line(line, sizeof line);
        if (n < 0) break;               /* EOF */
        if (n == 0) continue;

        /* tokenize: verb and up to two numeric args */
        const char *p = line;
        while (*p == ' ') p++;
        const char *verb = p;
        while (*p && *p != ' ') p++;
        size_t vlen = (size_t)(p - verb);

        long a = 0, b = 0;
        const char *rest = p;
        a = parse_long(rest, &rest);
        b = parse_long(rest, &rest);

        if (vlen == 3 && !strncmp(verb, "new", 3)) {
            cmd_new();
        } else if (vlen == 4 && !strncmp(verb, "note", 4)) {
            cmd_note(a);
        } else if (vlen == 6 && !strncmp(verb, "rename", 6)) {
            cmd_rename(a, b);
        } else if (vlen == 5 && !strncmp(verb, "write", 5)) {
            cmd_write_note(a, b);
        } else if (vlen == 4 && !strncmp(verb, "free", 4)) {
            cmd_free(a);
        } else if (vlen == 4 && !strncmp(verb, "show", 4)) {
            cmd_show(a);
        } else if (vlen == 6 && !strncmp(verb, "render", 6)) {
            cmd_render(a);
        } else if (vlen == 7 && !strncmp(verb, "promote", 7)) {
            cmd_promote(a);
        } else if (vlen == 4 && !strncmp(verb, "help", 4)) {
            print_help();
        } else if (vlen == 4 && !strncmp(verb, "quit", 4)) {
            emit("[registry] goodbye.\n");
            break;
        } else {
            emit("[registry] unknown command; type 'help'.\n");
        }
    }
    return 0;
}
