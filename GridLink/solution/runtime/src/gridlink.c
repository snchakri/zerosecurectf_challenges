/*
 * GridLink Meter Gateway  --  prepaid micro-grid energy-credit front-end.
 *
 * A small binary request/response service that a neighbourhood micro-grid
 * controller exposes to prepaid smart meters. Clients top up rupee balance,
 * pre-purchase kWh credit blocks, and the field-engineering diagnostic unlocks
 * a maintenance service token once a meter register crosses its factory ceiling.
 *
 * Wire format (little-endian):
 *   request  = "GLNK"(4) | opcode(u8) | flags(u8) | body_len(u16) | body[body_len]
 *   response = ASCII, one record per line, '\n' terminated.
 *
 * The service holds no secret on disk: the maintenance token comes from the
 * process environment (ZSCTF_FLAG); per-instance tariff / wallet / ceiling /
 * engineer PIN are derived deterministically from ZSCTF_SEED.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdarg.h>

#if defined(_WIN32)
#include <io.h>
#include <fcntl.h>
#endif

/* ---- published policy constants (also echoed in the connect banner) ------ */
#define MAGIC0 'G'
#define MAGIC1 'L'
#define MAGIC2 'N'
#define MAGIC3 'K'
#define HDR_LEN 8u
#define MAX_BODY 256u
#define MAX_BLOCK 300000000u   /* enterprise block-purchase ceiling (units) */

/* opcodes */
enum {
    OP_TOPUP  = 1,   /* buy credit, retail: u16 units                        */
    OP_STATUS = 2,   /* read meter + wallet                                  */
    OP_ADJUST = 3,   /* engineer fine-adjust: i32 delta + u32 pin            */
    OP_BLOCK  = 4,   /* enterprise bulk block pre-purchase: u32 units        */
    OP_DIAG   = 5    /* factory diagnostic: emit token when register tripped */
};

/* ---- per-instance configuration ------------------------------------------ */
typedef struct {
    uint32_t tariff_paise;     /* price of one kWh credit, in paise          */
    int64_t  wallet_paise;     /* opening rupee balance, in paise            */
    int64_t  maint_threshold;  /* register value that trips the diagnostic   */
    uint32_t tech_pin;         /* engineer adjust PIN (never transmitted)    */
} cfg_t;

typedef struct {
    int64_t wallet_paise;
    int64_t meter_credits;     /* kWh register */
} state_t;

static cfg_t   g_cfg;
static state_t g_state;
static const char *g_flag;

/* ---- deterministic per-instance derivation ------------------------------- */
static uint64_t fnv1a64(const char *s) {
    uint64_t h = 1469598103934665603ULL;
    if (s) {
        for (; *s; ++s) {
            h ^= (unsigned char)*s;
            h *= 1099511628211ULL;
        }
    }
    return h;
}

static uint64_t splitmix64(uint64_t *x) {
    uint64_t z = (*x += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static void derive_config(void) {
    const char *seed = getenv("ZSCTF_SEED");
    if (seed == NULL || seed[0] == '\0') {
        fprintf(stderr, "WARNING: ZSCTF_SEED unset; using non-unique default instance.\n");
        seed = "gridlink-default-seed";
    }
    uint64_t st = fnv1a64(seed);

    /* tariff in [500, 899] paise  (Rs 5.00 - Rs 8.99 / kWh) */
    g_cfg.tariff_paise = 500u + (uint32_t)(splitmix64(&st) % 400u);
    /* opening balance in [40000, 60000] paise (Rs 400 - Rs 600) */
    g_cfg.wallet_paise = 40000 + (int64_t)(splitmix64(&st) % 20001u);
    /* factory register ceiling in [900e6, 1100e6] kWh */
    g_cfg.maint_threshold = 900000000 + (int64_t)(splitmix64(&st) % 200000001u);
    /* engineer PIN: full 32-bit, kept server-side only */
    g_cfg.tech_pin = (uint32_t)splitmix64(&st);
    if (g_cfg.tech_pin == 0u) g_cfg.tech_pin = 0xA5A5A5A5u;

    g_state.wallet_paise  = g_cfg.wallet_paise;
    g_state.meter_credits = 0;
}

static void load_flag(void) {
    const char *f = getenv("ZSCTF_FLAG");
    if (f == NULL || f[0] == '\0') {
        fprintf(stderr, "WARNING: ZSCTF_FLAG unset; serving placeholder token. "
                        "Set ZSCTF_FLAG at deploy.\n");
        f = "zerosecurectf{REPLACE_ME_AT_DEPLOY}";
    }
    g_flag = f;
}

/* ---- framed I/O ---------------------------------------------------------- */
static int read_exact(unsigned char *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        size_t r = fread(buf + got, 1, n - got, stdin);
        if (r == 0) return 0;   /* EOF or error */
        got += r;
    }
    return 1;
}

static uint16_t rd_u16(const unsigned char *p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}
static uint32_t rd_u32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

#if defined(__GNUC__)
__attribute__((format(printf, 1, 2)))
#endif
static void line(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    fflush(stdout);
}

static void banner(void) {
    line("GridLink Meter Gateway");
    line("proto GLNK v1 le");
    line("config tariff_paise %" PRIu32, g_cfg.tariff_paise);
    line("config wallet_paise %" PRId64, g_state.wallet_paise);
    line("config maint_threshold %" PRId64, g_cfg.maint_threshold);
    line("config max_block %u", MAX_BLOCK);
    line("meter credits %" PRId64, g_state.meter_credits);
    line("opcodes TOPUP=1 STATUS=2 ADJUST=3 BLOCK=4 DIAG=5");
    line("ready");
}

/* ---- handlers ------------------------------------------------------------ */
static void op_topup(const unsigned char *body, uint16_t blen) {
    if (blen < 2) { line("ERR short_body"); return; }
    uint16_t units = rd_u16(body);
    if (units < 1) { line("ERR topup_policy"); return; }
    int64_t cost = (int64_t)units * (int64_t)g_cfg.tariff_paise;
    if (g_state.wallet_paise < cost) { line("ERR insufficient_funds"); return; }
    g_state.wallet_paise  -= cost;
    g_state.meter_credits += (int64_t)units;
    line("OK topup units=%u cost_paise=%" PRId64 " meter=%" PRId64 " wallet=%" PRId64,
         (unsigned)units, cost, g_state.meter_credits, g_state.wallet_paise);
}

static void op_status(void) {
    line("STATUS meter=%" PRId64 " wallet=%" PRId64,
         g_state.meter_credits, g_state.wallet_paise);
}

static void op_adjust(const unsigned char *body, uint16_t blen) {
    if (blen < 8) { line("ERR short_body"); return; }
    int32_t  delta = (int32_t)rd_u32(body);
    uint32_t pin   = rd_u32(body + 4);
    if (pin != g_cfg.tech_pin) { line("ERR bad_pin"); return; }
    if (delta < -100 || delta > 100) { line("ERR adjust_policy"); return; }
    g_state.meter_credits += (int64_t)delta;
    line("OK adjust meter=%" PRId64, g_state.meter_credits);
}

static void op_block(const unsigned char *body, uint16_t blen) {
    if (blen < 4) { line("ERR short_body"); return; }
    uint32_t units = rd_u32(body);
    if (units < 1u || units > MAX_BLOCK) { line("ERR block_policy"); return; }
    uint32_t cost_paise = units * g_cfg.tariff_paise;
    if (g_state.wallet_paise < (int64_t)cost_paise) { line("ERR insufficient_funds"); return; }
    g_state.wallet_paise  -= (int64_t)cost_paise;
    g_state.meter_credits += (int64_t)units;
    line("OK block units=%u cost_paise=%u meter=%" PRId64 " wallet=%" PRId64,
         units, cost_paise, g_state.meter_credits, g_state.wallet_paise);
}

static void op_diag(void) {
    if (g_state.meter_credits >= g_cfg.maint_threshold) {
        line("DIAG unlocked");
        line("FLAG %s", g_flag);
    } else {
        line("DIAG locked meter=%" PRId64 " threshold=%" PRId64,
             g_state.meter_credits, g_cfg.maint_threshold);
    }
}

int main(void) {
#if defined(_WIN32)
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    setvbuf(stdout, NULL, _IONBF, 0);

    derive_config();
    load_flag();
    banner();

    unsigned char hdr[HDR_LEN];
    unsigned char body[MAX_BODY];

    for (;;) {
        if (!read_exact(hdr, HDR_LEN)) break;   /* clean EOF */
        if (hdr[0] != MAGIC0 || hdr[1] != MAGIC1 ||
            hdr[2] != MAGIC2 || hdr[3] != MAGIC3) {
            line("ERR bad_magic");
            break;                               /* stream desynced; stop */
        }
        uint8_t  opcode = hdr[4];
        uint16_t blen   = rd_u16(hdr + 6);
        if (blen > MAX_BODY) { line("ERR body_too_long"); break; }
        if (blen > 0 && !read_exact(body, blen)) break;

        switch (opcode) {
            case OP_TOPUP:  op_topup(body, blen);  break;
            case OP_STATUS: op_status();           break;
            case OP_ADJUST: op_adjust(body, blen); break;
            case OP_BLOCK:  op_block(body, blen);  break;
            case OP_DIAG:   op_diag();             break;
            default:        line("ERR bad_opcode"); break;
        }
    }
    return 0;
}
