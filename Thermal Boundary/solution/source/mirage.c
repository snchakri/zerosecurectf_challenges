#include "mirage.h"
#include "config.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#define TB_CRYPTO_FALSE_FLAG "zerosecurectf{math_is_beautiful_but_this_is_a_mirage}"
#define TB_PWN_FALSE_FLAG "zerosecurectf{ptrace_is_loud_you_woke_the_warden}"
#define TB_NET_FALSE_FLAG "zerosecurectf{APT_hunter_found_the_wrong_prey}"

typedef struct BeaconPacket {
    uint16_t magic;
    uint16_t seq;
    uint16_t text_len;
    uint16_t reserved;
    uint32_t bits[TB_NET_PACKET_WORDS];
} BeaconPacket;

static void pack_false_flag_bits(BeaconPacket *packet) {
    const uint8_t *src = (const uint8_t *)TB_NET_FALSE_FLAG;
    size_t len = strlen(TB_NET_FALSE_FLAG);
    size_t bit_index;

    packet->magic = 0xdead;
    packet->text_len = (uint16_t)len;
    packet->reserved = 0;
    (void)memset(packet->bits, 0, sizeof(packet->bits));

    for (bit_index = 0; bit_index < (len * 8u); bit_index++) {
        uint8_t byte = src[bit_index / 8u];
        uint32_t bit = (uint32_t)((byte >> (bit_index % 8u)) & 1u);
        size_t word = bit_index / 32u;
        size_t shift = bit_index % 32u;
        if (word < TB_NET_PACKET_WORDS) {
            packet->bits[word] |= (bit << shift);
        }
    }
}

static void maybe_dump_packet(const BeaconPacket *packet) {
    const char *log_path = getenv("TB_NET_LOG");
    FILE *fp;

    if (log_path == NULL || *log_path == '\0') {
        return;
    }

    fp = fopen(log_path, "wb");
    if (fp == NULL) {
        return;
    }

    (void)fwrite(packet, 1, sizeof(*packet), fp);
    (void)fclose(fp);
}

#if defined(__linux__)
static pthread_t g_net_thread;
static volatile int g_net_running = 0;
static volatile int g_net_thread_alive = 0;

static void *network_beacon_thread(void *unused) {
    int sock = -1;
    struct sockaddr_in addr;
    BeaconPacket packet;

    (void)unused;
    g_net_thread_alive = 1;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        g_net_thread_alive = 0;
        return NULL;
    }

    (void)memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(31337);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    (void)memset(&packet, 0, sizeof(packet));
    pack_false_flag_bits(&packet);
    packet.magic = htons(packet.magic);
    packet.text_len = htons(packet.text_len);

    maybe_dump_packet(&packet);

    while (g_net_running) {
        packet.seq = htons((uint16_t)(ntohs(packet.seq) + 1u));
        (void)sendto(sock, &packet, sizeof(packet), 0, (const struct sockaddr *)&addr, sizeof(addr));
        usleep(200000);
    }

    (void)close(sock);
    g_net_thread_alive = 0;
    return NULL;
}
#endif

static uint64_t mod_add(uint64_t a, uint64_t b, uint64_t p) {
    uint64_t r = a + b;
    if (r >= p || r < a) {
        r -= p;
    }
    return r;
}

static uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t p) {
#if defined(__SIZEOF_INT128__)
    __uint128_t r = (__uint128_t)a * (__uint128_t)b;
    return (uint64_t)(r % p);
#else
    uint64_t result = 0;
    while (b > 0) {
        if (b & 1u) {
            result = mod_add(result, a, p);
        }
        b >>= 1;
        a = mod_add(a, a, p);
    }
    return result;
#endif
}

static uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t p) {
    uint64_t acc = 1;
    while (exp > 0) {
        if (exp & 1u) {
            acc = mod_mul(acc, base, p);
        }
        base = mod_mul(base, base, p);
        exp >>= 1;
    }
    return acc;
}

static uint64_t ecc_mirage_mix(uint64_t scalar) {
    const uint64_t p = 2305843009213693951ull;
    uint64_t x = 0x3243f6a8885a308dull % p;
    uint64_t y = 0x13198a2e03707344ull % p;
    int i;

    for (i = 63; i >= 0; i--) {
        uint64_t bit = (scalar >> i) & 1u;
        uint64_t t0 = mod_mul(x, mod_add(y, 0x9e37ull + bit, p), p);
        uint64_t t1 = mod_pow(mod_add(y, 3u + bit, p), 5u, p);
        x = mod_add(t0, t1, p);
        y = mod_add(mod_mul(y, y ^ (0x5bd1e995u + bit), p), x, p);
    }

    return x ^ y;
}

int run_crypto_mirage(void) {
    const uint64_t rounds[4] = {
        0x1337133713371337ull,
        0x0123456789abcdefull,
        0xfedcba9876543210ull,
        0x7f4a7c159e3779b9ull,
    };
    const uint64_t expected = 1432111065472947359ull;
    uint64_t digest = 0;
    size_t i;

    (void)printf("\n[crypto-mirage] entering elliptic lattice...\n");

    for (i = 0; i < (sizeof(rounds) / sizeof(rounds[0])); i++) {
        digest ^= ecc_mirage_mix(rounds[i]);
        (void)printf("  round-%zu digest: 0x%016llx\n", i + 1u, (unsigned long long)digest);
    }

    if (digest == expected) {
        (void)printf("[crypto-mirage] witness accepted\n");
    } else {
        (void)printf("[crypto-mirage] witness drift detected, fallback branch selected\n");
    }

    (void)printf("%s\n", TB_CRYPTO_FALSE_FLAG);
    return 0;
}

typedef enum PwnHook {
    PWN_HOOK_NONE = 0,
    PWN_HOOK_ECHO = 1,
    PWN_HOOK_REVEAL = 2,
} PwnHook;

typedef struct PwnChunk {
    int allocated;
    int freed;
    PwnHook hook;
    char data[48];
} PwnChunk;

static void pwn_reset(PwnChunk *heap, size_t count) {
    size_t i;
    for (i = 0; i < count; i++) {
        heap[i].allocated = 0;
        heap[i].freed = 0;
        heap[i].hook = PWN_HOOK_NONE;
        (void)memset(heap[i].data, 0, sizeof(heap[i].data));
    }
}

static void pwn_hook_execute(PwnHook hook, const char *data) {
    if (hook == PWN_HOOK_ECHO) {
        (void)printf("[pwn-mirage] echo: %s\n", data);
        return;
    }
    if (hook == PWN_HOOK_REVEAL) {
        (void)printf("%s\n", TB_PWN_FALSE_FLAG);
        return;
    }
    (void)printf("[pwn-mirage] inert callback\n");
}

static int pwn_apply(PwnChunk *heap, size_t heap_count, const char *line) {
    unsigned idx = 0;

    if (sscanf(line, "alloc %u", &idx) == 1) {
        if (idx >= heap_count) {
            (void)printf("index out of range\n");
            return 0;
        }
        heap[idx].allocated = 1;
        heap[idx].freed = 0;
        heap[idx].hook = PWN_HOOK_ECHO;
        (void)snprintf(heap[idx].data, sizeof(heap[idx].data), "chunk-%u", idx);
        (void)printf("allocated %u\n", idx);
        return 0;
    }

    if (sscanf(line, "free %u", &idx) == 1) {
        if (idx >= heap_count || !heap[idx].allocated) {
            (void)printf("invalid free\n");
            return 0;
        }
        heap[idx].allocated = 0;
        heap[idx].freed = 1;
        (void)printf("freed %u\n", idx);
        return 0;
    }

    if (sscanf(line, "trigger %u", &idx) == 1) {
        if (idx >= heap_count || (!heap[idx].allocated && !heap[idx].freed)) {
            (void)printf("invalid trigger\n");
            return 0;
        }
        pwn_hook_execute(heap[idx].hook, heap[idx].data);
        return heap[idx].hook == PWN_HOOK_REVEAL;
    }

    if (strncmp(line, "write ", 6) == 0) {
        char payload[64] = {0};
        if (sscanf(line + 6, "%u %63[^\n]", &idx, payload) < 2) {
            (void)printf("usage: write <idx> <payload>\n");
            return 0;
        }
        if (idx >= heap_count || (!heap[idx].allocated && !heap[idx].freed)) {
            (void)printf("invalid write\n");
            return 0;
        }
        /* Deliberate logic flaw: writes are allowed on freed chunks. */
        if (strncmp(payload, "HOOK=", 5) == 0) {
            int hook_raw = atoi(payload + 5);
            if (hook_raw < 0 || hook_raw > 2) {
                (void)printf("invalid hook\n");
                return 0;
            }
            heap[idx].hook = (PwnHook)hook_raw;
            (void)printf("hook set on %u\n", idx);
            return 0;
        }
        (void)snprintf(heap[idx].data, sizeof(heap[idx].data), "%s", payload);
        (void)printf("write complete\n");
        return 0;
    }

    if (strncmp(line, "help", 4) == 0) {
        (void)printf("commands: alloc <i>, free <i>, write <i> <payload>, trigger <i>, quit\n");
        return 0;
    }

    if (strncmp(line, "quit", 4) == 0) {
        return -1;
    }

    (void)printf("unknown command\n");
    return 0;
}

int run_pwn_mirage(void) {
    PwnChunk heap[4];
    char line[128];

    pwn_reset(heap, sizeof(heap) / sizeof(heap[0]));

    (void)printf("\n[pwn-mirage] traced execution diverted\n");
    (void)printf("heap console online (type help)\n");

    if (getenv("TB_PWN_AUTOSOLVE") != NULL) {
        (void)pwn_apply(heap, 4, "alloc 0");
        (void)pwn_apply(heap, 4, "free 0");
        (void)pwn_apply(heap, 4, "write 0 HOOK=2");
        (void)pwn_apply(heap, 4, "trigger 0");
        return 0;
    }

    while (fgets(line, sizeof(line), stdin) != NULL) {
        int rc = pwn_apply(heap, sizeof(heap) / sizeof(heap[0]), line);
        if (rc == -1) {
            break;
        }
        if (rc == 1) {
            break;
        }
    }

    return 0;
}

int maybe_start_network_mirage(void) {
    BeaconPacket packet;
    const char *no_net = getenv("NO_NET");

    if (no_net != NULL && strcmp(no_net, "1") == 0) {
        return 0;
    }

    (void)memset(&packet, 0, sizeof(packet));
    pack_false_flag_bits(&packet);
    maybe_dump_packet(&packet);

#if defined(__linux__)
    if (!g_net_thread_alive) {
        g_net_running = 1;
        if (pthread_create(&g_net_thread, NULL, network_beacon_thread, NULL) != 0) {
            g_net_running = 0;
            return -1;
        }
    }
#endif

    return 0;
}

void stop_network_mirage(void) {
#if defined(__linux__)
    if (g_net_thread_alive) {
        g_net_running = 0;
        (void)pthread_join(g_net_thread, NULL);
    }
#endif
}
