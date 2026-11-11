/*
 * ZSCTF :: Oxbow  (rev)
 * ------------------------------------------------------------------------
 * A vendor ships its license check as a *flattened* state machine. Instead
 * of a readable sequence of steps, the checker is a single dispatch loop:
 *
 *     state = ENTRY;
 *     while (running) { do_block[state](); state = next(state); }
 *
 * where every block does one small transform on the L-byte register file and
 * then hands control to the next block it names. The order of the blocks in
 * the image means nothing; the only thing that decides what runs after what
 * is the per-block selector `next()`. The selector branches on a predicate
 * computed from a byte baked into each block -- and some of those branches
 * lead to blocks that never run. (A river bend cut off from the stream is an
 * "oxbow".) The real pipeline is whatever path you get by following the live
 * edge out of each block from ENTRY to a halt block.
 *
 * The flag is NOT stored in the clear and is NOT recoverable by a single XOR.
 * Its bytes are SCATTERED across an image slot table (mixed with decoy slots)
 * and gathered by a "confluence" walk: a linked list whose next-pointer at each
 * step is encrypted under a hash chain seeded by the *correct key itself* and
 * advanced by each recovered byte. Consequences:
 *   - `strings` on the image reveals nothing;
 *   - there is no `ct ^ keystream(X)` one-shot: the keystream byte at position i
 *     depends on the whole recovered prefix, and the traversal order is itself
 *     encrypted, so bytes must be peeled strictly in order;
 *   - patching out the comparison is useless -- a wrong key seeds a wrong chain,
 *     walks the wrong (decoy) slots and unwraps to garbage, never the flag.
 * The only way to the flag is to recover the real pipeline the dispatcher
 * walks, run it backwards to the one key that satisfies it, then follow the
 * confluence walk that key unlocks.
 *
 * This file is the engine. It is identical for every team. The per-instance
 * secret lives entirely in the ".oxb" image (see gen.py), which is what a
 * player reverse-engineers.
 *
 * Build (reproducible):  gcc -O2 -fno-stack-protector -s -o oxbow oxbow.c
 * Run:                   printf '%s' "<license-key>" | ./oxbow challenge.oxb
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ======================================================================
 * SHA-256 (public-domain style reference implementation). Used only to
 * drive the confluence walk that gathers the flag. Matches Python hashlib.
 * ====================================================================== */
typedef struct { uint32_t s[8]; uint64_t len; uint8_t buf[64]; size_t n; } sha256_ctx;

static uint32_t ror32(uint32_t x, int r){ return (x >> r) | (x << (32 - r)); }

static const uint32_t K256[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_block(sha256_ctx *c, const uint8_t *p){
  uint32_t w[64];
  for (int i = 0; i < 16; i++)
    w[i] = (uint32_t)p[i*4]<<24 | (uint32_t)p[i*4+1]<<16 | (uint32_t)p[i*4+2]<<8 | p[i*4+3];
  for (int i = 16; i < 64; i++){
    uint32_t s0 = ror32(w[i-15],7) ^ ror32(w[i-15],18) ^ (w[i-15]>>3);
    uint32_t s1 = ror32(w[i-2],17) ^ ror32(w[i-2],19) ^ (w[i-2]>>10);
    w[i] = w[i-16] + s0 + w[i-7] + s1;
  }
  uint32_t a=c->s[0],b=c->s[1],cc=c->s[2],d=c->s[3],e=c->s[4],f=c->s[5],g=c->s[6],h=c->s[7];
  for (int i = 0; i < 64; i++){
    uint32_t S1 = ror32(e,6) ^ ror32(e,11) ^ ror32(e,25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t t1 = h + S1 + ch + K256[i] + w[i];
    uint32_t S0 = ror32(a,2) ^ ror32(a,13) ^ ror32(a,22);
    uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);
    uint32_t t2 = S0 + mj;
    h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
  }
  c->s[0]+=a; c->s[1]+=b; c->s[2]+=cc; c->s[3]+=d;
  c->s[4]+=e; c->s[5]+=f; c->s[6]+=g; c->s[7]+=h;
}

static void sha256_init(sha256_ctx *c){
  c->s[0]=0x6a09e667; c->s[1]=0xbb67ae85; c->s[2]=0x3c6ef372; c->s[3]=0xa54ff53a;
  c->s[4]=0x510e527f; c->s[5]=0x9b05688c; c->s[6]=0x1f83d9ab; c->s[7]=0x5be0cd19;
  c->len=0; c->n=0;
}
static void sha256_update(sha256_ctx *c, const uint8_t *p, size_t len){
  c->len += (uint64_t)len * 8;
  while (len){
    size_t take = 64 - c->n; if (take > len) take = len;
    memcpy(c->buf + c->n, p, take); c->n += take; p += take; len -= take;
    if (c->n == 64){ sha256_block(c, c->buf); c->n = 0; }
  }
}
static void sha256_final(sha256_ctx *c, uint8_t out[32]){
  uint64_t bits = c->len;
  uint8_t pad = 0x80; sha256_update(c, &pad, 1);
  uint8_t z = 0; while (c->n != 56) sha256_update(c, &z, 1);
  uint8_t L8[8]; for (int i = 0; i < 8; i++) L8[i] = (uint8_t)(bits >> (56 - 8*i));
  sha256_update(c, L8, 8);
  for (int i = 0; i < 8; i++){
    out[i*4]   = (uint8_t)(c->s[i]>>24); out[i*4+1] = (uint8_t)(c->s[i]>>16);
    out[i*4+2] = (uint8_t)(c->s[i]>>8);  out[i*4+3] = (uint8_t)(c->s[i]);
  }
}

/* one-shot SHA-256 over a buffer */
static void sha256_bytes(const uint8_t *in, size_t len, uint8_t out[32]){
  sha256_ctx c; sha256_init(&c); sha256_update(&c, in, len); sha256_final(&c, out);
}

/* ======================================================================
 * The Oxbow flattened checker.
 *
 * Image format (little-endian, ver=2):
 *   "OXBW" | u8 ver | u8 L | u16 flag_len | u16 nblk | u8 entry | u8 rsv
 *   u8 sbox[256]
 *   u8 perm[L]
 *   block[nblk]   (6 bytes each: op, k, sA, sB, pk, c)
 *   u8 expected[L]
 *   -- confluence trailer --
 *   u16 n_slots
 *   u8  cipher[n_slots]      scattered+chained flag bytes (+ decoy slots)
 *   u8  next_enc[n_slots]    key-chain-encrypted next-pointers
 *   u8  tag[2*n_slots]       per-slot 2-byte commitments (solver self-check)
 *   u8  checksum[4]          SHA256(flag)[:4]
 *   u8  decoy_ct[flag_len]   one-shot-XOR red herring -> rejectable near-flag
 * The engine reads only n_slots, cipher[] and next_enc[]; the rest of the
 * trailer serves the offline solver and is ignored here.
 *
 * Each block transforms the whole L-byte register file `b`, then selects its
 * successor: next = pred(pk, c) ? sA : sB. A block with op END halts.
 *
 * Per-byte transforms (operate on every b[i]):
 *   0x11 XORK k : b[i] ^= k
 *   0x22 ADDK k : b[i]  = (b[i] + k) & 0xff
 *   0x33 MULK k : b[i]  = (b[i] * k) & 0xff
 *   0x44 ROLK k : b[i]  = rol8(b[i], k & 7)
 *   0x55 ADDP k : b[i]  = (b[i] + k*(i+1)) & 0xff
 *   0x66 XORP k : b[i] ^= (k + i) & 0xff
 *   0x77 SBOX   : b[i]  = sbox[b[i]]
 *   0x88 PERM   : out[i] = b[perm[i]]
 *   0x99 CHN  k : for i=1..L-1: b[i] ^= rol8(b[i-1], k & 7)
 *   0x00 END    : halt
 * ====================================================================== */
enum { END=0x00, XORK=0x11, ADDK=0x22, MULK=0x33, ROLK=0x44, ADDP=0x55,
       XORP=0x66, SBOX=0x77, PERM=0x88, CHN=0x99 };

#define MAX_FLAG  512    /* upper bound on flag_len */
#define MAX_STEPS 100000 /* dispatcher step cap (defensive against bad images) */
#define BLK_SZ    6

static uint8_t rol8(uint8_t v, int r){ r &= 7; return (uint8_t)((v << r) | (v >> (8 - r))); }

/* Edge selector. The result is a function of the per-block byte c only. */
static int pred(uint8_t pk, uint8_t c){
  uint32_t x = c;
  switch (pk & 3){
    case 0:  return (int)(( x*x - x       ) & 1u);
    case 1:  return (int)(( x*x + x       ) & 1u);
    case 2:  return (int)((( x*x - x) & 1u) ^ 1u);
    default: return (int)(( x*x + x + 1u  ) & 1u);
  }
}

typedef struct {
  uint8_t  L, entry;
  uint16_t flag_len, nblk;
  uint16_t n_slots;
  uint8_t  sbox[256];
  uint8_t  perm[256];      /* only first L used */
  uint8_t *blocks;         /* nblk * BLK_SZ */
  uint8_t  expected[256];
  uint8_t *cipher;         /* n_slots */
  uint8_t *next_enc;       /* n_slots */
} image_t;

#define CONF_LABEL "oxbow|confluence|v2"

/* Gather the scattered flag by following the key-chained confluence walk.
 * Mirrors confluence_build() in gen.py byte for byte. */
static void confluence_extract(const image_t *im, const uint8_t *key, uint8_t *flag){
  uint8_t h[32];
  sha256_ctx c; sha256_init(&c);
  sha256_update(&c, (const uint8_t *)CONF_LABEL, sizeof(CONF_LABEL) - 1);
  sha256_update(&c, key, im->L);
  sha256_final(&c, h);
  int ns = im->n_slots;
  int p = h[0] % ns;
  for (int i = 0; i < im->flag_len; i++){
    uint8_t out = (uint8_t)(im->cipher[p] ^ h[0]);
    flag[i] = out;
    uint8_t buf[33];
    memcpy(buf, h, 32); buf[32] = out;
    sha256_bytes(buf, 33, h);          /* advance chain with recovered byte */
    p = (im->next_enc[p] ^ h[1]) % ns; /* decrypt pointer to the next bend   */
  }
}

static int load_image(const char *path, image_t *im){
  FILE *f = fopen(path, "rb");
  if (!f){ fprintf(stderr, "oxbow: cannot open image '%s'\n", path); return -1; }
  uint8_t hdr[12];
  if (fread(hdr, 1, 12, f) != 12 || memcmp(hdr, "OXBW", 4) != 0){
    fprintf(stderr, "oxbow: bad image magic\n"); fclose(f); return -1; }
  im->L        = hdr[5];
  im->flag_len = (uint16_t)(hdr[6] | hdr[7] << 8);
  im->nblk     = (uint16_t)(hdr[8] | hdr[9] << 8);
  im->entry    = hdr[10];
  if (im->L == 0 || im->L > 64){ fprintf(stderr, "oxbow: bad L\n"); fclose(f); return -1; }
  if (im->flag_len == 0 || im->flag_len > MAX_FLAG){
    fprintf(stderr, "oxbow: bad flag_len\n"); fclose(f); return -1; }
  if (im->nblk == 0 || im->nblk > 255 || im->entry >= im->nblk){
    fprintf(stderr, "oxbow: bad block table\n"); fclose(f); return -1; }
  if (fread(im->sbox, 1, 256, f) != 256){ fclose(f); return -1; }
  if (fread(im->perm, 1, im->L, f) != im->L){ fclose(f); return -1; }
  im->blocks = malloc((size_t)im->nblk * BLK_SZ);
  if (!im->blocks || fread(im->blocks, 1, (size_t)im->nblk * BLK_SZ, f) != (size_t)im->nblk * BLK_SZ){
    fclose(f); return -1; }
  if (fread(im->expected, 1, im->L, f) != im->L){ fclose(f); return -1; }
  uint8_t ns8[2];
  if (fread(ns8, 1, 2, f) != 2){ fclose(f); return -1; }
  im->n_slots = (uint16_t)(ns8[0] | ns8[1] << 8);
  if (im->n_slots < im->flag_len || im->n_slots > 255){
    fprintf(stderr, "oxbow: bad slot table\n"); fclose(f); return -1; }
  im->cipher   = malloc(im->n_slots);
  im->next_enc = malloc(im->n_slots);
  if (!im->cipher || !im->next_enc
      || fread(im->cipher,   1, im->n_slots, f) != im->n_slots
      || fread(im->next_enc, 1, im->n_slots, f) != im->n_slots){
    fclose(f); return -1; }
  /* tag[], checksum[] and decoy_ct[] follow but are only used by the solver. */
  fclose(f);
  return 0;
}

/* Walk the flattened dispatcher over register file b[0..L-1], in place. */
static void run(const image_t *im, uint8_t *b){
  uint8_t tmp[256];
  int L = im->L;
  int st = im->entry;
  for (int steps = 0; steps < MAX_STEPS; steps++){
    const uint8_t *blk = im->blocks + (size_t)st * BLK_SZ;
    uint8_t op = blk[0], k = blk[1], sA = blk[2], sB = blk[3], pk = blk[4], c = blk[5];
    switch (op){
      case XORK:{ for (int i=0;i<L;i++) b[i] ^= k; } break;
      case ADDK:{ for (int i=0;i<L;i++) b[i] = (uint8_t)(b[i] + k); } break;
      case MULK:{ for (int i=0;i<L;i++) b[i] = (uint8_t)(b[i] * k); } break;
      case ROLK:{ for (int i=0;i<L;i++) b[i] = rol8(b[i], k); } break;
      case ADDP:{ for (int i=0;i<L;i++) b[i] = (uint8_t)(b[i] + k*(i+1)); } break;
      case XORP:{ for (int i=0;i<L;i++) b[i] ^= (uint8_t)(k + i); } break;
      case SBOX:{ for (int i=0;i<L;i++) b[i] = im->sbox[b[i]]; } break;
      case PERM:{ for (int i=0;i<L;i++) tmp[i] = b[im->perm[i]];
                  for (int i=0;i<L;i++) b[i] = tmp[i]; } break;
      case CHN :{ for (int i=1;i<L;i++) b[i] ^= rol8(b[i-1], k); } break;
      case END : return;
      default  : return;   /* unknown opcode: halt defensively */
    }
    st = pred(pk, c) ? sA : sB;
    if (st >= im->nblk) return;  /* bad edge: halt defensively */
  }
}

int main(int argc, char **argv){
  const char *path = (argc > 1) ? argv[1] : "challenge.oxb";
  image_t im; memset(&im, 0, sizeof im);
  if (load_image(path, &im) != 0) return 2;

  /* read the license key (one line) from stdin */
  char line[128];
  if (!fgets(line, sizeof line, stdin)){ printf("DENIED no key provided\n"); return 1; }
  size_t klen = strlen(line);
  while (klen && (line[klen-1] == '\n' || line[klen-1] == '\r')) line[--klen] = 0;

  if (klen != im.L){
    printf("DENIED key must be exactly %d characters\n", im.L);
    return 1;
  }

  uint8_t inp[256], b[256];
  memcpy(inp, line, im.L);
  memcpy(b, line, im.L);
  run(&im, b);

  int ok = (memcmp(b, im.expected, im.L) == 0);

  /* The flag is reconstructed from the SUBMITTED key via the confluence walk,
   * regardless of `ok`. A wrong key (or a patched-out compare) therefore walks
   * the wrong slots and yields garbage; only the true key gathers the flag. */
  uint8_t flag[MAX_FLAG];
  confluence_extract(&im, inp, flag);

  if (ok){
    fwrite(flag, 1, im.flag_len, stdout);
    fputc('\n', stdout);
    return 0;
  } else {
    printf("DENIED invalid license key\n");
    return 1;
  }
}
