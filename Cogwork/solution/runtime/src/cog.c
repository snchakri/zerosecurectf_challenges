/*
 * ZSCTF :: Cogwork  (rev)
 * ------------------------------------------------------------------------
 * The "Cog" virtual machine: a tiny custom-ISA bytecode engine that a
 * fictional vendor ships as a license-key validator. It loads a bytecode
 * image (the ".cog" file), runs the embedded program over the license key
 * you type, and compares the transformed result to an embedded target. The
 * correct key is the sole gate: a wrong key is DENIED and the engine exits.
 *
 * ---- v2 image format: the "ratchet" flag-extraction standard (S2/S2a) ----
 * Once the gears line up (the key is correct) the engine does NOT print the
 * whole flag in one shot. It becomes a GENERATOR / state machine driven one
 * character per "crank notch":
 *
 *   S_0        = SHA256(RATCHET_LABEL || key)                 (seed from key)
 *   for i in 0..flag_len-1:
 *     tok_i    = SHA256(S_i || "t" || i_LE32)[:4]             (expected notch gate)
 *     read one submitted 4-byte token from stdin (one hex line);
 *     if submitted == tok_i:
 *         emit flag_ct[i] ^ SHA256(S_i || submitted || "e" || i_LE32)[0]   (real char)
 *     else:
 *         emit decoy_ct[i] ^ SHA256(decoy_seed || "d" || i_LE32)[0]        (decoy char)
 *     S_{i+1}  = SHA256(S_i || submitted || "a" || i_LE32)    (ratchet advance)
 *   finally print TRAIL = first 4 bytes of S_N, in hex.
 *
 * Why this is stronger than a one-shot XOR wrap:
 *   - `strings` on the image reveals nothing (flag stored XOR-wrapped);
 *   - there is NO single keystream(key): each flag byte is unwrapped with a
 *     byte fused from BOTH the running state AND the submitted token, so a
 *     one-shot `flag_ct ^ keystream(key)` yields garbage;
 *   - patching out the compare does not help: a wrong key seeds a wrong S_0,
 *     so every computed token is wrong and every notch routes to the DECOY;
 *   - the decoy path is token-INDEPENDENT (keyed only by the public
 *     decoy_seed), so any all-wrong-token walk assembles to exactly one
 *     fixed, per-instance "near-flag" -- a deliberate, format-INVALID bait.
 * The only way to the real flag is the true key (which produces the token
 * sequence) -- recovered by running the Cog program backwards.
 *
 * This file is the engine. It is identical for every team. The per-instance
 * secret lives entirely in the .cog image (see gen.py), which is what a
 * player reverse-engineers.
 *
 * Build (reproducible):  gcc -O2 -fno-stack-protector -s -o cog cog.c
 * Run:   printf '%s\n%s\n' "<license-key>" "<tok0_hex>" ... | ./cog challenge.cog
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ======================================================================
 * SHA-256 (public-domain style reference implementation). Used by the ratchet
 * (token gates + emit/decoy keystream bytes + state advance). Matches hashlib.
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

/* H(out, a||b||c||d): SHA-256 over up to four concatenated buffers. Used by the
 * ratchet below. Pass NULL/0 for unused buffers. */
static void H(uint8_t out[32],
              const uint8_t *a, size_t na, const uint8_t *b, size_t nb,
              const uint8_t *c, size_t nc, const uint8_t *d, size_t nd){
  sha256_ctx x; sha256_init(&x);
  if (na) sha256_update(&x, a, na);
  if (nb) sha256_update(&x, b, nb);
  if (nc) sha256_update(&x, c, nc);
  if (nd) sha256_update(&x, d, nd);
  sha256_final(&x, out);
}

/* ======================================================================
 * The Cog virtual machine.
 *
 * Image format (little-endian, v2):
 *   "COGW" | u8 ver(=2) | u8 L | u16 flag_len | u16 prog_len
 *   u8 sbox[256] | u8 perm[L] | u8 program[prog_len]
 *   u8 expected[L] | u8 flag_ct[flag_len]
 *   u8 decoy_seed[16] | u8 decoy_ct[flag_len]        (v2 ratchet trailer)
 *
 * Opcodes (operate on the whole L-byte register file `b`):
 *   0x11 XORK  k : b[i] ^= k
 *   0x22 ADDK  k : b[i]  = (b[i] + k)  & 0xff
 *   0x33 MULK  k : b[i]  = (b[i] * k)  & 0xff        (k odd -> invertible)
 *   0x44 ROLK  k : b[i]  = rol8(b[i], k & 7)
 *   0x55 ADDP  k : b[i]  = (b[i] + k*(i+1)) & 0xff
 *   0x66 SBOX    : b[i]  = sbox[b[i]]
 *   0x77 PERM    : out[i] = b[perm[i]]
 *   0x88 CHN   k : for i=1..L-1: b[i] ^= rol8(b[i-1], k & 7)   (running)
 *   0x99 END     : halt
 * ====================================================================== */
enum { XORK=0x11, ADDK=0x22, MULK=0x33, ROLK=0x44, ADDP=0x55,
       SBOX=0x66, PERM=0x77, CHN=0x88, END=0x99 };

#define MAX_FLAG 512   /* upper bound on flag_len; bounds the decrypt buffers */
#define DECOY_SEED_LEN 16

/* Ratchet domain-separation label (must match gen.py RATCHET_LABEL). */
static const uint8_t RATCHET_LABEL[] = "cogwork-ratchet-v1|";
#define RATCHET_LABEL_LEN (sizeof(RATCHET_LABEL) - 1)

static uint8_t rol8(uint8_t v, int r){ r &= 7; return (uint8_t)((v << r) | (v >> (8 - r))); }

typedef struct {
  uint8_t  L;
  uint16_t flag_len, prog_len;
  uint8_t  sbox[256];
  uint8_t  perm[256];      /* only first L used */
  uint8_t *program;
  uint8_t  expected[256];
  uint8_t *flag_ct;
  uint8_t  decoy_seed[DECOY_SEED_LEN];
  uint8_t *decoy_ct;
} image_t;

static int load_image(const char *path, image_t *im){
  FILE *f = fopen(path, "rb");
  if (!f){ fprintf(stderr, "cog: cannot open image '%s'\n", path); return -1; }
  uint8_t hdr[10];
  if (fread(hdr, 1, 10, f) != 10 || memcmp(hdr, "COGW", 4) != 0){
    fprintf(stderr, "cog: bad image magic\n"); fclose(f); return -1; }
  if (hdr[4] != 2){ fprintf(stderr, "cog: unsupported image version %d\n", hdr[4]); fclose(f); return -1; }
  im->L        = hdr[5];
  im->flag_len = (uint16_t)(hdr[6] | hdr[7] << 8);
  im->prog_len = (uint16_t)(hdr[8] | hdr[9] << 8);
  if (im->L == 0 || im->L > 64){ fprintf(stderr, "cog: bad L\n"); fclose(f); return -1; }
  if (im->flag_len == 0 || im->flag_len > MAX_FLAG){
    fprintf(stderr, "cog: bad flag_len\n"); fclose(f); return -1; }
  if (fread(im->sbox, 1, 256, f) != 256){ fclose(f); return -1; }
  if (fread(im->perm, 1, im->L, f) != im->L){ fclose(f); return -1; }
  im->program = malloc(im->prog_len);
  if (!im->program || fread(im->program, 1, im->prog_len, f) != im->prog_len){ fclose(f); return -1; }
  if (fread(im->expected, 1, im->L, f) != im->L){ fclose(f); return -1; }
  im->flag_ct = malloc(im->flag_len);
  if (!im->flag_ct || fread(im->flag_ct, 1, im->flag_len, f) != im->flag_len){ fclose(f); return -1; }
  if (fread(im->decoy_seed, 1, DECOY_SEED_LEN, f) != DECOY_SEED_LEN){
    fprintf(stderr, "cog: truncated decoy_seed\n"); fclose(f); return -1; }
  im->decoy_ct = malloc(im->flag_len);
  if (!im->decoy_ct || fread(im->decoy_ct, 1, im->flag_len, f) != im->flag_len){
    fprintf(stderr, "cog: truncated decoy_ct\n"); fclose(f); return -1; }
  fclose(f);
  return 0;
}

/* Run the embedded program over register file b[0..L-1], in place. */
static void run(const image_t *im, uint8_t *b){
  uint8_t tmp[256];
  const uint8_t *pc = im->program;
  const uint8_t *end = im->program + im->prog_len;
  int L = im->L;
  while (pc < end){
    uint8_t op = *pc++;
    switch (op){
      case XORK:{ uint8_t k = *pc++; for (int i=0;i<L;i++) b[i] ^= k; } break;
      case ADDK:{ uint8_t k = *pc++; for (int i=0;i<L;i++) b[i] = (uint8_t)(b[i] + k); } break;
      case MULK:{ uint8_t k = *pc++; for (int i=0;i<L;i++) b[i] = (uint8_t)(b[i] * k); } break;
      case ROLK:{ uint8_t k = *pc++; for (int i=0;i<L;i++) b[i] = rol8(b[i], k); } break;
      case ADDP:{ uint8_t k = *pc++; for (int i=0;i<L;i++) b[i] = (uint8_t)(b[i] + k*(i+1)); } break;
      case SBOX:{ for (int i=0;i<L;i++) b[i] = im->sbox[b[i]]; } break;
      case PERM:{ for (int i=0;i<L;i++) tmp[i] = b[im->perm[i]];
                  for (int i=0;i<L;i++) b[i] = tmp[i]; } break;
      case CHN :{ uint8_t k = *pc++; for (int i=1;i<L;i++) b[i] ^= rol8(b[i-1], k); } break;
      case END : return;
      default  : /* unknown opcode: halt defensively */ return;
    }
  }
}

/* 4-byte little-endian encoding of i (matches gen.py struct.pack("<I", i)). */
static void i4_le(uint32_t i, uint8_t out[4]){
  out[0] = (uint8_t)(i & 0xff); out[1] = (uint8_t)((i >> 8) & 0xff);
  out[2] = (uint8_t)((i >> 16) & 0xff); out[3] = (uint8_t)((i >> 24) & 0xff);
}

static int hexval(int ch){
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
  return -1;
}

/* Read one submitted token line from stdin and decode it into out[4].
 * A token is up to 8 hex nibbles (4 bytes, big-endian over the 4 bytes, i.e.
 * the first two hex chars are out[0]). Anything malformed -- non-hex chars, or
 * other than exactly 8 nibbles -- is treated as INVALID and zero-filled, which
 * can never match a canonical token, so that notch deterministically routes to
 * the decoy branch. Returns 0 on a read, -1 on EOF (also zero-fills out). */
static int read_token(uint8_t out[4]){
  char line[64];
  out[0] = out[1] = out[2] = out[3] = 0;
  if (!fgets(line, sizeof line, stdin)) return -1;
  size_t n = strlen(line);
  while (n && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = 0;
  /* count leading/trailing whitespace off */
  size_t a = 0; while (line[a] == ' ' || line[a] == '\t') a++;
  size_t b = strlen(line + a);
  while (b && (line[a+b-1] == ' ' || line[a+b-1] == '\t')) b--;
  if (b != 8) return 0;                 /* short/long -> stays zero-filled */
  uint8_t tmp[4];
  for (int i = 0; i < 4; i++){
    int hi = hexval((unsigned char)line[a + i*2]);
    int lo = hexval((unsigned char)line[a + i*2 + 1]);
    if (hi < 0 || lo < 0) return 0;     /* non-hex -> stays zero-filled */
    tmp[i] = (uint8_t)((hi << 4) | lo);
  }
  memcpy(out, tmp, 4);
  return 0;
}

int main(int argc, char **argv){
  const char *path = (argc > 1) ? argv[1] : "challenge.cog";
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

  /* The gear gate is the SOLE entry: a wrong key is denied and we exit. */
  if (!ok){
    printf("DENIED invalid license key\n");
    return 1;
  }

  /* ---- v2 ratchet: stream the flag one notch at a time ------------------
   * The engine is now a GENERATOR seeded from the recovered key. For each of
   * the flag_len notches it computes the expected per-step token, reads one
   * submitted token line, and emits either the real flag char (token matches)
   * or a decoy char (token wrong). The emit keystream byte is fused from both
   * the running state AND the submitted token, so there is no single XOR and
   * no compare to patch. The state is advanced by the SUBMITTED token, so a
   * correct walk reproduces the canonical path and the TRAIL checksum. */
  uint8_t S[32];
  H(S, RATCHET_LABEL, RATCHET_LABEL_LEN, inp, im.L, NULL, 0, NULL, 0);

  for (int i = 0; i < im.flag_len; i++){
    uint8_t i4[4]; i4_le((uint32_t)i, i4);

    uint8_t th[32];
    H(th, S, 32, (const uint8_t *)"t", 1, i4, 4, NULL, 0);   /* expected token */

    uint8_t sub[4];
    read_token(sub);                                          /* submitted token */

    int match = (memcmp(sub, th, 4) == 0);

    uint8_t ch;
    if (match){
      uint8_t eh[32];
      H(eh, S, 32, sub, 4, (const uint8_t *)"e", 1, i4, 4);
      ch = (uint8_t)(im.flag_ct[i] ^ eh[0]);                  /* real flag char */
    } else {
      uint8_t dh[32];
      H(dh, im.decoy_seed, DECOY_SEED_LEN, (const uint8_t *)"d", 1, i4, 4, NULL, 0);
      ch = (uint8_t)(im.decoy_ct[i] ^ dh[0]);                 /* decoy char */
    }
    putchar(ch);

    /* advance the ratchet by the submitted token */
    uint8_t ah[32];
    H(ah, S, 32, sub, 4, (const uint8_t *)"a", 1, i4, 4);
    memcpy(S, ah, 32);
  }
  putchar('\n');

  /* TRAIL: first 4 bytes of the final state S_N, as hex. On a fully correct
   * walk this equals the canonical checksum the solver predicts. */
  printf("TRAIL %02x%02x%02x%02x\n", S[0], S[1], S[2], S[3]);
  fflush(stdout);
  return 0;
}
