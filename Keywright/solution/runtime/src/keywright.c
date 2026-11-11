/*
 * ZSCTF :: Keywright  (rev)
 * ------------------------------------------------------------------------
 * An offline *license-key validator*, the kind a vendor ships so that a
 * product can check a key with no phone-home. The vendor's keygen produced,
 * for each customer, exactly one license key. This program re-checks it.
 *
 * It loads a per-customer "license definition" image (the ".kwl" file),
 * parses the license key you type into a vector of integer words, and checks
 * that the vector satisfies a whole SYSTEM of arithmetic constraints baked
 * into the image. If (and only if) every constraint holds, it unwraps and
 * prints the flag.
 *
 * The constraint system is a set of modular linear congruences
 *
 *        A * x  ==  t   (mod 2^32)
 *
 * where A (a dense square matrix) and t (the target vector) live in the
 * image in the clear, and x is the vector your key decodes to. Because A is
 * invertible over the ring Z/2^32, the system has exactly ONE solution x,
 * hence exactly one valid license key.
 *
 * The flag is NOT stored in the clear. It is XORed with a SHA-256 keystream
 * derived from the *correct key itself*, so:
 *   - `strings` on the image reveals nothing;
 *   - patching out the comparison is useless -- a wrong key derives a wrong
 *     keystream and unwraps to garbage, never the flag.
 * The only way to the flag is to recover the constraint system and SOLVE it
 * for the key that satisfies it.
 *
 * This file is the engine. It is identical for every team. The per-instance
 * secret lives entirely in the .kwl image (see gen.py), which is what a
 * player reverse-engineers.
 *
 * Build (reproducible):  gcc -O2 -fno-stack-protector -s -o keywright keywright.c
 * Run:                   printf '%s' "<license-key>" | ./keywright license.kwl
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

/* ======================================================================
 * SHA-256 (public-domain style reference implementation). Used only to
 * derive the flag keystream from the correct key. Matches Python hashlib.
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

/* keystream = SHA256(key || 0x00) || SHA256(key || 0x01) || ... truncated */
static void keystream(const uint8_t *key, size_t klen, uint8_t *out, size_t outlen){
  size_t done = 0; uint8_t j = 0;
  while (done < outlen){
    sha256_ctx c; sha256_init(&c);
    sha256_update(&c, key, klen);
    sha256_update(&c, &j, 1);
    uint8_t blk[32]; sha256_final(&c, blk);
    size_t take = outlen - done; if (take > 32) take = 32;
    memcpy(out + done, blk, take); done += take; j++;
  }
}

/* ======================================================================
 * The Keywright license-definition image.
 *
 * Image format (little-endian):
 *   "KWL1" | u8 n | u8 g | u16 flag_len
 *   u32 A[n*n]          (row-major constraint matrix, each entry mod 2^32)
 *   u32 t[n]            (target vector)
 *   u8  flag_ct[flag_len]
 *
 * A license key is `n` groups of `g` base-32 characters (Crockford-style
 * alphabet, no I/L/O/U), joined by '-'. Each group decodes, big-endian base
 * 32, to one unsigned word x[i] in [0, 32^g). The validator computes
 *      y[i] = sum_j A[i*n+j] * x[j]   (mod 2^32)
 * and accepts the key iff y == t.
 * ====================================================================== */
#define MAGIC   "KWL1"
#define MAX_N   16      /* upper bound on the number of words / matrix dim    */
#define MAX_G   8       /* upper bound on base-32 chars per group (<= 6 fits) */
#define MAX_FLAG 512    /* upper bound on flag_len; bounds the decrypt buffer */

/* Crockford-style base-32 alphabet (digits + consonants, no I L O U). */
static const char ALPHABET[33] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

typedef struct {
  uint8_t  n, g;
  uint16_t flag_len;
  uint32_t A[MAX_N * MAX_N];
  uint32_t t[MAX_N];
  uint8_t  flag_ct[MAX_FLAG];
} image_t;

static int rd_u32le(FILE *f, uint32_t *v){
  uint8_t b[4];
  if (fread(b, 1, 4, f) != 4) return -1;
  *v = (uint32_t)b[0] | (uint32_t)b[1]<<8 | (uint32_t)b[2]<<16 | (uint32_t)b[3]<<24;
  return 0;
}

static int load_image(const char *path, image_t *im){
  FILE *f = fopen(path, "rb");
  if (!f){ fprintf(stderr, "keywright: cannot open image '%s'\n", path); return -1; }
  uint8_t hdr[8];
  if (fread(hdr, 1, 8, f) != 8 || memcmp(hdr, MAGIC, 4) != 0){
    fprintf(stderr, "keywright: bad image magic\n"); fclose(f); return -1; }
  im->n        = hdr[4];
  im->g        = hdr[5];
  im->flag_len = (uint16_t)(hdr[6] | hdr[7] << 8);
  if (im->n == 0 || im->n > MAX_N){ fprintf(stderr, "keywright: bad n\n"); fclose(f); return -1; }
  if (im->g == 0 || im->g > MAX_G){ fprintf(stderr, "keywright: bad g\n"); fclose(f); return -1; }
  if (im->flag_len == 0 || im->flag_len > MAX_FLAG){
    fprintf(stderr, "keywright: bad flag_len\n"); fclose(f); return -1; }
  for (int i = 0; i < im->n * im->n; i++)
    if (rd_u32le(f, &im->A[i]) != 0){ fclose(f); return -1; }
  for (int i = 0; i < im->n; i++)
    if (rd_u32le(f, &im->t[i]) != 0){ fclose(f); return -1; }
  if (fread(im->flag_ct, 1, im->flag_len, f) != im->flag_len){ fclose(f); return -1; }
  fclose(f);
  return 0;
}

/* base-32 digit for a character, or -1 if not in the alphabet. */
static int b32_digit(int ch){
  ch = toupper((unsigned char)ch);
  for (int i = 0; i < 32; i++) if (ALPHABET[i] == ch) return i;
  return -1;
}

/* Normalize a typed key: uppercase, drop '-' and ASCII whitespace, keep the
 * rest verbatim. Returns the normalized length, or -1 if a disallowed
 * character is present. */
static int normalize(const char *in, char *out, int outcap){
  int k = 0;
  for (const char *p = in; *p; p++){
    unsigned char c = (unsigned char)*p;
    if (c == '-' || isspace(c)) continue;
    if (b32_digit(c) < 0) return -1;         /* not an alphabet character */
    if (k >= outcap) return -1;
    out[k++] = (char)toupper(c);
  }
  return k;
}

/* Decode n*g normalized base-32 chars into n words (big-endian per group). */
static void decode_words(const char *norm, int n, int g, uint32_t *x){
  for (int i = 0; i < n; i++){
    uint32_t v = 0;
    for (int p = 0; p < g; p++)
      v = v * 32u + (uint32_t)b32_digit(norm[i*g + p]);
    x[i] = v;
  }
}

/* Re-encode words into the canonical key string: n groups of g base-32 chars,
 * uppercase, joined by '-'. This canonical form keys the flag keystream, so
 * input formatting (dashes, case) does not matter. */
static void canonical_key(const uint32_t *x, int n, int g, char *out){
  int w = 0;
  for (int i = 0; i < n; i++){
    if (i) out[w++] = '-';
    for (int p = 0; p < g; p++){
      int shift = 5 * (g - 1 - p);
      out[w++] = ALPHABET[(x[i] >> shift) & 31u];
    }
  }
  out[w] = 0;
}

int main(int argc, char **argv){
  const char *path = (argc > 1) ? argv[1] : "license.kwl";
  image_t im; memset(&im, 0, sizeof im);
  if (load_image(path, &im) != 0) return 2;

  /* read the license key (one line) from stdin */
  char line[256];
  if (!fgets(line, sizeof line, stdin)){ printf("DENIED no key provided\n"); return 1; }
  size_t llen = strlen(line);
  while (llen && (line[llen-1] == '\n' || line[llen-1] == '\r')) line[--llen] = 0;

  char norm[MAX_N * MAX_G + 1];
  int nlen = normalize(line, norm, sizeof norm - 1);
  int need = im.n * im.g;
  if (nlen != need){
    printf("DENIED license key must be %d groups of %d characters (%d total)\n",
           im.n, im.g, need);
    return 1;
  }
  norm[nlen] = 0;

  uint32_t x[MAX_N];
  decode_words(norm, im.n, im.g, x);

  /* Evaluate the constraint system y = A*x over the ring Z/2^32. */
  uint32_t y[MAX_N];
  for (int i = 0; i < im.n; i++){
    uint32_t acc = 0;
    for (int j = 0; j < im.n; j++)
      acc = (uint32_t)(acc + (uint32_t)im.A[i*im.n + j] * (uint32_t)x[j]);
    y[i] = acc;
  }
  int ok = 1;
  for (int i = 0; i < im.n; i++) if (y[i] != im.t[i]) ok = 0;

  /* Derive the keystream from the CANONICAL key (re-encoded from the decoded
   * words) and unwrap the flag. A wrong key yields a wrong keystream ->
   * garbage. We only print on a constraint match, but even a patched binary
   * cannot recover the flag without the true key. */
  char ck[MAX_N * (MAX_G + 1) + 1];
  canonical_key(x, im.n, im.g, ck);

  uint8_t ks[MAX_FLAG];
  keystream((const uint8_t *)ck, strlen(ck), ks, im.flag_len);
  uint8_t flag[MAX_FLAG];
  for (int i = 0; i < im.flag_len; i++) flag[i] = im.flag_ct[i] ^ ks[i];

  if (ok){
    fwrite(flag, 1, im.flag_len, stdout);
    fputc('\n', stdout);
    return 0;
  } else {
    printf("DENIED invalid license key\n");
    return 1;
  }
}
