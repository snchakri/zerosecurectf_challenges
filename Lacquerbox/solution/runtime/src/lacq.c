/*
 * ZSCTF :: Lacquerbox  (rev)
 * ------------------------------------------------------------------------
 * A fictional vendor seals its license tokens inside a little home-grown
 * block cipher they call the "Lacquer". The sealer loads a cipher-spec image
 * (the ".lacq" file), runs its layered round-network over the token you type,
 * and compares the sealed result to a target baked into the image. If (and
 * only if) the token is the one the vendor would have issued, it unwraps and
 * prints the flag. Anything else just says DENIED.
 *
 * The transform is a balanced Feistel network: the block is split into two
 * halves and, round after round, one half is mixed into the other through a
 * key-dependent round function. The round subkeys and the two whitening keys
 * are not stored directly -- they are derived from a master seed in the image
 * by SHA-256 (a key schedule), exactly like a real cipher.
 *
 * The flag is NOT stored in the clear. It is XORed with a SHA-256 keystream
 * derived from the *correct token itself*, so:
 *   - `strings` on the image reveals nothing;
 *   - patching out the comparison is useless -- a wrong token derives a wrong
 *     keystream and unwraps to garbage, never the flag.
 * The only way to the flag is to recognise the Feistel structure and run the
 * network backwards to the one token that seals to the embedded target. A
 * Feistel round is invertible regardless of whether its round function is,
 * which is the whole point of the construction.
 *
 * This file is the engine. It is identical for every team. The per-instance
 * secret lives entirely in the .lacq image (see gen.py), which is what a
 * player reverse-engineers.
 *
 * Build (reproducible):  gcc -O2 -fno-stack-protector -s -o lacq lacq.c
 * Run:                   printf '%s' "<license-token>" | ./lacq challenge.lacq
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ======================================================================
 * SHA-256 (public-domain style reference implementation). Used to derive
 * the key schedule (round subkeys + whitening) from the master seed, and
 * the flag keystream from the correct token. Matches Python hashlib.
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

/* keystream = SHA256(key || 0x00) || SHA256(key || 0x01) || ... truncated.
 * Used to unwrap the flag from the correct token. */
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

/* kdf(master, tag, idx) -> outlen bytes:
 *   SHA256(master || tag || idx || 0) || SHA256(master || tag || idx || 1) ...
 * This is the cipher's key schedule. Round subkeys use tag "RK" (idx = round),
 * whitening keys use tag "WK" (idx = 1 for pre, 2 for post). */
static void kdf(const uint8_t *master, size_t mlen, const char *tag,
                uint8_t idx, uint8_t *out, size_t outlen){
  size_t done = 0; uint8_t j = 0;
  size_t tlen = strlen(tag);
  while (done < outlen){
    sha256_ctx c; sha256_init(&c);
    sha256_update(&c, master, mlen);
    sha256_update(&c, (const uint8_t*)tag, tlen);
    sha256_update(&c, &idx, 1);
    sha256_update(&c, &j, 1);
    uint8_t blk[32]; sha256_final(&c, blk);
    size_t take = outlen - done; if (take > 32) take = 32;
    memcpy(out + done, blk, take); done += take; j++;
  }
}

/* ======================================================================
 * The Lacquer cipher: a balanced Feistel network.
 *
 * Image format (little-endian):
 *   "LACQ" | u8 ver | u8 L | u8 R | u8 seed_len | u16 flag_len
 *   u8 sbox[256] | u8 master[seed_len]
 *   u8 expected[L] | u8 flag_ct[flag_len]
 *
 * Encryption of an L-byte block b (L even, h = L/2):
 *   b ^= wk1                              (pre-whitening)
 *   for r = 0 .. R-1:
 *       (Lh, Rh) = (b[0:h], b[h:L])
 *       b = Rh || (Lh XOR F(Rh, rk[r]))   (Feistel round + swap)
 *   b ^= wk2                              (post-whitening)
 *
 * Round function F(x[0:h], rk[0:h]) -> h bytes:
 *   t[i] = sbox[(x[i] + rk[i]) & 0xff]            substitution + key mix
 *   t[i] = rol8(t[i], x[(i+1) mod h] & 7)         data-dependent rotation
 *   for i = 1..h-1: t[i] ^= t[i-1]                intra-half diffusion
 * F need not be invertible; the Feistel structure is invertible regardless.
 * ====================================================================== */
#define MAX_L     64
#define MAX_R     64
#define MAX_SEED  64
#define MAX_FLAG  512

static uint8_t rol8(uint8_t v, int r){ r &= 7; return (uint8_t)((v << r) | (v >> (8 - r))); }

typedef struct {
  uint8_t  L, R, seed_len;
  uint16_t flag_len;
  uint8_t  sbox[256];
  uint8_t  master[MAX_SEED];
  uint8_t  expected[MAX_L];
  uint8_t *flag_ct;
} image_t;

static int load_image(const char *path, image_t *im){
  FILE *f = fopen(path, "rb");
  if (!f){ fprintf(stderr, "lacq: cannot open image '%s'\n", path); return -1; }
  uint8_t hdr[10];
  if (fread(hdr, 1, 10, f) != 10 || memcmp(hdr, "LACQ", 4) != 0){
    fprintf(stderr, "lacq: bad image magic\n"); fclose(f); return -1; }
  im->L        = hdr[5];
  im->R        = hdr[6];
  im->seed_len = hdr[7];
  im->flag_len = (uint16_t)(hdr[8] | hdr[9] << 8);
  if (im->L < 2 || im->L > MAX_L || (im->L & 1)){
    fprintf(stderr, "lacq: bad block length\n"); fclose(f); return -1; }
  if (im->R == 0 || im->R > MAX_R){
    fprintf(stderr, "lacq: bad round count\n"); fclose(f); return -1; }
  if (im->seed_len == 0 || im->seed_len > MAX_SEED){
    fprintf(stderr, "lacq: bad seed length\n"); fclose(f); return -1; }
  if (im->flag_len == 0 || im->flag_len > MAX_FLAG){
    fprintf(stderr, "lacq: bad flag_len\n"); fclose(f); return -1; }
  if (fread(im->sbox, 1, 256, f) != 256){ fclose(f); return -1; }
  if (fread(im->master, 1, im->seed_len, f) != im->seed_len){ fclose(f); return -1; }
  if (fread(im->expected, 1, im->L, f) != im->L){ fclose(f); return -1; }
  im->flag_ct = malloc(im->flag_len);
  if (!im->flag_ct || fread(im->flag_ct, 1, im->flag_len, f) != im->flag_len){ fclose(f); return -1; }
  fclose(f);
  return 0;
}

/* F(x, rk) -> out, all of length h */
static void F(const uint8_t *x, const uint8_t *rk, int h,
              const uint8_t *sbox, uint8_t *out){
  for (int i = 0; i < h; i++)
    out[i] = sbox[(uint8_t)(x[i] + rk[i])];
  for (int i = 0; i < h; i++)
    out[i] = rol8(out[i], x[(i + 1) % h] & 7);
  for (int i = 1; i < h; i++)
    out[i] ^= out[i - 1];
}

/* Encrypt b[0..L-1] in place with the Lacquer network. */
static void encrypt(const image_t *im, uint8_t *b){
  int L = im->L, h = L / 2, R = im->R;
  uint8_t wk1[MAX_L], wk2[MAX_L];
  kdf(im->master, im->seed_len, "WK", 1, wk1, L);
  kdf(im->master, im->seed_len, "WK", 2, wk2, L);

  for (int i = 0; i < L; i++) b[i] ^= wk1[i];

  uint8_t rk[MAX_L / 2], fout[MAX_L / 2], newb[MAX_L];
  for (int r = 0; r < R; r++){
    kdf(im->master, im->seed_len, "RK", (uint8_t)r, rk, h);
    const uint8_t *Lh = b;        /* left half  */
    const uint8_t *Rh = b + h;    /* right half */
    F(Rh, rk, h, im->sbox, fout);
    for (int i = 0; i < h; i++) newb[i]     = Rh[i];           /* new left = old right     */
    for (int i = 0; i < h; i++) newb[h + i] = Lh[i] ^ fout[i]; /* new right = L XOR F(R)   */
    memcpy(b, newb, L);
  }

  for (int i = 0; i < L; i++) b[i] ^= wk2[i];
}

int main(int argc, char **argv){
  const char *path = (argc > 1) ? argv[1] : "challenge.lacq";
  image_t im; memset(&im, 0, sizeof im);
  if (load_image(path, &im) != 0) return 2;

  /* read the license token (one line) from stdin */
  char line[256];
  if (!fgets(line, sizeof line, stdin)){ printf("DENIED no token provided\n"); return 1; }
  size_t klen = strlen(line);
  while (klen && (line[klen-1] == '\n' || line[klen-1] == '\r')) line[--klen] = 0;

  if (klen != im.L){
    printf("DENIED token must be exactly %d characters\n", im.L);
    return 1;
  }

  uint8_t inp[MAX_L], b[MAX_L];
  memcpy(inp, line, im.L);
  memcpy(b, line, im.L);
  encrypt(&im, b);

  int ok = (memcmp(b, im.expected, im.L) == 0);

  /* Derive the keystream from the TOKEN (not from the cipher output) and
   * unwrap the flag. A wrong token yields a wrong keystream -> garbage, so
   * even a patched binary cannot recover the flag without the true token. */
  uint8_t ks[MAX_FLAG];
  keystream(inp, im.L, ks, im.flag_len);
  uint8_t flag[MAX_FLAG];
  for (int i = 0; i < im.flag_len; i++) flag[i] = im.flag_ct[i] ^ ks[i];

  if (ok){
    fwrite(flag, 1, im.flag_len, stdout);
    fputc('\n', stdout);
    return 0;
  } else {
    printf("DENIED invalid license token\n");
    return 1;
  }
}
