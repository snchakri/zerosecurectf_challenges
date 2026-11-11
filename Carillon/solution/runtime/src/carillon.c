/*
 * ZSCTF :: Carillon  (rev)
 * ------------------------------------------------------------------------
 * A carillon is a set of bells driven by a studded barrel: the pins on the
 * rotating drum *are* the program, and the mechanism just follows them. This
 * engine is the same idea. The barrel (the ".car" image) holds an ENCRYPTED
 * table of little instruction records for a tiny register machine. The engine
 * is one flattened dispatch loop:
 *
 *     state = ENTRY;
 *     while (running) {
 *         rec = DECRYPT(image.blocks[state]);   // bytecode is ciphertext on disk
 *         execute(rec);                         // one register-VM instruction
 *         state = pred(rec) ? rec.sA : rec.sB;  // opaque-predicate next-state
 *     }
 *
 * There is no readable sequence of steps, and `strings`/objdump on the image
 * show only ciphertext: each block is XORed with a per-index SHA-256 keystream
 * and is only decrypted the instant the dispatcher fetches it. The order of
 * the blocks in the table means nothing -- the only thing that decides what
 * runs after what is the opaque predicate pred(pk,c), and the dead edges point
 * at decoy blocks that never run.
 *
 * The instructions build a small keyed permutation of the L-byte license key
 * over GF(2^8) (AES field, reduction poly 0x11B): R rounds of
 *      state <- A_r * state (+) c_r      (a full invertible matrix multiply)
 *      state <- SBOX[state]              (a bytewise substitution)
 * and the engine accepts the key iff the final state equals the embedded
 * target. This is NOT a per-byte comparison: every output byte depends on
 * every input byte, so recovering the key means modelling the whole system
 * the VM computes and inverting it (field linear algebra + the S-box), not
 * peeling one byte at a time.
 *
 * The flag is NOT stored in the clear and is NOT a one-shot XOR of the key.
 * It is split across NL *nested* layers (the "peel"): s0 = SHA256("..R.." || key)
 * opens layer 0, which decrypts to one flag fragment PLUS the seed that opens
 * layer 1, and so on -- each layer is an independent cipher (XOR-keystream,
 * GF(2^8)-affine, or add-mod-256, selected per layer) whose opening key only
 * exists after the previous layer is peeled. So:
 *   - `strings` on the image reveals nothing (every layer is ciphertext);
 *   - the flag cannot be recovered by one XOR against any keystream(key);
 *   - patching out the comparison is useless -- a wrong key derives a wrong s0
 *     and every layer peels to garbage, never the flag.
 * A parallel decoy lane (label "..D..") peels cleanly (its checksums pass) but
 * assembles to a near-flag that fails the strict flag format; the engine reads
 * the real lane. (See gen.py / writeup "Flag extraction".)
 *
 * This file is the engine. It is identical for every team. The per-instance
 * secret lives entirely in the ".car" image (see gen.py), which is what a
 * player reverse-engineers.
 *
 * Build (reproducible):  gcc -O2 -fno-stack-protector -s -o carillon carillon.c
 * Run:                   printf '%s' "<license-key>" | ./carillon challenge.car
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ======================================================================
 * SHA-256 (public-domain style reference implementation). Used to derive
 * the per-block bytecode decryption keystream AND the nested flag-peel
 * layer keystreams. Byte-for-byte compatible with Python hashlib.sha256.
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

/* ======================================================================
 * GF(2^8) multiply, AES reduction polynomial 0x11B (x^8+x^4+x^3+x+1).
 * ====================================================================== */
static uint8_t gfmul(uint8_t a, uint8_t b){
  uint8_t r = 0;
  for (int i = 0; i < 8; i++){
    if (b & 1) r ^= a;
    uint8_t hi = a & 0x80;
    a = (uint8_t)(a << 1);
    if (hi) a ^= 0x1B;
    b = (uint8_t)(b >> 1);
  }
  return r;
}

/* Multiplicative inverse in GF(2^8): a^254 (Fermat). gfinv(0)=0. */
static uint8_t gfinv(uint8_t a){
  if (!a) return 0;
  uint8_t r = 1, base = a; int e = 254;
  while (e){ if (e & 1) r = gfmul(r, base); base = gfmul(base, base); e >>= 1; }
  return r;
}

/* ======================================================================
 * The Carillon register VM.
 *
 * Image format (little-endian):
 *   "CARL" | u8 ver | u8 L | u8 R | u8 nreg | u16 flag_len | u16 nblk
 *          | u16 entry | u16 rsv
 *   u8 bkey[16]            (per-instance bytecode-decryption key)
 *   u8 sbox[256]
 *   block[nblk]            (10 bytes each, ENCRYPTED)
 *   u8 expected[L]
 *   --- nested flag-peel section ---
 *   u8 NL                  (number of peel layers)
 *   for each layer i in 0..NL-1:
 *       u16 plen_d | u8 tag_d[4] | u8 ct_d[plen_d]    (decoy lane)
 *       u16 plen_r | u8 tag_r[4] | u8 ct_r[plen_r]    (real lane)
 *   Each lane plaintext is  fragment(plen-32) || next_seed(32).
 *
 * Decrypted block record (10 bytes):
 *   op, d, a, imm, sA_lo, sA_hi, sB_lo, sB_hi, pk, c
 * Decryption of block i: plain[k] = cipher[k] ^ SHA256(bkey || u32le(i))[k],
 * computed lazily when the dispatcher fetches block i.
 *
 * Register file REG[nreg] holds bytes (GF(2^8) elements). The license key is
 * loaded into REG[0..L-1] at start; the rest are zero. Instructions:
 *   0x00 HALT
 *   0x1A CLR    d       REG[d] = 0
 *   0x2B MOV    d,a     REG[d] = REG[a]
 *   0x3C XORI   d,imm   REG[d] ^= imm
 *   0x4D GFMULI d,imm   REG[d] = gfmul(REG[d], imm)
 *   0x5E GFMAC  d,a,imm REG[d] ^= gfmul(REG[a], imm)      (matrix MAC)
 *   0x6F SBOXR  d       REG[d] = sbox[REG[d]]
 * The engine accepts iff REG[0..L-1] == expected[0..L-1] after the halt.
 * ====================================================================== */
enum { OP_HALT=0x00, OP_CLR=0x1A, OP_MOV=0x2B, OP_XORI=0x3C,
       OP_GFMULI=0x4D, OP_GFMAC=0x5E, OP_SBOXR=0x6F };

#define MAX_FLAG   512
#define MAX_STEPS  2000000      /* dispatcher step cap (defensive) */
#define BLK_SZ     10
#define MAX_NREG   64
#define MAX_LAYERS 64
#define PEEL_SEED  32           /* next-seed carried inside each layer */

/* Domain label that seeds the REAL peel lane:  s0 = SHA256(label || key). */
static const char PEEL_LABEL_R[] = "CARILLON-PEEL-v2|R|";

typedef struct {
  uint8_t  L, R, nreg;
  uint16_t flag_len, nblk, entry;
  uint8_t  bkey[16];
  uint8_t  sbox[256];
  uint8_t *blocks;              /* nblk * BLK_SZ, still encrypted */
  uint8_t  expected[64];
  /* nested flag-peel section (real lane is what the engine releases) */
  uint8_t  NL;
  uint16_t plen_r[MAX_LAYERS];
  uint8_t *ct_r[MAX_LAYERS];
  uint16_t plen_d[MAX_LAYERS];  /* decoy lane: parsed, never released */
  uint8_t *ct_d[MAX_LAYERS];
} image_t;

/* Decrypt block `idx` into out[BLK_SZ]. */
static void decrypt_block(const image_t *im, uint32_t idx, uint8_t out[BLK_SZ]){
  uint8_t msg[20];
  memcpy(msg, im->bkey, 16);
  msg[16] = (uint8_t)(idx & 0xff);
  msg[17] = (uint8_t)((idx >> 8) & 0xff);
  msg[18] = (uint8_t)((idx >> 16) & 0xff);
  msg[19] = (uint8_t)((idx >> 24) & 0xff);
  sha256_ctx c; sha256_init(&c);
  sha256_update(&c, msg, 20);
  uint8_t ks[32]; sha256_final(&c, ks);
  const uint8_t *ct = im->blocks + (size_t)idx * BLK_SZ;
  for (int k = 0; k < BLK_SZ; k++) out[k] = ct[k] ^ ks[k];
}

static int pred(uint8_t pk, uint8_t c){
  uint32_t x = c;
  switch (pk & 3){
    case 0:  return (int)(( x*x - x       ) & 1u);
    case 1:  return (int)(( x*x + x       ) & 1u);
    case 2:  return (int)((( x*x - x) & 1u) ^ 1u);
    default: return (int)(( x*x + x + 1u  ) & 1u);
  }
}

static int load_image(const char *path, image_t *im){
  FILE *f = fopen(path, "rb");
  if (!f){ fprintf(stderr, "carillon: cannot open image '%s'\n", path); return -1; }
  uint8_t hdr[32];
  if (fread(hdr, 1, 32, f) != 32 || memcmp(hdr, "CARL", 4) != 0){
    fprintf(stderr, "carillon: bad image magic\n"); fclose(f); return -1; }
  im->L        = hdr[5];
  im->R        = hdr[6];
  im->nreg     = hdr[7];
  im->flag_len = (uint16_t)(hdr[8]  | hdr[9]  << 8);
  im->nblk     = (uint16_t)(hdr[10] | hdr[11] << 8);
  im->entry    = (uint16_t)(hdr[12] | hdr[13] << 8);
  memcpy(im->bkey, hdr + 16, 16);
  if (im->L == 0 || im->L > 64){ fprintf(stderr, "carillon: bad L\n"); fclose(f); return -1; }
  if (im->nreg == 0 || im->nreg > MAX_NREG){ fprintf(stderr, "carillon: bad nreg\n"); fclose(f); return -1; }
  if (im->flag_len == 0 || im->flag_len > MAX_FLAG){
    fprintf(stderr, "carillon: bad flag_len\n"); fclose(f); return -1; }
  if (im->nblk == 0 || im->entry >= im->nblk){
    fprintf(stderr, "carillon: bad block table\n"); fclose(f); return -1; }
  if (fread(im->sbox, 1, 256, f) != 256){ fclose(f); return -1; }
  im->blocks = malloc((size_t)im->nblk * BLK_SZ);
  if (!im->blocks || fread(im->blocks, 1, (size_t)im->nblk * BLK_SZ, f) != (size_t)im->nblk * BLK_SZ){
    fclose(f); return -1; }
  if (fread(im->expected, 1, im->L, f) != im->L){ fclose(f); return -1; }

  /* --- nested flag-peel section --- */
  uint8_t nlb;
  if (fread(&nlb, 1, 1, f) != 1){ fclose(f); return -1; }
  if (nlb == 0 || nlb > MAX_LAYERS){
    fprintf(stderr, "carillon: bad peel layer count\n"); fclose(f); return -1; }
  im->NL = nlb;
  for (int i = 0; i < nlb; i++){
    uint8_t h[6];                       /* u16 plen | u8 tag[4] */
    /* decoy lane */
    if (fread(h, 1, 6, f) != 6){ fclose(f); return -1; }
    uint16_t pd = (uint16_t)(h[0] | h[1] << 8);
    if (pd < PEEL_SEED + 1 || pd > MAX_FLAG + PEEL_SEED){ fclose(f); return -1; }
    im->plen_d[i] = pd; im->ct_d[i] = malloc(pd);
    if (!im->ct_d[i] || fread(im->ct_d[i], 1, pd, f) != pd){ fclose(f); return -1; }
    /* real lane */
    if (fread(h, 1, 6, f) != 6){ fclose(f); return -1; }
    uint16_t pr = (uint16_t)(h[0] | h[1] << 8);
    if (pr < PEEL_SEED + 1 || pr > MAX_FLAG + PEEL_SEED){ fclose(f); return -1; }
    im->plen_r[i] = pr; im->ct_r[i] = malloc(pr);
    if (!im->ct_r[i] || fread(im->ct_r[i], 1, pr, f) != pr){ fclose(f); return -1; }
  }
  fclose(f);
  return 0;
}

/* ======================================================================
 * Nested flag peel. The flag is NOT a one-shot XOR: each layer is its own
 * cipher, and the seed that opens layer i+1 only appears after layer i is
 * decrypted. Layer keystream: SHA256(s || tag || u64le(j)), j = 0,1,...
 * Cipher type for a layer is s[0] % 3.
 * ====================================================================== */
static void peel_ks(const uint8_t s[32], uint8_t tag, uint8_t *out, size_t n){
  size_t done = 0; uint64_t j = 0;
  while (done < n){
    uint8_t msg[41];
    memcpy(msg, s, 32);
    msg[32] = tag;
    for (int k = 0; k < 8; k++) msg[33 + k] = (uint8_t)(j >> (8 * k));
    sha256_ctx c; sha256_init(&c);
    sha256_update(&c, msg, 41);
    uint8_t blk[32]; sha256_final(&c, blk);
    size_t take = n - done; if (take > 32) take = 32;
    memcpy(out + done, blk, take); done += take; j++;
  }
}

/* Decrypt one layer ciphertext ct[n] under seed s into out[n]. */
static void peel_layer(const uint8_t s[32], const uint8_t *ct, size_t n, uint8_t *out){
  uint8_t t = (uint8_t)(s[0] % 3);
  if (t == 0){
    uint8_t ks[MAX_FLAG + PEEL_SEED];
    peel_ks(s, 'X', ks, n);
    for (size_t j = 0; j < n; j++) out[j] = (uint8_t)(ct[j] ^ ks[j]);
  } else if (t == 1){
    uint8_t ksa[MAX_FLAG + PEEL_SEED], ksb[MAX_FLAG + PEEL_SEED];
    peel_ks(s, 'A', ksa, n);
    peel_ks(s, 'B', ksb, n);
    for (size_t j = 0; j < n; j++)
      out[j] = gfmul((uint8_t)(ct[j] ^ ksb[j]), gfinv((uint8_t)(ksa[j] | 1)));
  } else {
    uint8_t ksm[MAX_FLAG + PEEL_SEED];
    peel_ks(s, 'M', ksm, n);
    for (size_t j = 0; j < n; j++) out[j] = (uint8_t)(ct[j] - ksm[j]);
  }
}

/* Peel the REAL lane with `key` and assemble the flag. Returns its length. */
static size_t peel_flag(const image_t *im, const uint8_t *key, uint8_t *outflag){
  uint8_t s[32];
  { sha256_ctx c; sha256_init(&c);
    sha256_update(&c, (const uint8_t *)PEEL_LABEL_R, sizeof(PEEL_LABEL_R) - 1);
    sha256_update(&c, key, im->L);
    sha256_final(&c, s); }
  size_t total = 0;
  for (int i = 0; i < im->NL; i++){
    size_t n = im->plen_r[i];
    uint8_t P[MAX_FLAG + PEEL_SEED];
    peel_layer(s, im->ct_r[i], n, P);
    size_t fl = n - PEEL_SEED;
    if (total + fl <= MAX_FLAG){ memcpy(outflag + total, P, fl); total += fl; }
    memcpy(s, P + fl, PEEL_SEED);    /* next_seed opens the next layer */
  }
  return total;
}

/* Walk the flattened, encrypted dispatcher over register file REG, in place. */
static void run(const image_t *im, uint8_t *REG){
  uint32_t st = im->entry;
  int nreg = im->nreg;
  for (long steps = 0; steps < MAX_STEPS; steps++){
    uint8_t rec[BLK_SZ];
    decrypt_block(im, st, rec);
    uint8_t op = rec[0], d = rec[1], a = rec[2], imm = rec[3], pk = rec[8], c = rec[9];
    uint16_t sA = (uint16_t)(rec[4] | rec[5] << 8);
    uint16_t sB = (uint16_t)(rec[6] | rec[7] << 8);
    switch (op){
      case OP_CLR:    if (d < nreg) REG[d] = 0; break;
      case OP_MOV:    if (d < nreg && a < nreg) REG[d] = REG[a]; break;
      case OP_XORI:   if (d < nreg) REG[d] ^= imm; break;
      case OP_GFMULI: if (d < nreg) REG[d] = gfmul(REG[d], imm); break;
      case OP_GFMAC:  if (d < nreg && a < nreg) REG[d] ^= gfmul(REG[a], imm); break;
      case OP_SBOXR:  if (d < nreg) REG[d] = im->sbox[REG[d]]; break;
      case OP_HALT:   return;
      default:        return;   /* unknown opcode: halt defensively */
    }
    st = pred(pk, c) ? sA : sB;
    if (st >= im->nblk) return;  /* bad edge: halt defensively */
  }
}

int main(int argc, char **argv){
  const char *path = (argc > 1) ? argv[1] : "challenge.car";
  image_t im; memset(&im, 0, sizeof im);
  if (load_image(path, &im) != 0) return 2;

  char line[256];
  if (!fgets(line, sizeof line, stdin)){ printf("DENIED no key provided\n"); return 1; }
  size_t klen = strlen(line);
  while (klen && (line[klen-1] == '\n' || line[klen-1] == '\r')) line[--klen] = 0;

  if (klen != im.L){
    printf("DENIED key must be exactly %d characters\n", im.L);
    return 1;
  }

  uint8_t inp[256], REG[MAX_NREG];
  memcpy(inp, line, im.L);
  memset(REG, 0, sizeof REG);
  memcpy(REG, line, im.L);
  run(&im, REG);

  int ok = (memcmp(REG, im.expected, im.L) == 0);

  /* Reconstruct the flag by peeling the nested real lane with the submitted
   * key. A wrong key (even if the compare is patched to accept) derives a
   * wrong s0, so every layer peels to garbage -- never the flag. */
  uint8_t flag[MAX_FLAG];
  size_t flen = peel_flag(&im, inp, flag);

  if (ok){
    fwrite(flag, 1, flen, stdout);
    fputc('\n', stdout);
    return 0;
  } else {
    printf("DENIED invalid license key\n");
    return 1;
  }
}
