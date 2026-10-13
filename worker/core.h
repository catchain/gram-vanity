/*
 * Gram Vanity worker core: one candidate = 128-bit entropy -> 12-word BIP39 anchor ->
 * PBKDF2-HMAC-SHA512 (2048) -> SLIP-0010 m/44'/607'/0' -> ed25519 pubkey ->
 * TG Wallet address (StateInit hash) -> UQ... string -> pattern check.
 *
 * Same source builds as CUDA device code (worker.cu) and as plain C++ (host checks, tests).
 * Must match src/wallet.rs exactly; tests/test_host.cpp checks it against the Rust binary.
 */
#pragma once
#include <stdint.h>
#include <string.h>

#if defined(__CUDACC__) && !defined(VANITY_HOST_ONLY)
#define DEV_FN static __device__
#define DEV_INL static __device__ __forceinline__
#define DEV_CONST __constant__
#define UNROLL _Pragma("unroll")
#else
#define UNROLL
#define DEV_FN static inline
#define DEV_INL static inline
#define DEV_CONST
#endif

#include "ed25519/types.h"
#include "ed25519/protos.h"
#include "ed25519/fe.c"
#include "ed25519/ge.c"
#include "bip39_en.h"

/* ---------------- SHA-256 ---------------- */

DEV_CONST static const uint32_t K256[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

DEV_INL uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

DEV_FN void sha256_compress(uint32_t st[8], const uint8_t blk[64]) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++)
    w[i] = (uint32_t)blk[4*i] << 24 | (uint32_t)blk[4*i+1] << 16 | (uint32_t)blk[4*i+2] << 8 | blk[4*i+3];
  for (int i = 16; i < 64; i++) {
    uint32_t s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
    uint32_t s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10);
    w[i] = w[i-16] + s0 + w[i-7] + s1;
  }
  uint32_t a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
  UNROLL
  for (int i = 0; i < 64; i++) {
    uint32_t t1 = h + (rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
    uint32_t t2 = (rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22)) + ((a & b) ^ (a & c) ^ (b & c));
    h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
  }
  st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d; st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
}

/* len < 512 bytes is enough here */
DEV_FN void sha256(const uint8_t *msg, uint32_t len, uint8_t out[32]) {
  uint32_t st[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  uint8_t blk[64];
  uint32_t off = 0;
  while (len - off >= 64) { sha256_compress(st, msg + off); off += 64; }
  uint32_t r = len - off;
  memset(blk, 0, 64);
  memcpy(blk, msg + off, r);
  blk[r] = 0x80;
  if (r >= 56) { sha256_compress(st, blk); memset(blk, 0, 64); }
  uint64_t bits = (uint64_t)len * 8;
  for (int i = 0; i < 8; i++) blk[63 - i] = (uint8_t)(bits >> (8 * i));
  sha256_compress(st, blk);
  for (int i = 0; i < 8; i++) { out[4*i]=st[i]>>24; out[4*i+1]=st[i]>>16; out[4*i+2]=st[i]>>8; out[4*i+3]=st[i]; }
}

/* ---------------- SHA-512 (word-level blocks) ---------------- */

DEV_CONST static const uint64_t K512[80] = {
  0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,0x3956c25bf348b538ULL,
  0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,0xd807aa98a3030242ULL,0x12835b0145706fbeULL,
  0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,
  0xc19bf174cf692694ULL,0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
  0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,0x983e5152ee66dfabULL,
  0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,
  0x06ca6351e003826fULL,0x142929670a0e6e70ULL,0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,
  0x53380d139d95b3dfULL,0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
  0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,0xd192e819d6ef5218ULL,
  0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,
  0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,
  0x682e6ff3d6b2b8a3ULL,0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,0xca273eceea26619cULL,
  0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,
  0x113f9804bef90daeULL,0x1b710b35131c471bULL,0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,
  0x431d67c49c100d4cULL,0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL};

DEV_CONST static const uint64_t IV512[8] = {
  0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL};

DEV_INL uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

/* Always inlined: when blk words are compile-time constants (sha512_compress_64), the compiler
   folds them out of the first 16 rounds and the message schedule. */
DEV_INL void sha512_rounds(uint64_t st[8], const uint64_t blk[16]) {
  uint64_t w[16];
  UNROLL
  for (int i = 0; i < 16; i++) w[i] = blk[i];
  uint64_t a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
  UNROLL
  for (int i = 0; i < 80; i++) {
    uint64_t wi;
    if (i < 16) wi = w[i];
    else {
      uint64_t x = w[(i+1) & 15], y = w[(i+14) & 15];
      uint64_t s0 = rotr64(x,1) ^ rotr64(x,8) ^ (x >> 7);
      uint64_t s1 = rotr64(y,19) ^ rotr64(y,61) ^ (y >> 6);
      wi = w[i & 15] = w[i & 15] + s0 + w[(i+9) & 15] + s1;
    }
    uint64_t t1 = h + (rotr64(e,14) ^ rotr64(e,18) ^ rotr64(e,41)) + ((e & f) ^ (~e & g)) + K512[i] + wi;
    uint64_t t2 = (rotr64(a,28) ^ rotr64(a,34) ^ rotr64(a,39)) + ((a & b) ^ (a & c) ^ (b & c));
    h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
  }
  st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d; st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
}

DEV_FN void sha512_compress(uint64_t st[8], const uint64_t blk[16]) { sha512_rounds(st, blk); }

/* Second HMAC block for a 64-byte message after the 128-byte key block: m || 0x80 || 0... || len 1536.
   Words 8..15 are constants, so this is cheaper than sha512_compress (hot loop of PBKDF2). */
DEV_INL void sha512_compress_64(uint64_t st[8], const uint64_t m[8]) {
  uint64_t w[16];
  UNROLL
  for (int i = 0; i < 8; i++) w[i] = m[i];
  w[8] = 0x8000000000000000ULL;
  UNROLL
  for (int i = 9; i < 15; i++) w[i] = 0;
  w[15] = (128 + 64) * 8;
  sha512_rounds(st, w);
}

DEV_INL uint64_t load_be64(const uint8_t *p) {
  return (uint64_t)p[0]<<56 | (uint64_t)p[1]<<48 | (uint64_t)p[2]<<40 | (uint64_t)p[3]<<32 |
         (uint64_t)p[4]<<24 | (uint64_t)p[5]<<16 | (uint64_t)p[6]<<8 | (uint64_t)p[7];
}
DEV_INL void store_be64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8*i)); }

/* Block (128 bytes) -> 16 BE words */
DEV_INL void block_words(const uint8_t b[128], uint64_t w[16]) { for (int i = 0; i < 16; i++) w[i] = load_be64(b + 8*i); }

/* SHA-512 of a short message (len <= 111): one block */
DEV_FN void sha512_short(const uint8_t *msg, uint32_t len, uint8_t out[64]) {
  uint8_t b[128];
  memset(b, 0, 128);
  memcpy(b, msg, len);
  b[len] = 0x80;
  store_be64(b + 120, (uint64_t)len * 8);
  uint64_t w[16], st[8];
  block_words(b, w);
  for (int i = 0; i < 8; i++) st[i] = IV512[i];
  sha512_compress(st, w);
  for (int i = 0; i < 8; i++) store_be64(out + 8*i, st[i]);
}

/* HMAC-SHA512 with key <= 128 bytes and message <= 111 bytes */
DEV_FN void hmac_sha512(const uint8_t *key, uint32_t klen, const uint8_t *msg, uint32_t mlen, uint8_t out[64]) {
  uint8_t b[128];
  uint64_t w[16], is[8], os[8];
  for (int i = 0; i < 128; i++) b[i] = (i < (int)klen ? key[i] : 0) ^ 0x36;
  block_words(b, w);
  for (int i = 0; i < 8; i++) is[i] = IV512[i];
  sha512_compress(is, w);
  for (int i = 0; i < 128; i++) b[i] = (i < (int)klen ? key[i] : 0) ^ 0x5c;
  block_words(b, w);
  for (int i = 0; i < 8; i++) os[i] = IV512[i];
  sha512_compress(os, w);

  memset(b, 0, 128);
  memcpy(b, msg, mlen);
  b[mlen] = 0x80;
  store_be64(b + 120, (uint64_t)(128 + mlen) * 8);
  block_words(b, w);
  sha512_compress(is, w);
  for (int i = 0; i < 8; i++) w[i] = is[i];
  w[8] = 0x8000000000000000ULL;
  for (int i = 9; i < 15; i++) w[i] = 0;
  w[15] = (128 + 64) * 8;
  sha512_compress(os, w);
  for (int i = 0; i < 8; i++) store_be64(out + 8*i, os[i]);
}

/* BIP39 seed: PBKDF2-HMAC-SHA512(password = phrase (< 128 bytes), salt = "mnemonic", 2048, 64).
   Output as 8 big-endian words (the GPU stores them between the two kernels). */
DEV_FN void bip39_seed_words(const uint8_t *pw, uint32_t len, uint64_t acc[8]) {
  uint8_t b[128];
  uint64_t w[16], is[8], os[8], s[8], u[8];
  for (int i = 0; i < 128; i++) b[i] = (i < (int)len ? pw[i] : 0) ^ 0x36;
  block_words(b, w);
  for (int i = 0; i < 8; i++) is[i] = IV512[i];
  sha512_compress(is, w);
  for (int i = 0; i < 128; i++) b[i] = (i < (int)len ? pw[i] : 0) ^ 0x5c;
  block_words(b, w);
  for (int i = 0; i < 8; i++) os[i] = IV512[i];
  sha512_compress(os, w);

  /* U1 = HMAC(P, "mnemonic" || INT(1)) */
  w[0] = 0x6d6e656d6f6e6963ULL;         /* "mnemonic" */
  w[1] = 0x0000000180000000ULL;         /* INT(1) || 0x80 */
  for (int i = 2; i < 15; i++) w[i] = 0;
  w[15] = (128 + 12) * 8;
  for (int i = 0; i < 8; i++) s[i] = is[i];
  sha512_compress(s, w);
  for (int i = 0; i < 8; i++) u[i] = os[i];
  sha512_compress_64(u, s);
  for (int i = 0; i < 8; i++) acc[i] = u[i];

  /* U_r = HMAC(P, U_{r-1}): two fixed-padding compressions per round */
  for (int r = 1; r < 2048; r++) {
    UNROLL
    for (int i = 0; i < 8; i++) s[i] = is[i];
    sha512_compress_64(s, u);
    UNROLL
    for (int i = 0; i < 8; i++) u[i] = os[i];
    sha512_compress_64(u, s);
    UNROLL
    for (int i = 0; i < 8; i++) acc[i] ^= u[i];
  }
}

DEV_FN void bip39_seed(const uint8_t *pw, uint32_t len, uint8_t seed[64]) {
  uint64_t acc[8];
  bip39_seed_words(pw, len, acc);
  for (int i = 0; i < 8; i++) store_be64(seed + 8*i, acc[i]);
}

/* SLIP-0010 ed25519 m/44'/607'/0' -> 32-byte secret (ed25519 seed) */
DEV_FN void slip10_ton(const uint8_t seed[64], uint8_t secret[32]) {
  uint8_t I[64], data[37];
  const uint8_t k[12] = {'e','d','2','5','5','1','9',' ','s','e','e','d'};
  hmac_sha512(k, 12, seed, 64, I);
  const uint32_t path[3] = {44u | 0x80000000u, 607u | 0x80000000u, 0x80000000u};
  for (int j = 0; j < 3; j++) {
    data[0] = 0;
    memcpy(data + 1, I, 32);
    data[33] = path[j] >> 24; data[34] = path[j] >> 16; data[35] = path[j] >> 8; data[36] = path[j];
    uint8_t chain[32];
    memcpy(chain, I + 32, 32);
    hmac_sha512(chain, 32, data, 37, I);
  }
  memcpy(secret, I, 32);
}

DEV_FN void ed25519_pubkey(const uint8_t secret[32], uint8_t pub[32]) {
  uint8_t h[64];
  ge_p3 A;
  sha512_short(secret, 32, h);
  h[0] &= 248; h[31] &= 63; h[31] |= 64;
  ge_scalarmult_base(&A, h);
  ge_p3_tobytes(pub, &A);
}

/* ---------------- BIP39 phrase ---------------- */

/* 12 word indexes from 16 bytes of entropy (+4-bit SHA-256 checksum) */
DEV_FN void bip39_indexes(const uint8_t ent[16], uint16_t idx[12]) {
  uint8_t h[32], e[17];
  sha256(ent, 16, h);
  memcpy(e, ent, 16);
  e[16] = h[0] & 0xF0;
  for (int i = 0; i < 12; i++) {
    int bit = i * 11, v = 0;
    for (int k = 0; k < 11; k++, bit++) v = (v << 1) | ((e[bit >> 3] >> (7 - (bit & 7))) & 1);
    idx[i] = (uint16_t)v;
  }
}

/* Returns phrase length; buf needs 108 bytes */
DEV_FN uint32_t bip39_phrase(const uint8_t ent[16], char *buf) {
  uint16_t idx[12];
  bip39_indexes(ent, idx);
  uint32_t n = 0;
  for (int i = 0; i < 12; i++) {
    if (i) buf[n++] = ' ';
    int L = BIP39_LEN[idx[i]];
    for (int c = 0; c < L; c++) buf[n++] = BIP39_WORDS[idx[i]][c];
  }
  return n;
}

/* ---------------- TG Wallet address ---------------- */

DEV_CONST static const uint8_t CODE_HASH[32] = {  /* trampoline, 9149ae51...a768 */
  0x91,0x49,0xae,0x51,0xc1,0xe4,0x68,0x97,0x10,0xce,0xbf,0x78,0x30,0x29,0x7b,0x16,
  0xac,0xfb,0xad,0xb3,0x63,0xa9,0x20,0xa5,0x37,0x89,0x3e,0x7f,0xfe,0xec,0xa7,0x68};

DEV_CONST static const char B64URL[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#define WALLET_ID_MAINNET 0x7FFF7F11u

DEV_FN uint16_t crc16_xmodem(const uint8_t *d, int n) {
  uint16_t crc = 0;
  for (int i = 0; i < n; i++) {
    crc ^= (uint16_t)d[i] << 8;
    for (int k = 0; k < 8; k++) crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
  }
  return crc;
}

/* pubkey -> 48-char non-bounceable mainnet address (no terminator) */
DEV_FN void tg_address(const uint8_t pub[32], char out[48]) {
  uint8_t m[71], dh[32], ah[32], raw[36];
  /* data cell: rev u8=0, seqno u32=0, wallet_id u32, pubkey 256 -> 41 bytes */
  m[0] = 0x00; m[1] = 82;
  memset(m + 2, 0, 5);
  m[7] = (uint8_t)(WALLET_ID_MAINNET >> 24); m[8] = (uint8_t)(WALLET_ID_MAINNET >> 16); m[9] = (uint8_t)(WALLET_ID_MAINNET >> 8); m[10] = (uint8_t)WALLET_ID_MAINNET;
  memcpy(m + 11, pub, 32);
  sha256(m, 43, dh);
  /* StateInit: bits 00110, refs [code, data], both depth 0 */
  m[0] = 0x02; m[1] = 0x01; m[2] = 0x34;
  memset(m + 3, 0, 4);
  for (int i = 0; i < 32; i++) m[7 + i] = CODE_HASH[i];
  memcpy(m + 39, dh, 32);
  sha256(m, 71, ah);
  raw[0] = 0x51; raw[1] = 0x00;
  memcpy(raw + 2, ah, 32);
  uint16_t crc = crc16_xmodem(raw, 34);
  raw[34] = crc >> 8; raw[35] = crc & 0xFF;
  for (int i = 0; i < 12; i++) {
    uint32_t v = (uint32_t)raw[3*i] << 16 | (uint32_t)raw[3*i+1] << 8 | raw[3*i+2];
    out[4*i] = B64URL[(v >> 18) & 63]; out[4*i+1] = B64URL[(v >> 12) & 63];
    out[4*i+2] = B64URL[(v >> 6) & 63]; out[4*i+3] = B64URL[v & 63];
  }
}

/* ---------------- pattern ---------------- */

typedef struct {
  char prefix[12]; int plen;   /* chars right after "UQ" */
  char suffix[12]; int slen;
  int ci;                      /* case-insensitive */
} Pattern;

DEV_INL char lower(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; }

DEV_FN int pattern_match(const Pattern *p, const char a[48]) {
  for (int i = 0; i < p->plen; i++) {
    char x = a[2 + i], y = p->prefix[i];
    if (p->ci ? lower(x) != lower(y) : x != y) return 0;
  }
  for (int i = 0; i < p->slen; i++) {
    char x = a[48 - p->slen + i], y = p->suffix[i];
    if (p->ci ? lower(x) != lower(y) : x != y) return 0;
  }
  return 1;
}

/* ---------------- full candidate ---------------- */

/* Second half of a candidate (GPU: address_kernel): BIP39 seed -> pubkey -> address */
DEV_FN void seed_to_address(const uint8_t seed[64], uint8_t pub[32], char addr[48]) {
  uint8_t secret[32];
  slip10_ton(seed, secret);
  ed25519_pubkey(secret, pub);
  tg_address(pub, addr);
}

DEV_FN void candidate(const uint8_t ent[16], uint8_t pub[32], char addr[48]) {
  char phrase[112];
  uint8_t seed[64];
  uint32_t n = bip39_phrase(ent, phrase);
  bip39_seed((const uint8_t *)phrase, n, seed);
  seed_to_address(seed, pub, addr);
}

/* entropy_i = SHA-256(seed32 || gid u64 LE || iter u64 LE)[0..16] */
DEV_FN void derive_entropy(const uint8_t seed[32], uint64_t gid, uint64_t iter, uint8_t ent[16]) {
  uint8_t m[48], h[32];
  memcpy(m, seed, 32);
  for (int i = 0; i < 8; i++) { m[32 + i] = (uint8_t)(gid >> (8*i)); m[40 + i] = (uint8_t)(iter >> (8*i)); }
  sha256(m, 48, h);
  memcpy(ent, h, 16);
}
