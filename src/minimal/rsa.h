#ifndef RSA_C_H
#define RSA_C_H

#include <gmp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// i need to include this in the source file if i split this  -> .h|.c
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// ========== Attribute Macros ==========
#if defined(__GNUC__) || defined(__clang__)
#define __attr_nodiscard __attribute__((warn_unused_result))
#define __attr_malloc __attribute__((malloc))
#define __attr_hot __attribute__((hot))
#define __attr_cold __attribute__((cold))
#define __likely(x) __builtin_expect(!!(x), 1)
#define __unlikely(x) __builtin_expect(!!(x), 0)
#else
#define __attr_nodiscard
#define __attr_malloc
#define __attr_hot
#define __attr_cold
#define __likely(x) (x)
#define __unlikely(x) (x)
#endif

#ifdef __cplusplus
#define __restrict__ __restrict
#define __noexcept noexcept
#define __const_noexcept const noexcept
#else
#define __restrict__ restrict
#define __noexcept
#define __const_noexcept
#endif

// ========== Constants ==========
static const char b64tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const unsigned char OID_RSA_ENCRYPTION[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
static const uint32_t k[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
                               0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
                               0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
                               0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                               0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
                               0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

__attr_hot __attr_nodiscard int rsa_get_secure_random_bytes(uint8_t *__restrict__ buf, size_t len) __noexcept {
#ifdef _WIN32
#include <bcrypt.h>
#include <windows.h>
  return BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#else
  FILE *f = fopen("/dev/urandom", "rb");
  if (__unlikely(!f))
    return 0;
  size_t n = fread(buf, 1, len, f);
  fclose(f);
  return __likely(n == len);
#endif
}

// Key structures
typedef struct {
  mpz_t n;
  mpz_t e;
} rsa_public_key;

typedef struct {
  mpz_t n, e, d, p, q, dP, dQ, qInv;
} rsa_private_key;

typedef struct {
  uint32_t state[8];
  uint64_t bitlen;
  uint8_t data[64];
  uint32_t datalen;
} sha256_ctx;

__attr_hot static void sha256_transform(sha256_ctx *__restrict__ ctx, const uint8_t *__restrict__ data) __noexcept {
  uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
  int i;

  for (i = 0; i < 16; ++i)
    m[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) | (data[i * 4 + 2] << 8) | (data[i * 4 + 3]);
  for (; i < 64; ++i)
    m[i] = ((m[i - 2] >> 17 | m[i - 2] << 15) ^ (m[i - 2] >> 19 | m[i - 2] << 13) ^ (m[i - 2] >> 10)) + m[i - 7] +
           ((m[i - 15] >> 7 | m[i - 15] << 25) ^ (m[i - 15] >> 18 | m[i - 15] << 14) ^ (m[i - 15] >> 3)) + m[i - 16];

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  for (i = 0; i < 64; ++i) {
    t1 = h + ((e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^ (e >> 25 | e << 7)) + ((e & f) ^ ((~e) & g)) + k[i] + m[i];
    t2 = ((a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^ (a >> 22 | a << 10)) + ((a & b) ^ (a & c) ^ (b & c));
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

__attr_hot static void sha256_init(sha256_ctx *__restrict__ ctx) __noexcept {
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
  ctx->datalen = 0;
  ctx->bitlen = 0;
}

__attr_hot static void sha256_update(sha256_ctx *__restrict__ ctx, const uint8_t *__restrict__ data, size_t len) __noexcept {
  for (size_t i = 0; i < len; ++i) {
    ctx->data[ctx->datalen] = data[i];
    ctx->datalen++;
    if (ctx->datalen == 64) {
      sha256_transform(ctx, ctx->data);
      ctx->bitlen += 512;
      ctx->datalen = 0;
    }
  }
}

__attr_hot static void sha256_final(sha256_ctx *__restrict__ ctx, uint8_t *__restrict__ hash /* hash[32] */
                                                     ) __noexcept {
  uint32_t i = ctx->datalen;
  ctx->bitlen += ctx->datalen * 8;
  // Pad whatever data is left in the buffer.
  if (ctx->datalen < 56) {
    ctx->data[i++] = 0x80;
    while (i < 56)
      ctx->data[i++] = 0x00;
  } else {
    ctx->data[i++] = 0x80;
    while (i < 64)
      ctx->data[i++] = 0x00;
    sha256_transform(ctx, ctx->data);
    memset(ctx->data, 0, 56);
  }
  // Append to the padding the total message's length in bits and transform.
  ctx->data[63] = ctx->bitlen;
  ctx->data[62] = ctx->bitlen >> 8;
  ctx->data[61] = ctx->bitlen >> 16;
  ctx->data[60] = ctx->bitlen >> 24;
  ctx->data[59] = ctx->bitlen >> 32;
  ctx->data[58] = ctx->bitlen >> 40;
  ctx->data[57] = ctx->bitlen >> 48;
  ctx->data[56] = ctx->bitlen >> 56;
  sha256_transform(ctx, ctx->data);
  // Output hash in big-endian
  for (i = 0; i < 4; ++i) {
    for (uint32_t j = 0; j < 8; ++j) {
      hash[i + j * 4] = (ctx->state[j] >> (24 - i * 8)) & 0xff;
    }
  }
}

__attr_hot void sha256(const uint8_t *__restrict__ data, size_t len, uint8_t *__restrict__ out) __noexcept {
  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, len);
  sha256_final(&ctx, out);
}

__attr_hot static void mgf1_sha256(const uint8_t *__restrict__ seed, size_t seedlen, uint8_t *__restrict__ mask, size_t masklen) __noexcept {
  uint32_t counter = 0;
  uint8_t digest[32];
  size_t outpos = 0;
  while (outpos < masklen) {
    uint8_t cnt[4] = {(uint8_t)(counter >> 24), (uint8_t)(counter >> 16), (uint8_t)(counter >> 8), (uint8_t)(counter)};
    uint8_t *tmp = (uint8_t *)malloc(seedlen + 4);
    memcpy(tmp, seed, seedlen);
    memcpy(tmp + seedlen, cnt, 4);
    sha256(tmp, seedlen + 4, digest);
    free(tmp);
    size_t chunk = (masklen - outpos < 32) ? (masklen - outpos) : 32;
    memcpy(mask + outpos, digest, chunk);
    outpos += chunk;
    counter++;
  }
}

__attr_nodiscard __attr_hot int oaep_encode(const uint8_t *__restrict__ in, size_t inlen, uint8_t *__restrict__ out, size_t k, const uint8_t *__restrict__ label,
                                            size_t labellen) __noexcept {
  size_t hLen = 32;
  if (k < 2 * hLen + 2)
    return 0;
  if (inlen > k - 2 * hLen - 2)
    return 0;

  uint8_t lHash[32];
  sha256(label ? label : (const uint8_t *)"", labellen, lHash);

  // Data block: lHash || PS || 0x01 || M
  size_t ps_len = k - inlen - 2 * hLen - 2;
  uint8_t *DB = (uint8_t *)malloc(k - hLen - 1);
  memcpy(DB, lHash, hLen);
  memset(DB + hLen, 0, ps_len);
  DB[hLen + ps_len] = 0x01;
  memcpy(DB + hLen + ps_len + 1, in, inlen);

  // Generate random seed
  uint8_t *seed = (uint8_t *)malloc(hLen);
  if (__likely(rsa_get_secure_random_bytes(seed, hLen))) {
    for (size_t i = 0; i < hLen; ++i)
      seed[i] = rand() & 0xFF; // Replace with secure RNG in production
  }

  // Masks
  uint8_t *dbMask = (uint8_t *)malloc(k - hLen - 1);
  mgf1_sha256(seed, hLen, dbMask, k - hLen - 1);
  for (size_t i = 0; i < k - hLen - 1; ++i)
    DB[i] ^= dbMask[i];

  uint8_t *seedMask = (uint8_t *)malloc(hLen);
  mgf1_sha256(DB, k - hLen - 1, seedMask, hLen);
  for (size_t i = 0; i < hLen; ++i)
    seed[i] ^= seedMask[i];

  // Assemble encoded message
  out[0] = 0x00;
  memcpy(out + 1, seed, hLen);
  memcpy(out + 1 + hLen, DB, k - hLen - 1);

  free(DB);
  free(seed);
  free(dbMask);
  free(seedMask);
  return 1;
}

__attr_nodiscard __attr_hot int oaep_decode(const uint8_t *__restrict__ in, size_t k, uint8_t *__restrict__ out, size_t *__restrict__ outlen,
                                            const uint8_t *__restrict__ label, size_t labellen) __noexcept {
  size_t hLen = 32;
  if (k < 2 * hLen + 2)
    return 0;
  if (in[0] != 0x00)
    return 0;

  const uint8_t *maskedSeed = in + 1;
  const uint8_t *maskedDB = in + 1 + hLen;

  uint8_t seed[32];
  memcpy(seed, maskedSeed, hLen);

  uint8_t *DB = (uint8_t *)malloc(k - hLen - 1);
  memcpy(DB, maskedDB, k - hLen - 1);

  // Unmask seed
  uint8_t *seedMask = (uint8_t *)malloc(hLen);
  mgf1_sha256(DB, k - hLen - 1, seedMask, hLen);
  for (size_t i = 0; i < hLen; ++i)
    seed[i] ^= seedMask[i];

  // Unmask DB
  uint8_t *dbMask = (uint8_t *)malloc(k - hLen - 1);
  mgf1_sha256(seed, hLen, dbMask, k - hLen - 1);
  for (size_t i = 0; i < k - hLen - 1; ++i)
    DB[i] ^= dbMask[i];

  // Check lHash (for best security, use constant-time memcmp here)
  uint8_t lHash[32];
  sha256(label ? label : (const uint8_t *)"", labellen, lHash);
  if (__likely(memcmp(DB, lHash, hLen))) {
    free(DB);
    free(seedMask);
    free(dbMask);
    return 0;
  }

  // Find the 0x01 separator
  size_t i = hLen;
  while (i < k - hLen - 1 && DB[i] == 0x00)
    ++i;
  if (i == k - hLen - 1 || DB[i] != 0x01) {
    free(DB);
    free(seedMask);
    free(dbMask);
    return 0;
  }

  size_t mLen = k - hLen - 1 - i - 1;
  memcpy(out, DB + i + 1, mLen);
  *outlen = mLen;

  free(DB);
  free(seedMask);
  free(dbMask);
  return 1;
}

// Utility: modular inverse (returns 1 on success)
__attr_nodiscard int modinv(mpz_t rop, const mpz_t a, const mpz_t m) { return mpz_invert(rop, a, m) != 0; }

// Generate a random probable prime of given bits
void random_prime(mpz_t rop, gmp_randstate_t state, int bits) {
  do {
    mpz_urandomb(rop, state, bits);
    mpz_setbit(rop, bits - 1); // ensure high bit set
    mpz_setbit(rop, 0);        // ensure odd
  } while (!mpz_probab_prime_p(rop, 25));
}

// Key generation
void rsa_generate_keypair(rsa_public_key *pub, rsa_private_key *priv, int bits) {
  gmp_randstate_t state;
  gmp_randinit_mt(state);
  gmp_randseed_ui(state, (unsigned long)time(NULL));

  mpz_t p, q, phi, dP, dQ, qInv;
  mpz_inits(p, q, phi, dP, dQ, qInv, NULL);

  // Generate distinct primes p, q
  random_prime(p, state, bits / 2);
  do {
    random_prime(q, state, bits / 2);
  } while (mpz_cmp(p, q) == 0);

  // n = p*q
  mpz_init(priv->n);
  mpz_mul(priv->n, p, q);

  // phi = (p-1)*(q-1)
  mpz_sub_ui(p, p, 1);
  mpz_sub_ui(q, q, 1);
  mpz_mul(phi, p, q);

  // e = 65537
  mpz_init_set_ui(priv->e, 65537);

  // d = e^{-1} mod phi
  mpz_init(priv->d);
  if (!__unlikely(modinv(priv->d, priv->e, phi))) {
    printf("No modular inverse!\n");
    exit(1);
  }

  // restore p, q
  mpz_add_ui(p, p, 1);
  mpz_add_ui(q, q, 1);

  // CRT params
  mpz_init(priv->p);
  mpz_set(priv->p, p);
  mpz_init(priv->q);
  mpz_set(priv->q, q);

  mpz_init(dP);
  mpz_sub_ui(dP, p, 1);
  mpz_mod(priv->dP, priv->d, dP);

  mpz_init(dQ);
  mpz_sub_ui(dQ, q, 1);
  mpz_mod(priv->dQ, priv->d, dQ);

  mpz_init(qInv);
  if(!__unlikely(modinv(qInv, priv->q, priv->p))) {
    printf("No modular inverse!\n");
    exit(1);
  }
    
  mpz_set(priv->qInv, qInv);

  // Fill public key
  mpz_init_set(pub->n, priv->n);
  mpz_init_set(pub->e, priv->e);

  mpz_clears(p, q, phi, dP, dQ, qInv, NULL);
  gmp_randclear(state);
}

// Key storage: PEM-like (hex, one value per line)
__attr_nodiscard int rsa_save_public(const char *fname, const rsa_public_key *pub) {
  FILE *f = fopen(fname, "w");
  if (!__unlikely(f))
    return 0;
  gmp_fprintf(f, "%Zx\n%Zx\n", pub->n, pub->e);
  fclose(f);
  return 1;
}

__attr_nodiscard int rsa_load_public(const char *fname, rsa_public_key *pub) {
  FILE *f = fopen(fname, "r");
  if (!__unlikely(f))
    return 0;
  mpz_init(pub->n);
  mpz_init(pub->e);
  gmp_fscanf(f, "%Zx\n%Zx\n", pub->n, pub->e);
  fclose(f);
  return 1;
}

__attr_nodiscard int rsa_save_private(const char *fname, const rsa_private_key *priv) {
  FILE *f = fopen(fname, "w");
  if (!__unlikely(f))
    return 0;
  gmp_fprintf(f, "%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n", priv->n, priv->e, priv->d, priv->p, priv->q, priv->dP, priv->dQ, priv->qInv);
  fclose(f);
  return 1;
}

__attr_nodiscard int rsa_load_private(const char *fname, rsa_private_key *priv) {
  FILE *f = fopen(fname, "r");
  if (!__unlikely(f))
    return 0;
  mpz_inits(priv->n, priv->e, priv->d, priv->p, priv->q, priv->dP, priv->dQ, priv->qInv, NULL);
  gmp_fscanf(f, "%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n", priv->n, priv->e, priv->d, priv->p, priv->q, priv->dP, priv->dQ, priv->qInv);
  fclose(f);
  return 1;
}

// Encryption/Decryption
void rsa_encrypt(mpz_t out, const mpz_t in, const rsa_public_key *pub) { mpz_powm(out, in, pub->e, pub->n); }

void rsa_decrypt(mpz_t out, const mpz_t in, const rsa_private_key *priv) { mpz_powm(out, in, priv->d, priv->n); }

int rsa_encrypt_oaep(mpz_t out, const uint8_t *in, size_t inlen, const rsa_public_key *pub, const uint8_t *label, size_t labellen) {
  size_t k = (mpz_sizeinbase(pub->n, 2) + 7) / 8;
  uint8_t *em = (uint8_t *)malloc(k);
  if (!__unlikely(oaep_encode(in, inlen, em, k, label, labellen))) {
    free(em);
    return 0;
  }
  mpz_import(out, k, 1, 1, 1, 0, em);
  rsa_encrypt(out, out, pub); // in-place
  free(em);
  return 1;
}

int rsa_decrypt_oaep(uint8_t *out, size_t *outlen, const mpz_t in, const rsa_private_key *priv, const uint8_t *label, size_t labellen) {
  size_t k = (mpz_sizeinbase(priv->n, 2) + 7) / 8;
  uint8_t *em = (uint8_t *)malloc(k);
  mpz_t m;
  mpz_init(m);
  rsa_decrypt(m, in, priv);
  size_t tmplen;
  mpz_export(em, &tmplen, 1, 1, 1, 0, m);
  if (__likely(tmplen < k)) {
    memmove(em + (k - tmplen), em, tmplen);
    memset(em, 0, k - tmplen);
  }
  int ret = oaep_decode(em, k, out, outlen, label, labellen);
  mpz_clear(m);
  free(em);
  return ret;
}

// Utility
void rsa_clear_public(rsa_public_key *pub) {
  mpz_clear(pub->n);
  mpz_clear(pub->e);
}

void rsa_clear_private(rsa_private_key *priv) { mpz_clears(priv->n, priv->e, priv->d, priv->p, priv->q, priv->dP, priv->dQ, priv->qInv, NULL); }

// ASN.1/DER helpers
static size_t asn1_encode_len(unsigned char *out, size_t len) {
  if (__likely(len < 128)) {
    if (__likely(out))
      out[0] = (unsigned char)len;
    return 1;
  } else {
    size_t n = 0, l = len;
    while (l) {
      ++n;
      l >>= 8;
    }
    if (__likely(out))
      out[0] = 0x80 | n;
    for (size_t i = 0; i < n; ++i)
      if (__likely(out))
        out[1 + i] = (unsigned char)(len >> (8 * (n - 1 - i)));
    return 1 + n;
  }
}

static size_t asn1_encode_integer(const mpz_t x, unsigned char *out) {
  size_t count = (mpz_sizeinbase(x, 2) + 7) / 8;
  unsigned char *buf = (unsigned char *)malloc(count + 1); // extra for leading 0
  mpz_export(buf + 1, &count, 1, 1, 1, 0, x);
  buf[0] = 0x00; // for possible sign bit
  size_t off = 0;
  if (__likely(count && (buf[1] & 0x80))) {
    off = 0;
    count++;
  } else {
    off = 1;
  }
  if (__likely(out)) {
    *out++ = 0x02;
    size_t lenlen = asn1_encode_len(out, count);
    out += lenlen;
    memcpy(out, buf + off, count);
  }
  free(buf);
  size_t lenlen = asn1_encode_len(NULL, count);
  return 1 + lenlen + count;
}

// DER serialization
size_t rsa_serialize_public_der(const rsa_public_key *pub, unsigned char *der, size_t maxlen) {
  unsigned char tmp[2048];
  size_t nlen = asn1_encode_integer(pub->n, tmp);
  size_t elen = asn1_encode_integer(pub->e, tmp + nlen);

  size_t seqlen = nlen + elen;
  size_t lenlen = asn1_encode_len(NULL, seqlen);
  if (__likely(der)) {
    der[0] = 0x30;
    asn1_encode_len(der + 1, seqlen);
    memcpy(der + 1 + lenlen, tmp, nlen + elen);
  }
  return 1 + lenlen + nlen + elen;
}

size_t rsa_serialize_private_der(const rsa_private_key *priv, unsigned char *der, size_t maxlen) {
  unsigned char tmp[4096];
  size_t off = 0;
  mpz_t zero;
  mpz_init_set_ui(zero, 0);
  off += asn1_encode_integer(zero, tmp + off); // version = 0
  mpz_clear(zero);
  off += asn1_encode_integer(priv->n, tmp + off);
  off += asn1_encode_integer(priv->e, tmp + off);
  off += asn1_encode_integer(priv->d, tmp + off);
  off += asn1_encode_integer(priv->p, tmp + off);
  off += asn1_encode_integer(priv->q, tmp + off);
  off += asn1_encode_integer(priv->dP, tmp + off);
  off += asn1_encode_integer(priv->dQ, tmp + off);
  off += asn1_encode_integer(priv->qInv, tmp + off);

  size_t seqlen = off;
  size_t lenlen = asn1_encode_len(NULL, seqlen);
  if (__likely(der)) {
    der[0] = 0x30;
    asn1_encode_len(der + 1, seqlen);
    memcpy(der + 1 + lenlen, tmp, off);
  }
  return 1 + lenlen + off;
}

// --- ASN.1 DER deserialization (minimal, only for keys) ---
static size_t asn1_parse_len(const unsigned char *der, size_t *off) {
  size_t len = der[(*off)++];
  if (__likely(len & 0x80)) {
    int n = len & 0x7F;
    len = 0;
    while (n--)
      len = (len << 8) | der[(*off)++];
  }
  return len;
}

static size_t asn1_parse_integer(mpz_t x, const unsigned char *der, size_t *off) {
  if (__unlikely(der[*off] != 0x02))
    return 0;
  (*off)++;
  size_t ilen = asn1_parse_len(der, off);
  mpz_import(x, ilen, 1, 1, 1, 0, der + *off);
  (*off) += ilen;
  return ilen + 2; // tag + len + value
}

// PEM encoding/decoding
__attr_malloc char *pem_encode(const char *type, const unsigned char *der, size_t der_len) {
  size_t outlen = 4 * ((der_len + 2) / 3);
  char *out = (char *)malloc(outlen + 128);
  char *p = out;
  p += sprintf(p, "-----BEGIN %s-----\n", type);
  for (size_t i = 0; i < der_len; i += 3) {
    unsigned val = der[i] << 16;
    if (__likely(i + 1 < der_len))
      val |= der[i + 1] << 8;
    if (__likely(i + 2 < der_len))
      val |= der[i + 2];
    *p++ = b64tab[(val >> 18) & 0x3F];
    *p++ = b64tab[(val >> 12) & 0x3F];
    *p++ = (i + 1 < der_len) ? b64tab[(val >> 6) & 0x3F] : '=';
    *p++ = (i + 2 < der_len) ? b64tab[val & 0x3F] : '=';
    if (__unlikely(((i / 3 + 1) * 4) % 64 == 0))
      *p++ = '\n';
  }
  if (*(p - 1) != '\n')
    *p++ = '\n';
  sprintf(p, "-----END %s-----\n", type);
  return out;
}

__attr_malloc unsigned char *pem_decode(const char *pem, size_t *outlen) {
  const char *p = strstr(pem, "-----BEGIN");
  if (!__unlikely(p))
    return NULL;
  p = strchr(p, '\n');
  if (!__unlikely(p))
    return NULL;
  p++;
  const char *q = strstr(p, "-----END");
  if (!__unlikely(q))
    return NULL;
  char *buf = (char *)malloc(q - p + 1);
  size_t blen = 0;
  for (const char *t = p; t < q; ++t)
    if (isalnum(*t) || *t == '+' || *t == '/' || *t == '=')
      buf[blen++] = *t;
  buf[blen] = 0;
  size_t b64len = blen;
  *outlen = b64len / 4 * 3;
  unsigned char *out = (unsigned char *)malloc(*outlen);
  size_t j = 0;
  for (size_t i = 0; i < b64len; i += 4) {
    unsigned val = 0;
    for (int k = 0; k < 4; ++k) {
      char c = buf[i + k];
      val <<= 6;
      if ('A' <= c && c <= 'Z')
        val |= c - 'A';
      else if ('a' <= c && c <= 'z')
        val |= c - 'a' + 26;
      else if ('0' <= c && c <= '9')
        val |= c - '0' + 52;
      else if (c == '+')
        val |= 62;
      else if (c == '/')
        val |= 63;
      else if (c == '=')
        val |= 0;
    }
    if (j < *outlen)
      out[j++] = (val >> 16) & 0xFF;
    if (j < *outlen)
      out[j++] = (val >> 8) & 0xFF;
    if (j < *outlen)
      out[j++] = val & 0xFF;
  }
  free(buf);
  return out;
}

size_t rsa_deserialize_public_der(rsa_public_key *pub, const unsigned char *der, size_t len) {
  size_t off = 0;
  if (der[off++] != 0x30)
    return 0;
  size_t seqlen = asn1_parse_len(der, &off);
  mpz_init(pub->n);
  asn1_parse_integer(pub->n, der, &off);
  mpz_init(pub->e);
  asn1_parse_integer(pub->e, der, &off);
  return off;
}

size_t rsa_deserialize_private_der(rsa_private_key *priv, const unsigned char *der, size_t len) {
  size_t off = 0;
  if (der[off++] != 0x30)
    return 0;
  size_t seqlen = asn1_parse_len(der, &off);
  mpz_t t;
  mpz_init(t);
  asn1_parse_integer(t, der, &off); // version
  mpz_init(priv->n);
  asn1_parse_integer(priv->n, der, &off);
  mpz_init(priv->e);
  asn1_parse_integer(priv->e, der, &off);
  mpz_init(priv->d);
  asn1_parse_integer(priv->d, der, &off);
  mpz_init(priv->p);
  asn1_parse_integer(priv->p, der, &off);
  mpz_init(priv->q);
  asn1_parse_integer(priv->q, der, &off);
  mpz_init(priv->dP);
  asn1_parse_integer(priv->dP, der, &off);
  mpz_init(priv->dQ);
  asn1_parse_integer(priv->dQ, der, &off);
  mpz_init(priv->qInv);
  asn1_parse_integer(priv->qInv, der, &off);
  mpz_clear(t);
  return off;
}

// PEM file I/O
__attr_nodiscard int rsa_save_public_pem(const char *fname, const rsa_public_key *pub) {
  unsigned char der[4096];
  size_t derlen = rsa_serialize_public_der(pub, der, sizeof(der));
  char *pem = pem_encode("RSA PUBLIC KEY", der, derlen);
  FILE *f = fopen(fname, "w");
  if (!__unlikely(f)) {
    free(pem);
    return 0;
  }
  fputs(pem, f);
  fclose(f);
  free(pem);
  return 1;
}

__attr_nodiscard int rsa_load_public_pem(const char *fname, rsa_public_key *pub) {
  FILE *f = fopen(fname, "r");
  if (!__unlikely(f))
    return 0;
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  rewind(f);
  char *pem = (char *)malloc(sz + 1);
  fread(pem, 1, sz, f);
  pem[sz] = 0;
  fclose(f);
  size_t derlen;
  unsigned char *der = pem_decode(pem, &derlen);
  free(pem);
  int res = (rsa_deserialize_public_der(pub, der, derlen) > 0);
  free(der);
  return res;
}

__attr_nodiscard int rsa_save_private_pem(const char *fname, const rsa_private_key *priv) {
  unsigned char der[4096];
  size_t derlen = rsa_serialize_private_der(priv, der, sizeof(der));
  char *pem = pem_encode("RSA PRIVATE KEY", der, derlen);
  FILE *f = fopen(fname, "w");
  if (!__unlikely(f)) {
    free(pem);
    return 0;
  }
  fputs(pem, f);
  fclose(f);
  free(pem);
  return 1;
}

__attr_nodiscard int rsa_load_private_pem(const char *fname, rsa_private_key *priv) {
  FILE *f = fopen(fname, "r");
  if (!__unlikely(f))
    return 0;
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  rewind(f);
  char *pem = (char *)malloc(sz + 1);
  fread(pem, 1, sz, f);
  pem[sz] = 0;
  fclose(f);
  size_t derlen;
  unsigned char *der = pem_decode(pem, &derlen);
  free(pem);
  int res = (rsa_deserialize_private_der(priv, der, derlen) > 0);
  free(der);
  return res;
}


// X.509 (SubjectPublicKeyInfo) serialization/deserialization for public keys
static size_t encode_algorithm_identifier(unsigned char *out) {
  unsigned char algid[] = {
      0x30, 0x0d,                                           // SEQUENCE, length 13
      0x06, 0x09,                                           // OID, length 9
      0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // rsaEncryption
      0x05, 0x00                                            // NULL
  };
  if (out)
    memcpy(out, algid, sizeof(algid));
  return sizeof(algid);
}

size_t rsa_serialize_public_x509_der(const rsa_public_key *pub, unsigned char *der, size_t maxlen) {
  unsigned char pubkey_der[1024];
  size_t pubkey_len = rsa_serialize_public_der(pub, pubkey_der, sizeof(pubkey_der));
  // BIT STRING: 0 unused bits + public key DER
  unsigned char bitstr[1024];
  bitstr[0] = 0x00;
  memcpy(bitstr + 1, pubkey_der, pubkey_len);
  size_t bitstr_len = 1 + pubkey_len;

  unsigned char tmp[2048];
  size_t off = 0;
  off += encode_algorithm_identifier(tmp + off);
  tmp[off++] = 0x03; // BIT STRING tag
  off += asn1_encode_len(tmp + off, bitstr_len);
  memcpy(tmp + off, bitstr, bitstr_len);
  off += bitstr_len;

  if (__likely(der)) {
    der[0] = 0x30; // SEQUENCE
    size_t lenlen = asn1_encode_len(der + 1, off);
    memcpy(der + 1 + lenlen, tmp, off);
    return 1 + lenlen + off;
  }
  size_t lenlen = asn1_encode_len(NULL, off);
  return 1 + lenlen + off;
}

size_t rsa_serialize_private_pkcs8_der(const rsa_private_key *priv, unsigned char *der, size_t maxlen) {
  // 1. Encode private key as DER (PKCS#1)
  unsigned char pkcs1[4096];
  size_t pkcs1_len = rsa_serialize_private_der(priv, pkcs1, sizeof(pkcs1));

  // 2. build PKCS#8 structure:
  //   SEQUENCE {
  //     INTEGER(0),
  //     SEQUENCE { OID rsaEncryption, NULL },
  //     OCTET STRING (private key DER)
  //   }
  unsigned char algid[16];
  size_t algid_len = encode_algorithm_identifier(algid);

  unsigned char tmp[8192];
  size_t off = 0;
  // version
  tmp[off++] = 0x02;
  tmp[off++] = 0x01;
  tmp[off++] = 0x00;
  // algorithm identifier
  memcpy(tmp + off, algid, algid_len);
  off += algid_len;
  // privateKey OCTET STRING
  tmp[off++] = 0x04;
  off += asn1_encode_len(tmp + off, pkcs1_len);
  memcpy(tmp + off, pkcs1, pkcs1_len);
  off += pkcs1_len;

  if (__likely(der)) {
    der[0] = 0x30;
    size_t lenlen = asn1_encode_len(der + 1, off);
    memcpy(der + 1 + lenlen, tmp, off);
    return 1 + lenlen + off;
  }
  size_t lenlen = asn1_encode_len(NULL, off);
  return 1 + lenlen + off;
}

size_t rsa_deserialize_public_x509_der(rsa_public_key *pub, const unsigned char *der, size_t len) {
  size_t off = 0;
  // Expect SEQUENCE
  if (der[off++] != 0x30)
    return 0;
  size_t seqlen = asn1_parse_len(der, &off);

  // Skip AlgorithmIdentifier SEQUENCE
  if (der[off++] != 0x30)
    return 0;
  size_t alglen = asn1_parse_len(der, &off);
  off += alglen;

  // BIT STRING
  if (der[off++] != 0x03)
    return 0;
  size_t bitlen = asn1_parse_len(der, &off);
  unsigned char nbits = der[off++]; // number of unused bits, should be 0

  // The actual public key DER is at der+off, of length (bitlen - 1)
  return rsa_deserialize_public_der(pub, der + off, bitlen - 1) + off;
}

size_t rsa_deserialize_private_pkcs8_der(rsa_private_key *priv, const unsigned char *der, size_t len) {
  size_t off = 0;
  // Expect SEQUENCE
  if (der[off++] != 0x30)
    return 0;
  size_t seqlen = asn1_parse_len(der, &off);

  // Version INTEGER
  if (der[off++] != 0x02)
    return 0;
  size_t vlen = asn1_parse_len(der, &off);
  off += vlen;

  // AlgorithmIdentifier SEQUENCE
  if (der[off++] != 0x30)
    return 0;
  size_t alglen = asn1_parse_len(der, &off);
  off += alglen;

  // OCTET STRING
  if (der[off++] != 0x04)
    return 0;
  size_t pklen = asn1_parse_len(der, &off);

  // The actual private key DER is at der+off, length pklen
  return rsa_deserialize_private_der(priv, der + off, pklen) + off;
}

__attr_nodiscard int rsa_save_public_x509_pem(const char *fname, const rsa_public_key *pub) {
  unsigned char der[2048];
  size_t derlen = rsa_serialize_public_x509_der(pub, der, sizeof(der));
  char *pem = pem_encode("PUBLIC KEY", der, derlen);
  FILE *f = fopen(fname, "w");
  if (!__unlikely(f)) {
    free(pem);
    return 0;
  }
  fputs(pem, f);
  fclose(f);
  free(pem);
  return 1;
}

__attr_nodiscard int rsa_load_public_x509_pem(const char *fname, rsa_public_key *pub) {
  FILE *f = fopen(fname, "r");
  if (!__unlikely(f))
    return 0;
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  rewind(f);
  char *pem = (char *)malloc(sz + 1);
  fread(pem, 1, sz, f);
  pem[sz] = 0;
  fclose(f);
  size_t derlen;
  unsigned char *der = pem_decode(pem, &derlen);
  free(pem);
  int res = (rsa_deserialize_public_x509_der(pub, der, derlen) > 0);
  free(der);
  return res;
}

__attr_nodiscard int rsa_save_private_pkcs8_pem(const char *fname, const rsa_private_key *priv) {
  unsigned char der[4096];
  size_t derlen = rsa_serialize_private_pkcs8_der(priv, der, sizeof(der));
  char *pem = pem_encode("PRIVATE KEY", der, derlen);
  FILE *f = fopen(fname, "w");
  if (!__unlikely(f)) {
    free(pem);
    return 0;
  }
  fputs(pem, f);
  fclose(f);
  free(pem);
  return 1;
}

__attr_nodiscard int rsa_load_private_pkcs8_pem(const char *fname, rsa_private_key *priv) {
  FILE *f = fopen(fname, "r");
  if (!__unlikely(f))
    return 0;
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  rewind(f);
  char *pem = (char *)malloc(sz + 1);
  fread(pem, 1, sz, f);
  pem[sz] = 0;
  fclose(f);
  size_t derlen;
  unsigned char *der = pem_decode(pem, &derlen);
  free(pem);
  int res = (rsa_deserialize_private_pkcs8_der(priv, der, derlen) > 0);
  free(der);
  return res;
}


// File encryption/decryption
__attr_nodiscard int rsa_encrypt_file(const char *infile, const char *outfile, const rsa_public_key *pub) {
  FILE *fin = fopen(infile, "rb");
  FILE *fout = fopen(outfile, "wb");
  if (!fin || !fout) {
    if (fin)
      fclose(fin);
    if (fout)
      fclose(fout);
    return 0;
  }

  size_t nbytes = (mpz_sizeinbase(pub->n, 2) - 1) / 8; // max input bytes per block
  unsigned char *inbuf = (unsigned char *)malloc(nbytes);
  unsigned char *outbuf = (unsigned char *)malloc(mpz_sizeinbase(pub->n, 2) / 8 + 8);
  mpz_t m, c;
  mpz_inits(m, c, NULL);

  size_t read;
  while ((read = fread(inbuf, 1, nbytes, fin)) > 0) {
    mpz_import(m, read, 1, 1, 1, 0, inbuf);
    rsa_encrypt(c, m, pub);
    size_t clen;
    mpz_export(outbuf, &clen, 1, 1, 1, 0, c);
    fwrite(&clen, sizeof(size_t), 1, fout); // write block length
    fwrite(outbuf, 1, clen, fout);
  }

  mpz_clears(m, c, NULL);
  free(inbuf);
  free(outbuf);
  fclose(fin);
  fclose(fout);
  return 1;
}

__attr_nodiscard int rsa_decrypt_file(const char *infile, const char *outfile, const rsa_private_key *priv) {
  FILE *fin = fopen(infile, "rb");
  FILE *fout = fopen(outfile, "wb");
  if (!fin || !fout) {
    if (fin)
      fclose(fin);
    if (fout)
      fclose(fout);
    return 0;
  }

  unsigned char *inbuf = (unsigned char *)malloc(mpz_sizeinbase(priv->n, 2) / 8 + 8);
  unsigned char *outbuf = (unsigned char *)malloc(mpz_sizeinbase(priv->n, 2) / 8 + 8);
  mpz_t c, m;
  mpz_inits(c, m, NULL);

  size_t clen, mlen;
  while (fread(&clen, sizeof(size_t), 1, fin) == 1) {
    if (fread(inbuf, 1, clen, fin) != clen)
      break;
    mpz_import(c, clen, 1, 1, 1, 0, inbuf);
    rsa_decrypt(m, c, priv);
    mpz_export(outbuf, &mlen, 1, 1, 1, 0, m);
    fwrite(outbuf, 1, mlen, fout);
  }

  mpz_clears(c, m, NULL);
  free(inbuf);
  free(outbuf);
  fclose(fin);
  fclose(fout);
  return 1;
}

// Buffer/file helpers
__attr_nodiscard int save_file_hex(const char *fname, const unsigned char *buf, size_t len) {
  FILE *f = fopen(fname, "w");
  if (!__unlikely(f))
    return 0;
  for (size_t i = 0; i < len; ++i)
    fprintf(f, "%02x", buf[i]);
  fclose(f);
  return 1;
}

__attr_nodiscard int save_file_base64(const char *fname, const unsigned char *buf, size_t len) {
  FILE *f = fopen(fname, "w");
  if (!__unlikely(f))
    return 0;
  size_t i;
  for (i = 0; i + 2 < len; i += 3) {
    unsigned val = (buf[i] << 16) | (buf[i + 1] << 8) | buf[i + 2];
    fputc(b64tab[(val >> 18) & 0x3F], f);
    fputc(b64tab[(val >> 12) & 0x3F], f);
    fputc(b64tab[(val >> 6) & 0x3F], f);
    fputc(b64tab[val & 0x3F], f);
  }
  if (i < len) {
    unsigned val = buf[i] << 16;
    int pad = 0;
    if (i + 1 < len) {
      val |= buf[i + 1] << 8;
    } else {
      pad = 2;
    }
    if (i + 2 < len) {
      val |= buf[i + 2];
    } else if (pad == 0) {
      pad = 1;
    }
    fputc(b64tab[(val >> 18) & 0x3F], f);
    fputc(b64tab[(val >> 12) & 0x3F], f);
    fputc(pad < 2 ? b64tab[(val >> 6) & 0x3F] : '=', f);
    fputc(pad < 1 ? b64tab[val & 0x3F] : '=', f);
  }
  fputc('\n', f);
  fclose(f);
  return 1;
}

__attr_nodiscard int save_file_ascii(const char *fname, const unsigned char *buf, size_t len) {
  FILE *f = fopen(fname, "w");
  if (!__unlikely(f))
    return 0;
  for (size_t i = 0; i < len; ++i)
    fputc(isprint(buf[i]) ? buf[i] : '.', f);
  fclose(f);
  return 1;
}

#endif // RSA_C_H
