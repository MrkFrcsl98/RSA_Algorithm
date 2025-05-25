#ifndef RSA_C_H
#define RSA_C_H

#include <gmp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>


// ========== Debugging Macros ==========
#ifndef RSA_DEBUG
//#define RSA_DEBUG 1
#endif



#if RSA_DEBUG
// ANSI color codes for colored output
#define COLOR_RED    "\033[1;31m"
#define COLOR_GREEN  "\033[1;32m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_BLUE   "\033[1;34m"
#define COLOR_RESET  "\033[0m"

#define DBG(fmt, ...) fprintf(stderr, "[DEBUG] %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
static void print_file_info(const char *fname, FILE *f) {
    struct stat st;
    if (fname && stat(fname, &st) == 0) {
        fprintf(stderr, "[DEBUG] File: %s | Size: %ld bytes | Permissions: %o | Type: %s\n",
            fname,
            (long)st.st_size,
            st.st_mode & 0777,
            S_ISREG(st.st_mode) ? "regular" : S_ISDIR(st.st_mode) ? "directory" : "other");
    } else {
        fprintf(stderr, "[DEBUG] Could not stat file: %s\n", fname ? fname : "(null)");
    }
}

#define OK(fmt, ...)    fprintf(stderr, COLOR_GREEN  "[OK] "    fmt COLOR_RESET "\n", ##__VA_ARGS__)
#define ERROR(fmt, ...) fprintf(stderr, COLOR_RED    "[ERROR] " fmt COLOR_RESET "\n", ##__VA_ARGS__)
#define INFO(fmt, ...)  fprintf(stderr, COLOR_BLUE   "[INFO] "  fmt COLOR_RESET "\n", ##__VA_ARGS__)

// Hex dump utility
static void dump_hex(const unsigned char *buf, size_t len, const char *label) {
    fprintf(stderr, COLOR_YELLOW "[DUMP] %s (len=%zu): ", label, len);
    for (size_t i = 0; i < len; ++i)
        fprintf(stderr, "%02x", buf[i]);
    fprintf(stderr, COLOR_RESET "\n");
}

// Dump mpz_t in hex
static void dump_mpz(const mpz_t n, const char *label) {
    size_t count = (mpz_sizeinbase(n, 2) + 7) / 8;
    unsigned char *buf = (unsigned char*)malloc(count);
    if (!buf) {
        ERROR("Memory allocation failed in dump_mpz for %s", label);
        return;
    }
    mpz_export(buf, &count, 1, 1, 1, 0, n);
    dump_hex(buf, count, label);
    free(buf);
}
#else
#define OK(...)    ((void)0)
#define ERROR(...) ((void)0)
#define INFO(...)  ((void)0)
#define dump_hex(...) ((void)0)
#define dump_mpz(...) ((void)0)
#define DBG(...)    ((void)0)
static void print_file_info(...)  {}
#endif

#define RSA_MAX_FILE_SIZE (10 * 1024 * 1024) // 10mb



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




// ========== Secure Random Bytes ==========
__attr_nodiscard int rsa_get_secure_random_bytes(uint8_t *__restrict__ buf, size_t len) __noexcept {
    INFO("Requesting %zu secure random bytes", len);
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) {
        ERROR("Failed to open /dev/urandom for reading");
        return 0;
    }
    INFO("Opened /dev/urandom for reading");
    size_t n = fread(buf, 1, len, f);
    fclose(f);
    if (n != len) {
        ERROR("Read only %zu of %zu bytes from /dev/urandom", n, len);
        return 0;
    } else {
        OK("Successfully read %zu random bytes from /dev/urandom", n);
        dump_hex(buf, len, "/dev/urandom Output");
    }
    return 1;
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


static int is_file_too_large(FILE *f) {
    if (!f) return 1;
    long cur = ftell(f);
    if (cur == -1) return 1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz < 0) return 1;
    return sz > RSA_MAX_FILE_SIZE;
}

// ---- Blinding, Constant Time Modular Exponentiation, Constant Time Memory Comparisiom ----

// Constant-time ct_memcmp
static int ct_memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    unsigned char diff = 0;
    INFO("Comparing %zu bytes using ct_memcmp", n);
    for (size_t i = 0; i < n; ++i) {
        diff |= pa[i] ^ pb[i];
        if (pa[i] != pb[i]) {
            ERROR("Mismatch at offset %zu: %02x vs %02x", i, pa[i], pb[i]);
        }
    }
    if (diff == 0) {
        OK("ct_memcmp: Buffers are equal");
    } else {
        ERROR("ct_memcmp: Buffers are NOT equal");
    }
    return diff; // 0 if equal, nonzero if not
}

void ct_mpz_powm(mpz_t rop, const mpz_t base, const mpz_t exp, const mpz_t mod)
{
    mpz_t result, b;
    mpz_inits(result, b, NULL);
    mpz_set_ui(result, 1);
    mpz_mod(b, base, mod);

    size_t nbits = mpz_sizeinbase(exp, 2);
    INFO("ct_mpz_powm: base, exp, mod (hex):");
    dump_mpz(base, "base");
    dump_mpz(exp, "exp");
    dump_mpz(mod, "mod");
    for (ptrdiff_t i = nbits - 1; i >= 0; --i) {
        mpz_mul(result, result, result);
        mpz_mod(result, result, mod);

        if (mpz_tstbit(exp, i)) {
            mpz_mul(result, result, b);
            mpz_mod(result, result, mod);
        } else {
        }
    }
    mpz_set(rop, result);
    dump_mpz(rop, "ct_mpz_powm result");
    mpz_clears(result, b, NULL);
    OK("ct_mpz_powm completed");
}

// --- RSA blinding ---
void rsa_decrypt_blinded(mpz_t out, const mpz_t in, const rsa_private_key *priv) {
    INFO("rsa_decrypt_blinded: Starting blinded RSA decryption");
    gmp_randstate_t state;
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, (unsigned long)time(NULL) ^ (unsigned long)rand());

    mpz_t r, r_inv, blinded, tmp, gcd;
    mpz_inits(r, r_inv, blinded, tmp, gcd, NULL);

    // Generate random r with 1 < r < n, gcd(r, n) == 1
    int attempts = 0;
    do {
        mpz_urandomm(r, state, priv->n);
        mpz_gcd(gcd, r, priv->n);
        attempts++;
        INFO("Blinding attempt #%d: r generated", attempts);
        dump_mpz(r, "r");
        dump_mpz(gcd, "gcd(r, n)");
    } while (mpz_cmp_ui(r, 1) <= 0 || mpz_cmp_ui(gcd, 1) != 0);

    OK("Blinding factor r found in %d attempts", attempts);

    // blinded = in * r^e mod n
    INFO("Blinding input and computing r^e mod n");
    ct_mpz_powm(tmp, r, priv->e, priv->n);
    dump_mpz(tmp, "r^e mod n");
    mpz_mul(blinded, in, tmp);
    mpz_mod(blinded, blinded, priv->n);
    dump_mpz(blinded, "blinded input");

    // decrypted = blinded^d mod n
    INFO("Decrypting blinded value");
    ct_mpz_powm(tmp, blinded, priv->d, priv->n);
    dump_mpz(tmp, "blinded^d mod n");

    // r_inv = r^-1 mod n
    if (mpz_invert(r_inv, r, priv->n) == 0) {
        ERROR("Failed to invert blinding factor r modulo n (r has no inverse)");
    } else {
        OK("Computed modular inverse of r");
        dump_mpz(r_inv, "r_inv");
    }

    // out = decrypted * r_inv mod n
    mpz_mul(out, tmp, r_inv);
    mpz_mod(out, out, priv->n);
    dump_mpz(out, "final plaintext output");

    mpz_clears(r, r_inv, blinded, tmp, gcd, NULL);
    gmp_randclear(state);
    OK("rsa_decrypt_blinded completed successfully");
}

// ========== SHA256 Functions ==========

__attr_hot static void sha256_transform(sha256_ctx *__restrict__ ctx, const uint8_t *__restrict__ data) __noexcept {
    INFO("sha256_transform: Begin transformation with data:");
    dump_hex(data, 64, "Block Data");
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
    OK("sha256_transform: Transformation complete.");
}

__attr_hot static void sha256_init(sha256_ctx *__restrict__ ctx) __noexcept {
    if (!ctx) {
        ERROR("sha256_init: ctx is NULL");
        return;
    }
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
    OK("sha256_init: Context initialized.");
}

__attr_hot static void sha256_update(sha256_ctx *__restrict__ ctx, const uint8_t *__restrict__ data, size_t len) __noexcept {
    if (!ctx || (!data && len > 0)) {
        ERROR("sha256_update: invalid arguments (ctx=%p, data=%p, len=%zu)", ctx, data, len);
        return;
    }
    INFO("sha256_update: Updating with %zu bytes of data.", len);
    dump_hex(data, len, "Update Data");
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
    OK("sha256_update: Update complete.");
}

__attr_hot static void sha256_final(sha256_ctx *__restrict__ ctx, uint8_t *__restrict__ hash) __noexcept {
    if (!ctx || !hash) {
        ERROR("sha256_final: null argument(s): ctx=%p hash=%p", (void*)ctx, (void*)hash);
        return;
    }
    INFO("sha256_final: Finalizing SHA256 hash.");
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
    dump_hex(hash, 32, "SHA256 Hash Output");
    OK("sha256_final: Hash finalized.");
}

__attr_hot void sha256(const uint8_t *__restrict__ data, size_t len, uint8_t *__restrict__ out) __noexcept {
    if (!out || (len > 0 && !data)) {
        ERROR("sha256: invalid argument(s): out=%p data=%p len=%zu", (void*)out, (void*)data, len);
        return;
    }
    INFO("sha256: Hashing %zu bytes.", len);
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
    OK("sha256: Hashing complete.");
}

__attr_hot static void mgf1_sha256(const uint8_t *__restrict__ seed, size_t seedlen, uint8_t *__restrict__ mask, size_t masklen) __noexcept {
    if (!seed && seedlen) {
        ERROR("mgf1_sha256: seed is NULL but seedlen=%zu", seedlen);
        return;
    }
    if (!mask && masklen) {
        ERROR("mgf1_sha256: mask is NULL but masklen=%zu", masklen);
        return;
    }
    INFO("mgf1_sha256: Generating mask of length %zu from seed of length %zu", masklen, seedlen);
    dump_hex(seed, seedlen, "MGF1 Seed");
    uint32_t counter = 0;
    uint8_t digest[32];
    size_t outpos = 0;
    while (outpos < masklen) {
        uint8_t cnt[4] = {(uint8_t)(counter >> 24), (uint8_t)(counter >> 16), (uint8_t)(counter >> 8), (uint8_t)(counter)};
        uint8_t *tmp = (uint8_t *)malloc(seedlen + 4);
        if (!tmp) {
            ERROR("mgf1_sha256: malloc failed (seedlen+4=%zu)", seedlen + 4);
            return;
        }
        memcpy(tmp, seed, seedlen);
        memcpy(tmp + seedlen, cnt, 4);
        sha256(tmp, seedlen + 4, digest);
        free(tmp);
        size_t chunk = (masklen - outpos < 32) ? (masklen - outpos) : 32;
        memcpy(mask + outpos, digest, chunk);
        outpos += chunk;
        counter++;
    }
    dump_hex(mask, masklen, "MGF1 Mask Output");
    OK("mgf1_sha256: Mask generation complete.");
}

__attr_nodiscard __attr_hot int oaep_encode(
  const uint8_t *__restrict__ in, size_t inlen, uint8_t *__restrict__ out, size_t k,
  const uint8_t *__restrict__ label, size_t labellen) __noexcept
{
  size_t hLen = 32;
  DBG("oaep_encode: Entry (inlen=%zu, k=%zu, labellen=%zu)", inlen, k, labellen);

  if (k < 2 * hLen + 2) {
    ERROR("oaep_encode: Output buffer too small for OAEP: k=%zu", k);
    return 0;
  }
  if (inlen > k - 2 * hLen - 2) {
    ERROR("oaep_encode: Input too large: inlen=%zu, max=%zu", inlen, k - 2 * hLen - 2);
    return 0;
  }

  uint8_t lHash[32];
  sha256(label ? label : (const uint8_t *)"", labellen, lHash);
  dump_hex(lHash, 32, "oaep_encode: lHash");

  size_t ps_len = k - inlen - 2 * hLen - 2;
  uint8_t *DB = (uint8_t *)malloc(k - hLen - 1);
  if (!DB) {
    ERROR("oaep_encode: malloc failed for DB (%zu bytes)", k - hLen - 1);
    return 0;
  }
  memcpy(DB, lHash, hLen);
  memset(DB + hLen, 0, ps_len);
  DB[hLen + ps_len] = 0x01;
  memcpy(DB + hLen + ps_len + 1, in, inlen);

  dump_hex(DB, k - hLen - 1, "oaep_encode: DB before masking");

  uint8_t *seed = (uint8_t *)malloc(hLen);
  if (!seed) {
    ERROR("oaep_encode: malloc failed for seed");
    free(DB);
    return 0;
  }
  if (!__unlikely(rsa_get_secure_random_bytes(seed, hLen))) {
    ERROR("oaep_encode: secure random failed, using weak fallback");
    for (size_t i = 0; i < hLen; ++i)
      seed[i] = rand() & 0xFF;
  }
  dump_hex(seed, hLen, "oaep_encode: seed");

  uint8_t *dbMask = (uint8_t *)malloc(k - hLen - 1);
  if (!dbMask) {
    ERROR("oaep_encode: malloc failed for dbMask");
    free(DB); free(seed);
    return 0;
  }
  mgf1_sha256(seed, hLen, dbMask, k - hLen - 1);
  for (size_t i = 0; i < k - hLen - 1; ++i)
    DB[i] ^= dbMask[i];
  dump_hex(DB, k - hLen - 1, "oaep_encode: masked DB");

  uint8_t *seedMask = (uint8_t *)malloc(hLen);
  if (!seedMask) {
    ERROR("oaep_encode: malloc failed for seedMask");
    free(DB); free(seed); free(dbMask);
    return 0;
  }
  mgf1_sha256(DB, k - hLen - 1, seedMask, hLen);
  for (size_t i = 0; i < hLen; ++i)
    seed[i] ^= seedMask[i];
  dump_hex(seed, hLen, "oaep_encode: masked seed");

  out[0] = 0x00;
  memcpy(out + 1, seed, hLen);
  memcpy(out + 1 + hLen, DB, k - hLen - 1);

  dump_hex(out, k, "oaep_encode: OAEP encoded output");

  free(DB);
  free(seed);
  free(dbMask);
  free(seedMask);
  OK("oaep_encode: Success");
  return 1;
}

__attr_nodiscard __attr_hot int oaep_decode(
  const uint8_t *__restrict__ in, size_t k, uint8_t *__restrict__ out, size_t *__restrict__ outlen,
  const uint8_t *__restrict__ label, size_t labellen) __noexcept
{
  size_t hLen = 32;
  DBG("oaep_decode: Entry (k=%zu, labellen=%zu)", k, labellen);
  dump_hex(in, k, "oaep_decode: input");

  if (k < 2 * hLen + 2) {
    ERROR("oaep_decode: k too small for OAEP: k=%zu", k);
    return 0;
  }
  if (!in || !out || !outlen) {
    ERROR("oaep_decode: null argument(s): in=%p out=%p outlen=%p", (void*)in, (void*)out, (void*)outlen);
    return 0;
  }
  if (in[0] != 0x00) {
    ERROR("oaep_decode: leading byte is not 0x00");
    return 0;
  }

  const uint8_t *maskedSeed = in + 1;
  const uint8_t *maskedDB = in + 1 + hLen;

  uint8_t seed[32];
  memcpy(seed, maskedSeed, hLen);
  dump_hex(seed, hLen, "oaep_decode: maskedSeed");

  uint8_t *DB = (uint8_t *)malloc(k - hLen - 1);
  if (!DB) {
    ERROR("oaep_decode: malloc failed for DB");
    return 0;
  }
  memcpy(DB, maskedDB, k - hLen - 1);
  dump_hex(DB, k - hLen - 1, "oaep_decode: maskedDB");

  uint8_t *seedMask = (uint8_t *)malloc(hLen);
  if (!seedMask) {
    ERROR("oaep_decode: malloc failed for seedMask");
    free(DB);
    return 0;
  }
  mgf1_sha256(DB, k - hLen - 1, seedMask, hLen);
  for (size_t i = 0; i < hLen; ++i)
    seed[i] ^= seedMask[i];
  dump_hex(seed, hLen, "oaep_decode: seed");

  uint8_t *dbMask = (uint8_t *)malloc(k - hLen - 1);
  if (!dbMask) {
    ERROR("oaep_decode: malloc failed for dbMask");
    free(DB);
    free(seedMask);
    return 0;
  }
  mgf1_sha256(seed, hLen, dbMask, k - hLen - 1);
  for (size_t i = 0; i < k - hLen - 1; ++i)
    DB[i] ^= dbMask[i];
  dump_hex(DB, k - hLen - 1, "oaep_decode: DB");

  uint8_t lHash[32];
  sha256(label ? label : (const uint8_t *)"", labellen, lHash);
  dump_hex(lHash, 32, "oaep_decode: lHash");
  // Use constant time comparison in production for security
  if (__likely(ct_memcmp(DB, lHash, hLen))) {
    ERROR("oaep_decode: lHash mismatch");
    free(DB); free(seedMask); free(dbMask);
    return 0;
  }

  // OAEP decode (ending section)
  size_t i = hLen;
  while (i < k - hLen - 1 && DB[i] == 0x00)
    ++i;
  if (i == k - hLen - 1 || DB[i] != 0x01) {
    ERROR("oaep_decode: 0x01 separator not found in DB");
    free(DB);
    free(seedMask);
    free(dbMask);
    return 0;
  }

  size_t mLen = k - hLen - 1 - i - 1;
  memcpy(out, DB + i + 1, mLen);
  *outlen = mLen;

  dump_hex(out, mLen, "oaep_decode: Decoded output");

  free(DB);
  free(seedMask);
  free(dbMask);
  OK("oaep_decode: Success");
  return 1;
}

__attr_nodiscard int modinv(mpz_t rop, const mpz_t a, const mpz_t m) {
  int ret = mpz_invert(rop, a, m) != 0;
  if (!ret) DBG("modinv: no modular inverse exists!");
#ifdef RSA_DEBUG
  else {
    dump_mpz(rop, "modinv result");
  }
#endif
  return ret;
}

// Generate a random probable prime of given bits
void random_prime(mpz_t rop, gmp_randstate_t state, int bits) {
  if (!rop) {
    DBG("random_prime: rop=NULL");
    return;
  }
  int tries = 0;
  do {
    mpz_urandomb(rop, state, bits);
    mpz_setbit(rop, bits - 1); // ensure high bit set
    mpz_setbit(rop, 0);        // ensure odd
    ++tries;
  } while (!mpz_probab_prime_p(rop, 25));
  DBG("random_prime: generated probable prime in %d tries", tries);
  dump_mpz(rop, "random_prime result");
}

// Key generation
void rsa_generate_keypair(rsa_public_key *pub, rsa_private_key *priv, int bits) {
  DBG("rsa_generate_keypair: Start key generation (%d bits)", bits);
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

  dump_mpz(p, "p");
  dump_mpz(q, "q");

  // n = p*q
  mpz_init(priv->n);
  mpz_mul(priv->n, p, q);
  dump_mpz(priv->n, "n");

  // phi = (p-1)*(q-1)
  mpz_sub_ui(p, p, 1);
  mpz_sub_ui(q, q, 1);
  mpz_mul(phi, p, q);
  dump_mpz(phi, "phi");

  // e = 65537
  mpz_init_set_ui(priv->e, 65537);

  // d = e^{-1} mod phi
  mpz_init(priv->d);
  if (!__unlikely(modinv(priv->d, priv->e, phi))) {
    ERROR("rsa_generate_keypair: No modular inverse for 'e' (should not happen)");
    mpz_clears(p, q, phi, dP, dQ, qInv, priv->d, priv->e, priv->n, NULL);
    gmp_randclear(state);
    exit(1);
  }
  dump_mpz(priv->d, "d");

  // restore p, q
  mpz_add_ui(p, p, 1);
  mpz_add_ui(q, q, 1);

  // CRT params
  mpz_init(priv->p); mpz_set(priv->p, p);
  mpz_init(priv->q); mpz_set(priv->q, q);

  mpz_init(dP);
  mpz_sub_ui(dP, p, 1);
  mpz_mod(priv->dP, priv->d, dP);

  mpz_init(dQ);
  mpz_sub_ui(dQ, q, 1);
  mpz_mod(priv->dQ, priv->d, dQ);

  mpz_init(qInv);
  if(!__unlikely(modinv(qInv, priv->q, priv->p))) {
    ERROR("rsa_generate_keypair: No modular inverse for qInv");
    mpz_clears(p, q, phi, dP, dQ, qInv, priv->d, priv->e, priv->n, priv->p, priv->q, priv->dP, priv->dQ, NULL);
    gmp_randclear(state);
    exit(1);
  }
  mpz_set(priv->qInv, qInv);

  dump_mpz(priv->p, "priv->p");
  dump_mpz(priv->q, "priv->q");
  dump_mpz(priv->dP, "priv->dP");
  dump_mpz(priv->dQ, "priv->dQ");
  dump_mpz(priv->qInv, "priv->qInv");

  // Fill public key
  mpz_init_set(pub->n, priv->n);
  mpz_init_set(pub->e, priv->e);

  dump_mpz(pub->n, "pub->n");
  dump_mpz(pub->e, "pub->e");

  mpz_clears(p, q, phi, dP, dQ, qInv, NULL);
  gmp_randclear(state);
  OK("rsa_generate_keypair: Key generation complete");
}

// Key storage: PEM-like (hex, one value per line)
__attr_nodiscard int rsa_save_public(const char *fname, const rsa_public_key *pub) {
  FILE *f = fopen(fname, "w");
  if (!f) {
    ERROR("rsa_save_public: Failed to open '%s' for writing: %s", fname, strerror(errno));
    print_file_info(fname, f);
    return 0;
  }
  print_file_info(fname, f);
#ifdef RSA_DEBUG
  dump_mpz(pub->n, "rsa_save_public: n");
  dump_mpz(pub->e, "rsa_save_public: e");
#endif
  gmp_fprintf(f, "%Zx\n%Zx\n", pub->n, pub->e);
  fclose(f);
  OK("rsa_save_public: Written public key to '%s'", fname);
  return 1;
}

__attr_nodiscard int rsa_load_public(const char *fname, rsa_public_key *pub) {
  FILE *f = fopen(fname, "r");
  if (!f) {
    ERROR("rsa_load_public: Failed to open '%s' for reading: %s", fname, strerror(errno));
    print_file_info(fname, f);
    return 0;
  }
  if (is_file_too_large(f)) {
    ERROR("rsa_load_public: File '%s' too large (> %d bytes)", fname, RSA_MAX_FILE_SIZE);
    print_file_info(fname, f);
    fclose(f);
    return 0;
  }
  print_file_info(fname, f);
  mpz_init(pub->n);
  mpz_init(pub->e);
  gmp_fscanf(f, "%Zx\n%Zx\n", pub->n, pub->e);
#ifdef RSA_DEBUG
  dump_mpz(pub->n, "rsa_load_public: n");
  dump_mpz(pub->e, "rsa_load_public: e");
#endif
  fclose(f);
  OK("rsa_load_public: Loaded public key from '%s'", fname);
  return 1;
}

__attr_nodiscard int rsa_save_private(const char *fname, const rsa_private_key *priv) {
  FILE *f = fopen(fname, "w");
  if (!f) {
    ERROR("rsa_save_private: Failed to open '%s' for writing: %s", fname, strerror(errno));
    print_file_info(fname, f);
    return 0;
  }
  print_file_info(fname, f);
#ifdef RSA_DEBUG
  dump_mpz(priv->n, "rsa_save_private: n");
  dump_mpz(priv->e, "rsa_save_private: e");
  dump_mpz(priv->d, "rsa_save_private: d");
  dump_mpz(priv->p, "rsa_save_private: p");
  dump_mpz(priv->q, "rsa_save_private: q");
  dump_mpz(priv->dP, "rsa_save_private: dP");
  dump_mpz(priv->dQ, "rsa_save_private: dQ");
  dump_mpz(priv->qInv, "rsa_save_private: qInv");
#endif
  gmp_fprintf(f, "%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n", priv->n, priv->e, priv->d, priv->p, priv->q, priv->dP, priv->dQ, priv->qInv);
  fclose(f);
  OK("rsa_save_private: Written private key to '%s'", fname);
  return 1;
}

__attr_nodiscard int rsa_load_private(const char *fname, rsa_private_key *priv) {
  FILE *f = fopen(fname, "r");
  if (!f) {
    ERROR("rsa_load_private: Failed to open '%s' for reading: %s", fname, strerror(errno));
    print_file_info(fname, f);
    return 0;
  }
  if (is_file_too_large(f)) {
    ERROR("rsa_load_private: File '%s' too large (> %d bytes)", fname, RSA_MAX_FILE_SIZE);
    print_file_info(fname, f);
    fclose(f);
    return 0;
  }
  print_file_info(fname, f);
  mpz_inits(priv->n, priv->e, priv->d, priv->p, priv->q, priv->dP, priv->dQ, priv->qInv, NULL);
  gmp_fscanf(f, "%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n", priv->n, priv->e, priv->d, priv->p, priv->q, priv->dP, priv->dQ, priv->qInv);
#ifdef RSA_DEBUG
  dump_mpz(priv->n,   "rsa_load_private: n");
  dump_mpz(priv->e,   "rsa_load_private: e");
  dump_mpz(priv->d,   "rsa_load_private: d");
  dump_mpz(priv->p,   "rsa_load_private: p");
  dump_mpz(priv->q,   "rsa_load_private: q");
  dump_mpz(priv->dP,  "rsa_load_private: dP");
  dump_mpz(priv->dQ,  "rsa_load_private: dQ");
  dump_mpz(priv->qInv,"rsa_load_private: qInv");
#endif
  fclose(f);
  OK("rsa_load_private: Loaded private key from '%s'", fname);
  return 1;
}

void rsa_encrypt(mpz_t out, const mpz_t in, const rsa_public_key *pub) {
  if (!out || !in || !pub) {
    ERROR("rsa_encrypt: null argument(s): out=%p in=%p pub=%p", (void*)out, (void*)in, (void*)pub);
    return;
  }
#ifdef RSA_DEBUG
  dump_mpz(in, "rsa_encrypt: input");
#endif
  mpz_powm(out, in, pub->e, pub->n);
#ifdef RSA_DEBUG
  dump_mpz(out, "rsa_encrypt: output");
#endif
}

void rsa_decrypt(mpz_t out, const mpz_t in, const rsa_private_key *priv) {
  rsa_decrypt_blinded(out, in, priv);
}

int rsa_encrypt_oaep(mpz_t out, const uint8_t *in, size_t inlen, const rsa_public_key *pub, const uint8_t *label, size_t labellen) {
  if (!out || !in || !pub) {
    ERROR("rsa_encrypt_oaep: null argument(s): out=%p in=%p pub=%p", (void*)out, (void*)in, (void*)pub);
    return 0;
  }
  size_t k = (mpz_sizeinbase(pub->n, 2) + 7) / 8;
  uint8_t *em = (uint8_t *)malloc(k);
  if (!em) {
    ERROR("rsa_encrypt_oaep: malloc failed for em (%zu bytes)", k);
    return 0;
  }
  if (!__unlikely(oaep_encode(in, inlen, em, k, label, labellen))) {
    ERROR("rsa_encrypt_oaep: OAEP encoding failed");
    free(em);
    return 0;
  }
#ifdef RSA_DEBUG
  fprintf(stderr, COLOR_YELLOW "[DUMP] rsa_encrypt_oaep: encoded OAEP message (len=%zu): ", k);
  for (size_t i = 0; i < k; ++i) fprintf(stderr, "%02x", em[i]);
  fprintf(stderr, COLOR_RESET "\n");
#endif
  mpz_import(out, k, 1, 1, 1, 0, em);
  rsa_encrypt(out, out, pub); // in-place
  free(em);
  OK("rsa_encrypt_oaep: Success");
  return 1;
}

int rsa_decrypt_oaep(uint8_t *out, size_t *outlen, const mpz_t in, const rsa_private_key *priv, const uint8_t *label, size_t labellen) {
  if (!out || !outlen || !in || !priv) {
    ERROR("rsa_decrypt_oaep: null argument(s): out=%p outlen=%p in=%p priv=%p", (void*)out, (void*)outlen, (void*)in, (void*)priv);
    return 0;
  }
  size_t k = (mpz_sizeinbase(priv->n, 2) + 7) / 8;
  uint8_t *em = (uint8_t *)malloc(k);
  if (!em) {
    ERROR("rsa_decrypt_oaep: malloc failed for em (%zu bytes)", k);
    return 0;
  }
  mpz_t m;
  mpz_init(m);
  rsa_decrypt_blinded(m, in, priv);
  size_t tmplen;
  mpz_export(em, &tmplen, 1, 1, 1, 0, m);
  if (__likely(tmplen < k)) {
    memmove(em + (k - tmplen), em, tmplen);
    memset(em, 0, k - tmplen);
  }
#ifdef RSA_DEBUG
  fprintf(stderr, COLOR_YELLOW "[DUMP] rsa_decrypt_oaep: decrypted OAEP message (len=%zu): ", k);
  for (size_t i = 0; i < k; ++i) fprintf(stderr, "%02x", em[i]);
  fprintf(stderr, COLOR_RESET "\n");
#endif
  int ret = oaep_decode(em, k, out, outlen, label, labellen);
  mpz_clear(m);
  free(em);
  OK("rsa_decrypt_oaep: Success");
  return ret;
}

void rsa_clear_public(rsa_public_key *pub) {
  if (!pub) {
    DBG("rsa_clear_public: pub is NULL");
    return;
  }
  mpz_clear(pub->n);
  mpz_clear(pub->e);
}

void rsa_clear_private(rsa_private_key *priv) {
  if (!priv) {
    DBG("rsa_clear_private: priv is NULL");
    return;
  }
  mpz_clears(priv->n, priv->e, priv->d, priv->p, priv->q, priv->dP, priv->dQ, priv->qInv, NULL);
}

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
  if (!buf) {
    ERROR("asn1_encode_integer: malloc failed for buf (%zu bytes)", count + 1);
    return 0;
  }
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

size_t rsa_serialize_public_der(const rsa_public_key *pub, unsigned char *der, size_t maxlen) {
  if (!pub || !der) {
    ERROR("rsa_serialize_public_der: pub or der is NULL");
    return 0;
  }
  unsigned char tmp[2048];
  size_t nlen = asn1_encode_integer(pub->n, tmp);
  size_t elen = asn1_encode_integer(pub->e, tmp + nlen);

  size_t seqlen = nlen + elen;
  size_t lenlen = asn1_encode_len(NULL, seqlen);
  size_t total_len = 1 + lenlen + nlen + elen;
  if (total_len > maxlen) {
    ERROR("rsa_serialize_public_der: output buffer too small (%zu > %zu)", total_len, maxlen);
    return 0;
  }
  if (__likely(der)) {
    der[0] = 0x30;
    asn1_encode_len(der + 1, seqlen);
    memcpy(der + 1 + lenlen, tmp, nlen + elen);
  }
  OK("rsa_serialize_public_der: DER serialization done (len=%zu)", total_len);
  return total_len;
}
size_t rsa_serialize_private_der(const rsa_private_key *priv, unsigned char *der, size_t maxlen) {
  if (!priv || !der) {
    DBG("rsa_serialize_private_der: priv or der is NULL");
    return 0;
  }
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
  size_t total_len = 1 + lenlen + off;
  if (total_len > maxlen) {
    DBG("rsa_serialize_private_der: output buffer too small (%zu > %zu)", total_len, maxlen);
    return 0;
  }
  if (__likely(der)) {
    der[0] = 0x30;
    asn1_encode_len(der + 1, seqlen);
    memcpy(der + 1 + lenlen, tmp, off);
  }
  return total_len;
}

// --- ASN.1 DER deserialization (minimal, only for keys) ---
static size_t asn1_parse_len(const unsigned char *der, size_t *off) {
  if (!der || !off) {
    DBG("asn1_parse_len: der or off is NULL");
    return 0;
  }
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
  if (!x || !der || !off) {
    DBG("asn1_parse_integer: x, der, or off is NULL");
    return 0;
  }
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
  if (!type || !der) {
    DBG("pem_encode: type or der is NULL");
    return NULL;
  }
  size_t outlen = 4 * ((der_len + 2) / 3);
  char *out = (char *)malloc(outlen + 128);
  if (!out) {
    DBG("pem_encode: malloc failed for out (len %zu)", outlen + 128);
    return NULL;
  }
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
  if (!pem || !outlen) {
    DBG("pem_decode: pem or outlen is NULL");
    return NULL;
  }
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
  if (!buf) {
    DBG("pem_decode: malloc failed for buf (%zu bytes)", (size_t)(q - p + 1));
    return NULL;
  }
  size_t blen = 0;
  for (const char *t = p; t < q; ++t)
    if (isalnum(*t) || *t == '+' || *t == '/' || *t == '=')
      buf[blen++] = *t;
  buf[blen] = 0;
  size_t b64len = blen;
  *outlen = b64len / 4 * 3;
  unsigned char *out = (unsigned char *)malloc(*outlen);
  if (!out) {
    DBG("pem_decode: malloc failed for out (%zu bytes)", *outlen);
    free(buf);
    return NULL;
  }
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
  if (!pub || !der || len < 3) {
    DBG("rsa_deserialize_public_der: invalid input");
    return 0;
  }
  size_t off = 0;
  if (der[off++] != 0x30) {
    DBG("rsa_deserialize_public_der: SEQUENCE tag missing");
    return 0;
  }
  size_t seqlen = asn1_parse_len(der, &off);
  if (off + seqlen > len) {
    DBG("rsa_deserialize_public_der: encoded length overflows input buffer");
    return 0;
  }
  mpz_init(pub->n);
  if (!asn1_parse_integer(pub->n, der, &off)) {
    DBG("rsa_deserialize_public_der: failed to parse modulus");
    return 0;
  }
  mpz_init(pub->e);
  if (!asn1_parse_integer(pub->e, der, &off)) {
    DBG("rsa_deserialize_public_der: failed to parse exponent");
    return 0;
  }
  return off;
}

size_t rsa_deserialize_private_der(rsa_private_key *priv, const unsigned char *der, size_t len) {
  if (!priv || !der || len < 3) {
    DBG("rsa_deserialize_private_der: invalid input");
    return 0;
  }
  size_t off = 0;
  if (der[off++] != 0x30) {
    DBG("rsa_deserialize_private_der: SEQUENCE tag missing");
    return 0;
  }
  size_t seqlen = asn1_parse_len(der, &off);
  if (off + seqlen > len) {
    DBG("rsa_deserialize_private_der: encoded length overflows input buffer");
    return 0;
  }
  mpz_t t;
  mpz_init(t);
  if (!asn1_parse_integer(t, der, &off)) {
    DBG("rsa_deserialize_private_der: failed to parse version");
    mpz_clear(t);
    return 0;
  }
  mpz_init(priv->n);
  if (!asn1_parse_integer(priv->n, der, &off)) {
    DBG("rsa_deserialize_private_der: failed to parse n");
    mpz_clear(t);
    return 0;
  }
  mpz_init(priv->e);
  if (!asn1_parse_integer(priv->e, der, &off)) {
    DBG("rsa_deserialize_private_der: failed to parse e");
    mpz_clear(t);
    return 0;
  }
  mpz_init(priv->d);
  if (!asn1_parse_integer(priv->d, der, &off)) {
    DBG("rsa_deserialize_private_der: failed to parse d");
    mpz_clear(t);
    return 0;
  }
  mpz_init(priv->p);
  if (!asn1_parse_integer(priv->p, der, &off)) {
    DBG("rsa_deserialize_private_der: failed to parse p");
    mpz_clear(t);
    return 0;
  }
  mpz_init(priv->q);
  if (!asn1_parse_integer(priv->q, der, &off)) {
    DBG("rsa_deserialize_private_der: failed to parse q");
    mpz_clear(t);
    return 0;
  }
  mpz_init(priv->dP);
  if (!asn1_parse_integer(priv->dP, der, &off)) {
    DBG("rsa_deserialize_private_der: failed to parse dP");
    mpz_clear(t);
    return 0;
  }
  mpz_init(priv->dQ);
  if (!asn1_parse_integer(priv->dQ, der, &off)) {
    DBG("rsa_deserialize_private_der: failed to parse dQ");
    mpz_clear(t);
    return 0;
  }
  mpz_init(priv->qInv);
  if (!asn1_parse_integer(priv->qInv, der, &off)) {
    DBG("rsa_deserialize_private_der: failed to parse qInv");
    mpz_clear(t);
    return 0;
  }
  mpz_clear(t);
  return off;
}

// PEM file I/O
__attr_nodiscard int rsa_save_public_pem(const char *fname, const rsa_public_key *pub) {
  if (!fname || !pub) {
    DBG("rsa_save_public_pem: NULL argument");
    return 0;
  }
  unsigned char der[4096];
  size_t derlen = rsa_serialize_public_der(pub, der, sizeof(der));
  if (!derlen) {
    DBG("rsa_save_public_pem: DER serialization failed");
    return 0;
  }
  char *pem = pem_encode("RSA PUBLIC KEY", der, derlen);
  if (!pem) {
    DBG("rsa_save_public_pem: PEM encoding failed");
    return 0;
  }
  FILE *f = fopen(fname, "w");
  if (!f) {
    DBG("rsa_save_public_pem: Failed to open '%s' for writing: %s", fname, strerror(errno));
    print_file_info(fname, f);
    free(pem);
    return 0;
  }
  print_file_info(fname, f);
  if (fputs(pem, f) < 0) {
    DBG("rsa_save_public_pem: Failed to write PEM to file '%s'", fname);
    free(pem);
    fclose(f);
    return 0;
  }
  fclose(f);
  free(pem);
  return 1;
}

__attr_nodiscard int rsa_load_public_pem(const char *fname, rsa_public_key *pub) {
  if (!fname || !pub) {
    DBG("rsa_load_public_pem: NULL argument");
    return 0;
  }
  FILE *f = fopen(fname, "r");
  if (!f) {
    DBG("rsa_load_public_pem: Failed to open '%s' for reading: %s", fname, strerror(errno));
    print_file_info(fname, f);
    return 0;
  }
  if (is_file_too_large(f)) {
    DBG("rsa_load_public_pem: File '%s' too large (> %d bytes)", fname, RSA_MAX_FILE_SIZE);
    print_file_info(fname, f);
    fclose(f);
    return 0;
  }
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  rewind(f);
  char *pem = (char *)malloc(sz + 1);
  if (!pem) {
    DBG("rsa_load_public_pem: malloc failed (%ld bytes)", sz + 1);
    fclose(f);
    return 0;
  }
  size_t nread = fread(pem, 1, sz, f);
  pem[nread] = 0;
  fclose(f);
  size_t derlen;
  unsigned char *der = pem_decode(pem, &derlen);
  free(pem);
  if (!der) {
    DBG("rsa_load_public_pem: PEM decode failed");
    return 0;
  }
  int res = (rsa_deserialize_public_der(pub, der, derlen) > 0);
  free(der);
  return res;
}

__attr_nodiscard int rsa_save_private_pem(const char *fname, const rsa_private_key *priv) {
  if (!fname || !priv) {
    DBG("rsa_save_private_pem: NULL argument");
    return 0;
  }
  unsigned char der[4096];
  size_t derlen = rsa_serialize_private_der(priv, der, sizeof(der));
  if (!derlen) {
    DBG("rsa_save_private_pem: DER serialization failed");
    return 0;
  }
  char *pem = pem_encode("RSA PRIVATE KEY", der, derlen);
  if (!pem) {
    DBG("rsa_save_private_pem: PEM encoding failed");
    return 0;
  }
  FILE *f = fopen(fname, "w");
  if (!f) {
    DBG("rsa_save_private_pem: Failed to open '%s' for writing: %s", fname, strerror(errno));
    print_file_info(fname, f);
    free(pem);
    return 0;
  }
  print_file_info(fname, f);
  if (fputs(pem, f) < 0) {
    DBG("rsa_save_private_pem: Failed to write PEM to file '%s'", fname);
    free(pem);
    fclose(f);
    return 0;
  }
  fclose(f);
  free(pem);
  return 1;
}

__attr_nodiscard int rsa_load_private_pem(const char *fname, rsa_private_key *priv) {
  if (!fname || !priv) {
    DBG("rsa_load_private_pem: NULL argument");
    return 0;
  }
  FILE *f = fopen(fname, "r");
  if (!f) {
    DBG("rsa_load_private_pem: Failed to open '%s' for reading: %s", fname, strerror(errno));
    print_file_info(fname, f);
    return 0;
  }
  if (is_file_too_large(f)) {
    DBG("rsa_load_private_pem: File '%s' too large (> %d bytes)", fname, RSA_MAX_FILE_SIZE);
    print_file_info(fname, f);
    fclose(f);
    return 0;
  }
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  rewind(f);
  char *pem = (char *)malloc(sz + 1);
  if (!pem) {
    DBG("rsa_load_private_pem: malloc failed (%ld bytes)", sz + 1);
    fclose(f);
    return 0;
  }
  size_t nread = fread(pem, 1, sz, f);
  pem[nread] = 0;
  fclose(f);
  size_t derlen;
  unsigned char *der = pem_decode(pem, &derlen);
  free(pem);
  if (!der) {
    DBG("rsa_load_private_pem: PEM decode failed");
    return 0;
  }
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
  if (!pub || !der) {
    DBG("rsa_serialize_public_x509_der: NULL argument");
    return 0;
  }
  unsigned char pubkey_der[1024];
  size_t pubkey_len = rsa_serialize_public_der(pub, pubkey_der, sizeof(pubkey_der));
  if (!pubkey_len) {
    DBG("rsa_serialize_public_x509_der: public DER encode failed");
    return 0;
  }
  unsigned char bitstr[1024];
  if (pubkey_len + 1 > sizeof(bitstr)) {
    DBG("rsa_serialize_public_x509_der: BIT STRING buffer too small");
    return 0;
  }
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

  size_t lenlen = asn1_encode_len(NULL, off);
  size_t total_len = 1 + lenlen + off;
  if (total_len > maxlen) {
    DBG("rsa_serialize_public_x509_der: output buffer too small (%zu > %zu)", total_len, maxlen);
    return 0;
  }
  if (__likely(der)) {
    der[0] = 0x30; // SEQUENCE
    asn1_encode_len(der + 1, off);
    memcpy(der + 1 + lenlen, tmp, off);
    return total_len;
  }
  return total_len;
}

size_t rsa_serialize_private_pkcs8_der(const rsa_private_key *priv, unsigned char *der, size_t maxlen) {
  if (!priv || !der) {
    DBG("rsa_serialize_private_pkcs8_der: NULL argument");
    return 0;
  }
  unsigned char pkcs1[4096];
  size_t pkcs1_len = rsa_serialize_private_der(priv, pkcs1, sizeof(pkcs1));
  if (!pkcs1_len) {
    DBG("rsa_serialize_private_pkcs8_der: private DER encode failed");
    return 0;
  }

  unsigned char algid[16];
  size_t algid_len = encode_algorithm_identifier(algid);

  unsigned char tmp[8192];
  size_t off = 0;
  tmp[off++] = 0x02; // INTEGER
  tmp[off++] = 0x01; // length
  tmp[off++] = 0x00; // value
  memcpy(tmp + off, algid, algid_len);
  off += algid_len;
  tmp[off++] = 0x04; // OCTET STRING
  off += asn1_encode_len(tmp + off, pkcs1_len);
  memcpy(tmp + off, pkcs1, pkcs1_len);
  off += pkcs1_len;

  size_t lenlen = asn1_encode_len(NULL, off);
  size_t total_len = 1 + lenlen + off;
  if (total_len > maxlen) {
    DBG("rsa_serialize_private_pkcs8_der: output buffer too small (%zu > %zu)", total_len, maxlen);
    return 0;
  }
  if (__likely(der)) {
    der[0] = 0x30;
    asn1_encode_len(der + 1, off);
    memcpy(der + 1 + lenlen, tmp, off);
    return total_len;
  }
  return total_len;
}

size_t rsa_deserialize_public_x509_der(rsa_public_key *pub, const unsigned char *der, size_t len) {
  if (!pub || !der || len < 3) {
    DBG("rsa_deserialize_public_x509_der: invalid input");
    return 0;
  }
  size_t off = 0;
  if (der[off++] != 0x30) {
    DBG("rsa_deserialize_public_x509_der: SEQUENCE tag missing");
    return 0;
  }
  size_t seqlen = asn1_parse_len(der, &off);
  if (off + seqlen > len) {
    DBG("rsa_deserialize_public_x509_der: encoded length overflows input buffer");
    return 0;
  }
  if (der[off++] != 0x30) {
    DBG("rsa_deserialize_public_x509_der: AlgorithmIdentifier SEQUENCE tag missing");
    return 0;
  }
  size_t alglen = asn1_parse_len(der, &off);
  off += alglen;
  if (der[off++] != 0x03) {
    DBG("rsa_deserialize_public_x509_der: BIT STRING tag missing");
    return 0;
  }
  size_t bitlen = asn1_parse_len(der, &off);
  if (bitlen < 2 || off + bitlen > len) {
    DBG("rsa_deserialize_public_x509_der: BIT STRING length invalid");
    return 0;
  }
  unsigned char nbits = der[off++]; // unused bits, should be 0
  if (nbits != 0) {
    DBG("rsa_deserialize_public_x509_der: BIT STRING unused bits is not zero");
    return 0;
  }
  // The actual public key DER is at der+off, of length (bitlen - 1)
  return rsa_deserialize_public_der(pub, der + off, bitlen - 1) + off;
}

size_t rsa_deserialize_private_pkcs8_der(rsa_private_key *priv, const unsigned char *der, size_t len) {
  size_t off = 0;
  if (der[off++] != 0x30) {
    DBG("rsa_deserialize_private_pkcs8_der: Missing SEQUENCE tag");
    return 0;
  }
  size_t seqlen = asn1_parse_len(der, &off);

  if (der[off++] != 0x02) {
    DBG("rsa_deserialize_private_pkcs8_der: Missing version INTEGER tag");
    return 0;
  }
  size_t vlen = asn1_parse_len(der, &off);
  off += vlen;

  if (der[off++] != 0x30) {
    DBG("rsa_deserialize_private_pkcs8_der: Missing AlgorithmIdentifier SEQUENCE tag");
    return 0;
  }
  size_t alglen = asn1_parse_len(der, &off);
  off += alglen;

  if (der[off++] != 0x04) {
    DBG("rsa_deserialize_private_pkcs8_der: Missing OCTET STRING tag");
    return 0;
  }
  size_t pklen = asn1_parse_len(der, &off);

  // The actual private key DER is at der+off, length pklen
  return rsa_deserialize_private_der(priv, der + off, pklen) + off;
}

__attr_nodiscard int rsa_save_public_x509_pem(const char *fname, const rsa_public_key *pub) {
  if (!fname || !pub) {
    DBG("rsa_save_public_x509_pem: NULL argument");
    return 0;
  }
  unsigned char der[2048];
  size_t derlen = rsa_serialize_public_x509_der(pub, der, sizeof(der));
  char *pem = pem_encode("PUBLIC KEY", der, derlen);
  FILE *f = fopen(fname, "w");
  if (!__unlikely(f)) {
    DBG("rsa_save_public_x509_pem: Failed to open '%s' for writing", fname);
    free(pem);
    return 0;
  }
  fputs(pem, f);
  fclose(f);
  free(pem);
  return 1;
}

__attr_nodiscard int rsa_load_public_x509_pem(const char *fname, rsa_public_key *pub) {
  if (!fname || !pub) {
    DBG("rsa_load_public_x509_pem: NULL argument");
    return 0;
  }
  FILE *f = fopen(fname, "r");
  if (!__unlikely(f)) {
    DBG("rsa_load_public_x509_pem: Failed to open '%s' for reading", fname);
    return 0;
  }
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
  if (!fname || !priv) {
    DBG("rsa_save_private_pkcs8_pem: NULL argument");
    return 0;
  }
  unsigned char der[4096];
  size_t derlen = rsa_serialize_private_pkcs8_der(priv, der, sizeof(der));
  char *pem = pem_encode("PRIVATE KEY", der, derlen);
  FILE *f = fopen(fname, "w");
  if (!__unlikely(f)) {
    DBG("rsa_save_private_pkcs8_pem: Failed to open '%s' for writing", fname);
    free(pem);
    return 0;
  }
  fputs(pem, f);
  fclose(f);
  free(pem);
  return 1;
}

__attr_nodiscard int rsa_load_private_pkcs8_pem(const char *fname, rsa_private_key *priv) {
  if (!fname || !priv) {
    DBG("rsa_load_private_pkcs8_pem: NULL argument");
    return 0;
  }
  FILE *f = fopen(fname, "r");
  if (!__unlikely(f)) {
    DBG("rsa_load_private_pkcs8_pem: Failed to open '%s' for reading", fname);
    return 0;
  }
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
    DBG("rsa_encrypt_file: Cannot open input or output file");
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
    DBG("rsa_decrypt_file: Cannot open input or output file");
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
  if (!__unlikely(f)) {
    DBG("save_file_hex: Failed to open '%s' for writing", fname);
    return 0;
  }
  for (size_t i = 0; i < len; ++i)
    fprintf(f, "%02x", buf[i]);
  fclose(f);
  return 1;
}

__attr_nodiscard int save_file_base64(const char *fname, const unsigned char *buf, size_t len) {
  FILE *f = fopen(fname, "w");
  if (!__unlikely(f)) {
    DBG("save_file_base64: Failed to open '%s' for writing", fname);
    return 0;
  }
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
  if (!__unlikely(f)) {
    DBG("save_file_ascii: Failed to open '%s' for writing", fname);
    return 0;
  }
  for (size_t i = 0; i < len; ++i)
    fputc(isprint(buf[i]) ? buf[i] : '.', f);
  fclose(f);
  return 1;
}
#endif // RSA_C_H
