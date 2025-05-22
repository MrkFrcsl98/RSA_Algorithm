#pragma once
#ifndef RSA_ALGORITHM_C_H
#define RSA_ALGORITHM_C_H

#include <ctype.h>
#include <errno.h>
#include <gmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h> // For secure random bytes

#if defined(__GNUC__) || defined(__clang__)
#define __attr_nodiscard __attribute__((warn_unused_result))
#define __attr_malloc __attribute__((malloc))
#define __attr_hot __attribute__((hot))
#define __attr_cold __attribute__((cold))
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define __attr_nodiscard
#define __attr_malloc
#define __attr_hot
#define __attr_cold
#define likely(x)   (x)
#define unlikely(x) (x)
#endif

#ifdef __cplusplus
#define __restrict__ __restrict
#else
#define __restrict__ restrict
#endif

#ifdef __cplusplus
#define __noexcept noexcept
#define __const_noexcept const noexcept
#else
#define __noexcept
#define __const_noexcept
#endif

// ========== Secure Randomness ==========
__attr_hot static inline void get_secure_random_bytes(void *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("open /dev/urandom");
        abort();
    }
    ssize_t r = read(fd, buf, len);
    if (r != (ssize_t)len) {
        perror("read /dev/urandom");
        close(fd);
        abort();
    }
    close(fd);
}
__attr_hot static inline void gmp_randseed_secure(gmp_randstate_t rng) {
    unsigned char seed_buf[32];
    get_secure_random_bytes(seed_buf, sizeof(seed_buf));
    mpz_t seed;
    mpz_init(seed);
    mpz_import(seed, sizeof(seed_buf), 1, 1, 0, 0, seed_buf);
    gmp_randseed(rng, seed);
    mpz_clear(seed);
}

// ===== ENUMS =====
typedef enum
{
    KEYSIZE_1024 = 1024,
    KEYSIZE_2048 = 2048,
    KEYSIZE_3072 = 3072,
    KEYSIZE_4096 = 4096
} KeySize;

typedef enum
{
    OUTPUT_BINARY,
    OUTPUT_HEX,
    OUTPUT_BASE64
} OutputFormat;

// ===== STRUCTS =====
typedef struct
{
    mpz_t n, e;
} RSAPublicKey;

typedef struct
{
    mpz_t n, e, d, p, q, dP, dQ, qInv;
} RSAPrivateKey;

typedef struct
{
    RSAPublicKey public_key;
    RSAPrivateKey private_key;
} RSAKeyPair;

// ========== Utility Memory ==========
#define SECURE_FREE(p, sz) \
    do \
    { \
        if (likely(p)) \
        { \
            volatile unsigned char *vp = (volatile unsigned char *)(p); \
            for (size_t _i = 0; _i < (sz); ++_i) \
                vp[_i] = 0; \
            free((void *)p); \
        } \
    } while (0)
#define SAFE_MALLOC(size) \
    ({ \
        void *_p = malloc(size); \
        if (unlikely(!_p)) \
        { \
            fprintf(stderr, "Out of memory at %s:%d\n", __FILE__, __LINE__); \
            abort(); \
        } \
        _p; \
    })

// ========== ASN.1 DER ==========
__attr_hot static inline void encode_integer(const mpz_t x, uint8_t ** const out, size_t * const outlen) __noexcept
{
    size_t count = (mpz_sizeinbase(x, 2) + 7) / 8;
    if (unlikely(count == 0))
        count = 1;
    uint8_t * const bytes = (uint8_t *)SAFE_MALLOC(count + 2);
    mpz_export(bytes, &count, 1, 1, 1, 0, x);
    int prepend_zero = (bytes[0] & 0x80) ? 1 : 0;
    if (likely(prepend_zero))
    {
        memmove(bytes + 1, bytes, count);
        bytes[0] = 0x00;
        count += 1;
    }
    *outlen = 2 + count;
    *out = (uint8_t *)SAFE_MALLOC(*outlen);
    (*out)[0] = 0x02;
    (*out)[1] = (uint8_t)count;
    memcpy(*out + 2, bytes, count);
    SECURE_FREE(bytes, count + 1);
}

__attr_hot static inline void encode_octet_string(const uint8_t *data, size_t dlen, uint8_t ** const out, size_t * const outlen) __noexcept
{
    *outlen = 2 + dlen;
    *out = (uint8_t *)SAFE_MALLOC(*outlen);
    (*out)[0] = 0x04;
    (*out)[1] = (uint8_t)dlen;
    memcpy(*out + 2, data, dlen);
}

__attr_hot static inline void encode_null(uint8_t ** const out, size_t * const outlen) __noexcept
{
    *outlen = 2;
    *out = (uint8_t *)SAFE_MALLOC(*outlen);
    (*out)[0] = 0x05;
    (*out)[1] = 0x00;
}

__attr_hot static inline void encode_oid(const uint8_t *oid, size_t oidlen, uint8_t ** const out, size_t * const outlen) __noexcept
{
    *outlen = 2 + oidlen;
    *out = (uint8_t *)SAFE_MALLOC(*outlen);
    (*out)[0] = 0x06;
    (*out)[1] = (uint8_t)oidlen;
    memcpy(*out + 2, oid, oidlen);
}

__attr_hot static inline void encode_bit_string(const uint8_t *data, size_t dlen, uint8_t ** const out, size_t * const outlen) __noexcept
{
    *outlen = 3 + dlen;
    *out = (uint8_t *)SAFE_MALLOC(*outlen);
    (*out)[0] = 0x03;
    (*out)[1] = (uint8_t)(dlen + 1);
    (*out)[2] = 0x00;
    memcpy(*out + 3, data, dlen);
}

__attr_hot static inline void encode_sequence(uint8_t ** const fields, const size_t * const field_lens, const size_t num_fields, uint8_t ** const out, size_t * const outlen) __noexcept
{
    size_t seqlen = 0;
    for (size_t i = 0; i < num_fields; ++i)
        seqlen += field_lens[i];
    *outlen = 2 + seqlen;
    *out = (uint8_t *)SAFE_MALLOC(*outlen);
    (*out)[0] = 0x30;
    (*out)[1] = (uint8_t)seqlen;
    size_t offset = 2;
    for (size_t i = 0; i < num_fields; ++i)
    {
        memcpy(*out + offset, fields[i], field_lens[i]);
        offset += field_lens[i];
    }
}

// ========== BASE64 ENCODE/DECODE ==========
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

__attr_malloc __attr_nodiscard __attr_hot static inline char *base64_encode(const uint8_t * __restrict__ in, const size_t inlen) __noexcept
{
    const size_t outlen = 4 * ((inlen + 2) / 3);
    char * const out = (char *)SAFE_MALLOC(outlen + 1);
    size_t i = 0, j = 0;
    for (; i + 2 < inlen; i += 3)
    {
        uint32_t triple = (in[i] << 16) | (in[i+1] << 8) | in[i+2];
        out[j++] = b64_table[(triple >> 18) & 0x3F];
        out[j++] = b64_table[(triple >> 12) & 0x3F];
        out[j++] = b64_table[(triple >> 6) & 0x3F];
        out[j++] = b64_table[triple & 0x3F];
    }
    if (i < inlen)
    {
        uint32_t triple = in[i] << 16;
        out[j++] = b64_table[(triple >> 18) & 0x3F];
        if (i + 1 < inlen)
        {
            triple |= in[i+1] << 8;
            out[j++] = b64_table[(triple >> 12) & 0x3F];
            out[j++] = b64_table[(triple >> 6) & 0x3F];
        }
        else
        {
            out[j++] = b64_table[(triple >> 12) & 0x3F];
            out[j++] = '=';
        }
        out[j++] = '=';
    }
    out[outlen] = 0;
    return out;
}

__attr_malloc __attr_nodiscard __attr_hot static inline uint8_t *base64_decode(const char *in, size_t * const outlen) __noexcept
{
    static int dtable[256] = {0};
    static int dtable_initialized = 0;
    if (!dtable_initialized) {
        for (size_t i = 0; i < 64; i++)
            dtable[(uint8_t)b64_table[i]] = i + 1;
        dtable_initialized = 1;
    }
    const size_t inlen = strlen(in);
    size_t pad = 0, i = 0, j = 0;
    if (inlen >= 2 && in[inlen - 1] == '=')
        pad++;
    if (inlen >= 2 && in[inlen - 2] == '=')
        pad++;
    *outlen = (inlen * 3) / 4 - pad;
    uint8_t * const out = (uint8_t *)SAFE_MALLOC(*outlen);
    for (i = 0, j = 0; i < inlen;) {
        int val = 0;
        for (int n = 0; n < 4 && i < inlen;) {
            char c = in[i++];
            if (likely(dtable[(uint8_t)c])) {
                val = (val << 6) | (dtable[(uint8_t)c] - 1);
                n++;
            } else if (c == '=') {
                val <<= 6;
                n++;
            }
        }
        if (likely(j < *outlen))
            out[j++] = (val >> 16) & 0xFF;
        if (likely(j < *outlen))
            out[j++] = (val >> 8) & 0xFF;
        if (likely(j < *outlen))
            out[j++] = val & 0xFF;
    }
    return out;
}

// PEM WRAP/UNWRAP
__attr_malloc __attr_nodiscard __attr_hot static inline char *pem_wrap(const char *base64, const char *type) __noexcept
{
    const size_t typelen = strlen(type);
    const size_t b64len = strlen(base64);
    const size_t outlen = 32 + b64len + b64len / 64 * 2 + typelen * 2;
    char * const out = (char *)SAFE_MALLOC(outlen);
    sprintf(out, "-----BEGIN %s-----\n", type);
    size_t offset = strlen(out);
    for (size_t i = 0; i < b64len; i += 64)
    {
        strncat(out + offset, base64 + i, 64);
        offset += (b64len - i > 64 ? 64 : b64len - i);
        out[offset++] = '\n';
        out[offset] = 0;
    }
    sprintf(out + offset, "-----END %s-----\n", type);
    return out;
}

__attr_malloc __attr_nodiscard __attr_hot static inline char *strip_pem(const char *pem) __noexcept
{
    const char *begin = strstr(pem, "-----BEGIN");
    if (unlikely(!begin))
    {
        fprintf(stderr, "Failed to find PEM BEGIN header\n");
        return NULL;
    }
    begin = strchr(begin, '\n');
    const char *end = strstr(pem, "-----END");
    if (unlikely(!end))
    {
        fprintf(stderr, "Failed to find PEM END header\n");
        return NULL;
    }
    const size_t b64len = end - begin - 1;
    char * const b64 = (char *)SAFE_MALLOC(b64len + 1);
    size_t k = 0;
    for (const char *p = begin + 1; p < end; ++p)
        if (isalnum((unsigned char)*p) || *p == '+' || *p == '/' || *p == '=')
            b64[k++] = *p;
    b64[k] = 0;
    return b64;
}

// ========== HEX ENCODE/DECODE ==========
__attr_malloc __attr_nodiscard __attr_hot static inline char *bytes_to_hex(const uint8_t * __restrict__ data, const size_t len) __noexcept
{
    char * const out = (char *)SAFE_MALLOC(len * 2 + 1);
    for (size_t i = 0; i < len; ++i)
        sprintf(out + 2 * i, "%02x", data[i]);
    out[len * 2] = 0;
    return out;
}

__attr_malloc __attr_nodiscard __attr_hot static inline uint8_t *hex_to_bytes(const char *hex, size_t * const outlen) __noexcept
{
    const size_t len = strlen(hex) / 2;
    uint8_t * const out = (uint8_t *)SAFE_MALLOC(len);
    for (size_t i = 0; i < len; ++i)
    {
        if (unlikely(sscanf(hex + 2 * i, "%2hhx", &out[i]) != 1))
        {
            fprintf(stderr, "Invalid hex string at position %zu\n", i * 2);
            SECURE_FREE(out, len);
            *outlen = 0;
            return NULL;
        }
    }
    *outlen = len;
    return out;
}

// ========== FILE IO ==========
__attr_hot static inline int file_exists(const char *filename) __noexcept
{
    FILE * const f = fopen(filename, "rb");
    if (likely(f))
    {
        fclose(f);
        return 1;
    }
    return 0;
}

__attr_malloc __attr_nodiscard __attr_hot static inline uint8_t *read_file(const char *filename, size_t * const len) __noexcept
{
    FILE * const f = fopen(filename, "rb");
    if (unlikely(!f))
    {
        fprintf(stderr, "Failed to open file '%s' for reading: %s\n", filename, strerror(errno));
        return NULL;
    }
    if (unlikely(fseek(f, 0, SEEK_END) != 0))
    {
        fclose(f);
        return NULL;
    }
    const long flen = ftell(f);
    if (unlikely(flen < 0))
    {
        fclose(f);
        return NULL;
    }
    if (unlikely(fseek(f, 0, SEEK_SET) != 0))
    {
        fclose(f);
        return NULL;
    }
    uint8_t * const buf = (uint8_t *)SAFE_MALLOC(flen);
    const size_t r = fread(buf, 1, flen, f);
    fclose(f);
    if (unlikely(r != (size_t)flen))
    {
        SECURE_FREE(buf, flen);
        return NULL;
    }
    *len = flen;
    return buf;
}

__attr_hot static inline int write_file(const char *filename, const uint8_t * __restrict__ data, const size_t len) __noexcept
{
    FILE * const f = fopen(filename, "wb");
    if (unlikely(!f))
    {
        fprintf(stderr, "Failed to open '%s' for writing\n", filename);
        return 0;
    }
    const size_t w = fwrite(data, 1, len, f);
    fclose(f);
    if (unlikely(w != len))
    {
        fprintf(stderr, "Failed to write all data to '%s'\n", filename);
        return 0;
    }
    return 1;
}

__attr_hot static inline int write_text(const char *filename, const char *text) __noexcept
{
    FILE * const f = fopen(filename, "w");
    if (unlikely(!f))
    {
        fprintf(stderr, "Failed to open file '%s' for writing: %s\n", filename, strerror(errno));
        return 0;
    }
    const size_t w = fwrite(text, 1, strlen(text), f);
    fclose(f);
    if (unlikely(w != strlen(text)))
    {
        fprintf(stderr, "Error writing text to file '%s'\n", filename);
        return 0;
    }
    return 1;
}

// ========== RANDOM PRIME, MODINV, POWM ==========
__attr_hot static inline void random_prime(mpz_t out, const int bits, gmp_randstate_t rng) __noexcept
{
    int tries = 0;
    while (1)
    {
        mpz_urandomb(out, rng, bits);
        mpz_setbit(out, bits - 1);
        mpz_setbit(out, 0);
        if (likely(mpz_probab_prime_p(out, 40)))
            return;
        if (unlikely(++tries > 100000))
        {
            fprintf(stderr, "Failed to generate a random prime after 100000 tries\n");
            abort();
        }
    }
}

__attr_hot static inline void modinv(mpz_t out, const mpz_t a, const mpz_t m) __noexcept
{
    if (unlikely(!mpz_invert(out, a, m)))
    {
        fprintf(stderr, "No modular inverse exists\n");
        abort();
    }
}

__attr_hot static inline void powm(mpz_t out, const mpz_t base, const mpz_t exp, const mpz_t mod) __noexcept
{
    mpz_powm(out, base, exp, mod);
}

// ========== PKCS#1 v1.5 Padding ==========
__attr_nodiscard __attr_hot static inline int pkcs1_pad(const uint8_t * __restrict__ block, const size_t blocklen, uint8_t * __restrict__ padded, const size_t mod_bytes) __noexcept
{
    if (unlikely(blocklen > mod_bytes - 11))
    {
        fprintf(stderr, "Block too large for PKCS#1 v1.5 padding\n");
        return 0;
    }
    padded[0] = 0x00;
    padded[1] = 0x02;
    size_t pad_len = mod_bytes - 3 - blocklen;
    uint8_t *pad_bytes = (uint8_t *)SAFE_MALLOC(pad_len);
    get_secure_random_bytes(pad_bytes, pad_len);
    for (size_t i = 0; i < pad_len; ++i) {
        while (pad_bytes[i] == 0) {
            get_secure_random_bytes(&pad_bytes[i], 1);
        }
        padded[2 + i] = pad_bytes[i];
    }
    SECURE_FREE(pad_bytes, pad_len);
    padded[2 + pad_len] = 0x00;
    memcpy(padded + 3 + pad_len, block, blocklen);
    return 1;
}

__attr_nodiscard __attr_hot static inline int pkcs1_unpad(const uint8_t *padded, const size_t paddedlen, uint8_t *out, size_t * const outlen) __noexcept
{
    if (unlikely(paddedlen < 11 || padded[0] != 0x00 || padded[1] != 0x02))
    {
        fprintf(stderr, "Invalid PKCS#1 v1.5 padding detected\n");
        return 0;
    }
    size_t idx = 2;
    while (idx < paddedlen && padded[idx] != 0x00)
        ++idx;
    if (unlikely(idx == paddedlen || idx < 10))
    {
        fprintf(stderr, "Padding format error in PKCS#1 v1.5\n");
        return 0;
    }
    const size_t msglen = paddedlen - (idx + 1);
    memcpy(out, padded + idx + 1, msglen);
    *outlen = msglen;
    return 1;
}

// ========== KEY INIT/CLEAR ==========
__attr_hot static inline void rsa_public_key_init(RSAPublicKey * const key) __noexcept
{
    if (unlikely(!key))
    {
        fprintf(stderr, "Null RSAPublicKey pointer passed to init\n");
        abort();
    }
    mpz_init(key->n);
    mpz_init(key->e);
}
__attr_hot static inline void rsa_private_key_init(RSAPrivateKey * const key) __noexcept
{
    if (unlikely(!key))
    {
        fprintf(stderr, "Null RSAPrivateKey pointer passed to init\n");
        abort();
    }
    mpz_init(key->n);
    mpz_init(key->e);
    mpz_init(key->d);
    mpz_init(key->p);
    mpz_init(key->q);
    mpz_init(key->dP);
    mpz_init(key->dQ);
    mpz_init(key->qInv);
}
__attr_cold static inline void rsa_public_key_clear(RSAPublicKey * const key) __noexcept
{
    if (unlikely(!key))
        return;
    mpz_clear(key->n);
    mpz_clear(key->e);
}
__attr_cold static inline void rsa_private_key_clear(RSAPrivateKey * const key) __noexcept
{
    if (unlikely(!key))
        return;
    mpz_clear(key->n);
    mpz_clear(key->e);
    mpz_clear(key->d);
    mpz_clear(key->p);
    mpz_clear(key->q);
    mpz_clear(key->dP);
    mpz_clear(key->dQ);
    mpz_clear(key->qInv);
}

// ========== KEY GENERATION ==========
__attr_hot static inline void rsa_generate_keypair(RSAKeyPair * const kp, const KeySize bits) __noexcept
{
    if (unlikely(!kp))
    {
        fprintf(stderr, "Null RSAKeyPair pointer passed to key generation\n");
        abort();
    }
    gmp_randstate_t rng;
    gmp_randinit_mt(rng);
    gmp_randseed_secure(rng);
    mpz_t p, q, phi, d, e, dP, dQ, qInv;
    mpz_inits(p, q, phi, d, e, dP, dQ, qInv, NULL);
    random_prime(p, bits / 2, rng);
    int tries = 0;
    do
    {
        random_prime(q, bits / 2, rng);
        if (unlikely(++tries > 1000))
        {
            fprintf(stderr, "Failed to generate two unique primes for key generation\n");
            abort();
        }
    } while (!mpz_cmp(p, q));
    mpz_mul(kp->public_key.n, p, q);
    mpz_set_ui(e, 65537);
    mpz_set(kp->public_key.e, e);
    mpz_sub_ui(phi, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(phi, phi, q);
    modinv(d, e, phi);
    mpz_set(kp->private_key.n, kp->public_key.n);
    mpz_set(kp->private_key.e, e);
    mpz_set(kp->private_key.d, d);
    mpz_set(kp->private_key.p, p);
    mpz_set(kp->private_key.q, q);
    mpz_mod(dP, d, p);
    mpz_mod(dQ, d, q);
    modinv(qInv, q, p);
    mpz_set(kp->private_key.dP, dP);
    mpz_set(kp->private_key.dQ, dQ);
    mpz_set(kp->private_key.qInv, qInv);
    mpz_clears(p, q, phi, d, e, dP, dQ, qInv, NULL);
    gmp_randclear(rng);
}

// ========== ENCRYPTION/DECRYPTION ==========
__attr_nodiscard __attr_hot static inline int rsa_encrypt(const uint8_t * __restrict__ message, const size_t mlen, const RSAPublicKey * const pub, uint8_t * __restrict__ out, size_t * const outlen) __noexcept
{
    if (unlikely(!message || !pub || !outlen))
    {
        fprintf(stderr, "NULL pointer argument to rsa_encrypt\n");
        return 0;
    }
    const size_t mod_bytes = (mpz_sizeinbase(pub->n, 2) + 7) / 8;
    if (!out) { *outlen = mod_bytes; return 1; }
    uint8_t * const block = (uint8_t *)SAFE_MALLOC(mod_bytes);
    if (unlikely(!pkcs1_pad(message, mlen, block, mod_bytes)))
    {
        SECURE_FREE(block, mod_bytes);
        return 0;
    }
    mpz_t m, c;
    mpz_init(m);
    mpz_init(c);
    mpz_import(m, mod_bytes, 1, 1, 1, 0, block);
    if (unlikely(mpz_cmp(m, pub->n) >= 0))
    {
        fprintf(stderr, "Message representative out of range in rsa_encrypt\n");
        mpz_clear(m);
        mpz_clear(c);
        SECURE_FREE(block, mod_bytes);
        return 0;
    }
    powm(c, m, pub->e, pub->n);
    size_t clen = 0;
    mpz_export(out, &clen, 1, 1, 1, 0, c);
    *outlen = clen;
    mpz_clear(m);
    mpz_clear(c);
    SECURE_FREE(block, mod_bytes);
    return 1;
}

__attr_nodiscard __attr_hot static inline int rsa_decrypt(const uint8_t * __restrict__ enc, const size_t enclen, const RSAPrivateKey * const priv, uint8_t * __restrict__ out, size_t * const outlen) __noexcept
{
    if (unlikely(!enc || !priv || !out || !outlen))
    {
        fprintf(stderr, "NULL pointer argument to rsa_decrypt\n");
        return 0;
    }
    const size_t mod_bytes = (mpz_sizeinbase(priv->n, 2) + 7) / 8;
    mpz_t c, m;
    mpz_init(c);
    mpz_init(m);
    mpz_import(c, enclen, 1, 1, 1, 0, enc);
    powm(m, c, priv->d, priv->n);
    uint8_t * const padded = (uint8_t *)SAFE_MALLOC(mod_bytes);
    size_t paddedlen = 0;
    mpz_export(padded, &paddedlen, 1, 1, 1, 0, m);
    if (paddedlen < mod_bytes)
    {
        memmove(padded + (mod_bytes - paddedlen), padded, paddedlen);
        memset(padded, 0, mod_bytes - paddedlen);
        paddedlen = mod_bytes;
    }
    const int res = pkcs1_unpad(padded, paddedlen, out, outlen);
    SECURE_FREE(padded, mod_bytes);
    mpz_clear(c);
    mpz_clear(m);
    return res;
}

// ========== PEM/DER SERIALIZATION (PUBLIC KEY, PRIVATE KEY, X.509, PKCS#8) ==========
__attr_malloc __attr_nodiscard __attr_hot static inline char *rsa_public_key_to_pem(const RSAPublicKey * const pub) __noexcept
{
    if (unlikely(!pub))
    {
        fprintf(stderr, "Null RSAPublicKey pointer passed to serialization\n");
        return NULL;
    }
    uint8_t *en_n, *en_e, *seq;
    size_t len_n, len_e, len_seq;
    encode_integer(pub->n, &en_n, &len_n);
    encode_integer(pub->e, &en_e, &len_e);
    encode_sequence((uint8_t *[]){en_n, en_e}, (size_t[]){len_n, len_e}, 2, &seq, &len_seq);
    char * const b64 = base64_encode(seq, len_seq);
    char * const pem = pem_wrap(b64, "RSA PUBLIC KEY");
    SECURE_FREE(en_n, len_n);
    SECURE_FREE(en_e, len_e);
    SECURE_FREE(seq, len_seq);
    SECURE_FREE(b64, strlen(b64));
    return pem;
}

__attr_malloc __attr_nodiscard __attr_hot static inline char *rsa_private_key_to_pem(const RSAPrivateKey * const priv) __noexcept
{
    if (unlikely(!priv))
    {
        fprintf(stderr, "Null RSAPrivateKey pointer passed to serialization\n");
        return NULL;
    }
    uint8_t *en_vals[9], *seq;
    size_t lens[9], len_seq;
    mpz_t zero;
    mpz_init_set_ui(zero, 0);
    encode_integer(zero, &en_vals[0], &lens[0]);
    encode_integer(priv->n, &en_vals[1], &lens[1]);
    encode_integer(priv->e, &en_vals[2], &lens[2]);
    encode_integer(priv->d, &en_vals[3], &lens[3]);
    encode_integer(priv->p, &en_vals[4], &lens[4]);
    encode_integer(priv->q, &en_vals[5], &lens[5]);
    encode_integer(priv->dP, &en_vals[6], &lens[6]);
    encode_integer(priv->dQ, &en_vals[7], &lens[7]);
    encode_integer(priv->qInv, &en_vals[8], &lens[8]);
    encode_sequence(en_vals, lens, 9, &seq, &len_seq);
    char * const b64 = base64_encode(seq, len_seq);
    char * const pem = pem_wrap(b64, "RSA PRIVATE KEY");
    for (int i = 0; i < 9; ++i)
        SECURE_FREE(en_vals[i], lens[i]);
    SECURE_FREE(seq, len_seq);
    SECURE_FREE(b64, strlen(b64));
    mpz_clear(zero);
    return pem;
}

// --- X.509 SubjectPublicKeyInfo PEM ("-----BEGIN PUBLIC KEY-----") ---
__attr_malloc __attr_nodiscard __attr_hot static inline char *rsa_public_key_to_x509_pem(const RSAPublicKey * const pub) __noexcept
{
    if (unlikely(!pub))
    {
        fprintf(stderr, "Null RSAPublicKey pointer passed to X.509 serialization\n");
        return NULL;
    }
    static const uint8_t oid_rsaEncryption[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
    uint8_t *oid, *nullv, *algseq;
    size_t l_oid, l_nullv, l_algseq;
    encode_oid(oid_rsaEncryption, sizeof(oid_rsaEncryption), &oid, &l_oid);
    encode_null(&nullv, &l_nullv);
    encode_sequence((uint8_t *[]){oid, nullv}, (size_t[]){l_oid, l_nullv}, 2, &algseq, &l_algseq);
    SECURE_FREE(oid, l_oid);
    SECURE_FREE(nullv, l_nullv);

    uint8_t *en_n, *en_e, *pkseq;
    size_t len_n, len_e, len_pkseq;
    encode_integer(pub->n, &en_n, &len_n);
    encode_integer(pub->e, &en_e, &len_e);
    encode_sequence((uint8_t *[]){en_n, en_e}, (size_t[]){len_n, len_e}, 2, &pkseq, &len_pkseq);

    uint8_t *bitstr;
    size_t l_bitstr;
    encode_bit_string(pkseq, len_pkseq, &bitstr, &l_bitstr);

    uint8_t *spki;
    size_t l_spki;
    encode_sequence((uint8_t *[]){algseq, bitstr}, (size_t[]){l_algseq, l_bitstr}, 2, &spki, &l_spki);

    char *b64 = base64_encode(spki, l_spki);
    char *pem = pem_wrap(b64, "PUBLIC KEY");

    SECURE_FREE(algseq, l_algseq);
    SECURE_FREE(en_n, len_n);
    SECURE_FREE(en_e, len_e);
    SECURE_FREE(pkseq, len_pkseq);
    SECURE_FREE(bitstr, l_bitstr);
    SECURE_FREE(spki, l_spki);
    SECURE_FREE(b64, strlen(b64));
    return pem;
}

// --- PKCS#8 PrivateKeyInfo PEM ("-----BEGIN PRIVATE KEY-----") ---
__attr_malloc __attr_nodiscard __attr_hot static inline char *rsa_private_key_to_pkcs8_pem(const RSAPrivateKey * const priv) __noexcept
{
    if (unlikely(!priv))
    {
        fprintf(stderr, "Null RSAPrivateKey pointer passed to PKCS#8 serialization\n");
        return NULL;
    }
    static const uint8_t oid_rsaEncryption[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
    uint8_t *oid, *nullv, *algseq;
    size_t l_oid, l_nullv, l_algseq;
    encode_oid(oid_rsaEncryption, sizeof(oid_rsaEncryption), &oid, &l_oid);
    encode_null(&nullv, &l_nullv);
    encode_sequence((uint8_t *[]){oid, nullv}, (size_t[]){l_oid, l_nullv}, 2, &algseq, &l_algseq);
    SECURE_FREE(oid, l_oid);
    SECURE_FREE(nullv, l_nullv);

    uint8_t *en_vals[9], *seq;
    size_t lens[9], len_seq;
    mpz_t zero;
    mpz_init_set_ui(zero, 0);
    encode_integer(zero, &en_vals[0], &lens[0]);
    encode_integer(priv->n, &en_vals[1], &lens[1]);
    encode_integer(priv->e, &en_vals[2], &lens[2]);
    encode_integer(priv->d, &en_vals[3], &lens[3]);
    encode_integer(priv->p, &en_vals[4], &lens[4]);
    encode_integer(priv->q, &en_vals[5], &lens[5]);
    encode_integer(priv->dP, &en_vals[6], &lens[6]);
    encode_integer(priv->dQ, &en_vals[7], &lens[7]);
    encode_integer(priv->qInv, &en_vals[8], &lens[8]);
    encode_sequence(en_vals, lens, 9, &seq, &len_seq);

    uint8_t *octet;
    size_t l_octet;
    encode_octet_string(seq, len_seq, &octet, &l_octet);

    uint8_t *ver;
    size_t l_ver;
    encode_integer(zero, &ver, &l_ver);
    uint8_t *pkcs8;
    size_t l_pkcs8;
    encode_sequence((uint8_t *[]){ver, algseq, octet}, (size_t[]){l_ver, l_algseq, l_octet}, 3, &pkcs8, &l_pkcs8);
    mpz_clear(zero);

    char *b64 = base64_encode(pkcs8, l_pkcs8);
    char *pem = pem_wrap(b64, "PRIVATE KEY");

    for (int i = 0; i < 9; ++i)
        SECURE_FREE(en_vals[i], lens[i]);
    SECURE_FREE(seq, len_seq);
    SECURE_FREE(ver, l_ver);
    SECURE_FREE(algseq, l_algseq);
    SECURE_FREE(octet, l_octet);
    SECURE_FREE(pkcs8, l_pkcs8);
    SECURE_FREE(b64, strlen(b64));
    return pem;
}

// ========== FILE SAVE/LOAD PEM ==========
__attr_nodiscard __attr_hot static inline int rsa_public_key_save_pem(const char *filename, const RSAPublicKey * const pub) __noexcept
{
    char * const pem = rsa_public_key_to_pem(pub);
    if (unlikely(!pem))
        return 0;
    const int r = write_text(filename, pem);
    SECURE_FREE(pem, strlen(pem));
    return r;
}

__attr_nodiscard __attr_hot static inline int rsa_private_key_save_pem(const char *filename, const RSAPrivateKey * const priv) __noexcept
{
    char * const pem = rsa_private_key_to_pem(priv);
    if (unlikely(!pem))
        return 0;
    const int r = write_text(filename, pem);
    SECURE_FREE(pem, strlen(pem));
    return r;
}

// ========== DER PARSING HELPERS & LOADERS ==========
__attr_hot static inline int der_read_tag_len(const uint8_t *buf, size_t buflen, size_t *offset, uint8_t *tag, size_t *len)
{
    if (*offset + 2 > buflen) return 0;
    *tag = buf[*offset];
    (*offset)++;
    uint8_t l = buf[*offset];
    (*offset)++;
    if (l & 0x80) {
        size_t n = l & 0x7F;
        if (n > sizeof(size_t) || *offset + n > buflen) return 0;
        *len = 0;
        for (size_t i = 0; i < n; ++i) {
            *len = (*len << 8) | buf[*offset];
            (*offset)++;
        }
    } else {
        *len = l;
    }
    if (*offset + *len > buflen) return 0;
    return 1;
}

__attr_hot static inline int der_read_integer(const uint8_t *buf, size_t buflen, size_t *offset, mpz_t out)
{
    uint8_t tag = 0; size_t len = 0;
    if (!der_read_tag_len(buf, buflen, offset, &tag, &len) || tag != 0x02) return 0;
    mpz_import(out, len, 1, 1, 1, 0, buf + *offset);
    *offset += len;
    return 1;
}

__attr_hot static inline int der_expect_sequence(const uint8_t *buf, size_t buflen, size_t *offset, size_t *seqlen)
{
    uint8_t tag = 0;
    if (!der_read_tag_len(buf, buflen, offset, &tag, seqlen)) return 0;
    if (tag != 0x30) return 0;
    return 1;
}

__attr_hot static inline int rsa_public_key_load_pem(const char *filename, RSAPublicKey *pub)
{
    size_t pemlen = 0;
    char *pem = (char*)read_file(filename, &pemlen);
    if (!pem) return 0;
    char *b64 = strip_pem(pem);
    SECURE_FREE(pem, pemlen);
    if (!b64) return 0;
    size_t derlen = 0;
    uint8_t *der = base64_decode(b64, &derlen);
    SECURE_FREE(b64, strlen(b64));
    if (!der) return 0;

    size_t off = 0, seqlen = 0;
    rsa_public_key_init(pub);
    int ok = 0;
    if (der_expect_sequence(der, derlen, &off, &seqlen) &&
        der_read_integer(der, derlen, &off, pub->n) &&
        der_read_integer(der, derlen, &off, pub->e))
        ok = 1;

    SECURE_FREE(der, derlen);
    if (!ok) rsa_public_key_clear(pub);
    return ok;
}

__attr_hot static inline int rsa_private_key_load_pem(const char *filename, RSAPrivateKey *priv)
{
    size_t pemlen = 0;
    char *pem = (char*)read_file(filename, &pemlen);
    if (!pem) return 0;
    char *b64 = strip_pem(pem);
    SECURE_FREE(pem, pemlen);
    if (!b64) return 0;
    size_t derlen = 0;
    uint8_t *der = base64_decode(b64, &derlen);
    SECURE_FREE(b64, strlen(b64));
    if (!der) return 0;

    size_t off = 0, seqlen = 0;
    rsa_private_key_init(priv);
    mpz_t version; mpz_init(version);
    int ok = 0;
    if (der_expect_sequence(der, derlen, &off, &seqlen) &&
        der_read_integer(der, derlen, &off, version) &&
        der_read_integer(der, derlen, &off, priv->n) &&
        der_read_integer(der, derlen, &off, priv->e) &&
        der_read_integer(der, derlen, &off, priv->d) &&
        der_read_integer(der, derlen, &off, priv->p) &&
        der_read_integer(der, derlen, &off, priv->q) &&
        der_read_integer(der, derlen, &off, priv->dP) &&
        der_read_integer(der, derlen, &off, priv->dQ) &&
        der_read_integer(der, derlen, &off, priv->qInv))
        ok = 1;
    mpz_clear(version);

    SECURE_FREE(der, derlen);
    if (!ok) rsa_private_key_clear(priv);
    return ok;
}

// ========== LOADERS (X.509 / PKCS#8 PEM) ==========
__attr_hot static inline int rsa_public_key_load_x509_pem(const char *filename, RSAPublicKey *pub)
{
    size_t pemlen = 0;
    char *pem = (char*)read_file(filename, &pemlen);
    if (!pem) return 0;
    char *b64 = strip_pem(pem);
    SECURE_FREE(pem, pemlen);
    if (!b64) return 0;
    size_t derlen = 0;
    uint8_t *der = base64_decode(b64, &derlen);
    SECURE_FREE(b64, strlen(b64));
    if (!der) return 0;

    size_t off = 0, seqlen = 0;
    if (!der_expect_sequence(der, derlen, &off, &seqlen)) { SECURE_FREE(der, derlen); return 0; }
    uint8_t tag = 0; size_t tlen = 0;
    if (!der_read_tag_len(der, derlen, &off, &tag, &tlen)) { SECURE_FREE(der, derlen); return 0; }
    off += tlen;
    if (!der_read_tag_len(der, derlen, &off, &tag, &tlen) || tag != 0x03) { SECURE_FREE(der, derlen); return 0; }
    off += 1;
    if (!der_expect_sequence(der, derlen, &off, &seqlen)) { SECURE_FREE(der, derlen); return 0; }
    rsa_public_key_init(pub);
    int ok = 0;
    if (der_read_integer(der, derlen, &off, pub->n) &&
        der_read_integer(der, derlen, &off, pub->e))
        ok = 1;
    SECURE_FREE(der, derlen);
    if (!ok) rsa_public_key_clear(pub);
    return ok;
}

__attr_hot static inline int rsa_private_key_load_pkcs8_pem(const char *filename, RSAPrivateKey *priv)
{
    size_t pemlen = 0;
    char *pem = (char*)read_file(filename, &pemlen);
    if (!pem) return 0;
    char *b64 = strip_pem(pem);
    SECURE_FREE(pem, pemlen);
    if (!b64) return 0;
    size_t derlen = 0;
    uint8_t *der = base64_decode(b64, &derlen);
    SECURE_FREE(b64, strlen(b64));
    if (!der) return 0;

    size_t off = 0, seqlen = 0;
    if (!der_expect_sequence(der, derlen, &off, &seqlen)) { SECURE_FREE(der, derlen); return 0; }
    mpz_t version; mpz_init(version);
    if (!der_read_integer(der, derlen, &off, version)) { mpz_clear(version); SECURE_FREE(der, derlen); return 0; }
    uint8_t tag = 0; size_t tlen = 0;
    if (!der_read_tag_len(der, derlen, &off, &tag, &tlen)) { mpz_clear(version); SECURE_FREE(der, derlen); return 0; }
    off += tlen;
    if (!der_read_tag_len(der, derlen, &off, &tag, &tlen) || tag != 0x04) { mpz_clear(version); SECURE_FREE(der, derlen); return 0; }
    size_t inoff = off;
    off += tlen;
    rsa_private_key_init(priv);
    int ok = 0;
    size_t pkcs1off = inoff, pkcs1len = tlen;
    size_t seqoff = pkcs1off, seqlen2 = 0;
    if (der_expect_sequence(der, derlen, &seqoff, &seqlen2)) {
        mpz_t v2; mpz_init(v2);
        if (der_read_integer(der, derlen, &seqoff, v2) &&
            der_read_integer(der, derlen, &seqoff, priv->n) &&
            der_read_integer(der, derlen, &seqoff, priv->e) &&
            der_read_integer(der, derlen, &seqoff, priv->d) &&
            der_read_integer(der, derlen, &seqoff, priv->p) &&
            der_read_integer(der, derlen, &seqoff, priv->q) &&
            der_read_integer(der, derlen, &seqoff, priv->dP) &&
            der_read_integer(der, derlen, &seqoff, priv->dQ) &&
            der_read_integer(der, derlen, &seqoff, priv->qInv))
            ok = 1;
        mpz_clear(v2);
    }
    mpz_clear(version);
    SECURE_FREE(der, derlen);
    if (!ok) rsa_private_key_clear(priv);
    return ok;
}

#endif // RSA_ALGORITHM_C_H
