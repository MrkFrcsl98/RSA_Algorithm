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

#if defined(__GNUC__) || defined(__clang__)
#define ATTR_NODISCARD __attribute__((warn_unused_result))
#define ATTR_MALLOC __attribute__((malloc))
#define ATTR_HOT __attribute__((hot))
#define ATTR_COLD __attribute__((cold))
#else
#define ATTR_NODISCARD
#define ATTR_MALLOC
#define ATTR_HOT
#define ATTR_COLD
#endif

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

#define SECURE_FREE(p, sz)                                                                                                                                               \
    do                                                                                                                                                                   \
    {                                                                                                                                                                    \
        if (p)                                                                                                                                                           \
        {                                                                                                                                                                \
            volatile unsigned char *vp = (volatile unsigned char *)(p);                                                                                                  \
            for (size_t _i = 0; _i < (sz); ++_i)                                                                                                                         \
                vp[_i] = 0;                                                                                                                                              \
            free((void *)p);                                                                                                                                             \
        }                                                                                                                                                                \
    } while (0)
#define SAFE_MALLOC(size)                                                                                                                                                \
    ({                                                                                                                                                                   \
        void *_p = malloc(size);                                                                                                                                         \
        if (!_p)                                                                                                                                                         \
        {                                                                                                                                                                \
            fprintf(stderr, "Out of memory at %s:%d\n", __FILE__, __LINE__);                                                                                             \
            abort();                                                                                                                                                     \
        }                                                                                                                                                                \
        _p;                                                                                                                                                              \
    })

// ========== ASN.1 DER ==========

static inline void encode_integer(const mpz_t x, uint8_t **out, size_t *outlen) ATTR_HOT;
static inline void encode_integer(const mpz_t x, uint8_t **out, size_t *outlen)
{
    size_t count = (mpz_sizeinbase(x, 2) + 7) / 8;
    if (count == 0)
        count = 1;
    uint8_t *bytes = (uint8_t *)SAFE_MALLOC(count + 2); // +2 for safety
    mpz_export(bytes, &count, 1, 1, 1, 0, x);
    int prepend_zero = (bytes[0] & 0x80) ? 1 : 0;
    if (prepend_zero)
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
    SECURE_FREE(bytes, count + 1); // always free at least count+1 for safety
}

static inline void encode_sequence(uint8_t **fields, const size_t *field_lens, size_t num_fields, uint8_t **out, size_t *outlen) ATTR_HOT;
static inline void encode_sequence(uint8_t **fields, const size_t *field_lens, size_t num_fields, uint8_t **out, size_t *outlen)
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

static inline char *base64_encode(const uint8_t *in, size_t inlen) ATTR_MALLOC ATTR_NODISCARD ATTR_HOT;
static inline char *base64_encode(const uint8_t *in, size_t inlen)
{
    size_t outlen = 4 * ((inlen + 2) / 3);
    char *out = (char *)SAFE_MALLOC(outlen + 1);
    size_t i, j;
    for (i = 0, j = 0; i < inlen;)
    {
        uint32_t octet_a = i < inlen ? in[i++] : 0;
        uint32_t octet_b = i < inlen ? in[i++] : 0;
        uint32_t octet_c = i < inlen ? in[i++] : 0;
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;
        out[j++] = b64_table[(triple >> 18) & 0x3F];
        out[j++] = b64_table[(triple >> 12) & 0x3F];
        out[j++] = (i > inlen + 1) ? '=' : b64_table[(triple >> 6) & 0x3F];
        out[j++] = (i > inlen) ? '=' : b64_table[triple & 0x3F];
    }
    out[outlen] = 0;
    return out;
}

static inline uint8_t *base64_decode(const char *in, size_t *outlen) ATTR_MALLOC ATTR_NODISCARD ATTR_HOT;
static inline uint8_t *base64_decode(const char *in, size_t *outlen)
{
    int dtable[256] = {0};
    for (size_t i = 0; i < 64; i++)
        dtable[(uint8_t)b64_table[i]] = i + 1;
    size_t inlen = strlen(in), pad = 0, i, j;
    if (inlen >= 2 && in[inlen - 1] == '=')
        pad++;
    if (inlen >= 2 && in[inlen - 2] == '=')
        pad++;
    *outlen = (inlen * 3) / 4 - pad;
    uint8_t *out = (uint8_t *)SAFE_MALLOC(*outlen);
    uint32_t buf = 0;
    int k = 0;
    for (i = 0, j = 0; i < inlen;)
    {
        int val = 0;
        for (int n = 0; n < 4 && i < inlen;)
        {
            char c = in[i++];
            if (dtable[(uint8_t)c])
            {
                val = (val << 6) | (dtable[(uint8_t)c] - 1);
                n++;
            }
            else if (c == '=')
            {
                val <<= 6;
                n++;
            }
        }
        if (j < *outlen)
            out[j++] = (val >> 16) & 0xFF;
        if (j < *outlen)
            out[j++] = (val >> 8) & 0xFF;
        if (j < *outlen)
            out[j++] = val & 0xFF;
    }
    return out;
}

// PEM WRAP/UNWRAP
static inline char *pem_wrap(const char *base64, const char *type) ATTR_MALLOC ATTR_NODISCARD ATTR_HOT;
static inline char *pem_wrap(const char *base64, const char *type)
{
    size_t typelen = strlen(type);
    size_t b64len = strlen(base64);
    size_t outlen = 32 + b64len + b64len / 64 * 2 + typelen * 2;
    char *out = (char *)SAFE_MALLOC(outlen);
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

static inline char *strip_pem(const char *pem) ATTR_MALLOC ATTR_NODISCARD ATTR_HOT;
static inline char *strip_pem(const char *pem)
{
    const char *begin = strstr(pem, "-----BEGIN");
    if (!begin)
    {
        fprintf(stderr, "Failed to find PEM BEGIN header\n");
        return NULL;
    }
    begin = strchr(begin, '\n');
    const char *end = strstr(pem, "-----END");
    if (!end)
    {
        fprintf(stderr, "Failed to find PEM END header\n");
        return NULL;
    }
    size_t b64len = end - begin - 1;
    char *b64 = (char *)SAFE_MALLOC(b64len + 1);
    size_t k = 0;
    for (const char *p = begin + 1; p < end; ++p)
        if (isalnum((unsigned char)*p) || *p == '+' || *p == '/' || *p == '=')
            b64[k++] = *p;
    b64[k] = 0;
    return b64;
}

// ========== HEX ENCODE/DECODE ==========

static inline char *bytes_to_hex(const uint8_t *data, size_t len) ATTR_MALLOC ATTR_NODISCARD ATTR_HOT;
static inline char *bytes_to_hex(const uint8_t *data, size_t len)
{
    char *out = (char *)SAFE_MALLOC(len * 2 + 1);
    for (size_t i = 0; i < len; ++i)
        sprintf(out + 2 * i, "%02x", data[i]);
    out[len * 2] = 0;
    return out;
}

static inline uint8_t *hex_to_bytes(const char *hex, size_t *outlen) ATTR_MALLOC ATTR_NODISCARD ATTR_HOT;
static inline uint8_t *hex_to_bytes(const char *hex, size_t *outlen)
{
    size_t len = strlen(hex) / 2;
    uint8_t *out = (uint8_t *)SAFE_MALLOC(len);
    for (size_t i = 0; i < len; ++i)
    {
        if (sscanf(hex + 2 * i, "%2hhx", &out[i]) != 1)
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

static inline int file_exists(const char *filename) ATTR_HOT;
static inline int file_exists(const char *filename)
{
    FILE *f = fopen(filename, "rb");
    if (f)
    {
        fclose(f);
        return 1;
    }
    return 0;
}

static inline uint8_t *read_file(const char *filename, size_t *len) ATTR_MALLOC ATTR_NODISCARD ATTR_HOT;
static inline uint8_t *read_file(const char *filename, size_t *len)
{
    FILE *f = fopen(filename, "rb");
    if (!f)
    {
        fprintf(stderr, "Failed to open file '%s' for reading: %s\n", filename, strerror(errno));
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0)
    {
        fclose(f);
        return NULL;
    }
    long flen = ftell(f);
    if (flen < 0)
    {
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0)
    {
        fclose(f);
        return NULL;
    }
    uint8_t *buf = (uint8_t *)SAFE_MALLOC(flen);
    size_t r = fread(buf, 1, flen, f);
    fclose(f);
    if (r != (size_t)flen)
    {
        SECURE_FREE(buf, flen);
        return NULL;
    }
    *len = flen;
    return buf;
}

static inline int write_file(const char *filename, const uint8_t *data, size_t len) ATTR_HOT;
static inline int write_file(const char *filename, const uint8_t *data, size_t len)
{
    FILE *f = fopen(filename, "wb");
    if (!f)
    {
        fprintf(stderr, "Failed to open '%s' for writing\n", filename);
        return 0;
    }
    size_t w = fwrite(data, 1, len, f);
    fclose(f);
    if (w != len)
    {
        fprintf(stderr, "Failed to write all data to '%s'\n", filename);
        return 0;
    }
    return 1;
}

static inline int write_text(const char *filename, const char *text) ATTR_HOT;
static inline int write_text(const char *filename, const char *text)
{
    FILE *f = fopen(filename, "w");
    if (!f)
    {
        fprintf(stderr, "Failed to open file '%s' for writing: %s\n", filename, strerror(errno));
        return 0;
    }
    size_t w = fwrite(text, 1, strlen(text), f);
    fclose(f);
    if (w != strlen(text))
    {
        fprintf(stderr, "Error writing text to file '%s'\n", filename);
        return 0;
    }
    return 1;
}

// ========== RANDOM PRIME, MODINV, POWM ==========

static inline void random_prime(mpz_t out, int bits, gmp_randstate_t rng) ATTR_HOT;
static inline void random_prime(mpz_t out, int bits, gmp_randstate_t rng)
{
    int tries = 0;
    while (1)
    {
        mpz_urandomb(out, rng, bits);
        mpz_setbit(out, bits - 1);
        mpz_setbit(out, 0);
        if (mpz_probab_prime_p(out, 40))
            return;
        if (++tries > 1000)
        {
            fprintf(stderr, "Failed to generate a random prime after 1000 tries\n");
            abort();
        }
    }
}

static inline void modinv(mpz_t out, const mpz_t a, const mpz_t m) ATTR_HOT;
static inline void modinv(mpz_t out, const mpz_t a, const mpz_t m)
{
    if (!mpz_invert(out, a, m))
    {
        fprintf(stderr, "No modular inverse exists\n");
        abort();
    }
}

static inline void powm(mpz_t out, const mpz_t base, const mpz_t exp, const mpz_t mod) ATTR_HOT;
static inline void powm(mpz_t out, const mpz_t base, const mpz_t exp, const mpz_t mod)
{
    mpz_powm(out, base, exp, mod);
}

// ========== PKCS#1 v1.5 Padding ==========

static inline int pkcs1_pad(const uint8_t *block, size_t blocklen, uint8_t *padded, size_t mod_bytes) ATTR_NODISCARD ATTR_HOT;
static inline int pkcs1_pad(const uint8_t *block, size_t blocklen, uint8_t *padded, size_t mod_bytes)
{
    if (blocklen > mod_bytes - 11)
    {
        fprintf(stderr, "Block too large for PKCS#1 v1.5 padding\n");
        return 0;
    }
    padded[0] = 0x00;
    padded[1] = 0x02;
    for (size_t i = 0; i < mod_bytes - 3 - blocklen; ++i)
    {
        uint8_t r = 0;
        int pad_tries = 0;
        do
        {
            r = (uint8_t)((rand() % 255) + 1);
            if (++pad_tries > 1000)
            {
                fprintf(stderr, "Failed to find non-zero padding byte after 1000 tries\n");
                return 0;
            }
        } while (r == 0);
        padded[2 + i] = r;
    }
    padded[2 + (mod_bytes - 3 - blocklen)] = 0x00;
    memcpy(padded + 3 + (mod_bytes - 3 - blocklen), block, blocklen);
    return 1;
}

static inline int pkcs1_unpad(const uint8_t *padded, size_t paddedlen, uint8_t *out, size_t *outlen) ATTR_NODISCARD ATTR_HOT;
static inline int pkcs1_unpad(const uint8_t *padded, size_t paddedlen, uint8_t *out, size_t *outlen)
{
    if (paddedlen < 11 || padded[0] != 0x00 || padded[1] != 0x02)
    {
        fprintf(stderr, "Invalid PKCS#1 v1.5 padding detected\n");
        return 0;
    }
    size_t idx = 2;
    while (idx < paddedlen && padded[idx] != 0x00)
        ++idx;
    if (idx == paddedlen || idx < 10)
    {
        fprintf(stderr, "Padding format error in PKCS#1 v1.5\n");
        return 0;
    }
    size_t msglen = paddedlen - (idx + 1);
    memcpy(out, padded + idx + 1, msglen);
    *outlen = msglen;
    return 1;
}

// ========== KEY INIT/CLEAR ==========

static inline void rsa_public_key_init(RSAPublicKey *key) ATTR_HOT;
static inline void rsa_public_key_init(RSAPublicKey *key)
{
    if (!key)
    {
        fprintf(stderr, "Null RSAPublicKey pointer passed to init\n");
        abort();
    }
    mpz_init(key->n);
    mpz_init(key->e);
}
static inline void rsa_private_key_init(RSAPrivateKey *key) ATTR_HOT;
static inline void rsa_private_key_init(RSAPrivateKey *key)
{
    if (!key)
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
static inline void rsa_public_key_clear(RSAPublicKey *key) ATTR_COLD;
static inline void rsa_public_key_clear(RSAPublicKey *key)
{
    if (!key)
        return;
    mpz_clear(key->n);
    mpz_clear(key->e);
}
static inline void rsa_private_key_clear(RSAPrivateKey *key) ATTR_COLD;
static inline void rsa_private_key_clear(RSAPrivateKey *key)
{
    if (!key)
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

static inline void rsa_generate_keypair(RSAKeyPair *kp, KeySize bits) ATTR_HOT;
static inline void rsa_generate_keypair(RSAKeyPair *kp, KeySize bits)
{
    if (!kp)
    {
        fprintf(stderr, "Null RSAKeyPair pointer passed to key generation\n");
        abort();
    }
    gmp_randstate_t rng;
    gmp_randinit_mt(rng);
    gmp_randseed_ui(rng, (unsigned long)time(NULL));
    mpz_t p, q, phi, d, e, dP, dQ, qInv;
    mpz_inits(p, q, phi, d, e, dP, dQ, qInv, NULL);
    random_prime(p, bits / 2, rng);
    int tries = 0;
    do
    {
        random_prime(q, bits / 2, rng);
        if (++tries > 1000)
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

static inline int rsa_encrypt(const uint8_t *message, size_t mlen, const RSAPublicKey *pub, uint8_t *out, size_t *outlen) ATTR_NODISCARD ATTR_HOT;
static inline int rsa_encrypt(const uint8_t *message, size_t mlen, const RSAPublicKey *pub, uint8_t *out, size_t *outlen)
{
    if (!message || !pub || !out || !outlen)
    {
        fprintf(stderr, "NULL pointer argument to rsa_encrypt\n");
        return 0;
    }
    size_t mod_bytes = (mpz_sizeinbase(pub->n, 2) + 7) / 8;
    uint8_t *block = (uint8_t *)SAFE_MALLOC(mod_bytes);
    if (!pkcs1_pad(message, mlen, block, mod_bytes))
    {
        SECURE_FREE(block, mod_bytes);
        return 0;
    }
    mpz_t m, c;
    mpz_init(m);
    mpz_init(c);
    mpz_import(m, mod_bytes, 1, 1, 1, 0, block);
    if (mpz_cmp(m, pub->n) >= 0)
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

static inline int rsa_decrypt(const uint8_t *enc, size_t enclen, const RSAPrivateKey *priv, uint8_t *out, size_t *outlen) ATTR_NODISCARD ATTR_HOT;
static inline int rsa_decrypt(const uint8_t *enc, size_t enclen, const RSAPrivateKey *priv, uint8_t *out, size_t *outlen)
{
    if (!enc || !priv || !out || !outlen)
    {
        fprintf(stderr, "NULL pointer argument to rsa_decrypt\n");
        return 0;
    }
    size_t mod_bytes = (mpz_sizeinbase(priv->n, 2) + 7) / 8;
    mpz_t c, m;
    mpz_init(c);
    mpz_init(m);
    mpz_import(c, enclen, 1, 1, 1, 0, enc);
    powm(m, c, priv->d, priv->n);
    uint8_t *padded = (uint8_t *)SAFE_MALLOC(mod_bytes);
    size_t paddedlen = 0;
    mpz_export(padded, &paddedlen, 1, 1, 1, 0, m);
    if (paddedlen < mod_bytes)
    {
        memmove(padded + (mod_bytes - paddedlen), padded, paddedlen);
        memset(padded, 0, mod_bytes - paddedlen);
        paddedlen = mod_bytes;
    }
    int res = pkcs1_unpad(padded, paddedlen, out, outlen);
    SECURE_FREE(padded, mod_bytes);
    mpz_clear(c);
    mpz_clear(m);
    return res;
}

// ========== PEM/DER SERIALIZATION (PUBLIC KEY) ==========

static inline char *rsa_public_key_to_pem(const RSAPublicKey *pub) ATTR_MALLOC ATTR_NODISCARD ATTR_HOT;
static inline char *rsa_public_key_to_pem(const RSAPublicKey *pub)
{
    if (!pub)
    {
        fprintf(stderr, "Null RSAPublicKey pointer passed to serialization\n");
        return NULL;
    }
    uint8_t *en_n, *en_e, *seq;
    size_t len_n, len_e, len_seq;
    encode_integer(pub->n, &en_n, &len_n);
    encode_integer(pub->e, &en_e, &len_e);
    encode_sequence((uint8_t *[]){en_n, en_e}, (size_t[]){len_n, len_e}, 2, &seq, &len_seq);
    char *b64 = base64_encode(seq, len_seq);
    char *pem = pem_wrap(b64, "RSA PUBLIC KEY");
    SECURE_FREE(en_n, len_n);
    SECURE_FREE(en_e, len_e);
    SECURE_FREE(seq, len_seq);
    SECURE_FREE(b64, strlen(b64));
    return pem;
}

static inline char *rsa_private_key_to_pem(const RSAPrivateKey *priv) ATTR_MALLOC ATTR_NODISCARD ATTR_HOT;
static inline char *rsa_private_key_to_pem(const RSAPrivateKey *priv)
{
    if (!priv)
    {
        fprintf(stderr, "Null RSAPrivateKey pointer passed to serialization\n");
        return NULL;
    }
    uint8_t *en_vals[9], *seq;
    size_t lens[9], len_seq;
    mpz_t zero;
    mpz_init_set_ui(zero, 0);
    encode_integer(zero, &en_vals[0], &lens[0]); // version
    encode_integer(priv->n, &en_vals[1], &lens[1]);
    encode_integer(priv->e, &en_vals[2], &lens[2]);
    encode_integer(priv->d, &en_vals[3], &lens[3]);
    encode_integer(priv->p, &en_vals[4], &lens[4]);
    encode_integer(priv->q, &en_vals[5], &lens[5]);
    encode_integer(priv->dP, &en_vals[6], &lens[6]);
    encode_integer(priv->dQ, &en_vals[7], &lens[7]);
    encode_integer(priv->qInv, &en_vals[8], &lens[8]);
    encode_sequence(en_vals, lens, 9, &seq, &len_seq);
    char *b64 = base64_encode(seq, len_seq);
    char *pem = pem_wrap(b64, "RSA PRIVATE KEY");
    for (int i = 0; i < 9; ++i)
        SECURE_FREE(en_vals[i], lens[i]);
    SECURE_FREE(seq, len_seq);
    SECURE_FREE(b64, strlen(b64));
    mpz_clear(zero);
    return pem;
}

// ========== FILE SAVE/LOAD PEM ==========

static inline int rsa_public_key_save_pem(const char *filename, const RSAPublicKey *pub) ATTR_NODISCARD ATTR_HOT;
static inline int rsa_public_key_save_pem(const char *filename, const RSAPublicKey *pub)
{
    char *pem = rsa_public_key_to_pem(pub);
    if (!pem)
        return 0;
    int r = write_text(filename, pem);
    SECURE_FREE(pem, strlen(pem));
    return r;
}

static inline int rsa_private_key_save_pem(const char *filename, const RSAPrivateKey *priv) ATTR_NODISCARD ATTR_HOT;
static inline int rsa_private_key_save_pem(const char *filename, const RSAPrivateKey *priv)
{
    char *pem = rsa_private_key_to_pem(priv);
    if (!pem)
        return 0;
    int r = write_text(filename, pem);
    SECURE_FREE(pem, strlen(pem));
    return r;
}

#endif // RSA_ALGORITHM_C_H
