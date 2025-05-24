#ifndef RSA_C_H
#define RSA_C_H

#include <gmp.h>
#include <stddef.h>
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
#define __noexcept noexcept
#define __const_noexcept const noexcept
#else
#define __restrict__ restrict
#define __noexcept
#define __const_noexcept
#endif

// Key structures
typedef struct {
    mpz_t n;
    mpz_t e;
} rsa_public_key;

typedef struct {
    mpz_t n, e, d, p, q, dP, dQ, qInv;
} rsa_private_key;

// Function declarations

// Key generation
void rsa_generate_keypair(rsa_public_key *pub, rsa_private_key *priv, int bits);

// Key storage/loading (PEM-like)
__attr_nodiscard int rsa_save_public(const char *fname, const rsa_public_key *pub);
__attr_nodiscard int rsa_load_public(const char *fname, rsa_public_key *pub);
__attr_nodiscard int rsa_save_private(const char *fname, const rsa_private_key *priv);
__attr_nodiscard int rsa_load_private(const char *fname, rsa_private_key *priv);

// Encryption/Decryption
void rsa_encrypt(mpz_t out, const mpz_t in, const rsa_public_key *pub);
void rsa_decrypt(mpz_t out, const mpz_t in, const rsa_private_key *priv);

// Utility
void rsa_clear_public(rsa_public_key *pub);
void rsa_clear_private(rsa_private_key *priv);
__attr_nodiscard int modinv(mpz_t rop, const mpz_t a, const mpz_t m);
void random_prime(mpz_t rop, gmp_randstate_t state, int bits);

// DER serialization/deserialization
size_t rsa_serialize_public_der(const rsa_public_key *pub, unsigned char *der, size_t maxlen);
size_t rsa_deserialize_public_der(rsa_public_key *pub, const unsigned char *der, size_t len);
size_t rsa_serialize_private_der(const rsa_private_key *priv, unsigned char *der, size_t maxlen);
size_t rsa_deserialize_private_der(rsa_private_key *priv, const unsigned char *der, size_t len);

// PEM encoding/decoding
__attr_malloc char *pem_encode(const char *type, const unsigned char *der, size_t der_len);
__attr_malloc unsigned char *pem_decode(const char *pem, size_t *outlen);

// PEM file I/O
__attr_nodiscard int rsa_save_public_pem(const char *fname, const rsa_public_key *pub);
__attr_nodiscard int rsa_load_public_pem(const char *fname, rsa_public_key *pub);
__attr_nodiscard int rsa_save_private_pem(const char *fname, const rsa_private_key *priv);
__attr_nodiscard int rsa_load_private_pem(const char *fname, rsa_private_key *priv);

// X.509/PKCS#8
size_t rsa_serialize_public_x509_der(const rsa_public_key *pub, unsigned char *der, size_t maxlen);
size_t rsa_deserialize_public_x509_der(rsa_public_key *pub, const unsigned char *der, size_t len);
size_t rsa_serialize_private_pkcs8_der(const rsa_private_key *priv, unsigned char *der, size_t maxlen);
size_t rsa_deserialize_private_pkcs8_der(rsa_private_key *priv, const unsigned char *der, size_t len);
__attr_nodiscard int rsa_save_public_x509_pem(const char *fname, const rsa_public_key *pub);
__attr_nodiscard int rsa_load_public_x509_pem(const char *fname, rsa_public_key *pub);
__attr_nodiscard int rsa_save_private_pkcs8_pem(const char *fname, const rsa_private_key *priv);
__attr_nodiscard int rsa_load_private_pkcs8_pem(const char *fname, rsa_private_key *priv);

// File encryption/decryption
__attr_nodiscard int rsa_encrypt_file(const char *infile, const char *outfile, const rsa_public_key *pub);
__attr_nodiscard int rsa_decrypt_file(const char *infile, const char *outfile, const rsa_private_key *priv);

// Buffer/file helpers
__attr_nodiscard int save_file_hex(const char* fname, const unsigned char* buf, size_t len);
__attr_nodiscard int save_file_base64(const char* fname, const unsigned char* buf, size_t len);
__attr_nodiscard int save_file_ascii(const char* fname, const unsigned char* buf, size_t len);

#endif // RSA_C_H


// ========== Constants ==========
static const char b64tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const unsigned char OID_RSA_ENCRYPTION[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};

// Utility: modular inverse (returns 1 on success)
__attr_nodiscard int modinv(mpz_t rop, const mpz_t a, const mpz_t m)
{
    return mpz_invert(rop, a, m) != 0;
}

// Generate a random probable prime of given bits
void random_prime(mpz_t rop, gmp_randstate_t state, int bits)
{
    do
    {
        mpz_urandomb(rop, state, bits);
        mpz_setbit(rop, bits - 1); // ensure high bit set
        mpz_setbit(rop, 0);        // ensure odd
    } while (!mpz_probab_prime_p(rop, 25));
}

// Key generation
void rsa_generate_keypair(rsa_public_key *pub, rsa_private_key *priv, int bits)
{
    gmp_randstate_t state;
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, (unsigned long)time(NULL));

    mpz_t p, q, phi, dP, dQ, qInv;
    mpz_inits(p, q, phi, dP, dQ, qInv, NULL);

    // Generate distinct primes p, q
    random_prime(p, state, bits / 2);
    do
    {
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
    if (!modinv(priv->d, priv->e, phi))
    {
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
    modinv(qInv, priv->q, priv->p);
    mpz_set(priv->qInv, qInv);

    // Fill public key
    mpz_init_set(pub->n, priv->n);
    mpz_init_set(pub->e, priv->e);

    mpz_clears(p, q, phi, dP, dQ, qInv, NULL);
    gmp_randclear(state);
}

// Key storage: PEM-like (hex, one value per line)
__attr_nodiscard int rsa_save_public(const char *fname, const rsa_public_key *pub)
{
    FILE *f = fopen(fname, "w");
    if (!f)
        return 0;
    gmp_fprintf(f, "%Zx\n%Zx\n", pub->n, pub->e);
    fclose(f);
    return 1;
}

__attr_nodiscard int rsa_load_public(const char *fname, rsa_public_key *pub)
{
    FILE *f = fopen(fname, "r");
    if (!f)
        return 0;
    mpz_init(pub->n);
    mpz_init(pub->e);
    gmp_fscanf(f, "%Zx\n%Zx\n", pub->n, pub->e);
    fclose(f);
    return 1;
}

__attr_nodiscard int rsa_save_private(const char *fname, const rsa_private_key *priv)
{
    FILE *f = fopen(fname, "w");
    if (!f)
        return 0;
    gmp_fprintf(f, "%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n", priv->n, priv->e, priv->d, priv->p, priv->q, priv->dP, priv->dQ, priv->qInv);
    fclose(f);
    return 1;
}

__attr_nodiscard int rsa_load_private(const char *fname, rsa_private_key *priv)
{
    FILE *f = fopen(fname, "r");
    if (!f)
        return 0;
    mpz_inits(priv->n, priv->e, priv->d, priv->p, priv->q, priv->dP, priv->dQ, priv->qInv, NULL);
    gmp_fscanf(f, "%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n", priv->n, priv->e, priv->d, priv->p, priv->q, priv->dP, priv->dQ, priv->qInv);
    fclose(f);
    return 1;
}

// Encryption/Decryption
void rsa_encrypt(mpz_t out, const mpz_t in, const rsa_public_key *pub)
{
    mpz_powm(out, in, pub->e, pub->n);
}

void rsa_decrypt(mpz_t out, const mpz_t in, const rsa_private_key *priv)
{
    mpz_powm(out, in, priv->d, priv->n);
}

// Utility
void rsa_clear_public(rsa_public_key *pub)
{
    mpz_clear(pub->n);
    mpz_clear(pub->e);
}

void rsa_clear_private(rsa_private_key *priv)
{
    mpz_clears(priv->n, priv->e, priv->d, priv->p, priv->q, priv->dP, priv->dQ, priv->qInv, NULL);
}

// ASN.1/DER helpers
static size_t asn1_encode_len(unsigned char *out, size_t len)
{
    if (len < 128)
    {
        if (out)
            out[0] = (unsigned char)len;
        return 1;
    }
    else
    {
        size_t n = 0, l = len;
        while (l)
        {
            ++n;
            l >>= 8;
        }
        if (out)
            out[0] = 0x80 | n;
        for (size_t i = 0; i < n; ++i)
            if (out)
                out[1 + i] = (unsigned char)(len >> (8 * (n - 1 - i)));
        return 1 + n;
    }
}

static size_t asn1_encode_integer(const mpz_t x, unsigned char *out)
{
    size_t count = (mpz_sizeinbase(x, 2) + 7) / 8;
    unsigned char *buf = (unsigned char *)malloc(count + 1); // extra for leading 0
    mpz_export(buf + 1, &count, 1, 1, 1, 0, x);
    buf[0] = 0x00; // for possible sign bit
    size_t off = 0;
    if (count && (buf[1] & 0x80))
    {
        off = 0;
        count++;
    }
    else
    {
        off = 1;
    }
    if (out)
    {
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
size_t rsa_serialize_public_der(const rsa_public_key *pub, unsigned char *der, size_t maxlen)
{
    unsigned char tmp[2048];
    size_t nlen = asn1_encode_integer(pub->n, tmp);
    size_t elen = asn1_encode_integer(pub->e, tmp + nlen);

    size_t seqlen = nlen + elen;
    size_t lenlen = asn1_encode_len(NULL, seqlen);
    if (der)
    {
        der[0] = 0x30;
        asn1_encode_len(der + 1, seqlen);
        memcpy(der + 1 + lenlen, tmp, nlen + elen);
    }
    return 1 + lenlen + nlen + elen;
}

size_t rsa_serialize_private_der(const rsa_private_key *priv, unsigned char *der, size_t maxlen)
{
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
    if (der)
    {
        der[0] = 0x30;
        asn1_encode_len(der + 1, seqlen);
        memcpy(der + 1 + lenlen, tmp, off);
    }
    return 1 + lenlen + off;
}

// PEM encoding/decoding
__attr_malloc char *pem_encode(const char *type, const unsigned char *der, size_t der_len)
{
    size_t outlen = 4 * ((der_len + 2) / 3);
    char *out = (char *)malloc(outlen + 128);
    char *p = out;
    p += sprintf(p, "-----BEGIN %s-----\n", type);
    for (size_t i = 0; i < der_len; i += 3)
    {
        unsigned val = der[i] << 16;
        if (i + 1 < der_len)
            val |= der[i + 1] << 8;
        if (i + 2 < der_len)
            val |= der[i + 2];
        *p++ = b64tab[(val >> 18) & 0x3F];
        *p++ = b64tab[(val >> 12) & 0x3F];
        *p++ = (i + 1 < der_len) ? b64tab[(val >> 6) & 0x3F] : '=';
        *p++ = (i + 2 < der_len) ? b64tab[val & 0x3F] : '=';
        if (((i / 3 + 1) * 4) % 64 == 0)
            *p++ = '\n';
    }
    if (*(p - 1) != '\n')
        *p++ = '\n';
    sprintf(p, "-----END %s-----\n", type);
    return out;
}

__attr_malloc unsigned char *pem_decode(const char *pem, size_t *outlen)
{
    const char *p = strstr(pem, "-----BEGIN");
    if (!p)
        return NULL;
    p = strchr(p, '\n');
    if (!p)
        return NULL;
    p++;
    const char *q = strstr(p, "-----END");
    if (!q)
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
    for (size_t i = 0; i < b64len; i += 4)
    {
        unsigned val = 0;
        for (int k = 0; k < 4; ++k)
        {
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

// PEM file I/O
__attr_nodiscard int rsa_save_public_pem(const char *fname, const rsa_public_key *pub)
{
    unsigned char der[4096];
    size_t derlen = rsa_serialize_public_der(pub, der, sizeof(der));
    char *pem = pem_encode("RSA PUBLIC KEY", der, derlen);
    FILE *f = fopen(fname, "w");
    if (!f)
    {
        free(pem);
        return 0;
    }
    fputs(pem, f);
    fclose(f);
    free(pem);
    return 1;
}

__attr_nodiscard int rsa_load_public_pem(const char *fname, rsa_public_key *pub)
{
    FILE *f = fopen(fname, "r");
    if (!f)
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

__attr_nodiscard int rsa_save_private_pem(const char *fname, const rsa_private_key *priv)
{
    unsigned char der[4096];
    size_t derlen = rsa_serialize_private_der(priv, der, sizeof(der));
    char *pem = pem_encode("RSA PRIVATE KEY", der, derlen);
    FILE *f = fopen(fname, "w");
    if (!f)
    {
        free(pem);
        return 0;
    }
    fputs(pem, f);
    fclose(f);
    free(pem);
    return 1;
}

__attr_nodiscard int rsa_load_private_pem(const char *fname, rsa_private_key *priv)
{
    FILE *f = fopen(fname, "r");
    if (!f)
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

// --- ASN.1 DER deserialization (minimal, only for keys) ---
static size_t asn1_parse_len(const unsigned char *der, size_t *off)
{
    size_t len = der[(*off)++];
    if (len & 0x80)
    {
        int n = len & 0x7F;
        len = 0;
        while (n--)
            len = (len << 8) | der[(*off)++];
    }
    return len;
}

static size_t asn1_parse_integer(mpz_t x, const unsigned char *der, size_t *off)
{
    if (der[*off] != 0x02)
        return 0;
    (*off)++;
    size_t ilen = asn1_parse_len(der, off);
    mpz_import(x, ilen, 1, 1, 1, 0, der + *off);
    (*off) += ilen;
    return ilen + 2; // tag + len + value
}

size_t rsa_deserialize_public_der(rsa_public_key *pub, const unsigned char *der, size_t len)
{
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

size_t rsa_deserialize_private_der(rsa_private_key *priv, const unsigned char *der, size_t len)
{
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

// X.509 (SubjectPublicKeyInfo) serialization/deserialization for public keys
static size_t encode_algorithm_identifier(unsigned char *out)
{
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

size_t rsa_serialize_public_x509_der(const rsa_public_key *pub, unsigned char *der, size_t maxlen)
{
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

    if (der)
    {
        der[0] = 0x30; // SEQUENCE
        size_t lenlen = asn1_encode_len(der + 1, off);
        memcpy(der + 1 + lenlen, tmp, off);
        return 1 + lenlen + off;
    }
    size_t lenlen = asn1_encode_len(NULL, off);
    return 1 + lenlen + off;
}

size_t rsa_serialize_private_pkcs8_der(const rsa_private_key *priv, unsigned char *der, size_t maxlen)
{
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

    if (der)
    {
        der[0] = 0x30;
        size_t lenlen = asn1_encode_len(der + 1, off);
        memcpy(der + 1 + lenlen, tmp, off);
        return 1 + lenlen + off;
    }
    size_t lenlen = asn1_encode_len(NULL, off);
    return 1 + lenlen + off;
}

__attr_nodiscard int rsa_save_public_x509_pem(const char *fname, const rsa_public_key *pub)
{
    unsigned char der[2048];
    size_t derlen = rsa_serialize_public_x509_der(pub, der, sizeof(der));
    char *pem = pem_encode("PUBLIC KEY", der, derlen);
    FILE *f = fopen(fname, "w");
    if (!f)
    {
        free(pem);
        return 0;
    }
    fputs(pem, f);
    fclose(f);
    free(pem);
    return 1;
}

__attr_nodiscard int rsa_load_public_x509_pem(const char *fname, rsa_public_key *pub)
{
    FILE *f = fopen(fname, "r");
    if (!f)
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

__attr_nodiscard int rsa_save_private_pkcs8_pem(const char *fname, const rsa_private_key *priv)
{
    unsigned char der[4096];
    size_t derlen = rsa_serialize_private_pkcs8_der(priv, der, sizeof(der));
    char *pem = pem_encode("PRIVATE KEY", der, derlen);
    FILE *f = fopen(fname, "w");
    if (!f)
    {
        free(pem);
        return 0;
    }
    fputs(pem, f);
    fclose(f);
    free(pem);
    return 1;
}

__attr_nodiscard int rsa_load_private_pkcs8_pem(const char *fname, rsa_private_key *priv)
{
    FILE *f = fopen(fname, "r");
    if (!f)
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

size_t rsa_deserialize_public_x509_der(rsa_public_key *pub, const unsigned char *der, size_t len)
{
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

size_t rsa_deserialize_private_pkcs8_der(rsa_private_key *priv, const unsigned char *der, size_t len)
{
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

// File encryption/decryption
__attr_nodiscard int rsa_encrypt_file(const char *infile, const char *outfile, const rsa_public_key *pub)
{
    FILE *fin = fopen(infile, "rb");
    FILE *fout = fopen(outfile, "wb");
    if (!fin || !fout)
    {
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
    while ((read = fread(inbuf, 1, nbytes, fin)) > 0)
    {
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

__attr_nodiscard int rsa_decrypt_file(const char *infile, const char *outfile, const rsa_private_key *priv)
{
    FILE *fin = fopen(infile, "rb");
    FILE *fout = fopen(outfile, "wb");
    if (!fin || !fout)
    {
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
    while (fread(&clen, sizeof(size_t), 1, fin) == 1)
    {
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
__attr_nodiscard int save_file_hex(const char* fname, const unsigned char* buf, size_t len) {
    FILE* f = fopen(fname, "w");
    if (!f) return 0;
    for (size_t i = 0; i < len; ++i)
        fprintf(f, "%02x", buf[i]);
    fclose(f);
    return 1;
}

__attr_nodiscard int save_file_base64(const char* fname, const unsigned char* buf, size_t len) {
    FILE* f = fopen(fname, "w");
    if (!f) return 0;
    size_t i;
    for (i = 0; i + 2 < len; i += 3) {
        unsigned val = (buf[i] << 16) | (buf[i+1] << 8) | buf[i+2];
        fputc(b64tab[(val >> 18) & 0x3F], f);
        fputc(b64tab[(val >> 12) & 0x3F], f);
        fputc(b64tab[(val >> 6) & 0x3F], f);
        fputc(b64tab[val & 0x3F], f);
    }
    if (i < len) {
        unsigned val = buf[i] << 16;
        int pad = 0;
        if (i + 1 < len) {
            val |= buf[i+1] << 8;
        } else {
            pad = 2;
        }
        if (i + 2 < len) {
            val |= buf[i+2];
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

__attr_nodiscard int save_file_ascii(const char* fname, const unsigned char* buf, size_t len) {
    FILE* f = fopen(fname, "w");
    if (!f) return 0;
    for (size_t i = 0; i < len; ++i)
        fputc(isprint(buf[i]) ? buf[i] : '.', f);
    fclose(f);
    return 1;
}
