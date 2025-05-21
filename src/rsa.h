#ifndef RSA_ALGORITHM_C_H
#define RSA_ALGORITHM_C_H

#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

// ===== ENUMS =====
typedef enum {
    KEYSIZE_1024 = 1024,
    KEYSIZE_2048 = 2048,
    KEYSIZE_3072 = 3072,
    KEYSIZE_4096 = 4096
} KeySize;

typedef enum {
    OUTPUT_BINARY,
    OUTPUT_HEX,
    OUTPUT_BASE64
} OutputFormat;

// ===== STRUCTS =====

typedef struct {
    mpz_t n, e;
} RSAPublicKey;

typedef struct {
    mpz_t n, e, d, p, q, dP, dQ, qInv;
} RSAPrivateKey;

typedef struct {
    RSAPublicKey public_key;
    RSAPrivateKey private_key;
} RSAKeyPair;


// ========== Utility Memory ==========

#define SAFE_MALLOC(size) ({ void* p = malloc(size); if (!p) { fprintf(stderr, "Out of memory\n"); exit(1); } p; })

// ========== ASN.1 DER ==========

static void encode_integer(const mpz_t x, uint8_t **out, size_t *outlen) {
    size_t count = (mpz_sizeinbase(x, 2) + 7) / 8;
    if (count == 0) count = 1;
    uint8_t *bytes = (uint8_t*)SAFE_MALLOC(count + 1);
    mpz_export(bytes, &count, 1, 1, 1, 0, x);
    if (bytes[0] & 0x80) {
        memmove(bytes + 1, bytes, count);
        bytes[0] = 0x00;
        count += 1;
    }
    *outlen = 2 + count;
    *out = (uint8_t*)SAFE_MALLOC(*outlen);
    (*out)[0] = 0x02;
    (*out)[1] = (uint8_t)count;
    memcpy(*out + 2, bytes, count);
    free(bytes);
}

static void encode_sequence(uint8_t **fields, size_t *field_lens, size_t num_fields, uint8_t **out, size_t *outlen) {
    size_t seqlen = 0;
    for (size_t i = 0; i < num_fields; ++i) seqlen += field_lens[i];
    *outlen = 2 + seqlen;
    *out = (uint8_t*)SAFE_MALLOC(*outlen);
    (*out)[0] = 0x30;
    (*out)[1] = (uint8_t)seqlen;
    size_t offset = 2;
    for (size_t i = 0; i < num_fields; ++i) {
        memcpy(*out + offset, fields[i], field_lens[i]);
        offset += field_lens[i];
    }
}

// ========== BASE64 ENCODE/DECODE ==========

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char* base64_encode(const uint8_t* in, size_t inlen) {
    size_t outlen = 4 * ((inlen + 2) / 3);
    char* out = (char*)SAFE_MALLOC(outlen + 1);
    size_t i, j;
    for (i = 0, j = 0; i < inlen;) {
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

static uint8_t* base64_decode(const char* in, size_t *outlen) {
    int dtable[256] = {0};
    for (size_t i = 0; i < 64; i++) dtable[(uint8_t)b64_table[i]] = i + 1;
    size_t inlen = strlen(in), pad = 0, i, j;
    if (inlen >= 2 && in[inlen - 1] == '=') pad++;
    if (inlen >= 2 && in[inlen - 2] == '=') pad++;
    *outlen = (inlen*3)/4 - pad;
    uint8_t* out = (uint8_t*)SAFE_MALLOC(*outlen);
    uint32_t buf = 0;
    int k = 0;
    for (i = 0, j = 0; i < inlen;) {
        int val = 0;
        for (int n = 0; n < 4 && i < inlen; ) {
            char c = in[i++];
            if (dtable[(uint8_t)c]) {
                val = (val << 6) | (dtable[(uint8_t)c] - 1);
                n++;
            } else if (c == '=') {
                val <<= 6;
                n++;
            }
        }
        if (j < *outlen) out[j++] = (val >> 16) & 0xFF;
        if (j < *outlen) out[j++] = (val >> 8) & 0xFF;
        if (j < *outlen) out[j++] = val & 0xFF;
    }
    return out;
}

// PEM WRAP/UNWRAP
static char* pem_wrap(const char* base64, const char* type) {
    size_t typelen = strlen(type);
    size_t b64len = strlen(base64);
    size_t outlen = 32 + b64len + b64len/64*2 + typelen*2;
    char* out = (char*)SAFE_MALLOC(outlen);
    sprintf(out, "-----BEGIN %s-----\n", type);
    size_t offset = strlen(out);
    for (size_t i=0; i < b64len; i+=64) {
        strncat(out+offset, base64+i, 64);
        offset += (b64len-i > 64 ? 64 : b64len-i);
        out[offset++] = '\n';
        out[offset] = 0;
    }
    sprintf(out+offset, "-----END %s-----\n", type);
    return out;
}

static char* strip_pem(const char* pem) {
    const char* begin = strstr(pem, "-----BEGIN");
    if (!begin) return NULL;
    begin = strchr(begin, '\n');
    const char* end = strstr(pem, "-----END");
    if (!end) return NULL;
    size_t b64len = end - begin - 1;
    char* b64 = (char*)SAFE_MALLOC(b64len + 1);
    size_t k = 0;
    for (const char* p = begin+1; p < end; ++p)
        if (isalnum((unsigned char)*p) || *p == '+' || *p == '/' || *p == '=')
            b64[k++] = *p;
    b64[k] = 0;
    return b64;
}

// ========== HEX ENCODE/DECODE ==========

static char* bytes_to_hex(const uint8_t* data, size_t len) {
    char* out = (char*)SAFE_MALLOC(len*2+1);
    for (size_t i = 0; i < len; ++i) sprintf(out+2*i, "%02x", data[i]);
    out[len*2] = 0;
    return out;
}

static uint8_t* hex_to_bytes(const char* hex, size_t* outlen) {
    size_t len = strlen(hex) / 2;
    uint8_t* out = (uint8_t*)SAFE_MALLOC(len);
    for (size_t i = 0; i < len; ++i) {
        sscanf(hex + 2*i, "%2hhx", &out[i]);
    }
    *outlen = len;
    return out;
}

// ========== FILE IO ==========

static int file_exists(const char* filename) {
    FILE* f = fopen(filename, "rb");
    if (f) { fclose(f); return 1; }
    return 0;
}

static uint8_t* read_file(const char* filename, size_t *len) {
    FILE* f = fopen(filename, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long flen = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t* buf = (uint8_t*)SAFE_MALLOC(flen);
    fread(buf, 1, flen, f);
    fclose(f);
    *len = flen;
    return buf;
}

static int write_file(const char* filename, const uint8_t* data, size_t len) {
    FILE* f = fopen(filename, "wb");
    if (!f) return 0;
    fwrite(data, 1, len, f);
    fclose(f);
    return 1;
}

static int write_text(const char* filename, const char* text) {
    FILE* f = fopen(filename, "w");
    if (!f) return 0;
    fwrite(text, 1, strlen(text), f);
    fclose(f);
    return 1;
}

// ========== RANDOM PRIME, MODINV, POWM ==========

static void random_prime(mpz_t out, int bits, gmp_randstate_t rng) {
    while (1) {
        mpz_urandomb(out, rng, bits);
        mpz_setbit(out, bits-1);
        mpz_setbit(out, 0);
        if (mpz_probab_prime_p(out, 25)) return;
    }
}
static void modinv(mpz_t out, const mpz_t a, const mpz_t m) {
    if (!mpz_invert(out, a, m)) {
        fprintf(stderr, "No modular inverse\n");
        exit(1);
    }
}
static void powm(mpz_t out, const mpz_t base, const mpz_t exp, const mpz_t mod) {
    mpz_powm(out, base, exp, mod);
}

// ========== PKCS#1 v1.5 Padding ==========

static int pkcs1_pad(const uint8_t* block, size_t blocklen, uint8_t* padded, size_t mod_bytes) {
    if (blocklen > mod_bytes - 11) return 0;
    padded[0] = 0x00;
    padded[1] = 0x02;
    srand((unsigned)time(NULL));
    size_t pad_len = mod_bytes - 3 - blocklen;
    for (size_t i = 0; i < pad_len; ++i) {
        uint8_t r = 0;
        do { r = (uint8_t)((rand() % 255) + 1); } while (r == 0);
        padded[2 + i] = r;
    }
    padded[2 + pad_len] = 0x00;
    memcpy(padded + 3 + pad_len, block, blocklen);
    return 1;
}

static int pkcs1_unpad(const uint8_t* padded, size_t paddedlen, uint8_t* out, size_t* outlen) {
    if (paddedlen < 11 || padded[0] != 0x00 || padded[1] != 0x02) return 0;
    size_t idx = 2;
    while (idx < paddedlen && padded[idx] != 0x00) ++idx;
    if (idx == paddedlen || idx < 10) return 0;
    size_t msglen = paddedlen - (idx + 1);
    memcpy(out, padded + idx + 1, msglen);
    *outlen = msglen;
    return 1;
}

// ========== KEY INIT/CLEAR ==========

static void rsa_public_key_init(RSAPublicKey* key) {
    mpz_init(key->n);
    mpz_init(key->e);
}
static void rsa_private_key_init(RSAPrivateKey* key) {
    mpz_init(key->n); mpz_init(key->e); mpz_init(key->d);
    mpz_init(key->p); mpz_init(key->q); mpz_init(key->dP);
    mpz_init(key->dQ); mpz_init(key->qInv);
}
static void rsa_public_key_clear(RSAPublicKey* key) {
    mpz_clear(key->n); mpz_clear(key->e);
}
static void rsa_private_key_clear(RSAPrivateKey* key) {
    mpz_clear(key->n); mpz_clear(key->e); mpz_clear(key->d);
    mpz_clear(key->p); mpz_clear(key->q); mpz_clear(key->dP);
    mpz_clear(key->dQ); mpz_clear(key->qInv);
}

// ========== KEY GENERATION ==========

static void rsa_generate_keypair(RSAKeyPair* kp, KeySize bits) {
    gmp_randstate_t rng;
    gmp_randinit_mt(rng);
    gmp_randseed_ui(rng, (unsigned long)time(NULL));
    mpz_t p, q, phi, d, e, dP, dQ, qInv;
    mpz_inits(p, q, phi, d, e, dP, dQ, qInv, NULL);
    random_prime(p, bits/2, rng);
    do { random_prime(q, bits/2, rng); } while (!mpz_cmp(p, q));
    mpz_mul(kp->public_key.n, p, q);
    mpz_set_ui(e, 65537);
    mpz_set(kp->public_key.e, e);
    mpz_sub_ui(phi, p, 1); mpz_sub_ui(q, q, 1); mpz_mul(phi, phi, q);
    modinv(d, e, phi);
    mpz_set(kp->private_key.n, kp->public_key.n); mpz_set(kp->private_key.e, e); mpz_set(kp->private_key.d, d);
    mpz_set(kp->private_key.p, p); mpz_set(kp->private_key.q, q);
    mpz_mod(dP, d, p); mpz_mod(dQ, d, q); modinv(qInv, q, p);
    mpz_set(kp->private_key.dP, dP); mpz_set(kp->private_key.dQ, dQ); mpz_set(kp->private_key.qInv, qInv);
    mpz_clears(p, q, phi, d, e, dP, dQ, qInv, NULL);
    gmp_randclear(rng);
}

// ========== ENCRYPTION/DECRYPTION ==========

static int rsa_encrypt(const uint8_t* message, size_t mlen, const RSAPublicKey* pub, uint8_t* out, size_t* outlen) {
    size_t mod_bytes = (mpz_sizeinbase(pub->n, 2) + 7) / 8;
    uint8_t* block = (uint8_t*)SAFE_MALLOC(mod_bytes);
    if (!pkcs1_pad(message, mlen, block, mod_bytes)) return 0;
    mpz_t m, c;
    mpz_init(m); mpz_init(c);
    mpz_import(m, mod_bytes, 1, 1, 1, 0, block);
    if (mpz_cmp(m, pub->n) >= 0) { mpz_clear(m); mpz_clear(c); free(block); return 0; }
    powm(c, m, pub->e, pub->n);
    size_t clen = 0;
    mpz_export(out, &clen, 1, 1, 1, 0, c);
    *outlen = clen;
    mpz_clear(m); mpz_clear(c); free(block);
    return 1;
}

static int rsa_decrypt(const uint8_t* enc, size_t enclen, const RSAPrivateKey* priv, uint8_t* out, size_t* outlen) {
    size_t mod_bytes = (mpz_sizeinbase(priv->n, 2) + 7) / 8;
    mpz_t c, m;
    mpz_init(c); mpz_init(m);
    mpz_import(c, enclen, 1, 1, 1, 0, enc);
    powm(m, c, priv->d, priv->n);
    uint8_t* padded = (uint8_t*)SAFE_MALLOC(mod_bytes);
    size_t paddedlen = 0;
    mpz_export(padded, &paddedlen, 1, 1, 1, 0, m);
    if (paddedlen < mod_bytes) {
        memmove(padded + (mod_bytes - paddedlen), padded, paddedlen);
        memset(padded, 0, mod_bytes - paddedlen);
        paddedlen = mod_bytes;
    }
    int res = pkcs1_unpad(padded, paddedlen, out, outlen);
    free(padded);
    mpz_clear(c); mpz_clear(m);
    return res;
}

// ========== PEM/DER SERIALIZATION (PUBLIC KEY) ==========

static char* rsa_public_key_to_pem(const RSAPublicKey* pub) {
    uint8_t *en_n, *en_e, *seq;
    size_t len_n, len_e, len_seq;
    encode_integer(pub->n, &en_n, &len_n);
    encode_integer(pub->e, &en_e, &len_e);
    encode_sequence((uint8_t*[]){en_n, en_e}, (size_t[]){len_n, len_e}, 2, &seq, &len_seq);
    char* b64 = base64_encode(seq, len_seq);
    char* pem = pem_wrap(b64, "RSA PUBLIC KEY");
    free(en_n); free(en_e); free(seq); free(b64);
    return pem;
}
static char* rsa_private_key_to_pem(const RSAPrivateKey* priv) {
    uint8_t *en_vals[9], *seq;
    size_t lens[9], len_seq;
    mpz_t zero; mpz_init_set_ui(zero, 0);
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
    char* b64 = base64_encode(seq, len_seq);
    char* pem = pem_wrap(b64, "RSA PRIVATE KEY");
    for (int i=0; i<9; ++i) free(en_vals[i]);
    free(seq); free(b64); mpz_clear(zero);
    return pem;
}

// ========== FILE SAVE/LOAD PEM ==========

static int rsa_public_key_save_pem(const char* filename, const RSAPublicKey* pub) {
    char* pem = rsa_public_key_to_pem(pub);
    int r = write_text(filename, pem);
    free(pem);
    return r;
}
static int rsa_private_key_save_pem(const char* filename, const RSAPrivateKey* priv) {
    char* pem = rsa_private_key_to_pem(priv);
    int r = write_text(filename, pem);
    free(pem);
    return r;
}

// ========== You can add more helpers as needed for DER decode, etc ==========

#endif // RSA_ALGORITHM_C_H
