#ifndef RSA_MINIMAL_C_H
#define RSA_MINIMAL_C_H

#include <gmp.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// --- Key Structures ---

typedef struct {
    mpz_t n, e;
} rsa_public_key;

typedef struct {
    mpz_t n, e, d;
} rsa_private_key;

typedef struct {
    rsa_public_key pub;
    rsa_private_key priv;
} rsa_keypair;

// --- Key Init/Clear ---

static void rsa_init_public_key(rsa_public_key* key) {
    mpz_init(key->n);
    mpz_init(key->e);
}
static void rsa_clear_public_key(rsa_public_key* key) {
    mpz_clear(key->n);
    mpz_clear(key->e);
}
static void rsa_init_private_key(rsa_private_key* key) {
    mpz_init(key->n);
    mpz_init(key->e);
    mpz_init(key->d);
}
static void rsa_clear_private_key(rsa_private_key* key) {
    mpz_clear(key->n);
    mpz_clear(key->e);
    mpz_clear(key->d);
}
static void rsa_init_keypair(rsa_keypair* kp) {
    rsa_init_public_key(&kp->pub);
    rsa_init_private_key(&kp->priv);
}
static void rsa_clear_keypair(rsa_keypair* kp) {
    rsa_clear_public_key(&kp->pub);
    rsa_clear_private_key(&kp->priv);
}

// --- Key Generation ---

static void rsa_random_prime(mpz_t out, int bits, gmp_randstate_t rng) {
    while (1) {
        mpz_urandomb(out, rng, bits);
        mpz_setbit(out, bits - 1);
        mpz_setbit(out, 0);
        mpz_nextprime(out, out);
        if (mpz_probab_prime_p(out, 25)) break;
    }
}

static int rsa_generate_keys(rsa_keypair* keys, int bits) {
    gmp_randstate_t rng;
    gmp_randinit_mt(rng);
    gmp_randseed_ui(rng, (unsigned long)time(NULL));

    mpz_t p, q, phi, gcd, tmp;
    mpz_inits(p, q, phi, gcd, tmp, NULL);

    // Generate two distinct primes
    do {
        rsa_random_prime(p, bits / 2, rng);
        rsa_random_prime(q, bits / 2, rng);
    } while (mpz_cmp(p, q) == 0);

    mpz_mul(keys->pub.n, p, q);
    mpz_set(keys->priv.n, keys->pub.n);

    mpz_sub_ui(tmp, p, 1);
    mpz_sub_ui(phi, q, 1);
    mpz_mul(phi, phi, tmp);

    mpz_set_ui(keys->pub.e, 65537);
    mpz_set(keys->priv.e, keys->pub.e);

    mpz_gcd(gcd, keys->pub.e, phi);
    if (mpz_cmp_ui(gcd, 1) != 0) { goto fail; }
    if (mpz_invert(keys->priv.d, keys->pub.e, phi) == 0) { goto fail; }

    mpz_clears(p, q, phi, gcd, tmp, NULL);
    gmp_randclear(rng);
    return 0;
fail:
    mpz_clears(p, q, phi, gcd, tmp, NULL);
    gmp_randclear(rng);
    return -1;
}

// --- Internal Helpers ---

static size_t rsa_modulus_bytes(const mpz_t n) {
    return (mpz_sizeinbase(n, 2) + 7) / 8;
}
static void rsa_mpz_to_bytes(const mpz_t val, uint8_t* buf, size_t sz) {
    memset(buf, 0, sz);
    size_t written;
    mpz_export(buf + (sz - ((mpz_sizeinbase(val, 2) + 7) / 8)), &written, 1, 1, 1, 0, val);
}
static void rsa_bytes_to_mpz(mpz_t out, const uint8_t* buf, size_t sz) {
    mpz_import(out, sz, 1, 1, 1, 0, buf);
}

// --- Encryption/Decryption ---

static int rsa_encrypt(const rsa_public_key* pub, const uint8_t* msg, size_t msglen, uint8_t* out, size_t* outlen) {
    size_t block_bytes = rsa_modulus_bytes(pub->n);
    size_t written = 0;
    mpz_t m, ciph;
    mpz_init(m); mpz_init(ciph);
    for (size_t i = 0; i < msglen; ++i) {
        mpz_set_ui(m, msg[i]);
        mpz_powm(ciph, m, pub->e, pub->n);
        if (written + block_bytes > *outlen) { mpz_clear(m); mpz_clear(ciph); return -1; }
        rsa_mpz_to_bytes(ciph, out + written, block_bytes);
        written += block_bytes;
    }
    mpz_clear(m); mpz_clear(ciph);
    *outlen = written;
    return 0;
}

static int rsa_decrypt(const rsa_private_key* priv, const uint8_t* in, size_t inlen, uint8_t* out, size_t* outlen) {
    size_t block_bytes = rsa_modulus_bytes(priv->n);
    if (inlen % block_bytes != 0) return -1;
    size_t blocks = inlen / block_bytes, written = 0;
    mpz_t ciph, m;
    mpz_init(ciph); mpz_init(m);
    for (size_t i = 0; i < blocks; ++i) {
        rsa_bytes_to_mpz(ciph, in + i*block_bytes, block_bytes);
        mpz_powm(m, ciph, priv->d, priv->n);
        if (written + 1 > *outlen) { mpz_clear(ciph); mpz_clear(m); return -1; }
        out[written++] = (uint8_t)mpz_get_ui(m);
    }
    mpz_clear(ciph); mpz_clear(m);
    *outlen = written;
    return 0;
}

// --- File Encryption/Decryption ---

static int rsa_encrypt_file(const char* in_path, const char* out_path, const rsa_public_key* pub) {
    FILE* in = fopen(in_path, "rb");
    FILE* out = fopen(out_path, "wb");
    if (!in || !out) { if (in) fclose(in); if (out) fclose(out); return -1; }
    size_t block_bytes = rsa_modulus_bytes(pub->n);
    uint8_t inbuf[1024], outbuf[1024 * 8];
    size_t n, outlen;
    int ret = 0;
    while ((n = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        outlen = sizeof(outbuf);
        if (rsa_encrypt(pub, inbuf, n, outbuf, &outlen) != 0) { ret = -1; break; }
        if (fwrite(outbuf, 1, outlen, out) != outlen) { ret = -1; break; }
    }
    fclose(in); fclose(out);
    return ret;
}
static int rsa_decrypt_file(const char* in_path, const char* out_path, const rsa_private_key* priv) {
    FILE* in = fopen(in_path, "rb");
    FILE* out = fopen(out_path, "wb");
    if (!in || !out) { if (in) fclose(in); if (out) fclose(out); return -1; }
    size_t block_bytes = rsa_modulus_bytes(priv->n);
    uint8_t inbuf[1024 * 8], outbuf[1024];
    size_t n, outlen;
    int ret = 0;
    while ((n = fread(inbuf, 1, block_bytes, in)) == block_bytes) {
        outlen = sizeof(outbuf);
        if (rsa_decrypt(priv, inbuf, block_bytes, outbuf, &outlen) != 0) { ret = -1; break; }
        if (fwrite(outbuf, 1, outlen, out) != outlen) { ret = -1; break; }
    }
    fclose(in); fclose(out);
    return ret;
}

// --- Hex Utility ---

static void rsa_hex_encode(const uint8_t* data, size_t len, char* out, size_t out_sz) {
    static const char* hex = "0123456789abcdef";
    if (out_sz < len * 2 + 1) return;
    for (size_t i = 0; i < len; ++i) {
        out[2*i] = hex[(data[i] >> 4) & 0xF];
        out[2*i+1] = hex[data[i] & 0xF];
    }
    out[2*len] = 0;
}

#endif // RSA_MINIMAL_C_H
