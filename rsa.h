// rsa_minimal_capi.hpp
#pragma once
#include <gmp.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>

namespace RSA {

enum class KeySize {
    Bits1024 = 1024,
    Bits2048 = 2048,
    Bits3072 = 3072,
    Bits4096 = 4096
};

// -------- Key Structures (C API) --------
struct PublicKey {
    mpz_t n, e;
    PublicKey() { mpz_init(n); mpz_init(e); }
    ~PublicKey() { mpz_clear(n); mpz_clear(e); }
    // Copy/assign omitted for brevity (easy to add if needed)
};

struct PrivateKey {
    mpz_t n, e, d;
    PrivateKey() { mpz_init(n); mpz_init(e); mpz_init(d); }
    ~PrivateKey() { mpz_clear(n); mpz_clear(e); mpz_clear(d); }
};

struct KeyPair {
    PublicKey public_key;
    PrivateKey private_key;
};

// -------- Key Generation --------
class KeyGenerator {
public:
    static int generate(KeyPair& kp, KeySize bits = KeySize::Bits2048) {
        int num_bits = static_cast<int>(bits);
        gmp_randstate_t rng;
        gmp_randinit_mt(rng);
        gmp_randseed_ui(rng, (unsigned long)std::time(nullptr));

        mpz_t p, q, phi, gcd, tmp;
        mpz_inits(p, q, phi, gcd, tmp, nullptr);

        // Generate two distinct primes
        do {
            random_prime(p, num_bits / 2, rng);
            random_prime(q, num_bits / 2, rng);
        } while (mpz_cmp(p, q) == 0);

        mpz_mul(kp.public_key.n, p, q);
        mpz_set(kp.private_key.n, kp.public_key.n);

        // phi = (p-1)*(q-1)
        mpz_sub_ui(tmp, p, 1);
        mpz_sub_ui(phi, q, 1);
        mpz_mul(phi, phi, tmp);

        mpz_set_ui(kp.public_key.e, 65537);
        mpz_set(kp.private_key.e, kp.public_key.e);

        mpz_gcd(gcd, kp.public_key.e, phi);
        if (mpz_cmp_ui(gcd, 1) != 0) { goto fail; }
        if (mpz_invert(kp.private_key.d, kp.public_key.e, phi) == 0) { goto fail; }

        mpz_clears(p, q, phi, gcd, tmp, nullptr);
        gmp_randclear(rng);
        return 0;
    fail:
        mpz_clears(p, q, phi, gcd, tmp, nullptr);
        gmp_randclear(rng);
        return -1;
    }
private:
    static void random_prime(mpz_t out, int bits, gmp_randstate_t rng) {
        while (1) {
            mpz_urandomb(out, rng, bits);
            mpz_setbit(out, bits - 1); // ensure high bit set
            mpz_setbit(out, 0);        // ensure odd
            mpz_nextprime(out, out);
            if (mpz_probab_prime_p(out, 25)) break;
        }
    }
};

// -------- Internal Helpers (C API) --------
namespace Internal {
    inline size_t modulus_bytes(const mpz_t n) {
        return (mpz_sizeinbase(n, 2) + 7) / 8;
    }
    inline void mpz_to_bytes(const mpz_t val, uint8_t* buf, size_t sz) {
        std::memset(buf, 0, sz);
        size_t written;
        mpz_export(buf + (sz - ((mpz_sizeinbase(val, 2) + 7) / 8)), &written, 1, 1, 1, 0, val);
    }
    inline void bytes_to_mpz(mpz_t out, const uint8_t* buf, size_t sz) {
        mpz_import(out, sz, 1, 1, 1, 0, buf);
    }
}

// -------- Parameter Structs --------
struct EncryptParams {
    const char* message;         // Null-terminated string for text, or nullptr if not used
    const uint8_t* message_data; // Binary data, or nullptr if not used
    size_t message_len;          // Used if message_data != nullptr
    const char* input_file;      // Or nullptr
    const char* output_file;     // Or nullptr
    const PublicKey* pub_key;    // Required
};

struct DecryptParams {
    const uint8_t* encrypted_data; // Or nullptr
    size_t encrypted_len;          // Used if encrypted_data != nullptr
    const char* input_file;        // Or nullptr
    const char* output_file;       // Or nullptr
    const PrivateKey* priv_key;    // Required
};

// -------- Message Encryption/Decryption (C API) --------
namespace Message {
    inline int Encrypt(const char* message, const PublicKey& pub, uint8_t* outbuf, size_t outbuf_sz) {
        size_t block_bytes = Internal::modulus_bytes(pub.n);
        size_t written = 0;
        mpz_t m, ciph;
        mpz_init(m); mpz_init(ciph);
        for (size_t i = 0; message[i]; ++i) {
            mpz_set_ui(m, (uint8_t)message[i]);
            mpz_powm(ciph, m, pub.e, pub.n);
            if (written + block_bytes > outbuf_sz) { mpz_clear(m); mpz_clear(ciph); return -1; }
            Internal::mpz_to_bytes(ciph, outbuf + written, block_bytes);
            written += block_bytes;
        }
        mpz_clear(m); mpz_clear(ciph);
        return (int)written;
    }
    inline int Encrypt(const uint8_t* data, size_t len, const PublicKey& pub, uint8_t* outbuf, size_t outbuf_sz) {
        size_t block_bytes = Internal::modulus_bytes(pub.n);
        size_t written = 0;
        mpz_t m, ciph;
        mpz_init(m); mpz_init(ciph);
        for (size_t i = 0; i < len; ++i) {
            mpz_set_ui(m, data[i]);
            mpz_powm(ciph, m, pub.e, pub.n);
            if (written + block_bytes > outbuf_sz) { mpz_clear(m); mpz_clear(ciph); return -1; }
            Internal::mpz_to_bytes(ciph, outbuf + written, block_bytes);
            written += block_bytes;
        }
        mpz_clear(m); mpz_clear(ciph);
        return (int)written;
    }
    inline int Decrypt(const uint8_t* enc, size_t enclen, const PrivateKey& priv, uint8_t* outbuf, size_t outbuf_sz) {
        size_t block_bytes = Internal::modulus_bytes(priv.n);
        if (enclen % block_bytes != 0) return -1;
        size_t blocks = enclen / block_bytes, written = 0;
        mpz_t ciph, m;
        mpz_init(ciph); mpz_init(m);
        for (size_t i = 0; i < blocks; ++i) {
            Internal::bytes_to_mpz(ciph, enc + i*block_bytes, block_bytes);
            mpz_powm(m, ciph, priv.d, priv.n);
            if (written + 1 > outbuf_sz) { mpz_clear(ciph); mpz_clear(m); return -1; }
            outbuf[written++] = (uint8_t)mpz_get_ui(m);
        }
        mpz_clear(ciph); mpz_clear(m);
        return (int)written;
    }
    inline int Encrypt(const EncryptParams& params, uint8_t* outbuf, size_t outbuf_sz) {
        if (!params.pub_key) return -1;
        if (params.message)
            return Encrypt(params.message, *params.pub_key, outbuf, outbuf_sz);
        if (params.message_data && params.message_len)
            return Encrypt(params.message_data, params.message_len, *params.pub_key, outbuf, outbuf_sz);
        return -1;
    }
    inline int Decrypt(const DecryptParams& params, uint8_t* outbuf, size_t outbuf_sz) {
        if (!params.priv_key) return -1;
        if (params.encrypted_data && params.encrypted_len)
            return Decrypt(params.encrypted_data, params.encrypted_len, *params.priv_key, outbuf, outbuf_sz);
        return -1;
    }
}

// -------- File Encryption/Decryption (C API) --------
namespace File {
    inline int Encrypt(const char* input_file, const char* output_file, const PublicKey& pub) {
        FILE* in = std::fopen(input_file, "rb");
        FILE* out = std::fopen(output_file, "wb");
        if (!in || !out) { if (in) std::fclose(in); if (out) std::fclose(out); return -1; }
        size_t block_bytes = Internal::modulus_bytes(pub.n);
        uint8_t inbuf[1024], outbuf[1024 * 8];
        size_t n;
        int ret = 0;
        while ((n = std::fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
            int written = Message::Encrypt(inbuf, n, pub, outbuf, sizeof(outbuf));
            if (written < 0) { ret = -1; break; }
            if (std::fwrite(outbuf, 1, written, out) != (size_t)written) { ret = -1; break; }
        }
        std::fclose(in); std::fclose(out);
        return ret;
    }
    inline int Decrypt(const char* input_file, const char* output_file, const PrivateKey& priv) {
        FILE* in = std::fopen(input_file, "rb");
        FILE* out = std::fopen(output_file, "wb");
        if (!in || !out) { if (in) std::fclose(in); if (out) std::fclose(out); return -1; }
        size_t block_bytes = Internal::modulus_bytes(priv.n);
        uint8_t inbuf[1024 * 8], outbuf[1024];
        size_t n;
        int ret = 0;
        while ((n = std::fread(inbuf, 1, block_bytes, in)) == block_bytes) {
            int written = Message::Decrypt(inbuf, block_bytes, priv, outbuf, sizeof(outbuf));
            if (written < 0) { ret = -1; break; }
            if (std::fwrite(outbuf, 1, written, out) != (size_t)written) { ret = -1; break; }
        }
        std::fclose(in); std::fclose(out);
        return ret;
    }
    inline int Encrypt(const EncryptParams& params) {
        if (!params.pub_key || !params.input_file || !params.output_file) return -1;
        return Encrypt(params.input_file, params.output_file, *params.pub_key);
    }
    inline int Decrypt(const DecryptParams& params) {
        if (!params.priv_key || !params.input_file || !params.output_file) return -1;
        return Decrypt(params.input_file, params.output_file, *params.priv_key);
    }
}

// -------- Utility: Hex encoding for display --------
inline void hex_encode(const uint8_t* data, size_t len, char* out, size_t out_sz) {
    static const char* hex = "0123456789abcdef";
    if (out_sz < len * 2 + 1) return;
    for (size_t i = 0; i < len; ++i) {
        out[2*i] = hex[(data[i] >> 4) & 0xF];
        out[2*i+1] = hex[data[i] & 0xF];
    }
    out[2*len] = 0;
}

} // namespace RSA
