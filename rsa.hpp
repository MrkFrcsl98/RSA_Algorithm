#pragma once
#include <gmpxx.h>
#include <vector>
#include <string>
#include <random>
#include <ctime>
#include <stdexcept>
#include <sstream>
#include <iostream>
#include <iomanip>

namespace RSA_Cipher
{

// Helper: mpz_class <-> std::vector<uint8_t>
inline std::vector<uint8_t> mpz_to_bytes(const mpz_class &value) {
    size_t count = (mpz_sizeinbase(value.get_mpz_t(), 2) + 7) / 8;
    std::vector<uint8_t> bytes(count ? count : 1, 0);
    mpz_export(bytes.data(), &count, 1, 1, 1, 0, value.get_mpz_t());
    if (bytes.empty()) bytes.push_back(0);
    // Remove leading zeros
    while(bytes.size() > 1 && bytes[0] == 0)
        bytes.erase(bytes.begin());
    return bytes;
}
inline mpz_class bytes_to_mpz(const std::vector<uint8_t> &bytes) {
    mpz_class value;
    mpz_import(value.get_mpz_t(), bytes.size(), 1, 1, 1, 0, bytes.data());
    return value;
}

// PEM/DER logic
namespace detail
{
inline std::vector<uint8_t> encode_asn1_integer(const std::vector<uint8_t> &value)
{
    std::vector<uint8_t> val = value;
    if (!val.empty() && (val[0] & 0x80))
        val.insert(val.begin(), 0x00);
    std::vector<uint8_t> out = {0x02};
    if (val.size() < 128)
        out.push_back(static_cast<uint8_t>(val.size()));
    else
    {
        size_t len = val.size();
        std::vector<uint8_t> len_bytes;
        while (len)
        {
            len_bytes.insert(len_bytes.begin(), len & 0xFF);
            len >>= 8;
        }
        out.push_back(0x80 | len_bytes.size());
        out.insert(out.end(), len_bytes.begin(), len_bytes.end());
    }
    out.insert(out.end(), val.begin(), val.end());
    return out;
}
inline std::vector<uint8_t> encode_asn1_sequence(const std::vector<std::vector<uint8_t>> &elements)
{
    std::vector<uint8_t> content;
    for (const auto &e : elements)
        content.insert(content.end(), e.begin(), e.end());
    std::vector<uint8_t> out = {0x30};
    if (content.size() < 128)
        out.push_back(static_cast<uint8_t>(content.size()));
    else
    {
        size_t len = content.size();
        std::vector<uint8_t> len_bytes;
        while (len)
        {
            len_bytes.insert(len_bytes.begin(), len & 0xFF);
            len >>= 8;
        }
        out.push_back(0x80 | len_bytes.size());
        out.insert(out.end(), len_bytes.begin(), len_bytes.end());
    }
    out.insert(out.end(), content.begin(), content.end());
    return out;
}
inline std::string base64_encode(const std::vector<uint8_t> &data)
{
    static const char *base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, valb = -6;
    for (uint8_t c : data)
    {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0)
        {
            out.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4)
        out.push_back('=');
    return out;
}
inline std::string wrap_pem(const std::string &b64, const std::string &type)
{
    std::string out = "-----BEGIN " + type + "-----\n";
    for (size_t i = 0; i < b64.size(); i += 64)
        out += b64.substr(i, 64) + "\n";
    out += "-----END " + type + "-----\n";
    return out;
}
} // namespace detail

// Random prime generation using GMP
inline mpz_class random_prime(int bits, gmp_randclass &rng) {
    mpz_class p;
    while (true) {
        p = rng.get_z_bits(bits);
        mpz_setbit(p.get_mpz_t(), bits - 1); // ensure top bit set
        mpz_setbit(p.get_mpz_t(), 0);        // ensure odd
        if (mpz_probab_prime_p(p.get_mpz_t(), 25)) // 25 rounds for good confidence
            return p;
    }
}

// Modular inverse using GMP (already exists as mpz_invert)
inline mpz_class modinv(const mpz_class &a, const mpz_class &m) {
    mpz_class inv;
    if (mpz_invert(inv.get_mpz_t(), a.get_mpz_t(), m.get_mpz_t()) == 0)
        throw std::runtime_error("No modular inverse exists");
    return inv;
}

// Modular exponentiation using GMP (already exists as mpz_powm)
inline mpz_class powm(const mpz_class &base, const mpz_class &exp, const mpz_class &mod) {
    mpz_class result;
    mpz_powm(result.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
    return result;
}

// ====== RSA Class ======
class RSA
{
public:
    mpz_class n, e, d, p, q, dp, dq, qinv;

    RSA(int bits = 2048)
    {
        // Use the current time as the seed for randomness
        gmp_randclass rng(gmp_randinit_mt);
        rng.seed(static_cast<unsigned long>(std::time(nullptr)));

        p = random_prime(bits / 2, rng);
        do { q = random_prime(bits / 2, rng); } while (q == p);
        n = p * q;
        mpz_class phi = (p - 1) * (q - 1);
        e = 65537;
        d = modinv(e, phi);
        dp = d % (p - 1);
        dq = d % (q - 1);
        qinv = modinv(q, p);
    }

    std::vector<mpz_class> encrypt(const std::vector<uint8_t> &message) const
    {
        std::vector<mpz_class> ciphertexts;
        for (uint8_t c : message)
            ciphertexts.push_back(powm(c, e, n));
        return ciphertexts;
    }

    std::vector<uint8_t> decrypt(const std::vector<mpz_class> &ciphertexts) const
    {
        std::vector<uint8_t> message;
        for (const auto &c : ciphertexts) {
            mpz_class m = powm(c, d, n);
            message.push_back(static_cast<uint8_t>(m.get_ui() & 0xFF)); // Only lowest byte
        }
        return message;
    }

    std::vector<uint8_t> get_public_key_der() const
    {
        return detail::encode_asn1_sequence({
            detail::encode_asn1_integer(mpz_to_bytes(n)),
            detail::encode_asn1_integer(mpz_to_bytes(e))
        });
    }
    std::string get_public_key_pem() const
    {
        return detail::wrap_pem(detail::base64_encode(get_public_key_der()), "RSA PUBLIC KEY");
    }
    std::vector<uint8_t> get_private_key_der() const
    {
        return detail::encode_asn1_sequence({
            detail::encode_asn1_integer({0x00}),
            detail::encode_asn1_integer(mpz_to_bytes(n)),
            detail::encode_asn1_integer(mpz_to_bytes(e)),
            detail::encode_asn1_integer(mpz_to_bytes(d)),
            detail::encode_asn1_integer(mpz_to_bytes(p)),
            detail::encode_asn1_integer(mpz_to_bytes(q)),
            detail::encode_asn1_integer(mpz_to_bytes(dp)),
            detail::encode_asn1_integer(mpz_to_bytes(dq)),
            detail::encode_asn1_integer(mpz_to_bytes(qinv))
        });
    }
    std::string get_private_key_pem() const
    {
        return detail::wrap_pem(detail::base64_encode(get_private_key_der()), "RSA PRIVATE KEY");
    }
    void print_keys() const
    {
        std::cout << "Public key (e, n):\n" << e.get_str() << "\n" << n.get_str() << "\n";
        std::cout << "Private key (d):\n" << d.get_str() << "\n";
    }
};

} // namespace RSA_Cipher
