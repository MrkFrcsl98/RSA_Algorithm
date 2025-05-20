#pragma once

#include <cstdint>
#include <random>
#include <stdexcept>
#include <iostream>
#include <string>
#include <vector>
#include <limits>
#include <algorithm>

namespace RSA_Cipher {

class FastRand {
public:
    FastRand() : gen_(std::random_device{}()) {}

    uint64_t get(uint64_t min, uint64_t max) {
        std::uniform_int_distribution<uint64_t> dist(min, max);
        return dist(gen_);
    }

private:
    std::mt19937_64 gen_;
};

class RSA {
public:
    RSA(uint16_t bitlen = 32) { // Default: demonstration only
        if (bitlen < 8) throw std::invalid_argument("Bit length too small.");
        generate_keys(bitlen);
    }

    std::vector<uint64_t> encrypt(const std::string& message) const {
        std::vector<uint64_t> ciphertext;
        ciphertext.reserve(message.size());
        for (unsigned char c : message)
            ciphertext.push_back(mod_exp(c, e_, n_));
        return ciphertext;
    }

    std::string decrypt(const std::vector<uint64_t>& ciphertext) const {
        std::string message;
        message.reserve(ciphertext.size());
        for (uint64_t c : ciphertext) {
            uint64_t m = mod_exp(c, d_, n_);
            if (m > 255) throw std::runtime_error("Decrypted value out of char range.");
            message += static_cast<char>(m);
        }
        return message;
    }

    void print_keys() const {
        std::cout << "Public Key:  (e = " << e_ << ", n = " << n_ << ")\n";
        std::cout << "Private Key: (d = " << d_ << ", n = " << n_ << ")\n";
    }

    uint64_t get_public_key_e() const { return e_; }
    uint64_t get_public_key_n() const { return n_; }
    uint64_t get_private_key_d() const { return d_; }

private:
    uint64_t e_{0}, d_{0}, n_{0};

    static uint64_t mod_exp(uint64_t base, uint64_t exp, uint64_t mod) {
        uint64_t result = 1;
        base %= mod;
        while (exp) {
            if (exp & 1) result = (result * base) % mod;
            base = (base * base) % mod;
            exp >>= 1;
        }
        return result;
    }

    static uint64_t gcd(uint64_t a, uint64_t b) {
        while (b) { uint64_t t = b; b = a % b; a = t; }
        return a;
    }

    // Miller-Rabin Primality Test (probabilistic, much faster than trial division)
    static bool is_prime(uint64_t n, int rounds = 6) {
        if (n < 2 || n % 2 == 0) return n == 2;
        uint64_t d = n - 1, s = 0;
        while (d % 2 == 0) { d >>= 1; ++s; }
        FastRand rnd;
        for (int i = 0; i < rounds; ++i) {
            uint64_t a = rnd.get(2, n - 2);
            uint64_t x = mod_exp(a, d, n);
            if (x == 1 || x == n - 1)
                continue;
            bool witness = false;
            for (uint64_t r = 1; r < s; ++r) {
                x = mod_exp(x, 2, n);
                if (x == n - 1) { witness = true; break; }
            }
            if (!witness) return false;
        }
        return true;
    }

    // Extended Euclidean Algorithm for modular inverse
    static uint64_t modinv(uint64_t a, uint64_t m) {
        int64_t m0 = m, x0 = 0, x1 = 1;
        while (a > 1) {
            int64_t q = a / m, t = m;
            m = a % m; a = t;
            t = x0; x0 = x1 - q * x0; x1 = t;
        }
        return x1 < 0 ? x1 + m0 : x1;
    }

    static uint64_t gen_prime(uint16_t bitlen) {
        FastRand rnd;
        uint64_t min = 1ULL << (bitlen - 1), max = (1ULL << bitlen) - 1;
        uint64_t p;
        do {
            p = rnd.get(min, max) | 1ULL; // Force odd
        } while (!is_prime(p));
        return p;
    }

    void generate_keys(uint16_t bitlen) {
        uint16_t half = bitlen / 2;
        uint64_t p = gen_prime(half), q;
        do { q = gen_prime(half); } while (q == p);
        n_ = p * q;
        uint64_t phi = (p - 1) * (q - 1);

        // Common public exponent, or random odd coprime to phi
        const uint64_t candidates[] = {65537, 17, 3};
        e_ = 0;
        for (uint64_t cand : candidates)
            if (cand < phi && gcd(cand, phi) == 1) { e_ = cand; break; }
        FastRand rnd;
        while (!e_) {
            uint64_t e_try = rnd.get(3, phi - 1) | 1ULL;
            if (gcd(e_try, phi) == 1) { e_ = e_try; break; }
        }

        d_ = modinv(e_, phi);
        if (!d_) throw std::runtime_error("Failed to compute modular inverse.");
    }
};

} // namespace RSA_Cipher
