
#pragma once // header guard

#include <ctime>
#include <exception>
#include <iostream>
#include <string>
#include <type_traits>
#include <vector>

namespace RSA_Cipher
{
typedef unsigned long int __uint64_t;
typedef unsigned int __uint32_t;
typedef unsigned short int __uint16_t;
typedef unsigned char __uint8_t;
typedef const char *__ccharptr_t;
typedef char *__charptr_t;

class PRNG
{
  private:
    static constexpr __uint64_t N = 0x270;
    static constexpr __uint64_t M = 0x17B;
    static constexpr __uint64_t MATRIX_A = 0x9908b0dfUL;
    static constexpr __uint64_t UPPER_MASK = 0x80000000UL;
    static constexpr __uint64_t LOWER_MASK = 0x7fffffffUL;

    __uint64_t state;
    __uint64_t mt[N];
    int mti;

    void init_mersenne_twister(__uint64_t seed)
    {
        mt[0] = seed;
        for (mti = 1; mti < N; mti++)
        {
            mt[mti] = (1812433253UL * (mt[mti - 1] ^ (mt[mti - 1] >> 30)) + mti);
        }
    }

  public:
    PRNG(__uint64_t seed = std::time(nullptr), __uint64_t sequence = 1) : state(seed), mti(N)
    {
        init_mersenne_twister(seed);
    };

    __attribute__((cold)) const __uint64_t MersenneTwister(const __uint64_t min, const __uint64_t max)
    {
        if (min >= max) [[unlikely]]
            throw std::invalid_argument("min must be less than max");
        __uint64_t y;
        static const __uint64_t mag01[2] = {0x0UL, MATRIX_A};
        if (mti >= N)
        {
            int kk;
            for (kk = 0; kk < N - M; kk++)
            {
                y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
                mt[kk] = mt[kk + M] ^ (y >> 1) ^ mag01[y & 0x1UL];
            }
            for (; kk < N - 1; kk++)
            {
                y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
                mt[kk] = mt[kk + (M - N)] ^ (y >> 1) ^ mag01[y & 0x1UL];
            }
            y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
            mt[N - 1] = mt[M - 1] ^ (y >> 1) ^ mag01[y & 0x1UL];
            mti = 0;
        }
        y = mt[mti++];
        y ^= (y >> 11);
        y ^= (y << 7) & 0x9d2c5680UL;
        y ^= (y << 15) & 0xefc60000UL;
        y ^= (y >> 18);
        return min + (y % (max - min + 1));
    };

    __attribute__((cold)) void reseed(__uint64_t new_seed)
    {
        state = new_seed;
        init_mersenne_twister(new_seed);
    };
};

class RSA {
    __uint64_t __e;
    __uint64_t __d;
    __uint64_t __n;
public:
    explicit RSA() {
        this->__generate_keys();
    }
    ~RSA() = default;

    std::vector<__uint64_t> Encrypt(const std::string& message) const {
        std::vector<__uint64_t> ciphertext;
        for(char c : message)
            ciphertext.push_back(mod_pow(static_cast<__uint64_t>(c), __e, __n));
        return ciphertext;
    }

    std::string Decrypt(const std::vector<__uint64_t>& ciphertext) const {
        std::string plaintext;
        for(auto c : ciphertext)
            plaintext += static_cast<char>(mod_pow(c, __d, __n));
        return plaintext;
    }

    // For output/inspection:
    void PrintKeys() const {
        std::cout << "Public Key: (e = " << __e << ", n = " << __n << ")\n";
        std::cout << "Private Key: (d = " << __d << ", n = " << __n << ")\n";
    }

private:
    // Efficient modular exponentiation
    static __uint64_t mod_pow(__uint64_t base, __uint64_t exp, __uint64_t mod) {
        __uint64_t result = 1;
        base %= mod;
        while(exp > 0) {
            if(exp & 1)
                result = (result * base) % mod;
            base = (base * base) % mod;
            exp >>= 1;
        }
        return result;
    }

    bool is_prime(__uint64_t n) const {
        if (n < 2) return false;
        for (__uint64_t i = 2; i*i <= n; ++i)
            if (n % i == 0) return false;
        return true;
    }

    __uint64_t gcd(__uint64_t a, __uint64_t b) const {
        while (b != 0) {
            __uint64_t t = b;
            b = a % b;
            a = t;
        }
        return a;
    }

    __uint64_t modinv(__uint64_t a, __uint64_t m) const {
        __int64_t m0 = m, t, q;
        __int64_t x0 = 0, x1 = 1;
        if (m == 1) return 0;
        while (a > 1) {
            q = a / m;
            t = m, m = a % m, a = t;
            t = x0, x0 = x1 - q * x0, x1 = t;
        }
        if (x1 < 0) x1 += m0;
        return x1;
    }

    void __generate_keys() {
        PRNG generator;
        __uint64_t p = 0, q = 0, phi = 0;
        // For demonstration, decent range (still insecure!)
        do { p = generator.MersenneTwister(1000, 5000); } while (!is_prime(p));
        do { q = generator.MersenneTwister(1000, 5000); } while (!is_prime(q) || q == p);
        __n = p * q;
        phi = (p - 1) * (q - 1);
        do { __e = generator.MersenneTwister(3, phi - 1); } while (gcd(__e, phi) != 1);
        __d = modinv(__e, phi);
    }
};
}; // namespace RSA_Cipher
