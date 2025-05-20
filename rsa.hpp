#pragma once
#include <algorithm>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace RSA_Cipher
{

// ========== Minimal Big Integer Implementation ========== //
class BigInt
{
    static constexpr uint64_t BASE = 0x100000000ULL;

  public:
    std::vector<uint32_t> digits;
    bool negative = false;

    // --- Constructors ---
    BigInt(int64_t value = 0) : negative(value < 0)
    {
        uint64_t val = negative ? -value : value;
        if (val == 0)
            digits.push_back(0);
        else
            while (val)
            {
                digits.push_back(val & 0xFFFFFFFF);
                val >>= 32;
            }
    }
    BigInt(const std::vector<uint8_t> &bytes)
    {
        negative = false;
        size_t nb = bytes.size();
        size_t nd = (nb + 3) / 4;
        digits = std::vector<uint32_t>(nd, 0);
        for (size_t i = 0; i < nb; ++i)
        {
            size_t d = (nb - 1 - i) / 4;
            digits[d] |= uint32_t(bytes[i]) << (8 * ((nb - 1 - i) % 4));
        }
        trim();
    }
    static BigInt random_bits(size_t bits, std::mt19937 &rng)
    {
        size_t bytes = (bits + 7) / 8;
        std::vector<uint8_t> b(bytes);
        for (auto &v : b)
            v = uint8_t(rng());
        b[0] |= 0x80;  // Ensure high bit (bit length)
        b.back() |= 1; // Ensure odd
        if (bytes == 1 && b[0] < 3)
            b[0] = 3; // At least 3 for 1-byte primes
        return BigInt(b);
    }
    static BigInt random_prime(size_t bits, std::mt19937 &rng, int rounds = 16)
    {
        int attempts = 0;
        while (true)
        {
            BigInt p = random_bits(bits, rng);
            if (p.is_odd() && p.is_probable_prime(rounds))
                return p;
            p.print("p = ");
            std::cout << std::endl;
            if (++attempts > 100000)
                throw std::runtime_error("Prime search failed: too many attempts");
        }
    }
    void trim()
    {
        while (digits.size() > 1 && digits.back() == 0)
            digits.pop_back();
        if (digits.size() == 1 && digits[0] == 0)
            negative = false;
    }

    // --- Comparison operators ---
    bool operator<(const BigInt &o) const
    {
        if (negative != o.negative)
            return negative;
        if (digits.size() != o.digits.size())
            return negative ? digits.size() > o.digits.size() : digits.size() < o.digits.size();
        for (int i = int(digits.size()) - 1; i >= 0; --i)
            if (digits[i] != o.digits[i])
                return negative ? digits[i] > o.digits[i] : digits[i] < o.digits[i];
        return false;
    }
    bool operator>(const BigInt &o) const
    {
        return o < *this;
    }
    bool operator==(const BigInt &o) const
    {
        return negative == o.negative && digits == o.digits;
    }
    bool operator!=(const BigInt &o) const
    {
        return !(*this == o);
    }
    bool operator<=(const BigInt &o) const
    {
        return !(*this > o);
    }
    bool operator>=(const BigInt &o) const
    {
        return !(*this < o);
    }
    bool is_zero() const
    {
        return digits.size() == 1 && digits[0] == 0;
    }
    BigInt abs() const
    {
        BigInt r = *this;
        r.negative = false;
        return r;
    }
    bool is_odd() const
    {
        return digits[0] & 1;
    }

    // --- Arithmetic ---
    BigInt operator-() const
    {
        BigInt r = *this;
        if (!is_zero())
            r.negative = !negative;
        return r;
    }

    BigInt operator+(const BigInt &o) const
    {
        if (negative == o.negative)
        {
            BigInt res;
            res.negative = negative;
            const auto &a = digits, &b = o.digits;
            size_t n = std::max(a.size(), b.size());
            res.digits.resize(n, 0);
            uint64_t carry = 0;
            for (size_t i = 0; i < n; ++i)
            {
                uint64_t s = carry;
                if (i < a.size())
                    s += a[i];
                if (i < b.size())
                    s += b[i];
                res.digits[i] = s & 0xFFFFFFFF;
                carry = s >> 32;
            }
            if (carry)
                res.digits.push_back(uint32_t(carry));
            res.trim();
            return res;
        }
        return *this - (-o);
    }
    BigInt operator-(const BigInt &o) const
    {
        if (negative != o.negative)
            return *this + (-o);
        if (abs() < o.abs())
            return -(o - *this);
        BigInt res = *this;
        uint64_t borrow = 0;
        for (size_t i = 0; i < o.digits.size() || borrow; ++i)
        {
            uint64_t s = res.digits[i] - borrow;
            if (i < o.digits.size())
                s -= o.digits[i];
            if (s >> 63)
            {
                s += BASE;
                borrow = 1;
            }
            else
                borrow = 0;
            res.digits[i] = s & 0xFFFFFFFF;
        }
        res.trim();
        return res;
    }
    BigInt operator*(const BigInt &o) const
    {
        BigInt res;
        res.digits.resize(digits.size() + o.digits.size(), 0);
        for (size_t i = 0; i < digits.size(); ++i)
        {
            uint64_t carry = 0;
            for (size_t j = 0; j < o.digits.size() || carry; ++j)
            {
                uint64_t s = res.digits[i + j] + carry + uint64_t(digits[i]) * (j < o.digits.size() ? o.digits[j] : 0);
                res.digits[i + j] = s & 0xFFFFFFFF;
                carry = s >> 32;
            }
        }
        res.negative = negative != o.negative;
        res.trim();
        return res;
    }
    // Bitwise OR
    BigInt operator|(const BigInt &o) const
    {
        BigInt res;
        size_t n = std::max(digits.size(), o.digits.size());
        res.digits.resize(n, 0);
        for (size_t i = 0; i < n; ++i)
        {
            uint32_t a = i < digits.size() ? digits[i] : 0;
            uint32_t b = i < o.digits.size() ? o.digits[i] : 0;
            res.digits[i] = a | b;
        }
        res.trim();
        return res;
    }
    // Bitwise shift left/right
    BigInt operator<<(int b) const
    {
        BigInt res = *this;
        int words = b / 32, bits = b % 32;
        if (bits)
        {
            uint64_t carry = 0;
            for (size_t i = 0; i < res.digits.size(); ++i)
            {
                uint64_t v = (uint64_t(res.digits[i]) << bits) | carry;
                res.digits[i] = v & 0xFFFFFFFF;
                carry = v >> 32;
            }
            if (carry)
                res.digits.push_back(uint32_t(carry));
        }
        if (words)
            res.digits.insert(res.digits.begin(), words, 0);
        res.trim();
        return res;
    }
    BigInt operator>>(int b) const
    {
        BigInt res = *this;
        int words = b / 32, bits = b % 32;
        if (words >= int(res.digits.size()))
            return BigInt(0);
        res.digits.erase(res.digits.begin(), res.digits.begin() + words);
        if (bits)
        {
            uint32_t carry = 0;
            for (int i = int(res.digits.size()) - 1; i >= 0; --i)
            {
                uint32_t v = res.digits[i];
                res.digits[i] = (v >> bits) | carry;
                carry = v << (32 - bits);
            }
        }
        res.trim();
        return res;
    }
    BigInt operator&(uint64_t v) const
    {
        BigInt res;
        res.digits = std::vector<uint32_t>(1, digits.empty() ? 0 : (digits[0] & v));
        res.negative = false;
        return res;
    }
    // Division and modulo
    std::pair<BigInt, BigInt> divmod(const BigInt &o) const
    {
        if (o.is_zero())
            throw std::runtime_error("Div by zero");
        BigInt n = abs(), d = o.abs(), q = 0, r = 0;
        for (int i = int(n.digits.size()) * 32 - 1; i >= 0; --i)
        {
            r = (r << 1) + ((n >> i) & 1);
            if (r >= d)
            {
                r = r - d;
                q = q | (BigInt(1) << i);
            }
        }
        q.negative = negative != o.negative;
        r.negative = negative;
        q.trim();
        r.trim();
        return {q, r};
    }
    BigInt operator/(const BigInt &o) const
    {
        return divmod(o).first;
    }
    BigInt operator%(const BigInt &o) const
    {
        return divmod(o).second;
    }

    // Modular exponentiation
    BigInt modexp(BigInt e, BigInt mod) const
    {
        BigInt base = *this % mod, result = 1;
        while (!e.is_zero())
        {
            if ((e.digits[0] & 1) != 0)
                result = (result * base) % mod;
            base = (base * base) % mod;
            e = e >> 1;
        }
        return result;
    }
    // Modular inverse
    BigInt modinv(const BigInt &m) const
    {
        BigInt a = *this % m, b = m, x0 = 0, x1 = 1;
        while (!a.is_zero())
        {
            BigInt q = b / a, t = b % a;
            b = a;
            a = t;
            BigInt tmp = x0;
            x0 = x1 - q * x0;
            x1 = tmp;
        }
        if (b != 1)
            throw std::runtime_error("No modular inverse");
        if (x1 < 0)
            x1 = x1 + m;
        return x1;
    }
    // Miller-Rabin test
    bool is_probable_prime(int rounds = 8) const
    {
        if (*this < 2)
            return false;
        if (*this == 2 || *this == 3)
            return true;
        if (!is_odd())
            return false;
        BigInt d = *this - 1;
        int s = 0;
        while ((d & 1) == 0)
        {
            d = d >> 1;
            s++;
        }
        std::mt19937 rng((uint32_t)std::time(nullptr));
        for (int i = 0; i < rounds; ++i)
        {
            // Generate random a in [2, *this - 2]
            BigInt a;
            do
            {
                a = BigInt::random_bits(this->to_bytes().size() * 8, rng);
            } while (a < 2 || a > (*this - 2));
            BigInt x = a.modexp(d, *this);
            if (x == 1 || x == *this - 1)
                continue;
            bool ok = false;
            for (int r = 1; r < s; ++r)
            {
                x = x.modexp(2, *this);
                if (x == *this - 1)
                {
                    ok = true;
                    break;
                }
            }
            if (!ok)
                return false;
        }
        return true;
    }

    // --- Conversion helpers ---
    std::vector<uint8_t> to_bytes() const
    {
        size_t n = digits.size() * 4;
        std::vector<uint8_t> bytes(n, 0);
        for (size_t i = 0; i < digits.size(); ++i)
        {
            for (int j = 0; j < 4; ++j)
                bytes[n - 4 * (i + 1) + j] = (digits[i] >> (8 * (3 - j))) & 0xFF;
        }
        // Remove leading zeros
        while (bytes.size() > 1 && bytes[0] == 0)
            bytes.erase(bytes.begin());
        return bytes;
    }
    void print(const char *label = "") const
    {
        if (label)
            std::cout << label;
        for (auto b : to_bytes())
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        std::cout << std::dec << std::endl;
    }
    uint32_t to_uint32() const
    {
        if (digits.empty())
            return 0;
        return digits[0];
    }
    uint8_t to_uint8() const
    {
        if (digits.empty())
            return 0;
        return static_cast<uint8_t>(digits[0] & 0xFF);
    }
};

// ========== ASN.1 DER and PEM encoding ========== //
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

// ========== RSA Implementation ========== //
class RSA
{
  public:
    BigInt n, e, d, p, q, dp, dq, qinv;

    RSA(int bits = 512)
    { // Use 512+ for demo, 1024+ for more realism (slow!)
        std::random_device rd;
        std::mt19937 rng(rd());
        p = BigInt::random_prime(bits / 2, rng);
        std::cout << "++" << std::endl;
        do
        {
            q = BigInt::random_prime(bits / 2, rng);
        } while (q == p);
        n = p * q;
        BigInt phi = (p - 1) * (q - 1);
        e = 65537;
        d = e.modinv(phi);
        dp = d % (p - 1);
        dq = d % (q - 1);
        qinv = q.modinv(p);
    }

    std::vector<BigInt> encrypt(const std::vector<uint8_t> &message) const
    {
        std::vector<BigInt> ciphertexts;
        for (uint8_t c : message)
            ciphertexts.push_back(BigInt(c).modexp(e, n));
        return ciphertexts;
    }
    std::vector<uint8_t> decrypt(const std::vector<BigInt> &ciphertexts) const
    {
        std::vector<uint8_t> message;
        for (const auto &c : ciphertexts)
            message.push_back(c.modexp(d, n).to_uint8());
        return message;
    }
    std::vector<uint8_t> get_public_key_der() const
    {
        return detail::encode_asn1_sequence({detail::encode_asn1_integer(n.to_bytes()), detail::encode_asn1_integer(e.to_bytes())});
    }
    std::string get_public_key_pem() const
    {
        return detail::wrap_pem(detail::base64_encode(get_public_key_der()), "RSA PUBLIC KEY");
    }
    std::vector<uint8_t> get_private_key_der() const
    {
        return detail::encode_asn1_sequence({detail::encode_asn1_integer({0x00}), detail::encode_asn1_integer(n.to_bytes()), detail::encode_asn1_integer(e.to_bytes()),
                                             detail::encode_asn1_integer(d.to_bytes()), detail::encode_asn1_integer(p.to_bytes()),
                                             detail::encode_asn1_integer(q.to_bytes()), detail::encode_asn1_integer(dp.to_bytes()),
                                             detail::encode_asn1_integer(dq.to_bytes()), detail::encode_asn1_integer(qinv.to_bytes())});
    }
    std::string get_private_key_pem() const
    {
        return detail::wrap_pem(detail::base64_encode(get_private_key_der()), "RSA PRIVATE KEY");
    }
    void print_keys() const
    {
        std::cout << "Public key (e, n):\n";
        e.print();
        n.print();
        std::cout << "Private key (d):\n";
        d.print();
    }
};

} // namespace RSA_Cipher
