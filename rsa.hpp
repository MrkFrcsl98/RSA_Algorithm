#pragma once
#include <algorithm>
#include <ctime>
#include <fstream>
#include <gmpxx.h>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <type_traits>
#include <vector>
#include <iomanip>
#include <cctype>

namespace PEM_DER {

// Minimal ASN.1 DER INTEGER encoding
inline std::vector<uint8_t> encode_integer(const mpz_class& x) {
    std::vector<uint8_t> bytes;
    size_t count = (mpz_sizeinbase(x.get_mpz_t(), 2) + 7) / 8;
    if (count == 0) count = 1;
    bytes.resize(count);
    mpz_export(bytes.data(), &count, 1, 1, 1, 0, x.get_mpz_t());
    // ASN.1 INTEGER: add leading 0 if sign bit set
    if (bytes[0] & 0x80) bytes.insert(bytes.begin(), 0x00);

    std::vector<uint8_t> out = {0x02};
    if (bytes.size() < 128) {
        out.push_back(uint8_t(bytes.size()));
    } else {
        std::vector<uint8_t> len;
        size_t lenval = bytes.size();
        while (lenval) { len.insert(len.begin(), lenval & 0xFF); lenval >>= 8; }
        out.push_back(0x80 | len.size());
        out.insert(out.end(), len.begin(), len.end());
    }
    out.insert(out.end(), bytes.begin(), bytes.end());
    return out;
}

// Minimal ASN.1 DER SEQUENCE encoding
inline std::vector<uint8_t> encode_sequence(const std::vector<std::vector<uint8_t>>& fields) {
    std::vector<uint8_t> seq_data;
    for (const auto& f : fields) seq_data.insert(seq_data.end(), f.begin(), f.end());
    std::vector<uint8_t> out = {0x30};
    if (seq_data.size() < 128) {
        out.push_back(uint8_t(seq_data.size()));
    } else {
        std::vector<uint8_t> len;
        size_t lenval = seq_data.size();
        while (lenval) { len.insert(len.begin(), lenval & 0xFF); lenval >>= 8; }
        out.push_back(0x80 | len.size());
        out.insert(out.end(), len.begin(), len.end());
    }
    out.insert(out.end(), seq_data.begin(), seq_data.end());
    return out;
}

// Minimal ASN.1 DER INTEGER decoding
inline mpz_class decode_integer(const std::vector<uint8_t>& der, size_t& idx) {
    if (der[idx++] != 0x02) throw std::runtime_error("ASN.1: expected INTEGER");
    size_t len = der[idx++];
    if (len & 0x80) {
        size_t n = len & 0x7F; len = 0;
        for (size_t i = 0; i < n; ++i) len = (len << 8) | der[idx++];
    }
    std::vector<uint8_t> bytes(der.begin() + idx, der.begin() + idx + len);
    idx += len;
    // Remove leading 0 if present for positive sign
    if (bytes.size() > 1 && bytes[0] == 0x00) bytes.erase(bytes.begin());
    mpz_class val;
    mpz_import(val.get_mpz_t(), bytes.size(), 1, 1, 1, 0, bytes.data());
    return val;
}

// Minimal ASN.1 DER SEQUENCE decoding
inline void decode_sequence(const std::vector<uint8_t>& der, size_t& idx, size_t& seq_end) {
    if (der[idx++] != 0x30) throw std::runtime_error("ASN.1: expected SEQUENCE");
    size_t len = der[idx++];
    if (len & 0x80) {
        size_t n = len & 0x7F; len = 0;
        for (size_t i = 0; i < n; ++i) len = (len << 8) | der[idx++];
    }
    seq_end = idx + len;
}

// Base64 encode
inline std::string base64_encode(const std::vector<uint8_t>& in) {
    static const char* b64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val=0, valb=-6;
    for(uint8_t c : in){
        val = (val<<8) + c;
        valb += 8;
        while(valb>=0){ out.push_back(b64[(val>>valb)&0x3F]); valb-=6;}
    }
    if(valb>-6) out.push_back(b64[((val<<8)>>(valb+8))&0x3F]);
    while(out.size()%4) out.push_back('=');
    return out;
}

// Base64 decode
inline std::vector<uint8_t> base64_decode(const std::string& in){
    static const std::string b64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<uint8_t> out; std::vector<int> T(256,-1);
    for(int i=0;i<64;i++) T[b64[i]]=i;
    int val=0, valb=-8;
    for(uint8_t c : in){
        if(T[c]==-1) continue;
        val = (val<<6) + T[c];
        valb += 6;
        if(valb>=0){ out.push_back(uint8_t((val>>valb)&0xFF)); valb-=8;}
    }
    return out;
}

// PEM encode
inline std::string pem_wrap(const std::string& base64, const std::string& type) {
    std::ostringstream oss;
    oss << "-----BEGIN " << type << "-----\n";
    for (size_t i=0; i<base64.size(); i+=64)
        oss << base64.substr(i, 64) << "\n";
    oss << "-----END " << type << "-----\n";
    return oss.str();
}

// PEM decode
inline std::string strip_pem(const std::string& pem) {
    auto begin = pem.find("-----BEGIN");
    if (begin == std::string::npos) throw std::runtime_error("Invalid PEM: no BEGIN");
    begin = pem.find('\n', begin);
    auto end = pem.find("-----END");
    if (end == std::string::npos) throw std::runtime_error("Invalid PEM: no END");
    std::string b64 = pem.substr(begin+1, end-begin-1);
    std::string out;
    for (char c : b64) if (isalnum(c) || c=='+' || c=='/' || c=='=') out += c;
    return out;
}

} // namespace PEM_DER

namespace RSA_Cipher
{

enum class KeySize
{
    Bits1024 = 1024,
    Bits2048 = 2048,
    Bits3072 = 3072,
    Bits4096 = 4096
};

class RSAUtils
{
  public:
    static std::vector<uint8_t> mpz_to_bytes(const mpz_class &value)
    {
        size_t count = (mpz_sizeinbase(value.get_mpz_t(), 2) + 7) / 8;
        std::vector<uint8_t> bytes(count ? count : 1, 0);
        mpz_export(bytes.data(), &count, 1, 1, 1, 0, value.get_mpz_t());
        if (bytes.empty())
            bytes.push_back(0);
        while (bytes.size() > 1 && bytes[0] == 0)
            bytes.erase(bytes.begin());
        return bytes;
    }
    static mpz_class bytes_to_mpz(const std::vector<uint8_t> &bytes)
    {
        mpz_class value;
        mpz_import(value.get_mpz_t(), bytes.size(), 1, 1, 1, 0, bytes.data());
        return value;
    }
    static std::vector<uint8_t> read_file(const std::string &filename)
    {
        std::ifstream file(filename, std::ios::binary);
        if (!file)
            throw std::runtime_error("Cannot open file for read: " + filename);
        return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    }
    static void write_file(const std::string &filename, const std::vector<uint8_t> &data)
    {
        std::ofstream file(filename, std::ios::binary);
        if (!file)
            throw std::runtime_error("Cannot open file for write: " + filename);
        file.write(reinterpret_cast<const char *>(data.data()), data.size());
    }
    static bool file_exists(const std::string &filename)
    {
        std::ifstream f(filename, std::ios::binary);
        return f.good();
    }
    static mpz_class random_prime(int bits, gmp_randclass &rng)
    {
        mpz_class p;
        while (true)
        {
            p = rng.get_z_bits(bits);
            mpz_setbit(p.get_mpz_t(), bits - 1);
            mpz_setbit(p.get_mpz_t(), 0);
            if (mpz_probab_prime_p(p.get_mpz_t(), 25))
                return p;
        }
    }
    static mpz_class modinv(const mpz_class &a, const mpz_class &m)
    {
        mpz_class inv;
        if (mpz_invert(inv.get_mpz_t(), a.get_mpz_t(), m.get_mpz_t()) == 0)
            throw std::runtime_error("No modular inverse exists");
        return inv;
    }
    static mpz_class powm(const mpz_class &base, const mpz_class &exp, const mpz_class &mod)
    {
        mpz_class result;
        mpz_powm(result.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
        return result;
    }
};

class RSAPublicKey
{
  public:
    mpz_class n, e;
    RSAPublicKey() = default;
    RSAPublicKey(const mpz_class &n_, const mpz_class &e_) : n(n_), e(e_) {}

    std::vector<uint8_t> to_der() const {
        using namespace PEM_DER;
        std::vector<std::vector<uint8_t>> fields = {
            encode_integer(n),
            encode_integer(e)
        };
        return encode_sequence(fields);
    }
    std::string to_pem() const {
        return PEM_DER::pem_wrap(PEM_DER::base64_encode(to_der()), "RSA PUBLIC KEY");
    }
    static RSAPublicKey from_der(const std::vector<uint8_t>& der) {
        size_t idx = 0, seq_end = 0;
        PEM_DER::decode_sequence(der, idx, seq_end);
        mpz_class n = PEM_DER::decode_integer(der, idx);
        mpz_class e = PEM_DER::decode_integer(der, idx);
        return RSAPublicKey(n, e);
    }
    static RSAPublicKey from_pem(const std::string& pem) {
        auto der = PEM_DER::base64_decode(PEM_DER::strip_pem(pem));
        return from_der(der);
    }

    // New: Save/load methods
    void save_pem(const std::string& filename) const {
        std::ofstream(filename) << to_pem();
    }
    void save_der(const std::string& filename) const {
        auto der = to_der();
        std::ofstream(filename, std::ios::binary).write(reinterpret_cast<const char*>(der.data()), der.size());
    }
    static RSAPublicKey load_pem(const std::string& filename) {
        std::ifstream f(filename);
        std::ostringstream ss; ss << f.rdbuf();
        return from_pem(ss.str());
    }
    static RSAPublicKey load_der(const std::string& filename) {
        std::ifstream f(filename, std::ios::binary);
        std::vector<uint8_t> buf((std::istreambuf_iterator<char>(f)), {});
        return from_der(buf);
    }
};

class RSAPrivateKey
{
  public:
    mpz_class n, e, d, p, q, dP, dQ, qInv;
    RSAPrivateKey() = default;
    // Constructor for full PKCS#1
    RSAPrivateKey(const mpz_class &n_, const mpz_class &e_, const mpz_class &d_,
                  const mpz_class &p_, const mpz_class &q_,
                  const mpz_class &dP_, const mpz_class &dQ_, const mpz_class &qInv_)
        : n(n_), e(e_), d(d_), p(p_), q(q_), dP(dP_), dQ(dQ_), qInv(qInv_) {}
    // Minimal constructor for legacy use (p, q, dP, dQ, qInv will be zero)
    RSAPrivateKey(const mpz_class &n_, const mpz_class &e_, const mpz_class &d_)
        : n(n_), e(e_), d(d_), p(0), q(0), dP(0), dQ(0), qInv(0) {}

    std::vector<uint8_t> to_der() const {
        using namespace PEM_DER;
        std::vector<std::vector<uint8_t>> fields = {
            encode_integer(0), // Version
            encode_integer(n),
            encode_integer(e),
            encode_integer(d),
            encode_integer(p),
            encode_integer(q),
            encode_integer(dP),
            encode_integer(dQ),
            encode_integer(qInv)
        };
        return encode_sequence(fields);
    }
    std::string to_pem() const {
        return PEM_DER::pem_wrap(PEM_DER::base64_encode(to_der()), "RSA PRIVATE KEY");
    }
    static RSAPrivateKey from_der(const std::vector<uint8_t>& der) {
        size_t idx = 0, seq_end = 0;
        PEM_DER::decode_sequence(der, idx, seq_end);
        mpz_class version = PEM_DER::decode_integer(der, idx);
        mpz_class n = PEM_DER::decode_integer(der, idx);
        mpz_class e = PEM_DER::decode_integer(der, idx);
        mpz_class d = PEM_DER::decode_integer(der, idx);
        mpz_class p = PEM_DER::decode_integer(der, idx);
        mpz_class q = PEM_DER::decode_integer(der, idx);
        mpz_class dP = PEM_DER::decode_integer(der, idx);
        mpz_class dQ = PEM_DER::decode_integer(der, idx);
        mpz_class qInv = PEM_DER::decode_integer(der, idx);
        return RSAPrivateKey(n, e, d, p, q, dP, dQ, qInv);
    }
    static RSAPrivateKey from_pem(const std::string& pem) {
        auto der = PEM_DER::base64_decode(PEM_DER::strip_pem(pem));
        return from_der(der);
    }

    // New: Save/load methods
    void save_pem(const std::string& filename) const {
        std::ofstream(filename) << to_pem();
    }
    void save_der(const std::string& filename) const {
        auto der = to_der();
        std::ofstream(filename, std::ios::binary).write(reinterpret_cast<const char*>(der.data()), der.size());
    }
    static RSAPrivateKey load_pem(const std::string& filename) {
        std::ifstream f(filename);
        std::ostringstream ss; ss << f.rdbuf();
        return from_pem(ss.str());
    }
    static RSAPrivateKey load_der(const std::string& filename) {
        std::ifstream f(filename, std::ios::binary);
        std::vector<uint8_t> buf((std::istreambuf_iterator<char>(f)), {});
        return from_der(buf);
    }
};

struct RSAKeyPair
{
    RSAPublicKey public_key;
    RSAPrivateKey private_key;

    // New: Save/load methods for the key pair
    void save_pem(const std::string& pubfile, const std::string& privfile) const {
        public_key.save_pem(pubfile);
        private_key.save_pem(privfile);
    }
    void save_der(const std::string& pubfile, const std::string& privfile) const {
        public_key.save_der(pubfile);
        private_key.save_der(privfile);
    }
    static RSAKeyPair load_pem(const std::string& pubfile, const std::string& privfile) {
        return {RSAPublicKey::load_pem(pubfile), RSAPrivateKey::load_pem(privfile)};
    }
    static RSAKeyPair load_der(const std::string& pubfile, const std::string& privfile) {
        return {RSAPublicKey::load_der(pubfile), RSAPrivateKey::load_der(privfile)};
    }
};

class RSAKeyGenerator
{
  public:
    static RSAKeyPair generate(KeySize bits = KeySize::Bits2048)
    {
        int num_bits = static_cast<int>(bits);
        if (num_bits < 512)
            throw std::runtime_error("Key size too small");
        gmp_randclass rng(gmp_randinit_mt);
        rng.seed(static_cast<unsigned long>(std::time(nullptr)));
        mpz_class p = RSAUtils::random_prime(num_bits / 2, rng);
        mpz_class q;
        do {
            q = RSAUtils::random_prime(num_bits / 2, rng);
        } while (q == p);

        mpz_class n = p * q;
        mpz_class phi = (p - 1) * (q - 1);
        mpz_class e = 65537;
        mpz_class d = RSAUtils::modinv(e, phi);
        // For PKCS#1 fields
        mpz_class dP = d % (p - 1);
        mpz_class dQ = d % (q - 1);
        mpz_class qInv = RSAUtils::modinv(q, p);

        RSAPublicKey pub(n, e);
        RSAPrivateKey priv(n, e, d, p, q, dP, dQ, qInv);
        return {pub, priv};
    }
};

class RSAEncryptionResult
{
    std::vector<mpz_class> ciphertext;

  public:
    RSAEncryptionResult(std::vector<mpz_class> &&ct) : ciphertext(std::move(ct)) {}

    std::vector<uint8_t> asRaw() const {
        std::vector<uint8_t> all_bytes;
        if (ciphertext.empty()) return all_bytes;
        size_t mod_bytes = (mpz_sizeinbase(ciphertext[0].get_mpz_t(), 2) + 7) / 8;
        for (const auto& block : ciphertext) {
            auto bytes = RSAUtils::mpz_to_bytes(block);
            if (bytes.size() < mod_bytes)
                bytes.insert(bytes.begin(), mod_bytes - bytes.size(), 0);
            all_bytes.insert(all_bytes.end(), bytes.begin(), bytes.end());
        }
        return all_bytes;
    }
    const std::vector<mpz_class> &asVector() const { return ciphertext; }
    void saveRawToFile(const std::string &filename) const {
        RSAUtils::write_file(filename, asRaw());
    }
};

class RSADecryptionResult
{
    std::vector<uint8_t> plaintext;

  public:
    RSADecryptionResult(std::vector<uint8_t> &&pt) : plaintext(std::move(pt)) {}
    std::string asString() const { return std::string(plaintext.begin(), plaintext.end()); }
    const std::vector<uint8_t> &asVector() const { return plaintext; }
    void saveToFile(const std::string &filename) const { RSAUtils::write_file(filename, plaintext); }
};

class RSAEncryptor
{
    const RSAPublicKey &pub;
  public:
    explicit RSAEncryptor(const RSAPublicKey &pub_) : pub(pub_) {}
    RSAEncryptionResult encrypt(const std::string &message_or_filename) const
    {
        if (RSAUtils::file_exists(message_or_filename))
        {
            auto data = RSAUtils::read_file(message_or_filename);
            return encrypt(data);
        }
        std::vector<uint8_t> message(message_or_filename.begin(), message_or_filename.end());
        return encrypt(message);
    }
    RSAEncryptionResult encrypt(const std::vector<uint8_t> &message) const
    {
        std::vector<mpz_class> ciphertexts;
        for (uint8_t c : message)
            ciphertexts.push_back(RSAUtils::powm(c, pub.e, pub.n));
        return RSAEncryptionResult(std::move(ciphertexts));
    }
};

class RSADecryptor
{
    const RSAPrivateKey &priv;
  public:
    explicit RSADecryptor(const RSAPrivateKey &priv_) : priv(priv_) {}
    RSADecryptionResult decrypt(const std::vector<mpz_class> &ciphertexts) const
    {
        std::vector<uint8_t> message;
        for (const auto &c : ciphertexts)
        {
            mpz_class m = RSAUtils::powm(c, priv.d, priv.n);
            message.push_back(static_cast<uint8_t>(m.get_ui() & 0xFF));
        }
        return RSADecryptionResult(std::move(message));
    }
};

class RSAFileHandler
{
  public:
    static void encrypt_file(const std::string &in_filename, const std::string &out_filename, const RSAPublicKey &pub)
    {
        RSAEncryptor enc(pub);
        auto result = enc.encrypt(in_filename);
        result.saveRawToFile(out_filename);
    }
    static void decrypt_file(const std::string &in_filename, const std::string &out_filename, const RSAPrivateKey &priv) {
    size_t block_size = (mpz_sizeinbase(priv.n.get_mpz_t(), 2) + 7) / 8;
    decrypt_file(in_filename, out_filename, priv, block_size);
    }
    static void decrypt_file(const std::string &in_filename, const std::string &out_filename, const RSAPrivateKey &priv, size_t block_size)
    {
        RSADecryptor dec(priv);
        auto all_bytes = RSAUtils::read_file(in_filename);
        std::vector<mpz_class> blocks;
        for (size_t i = 0; i < all_bytes.size(); i += block_size)
        {
            std::vector<uint8_t> sub(all_bytes.begin() + i, all_bytes.begin() + std::min(all_bytes.size(), i + block_size));
            blocks.push_back(RSAUtils::bytes_to_mpz(sub));
        }
        auto result = dec.decrypt(blocks);
        result.saveToFile(out_filename);
    }

    static std::vector<mpz_class> loadRawCiphertext(const std::string &filename, size_t block_size)
    {
        auto all_bytes = RSAUtils::read_file(filename);
        std::vector<mpz_class> blocks;
        for (size_t i = 0; i < all_bytes.size(); i += block_size)
        {
            std::vector<uint8_t> sub(all_bytes.begin() + i, all_bytes.begin() + std::min(all_bytes.size(), i + block_size));
            blocks.push_back(RSAUtils::bytes_to_mpz(sub));
        }
        return blocks;
    }

    static std::vector<uint8_t> loadRawPlaintext(const std::string &filename)
    {
        return RSAUtils::read_file(filename);
    }
};

} // namespace RSA_Cipher
