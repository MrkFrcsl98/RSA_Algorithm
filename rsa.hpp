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
#include <iostream>

// ===== PEM_DER utilities (ASN.1 DER, Base64, PEM) =====
namespace PEM_DER {
inline std::vector<uint8_t> encode_integer(const mpz_class& x) {
    std::vector<uint8_t> bytes;
    size_t count = (mpz_sizeinbase(x.get_mpz_t(), 2) + 7) / 8;
    if (count == 0) count = 1;
    bytes.resize(count);
    mpz_export(bytes.data(), &count, 1, 1, 1, 0, x.get_mpz_t());
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
inline mpz_class decode_integer(const std::vector<uint8_t>& der, size_t& idx) {
    if (der[idx++] != 0x02) throw std::runtime_error("ASN.1: expected INTEGER");
    size_t len = der[idx++];
    if (len & 0x80) {
        size_t n = len & 0x7F; len = 0;
        for (size_t i = 0; i < n; ++i) len = (len << 8) | der[idx++];
    }
    std::vector<uint8_t> bytes(der.begin() + idx, der.begin() + idx + len);
    idx += len;
    if (bytes.size() > 1 && bytes[0] == 0x00) bytes.erase(bytes.begin());
    mpz_class val;
    mpz_import(val.get_mpz_t(), bytes.size(), 1, 1, 1, 0, bytes.data());
    return val;
}
inline void decode_sequence(const std::vector<uint8_t>& der, size_t& idx, size_t& seq_end) {
    if (der[idx++] != 0x30) throw std::runtime_error("ASN.1: expected SEQUENCE");
    size_t len = der[idx++];
    if (len & 0x80) {
        size_t n = len & 0x7F; len = 0;
        for (size_t i = 0; i < n; ++i) len = (len << 8) | der[idx++];
    }
    seq_end = idx + len;
}
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
inline std::string pem_wrap(const std::string& base64, const std::string& type) {
    std::ostringstream oss;
    oss << "-----BEGIN " << type << "-----\n";
    for (size_t i=0; i<base64.size(); i+=64)
        oss << base64.substr(i, 64) << "\n";
    oss << "-----END " << type << "-----\n";
    return oss.str();
}
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

// ================= RSA Core =====================
namespace RSA {

enum class KeySize { Bits1024=1024, Bits2048=2048, Bits3072=3072, Bits4096=4096 };
enum class OutputFormat { Binary, Hex, Base64 };

// ----- Key classes -----
class RSAPublicKey {
public:
    mpz_class n, e;
    RSAPublicKey() : n(0), e(0) {}
    RSAPublicKey(const mpz_class &n_, const mpz_class &e_) : n(n_), e(e_) {}
    std::vector<uint8_t> to_der() const {
        std::vector<std::vector<uint8_t>> fields = {
            PEM_DER::encode_integer(n),
            PEM_DER::encode_integer(e)
        };
        return PEM_DER::encode_sequence(fields);
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
    void save_pem(const std::string& filename) const {
        std::ofstream(filename) << to_pem();
    }
    static RSAPublicKey load_pem(const std::string& filename) {
        std::ifstream f(filename);
        if (!f) throw std::runtime_error("Cannot open public PEM: " + filename);
        std::ostringstream ss; ss << f.rdbuf();
        return from_pem(ss.str());
    }
};
class RSAPrivateKey {
public:
    mpz_class n, e, d, p, q, dP, dQ, qInv;
    RSAPrivateKey() : n(0), e(0), d(0), p(0), q(0), dP(0), dQ(0), qInv(0) {}
    RSAPrivateKey(const mpz_class &n_, const mpz_class &e_, const mpz_class &d_,
                  const mpz_class &p_, const mpz_class &q_,
                  const mpz_class &dP_, const mpz_class &dQ_, const mpz_class &qInv_)
        : n(n_), e(e_), d(d_), p(p_), q(q_), dP(dP_), dQ(dQ_), qInv(qInv_) {}
    std::vector<uint8_t> to_der() const {
        std::vector<std::vector<uint8_t>> fields = {
            PEM_DER::encode_integer(0),
            PEM_DER::encode_integer(n),
            PEM_DER::encode_integer(e),
            PEM_DER::encode_integer(d),
            PEM_DER::encode_integer(p),
            PEM_DER::encode_integer(q),
            PEM_DER::encode_integer(dP),
            PEM_DER::encode_integer(dQ),
            PEM_DER::encode_integer(qInv)
        };
        return PEM_DER::encode_sequence(fields);
    }
    std::string to_pem() const {
        return PEM_DER::pem_wrap(PEM_DER::base64_encode(to_der()), "RSA PRIVATE KEY");
    }
    static RSAPrivateKey from_der(const std::vector<uint8_t>& der) {
        size_t idx = 0, seq_end = 0;
        PEM_DER::decode_sequence(der, idx, seq_end);
        (void)PEM_DER::decode_integer(der, idx); // version
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
    void save_pem(const std::string& filename) const {
        std::ofstream(filename) << to_pem();
    }
    static RSAPrivateKey load_pem(const std::string& filename) {
        std::ifstream f(filename);
        if (!f) throw std::runtime_error("Cannot open private PEM: " + filename);
        std::ostringstream ss; ss << f.rdbuf();
        return from_pem(ss.str());
    }
};

struct KeyPair {
    RSAPublicKey public_key;
    RSAPrivateKey private_key;
};

// ----- Utils -----
namespace UTIL {
inline std::vector<uint8_t> mpz_to_bytes(const mpz_class &value) {
    size_t count = (mpz_sizeinbase(value.get_mpz_t(), 2) + 7) / 8;
    std::vector<uint8_t> bytes(count ? count : 1, 0);
    mpz_export(bytes.data(), &count, 1, 1, 1, 0, value.get_mpz_t());
    if (bytes.empty())
        bytes.push_back(0);
    while (bytes.size() > 1 && bytes[0] == 0)
        bytes.erase(bytes.begin());
    return bytes;
}
inline mpz_class bytes_to_mpz(const std::vector<uint8_t> &bytes) {
    mpz_class value;
    mpz_import(value.get_mpz_t(), bytes.size(), 1, 1, 1, 0, bytes.data());
    return value;
}
inline std::vector<uint8_t> read_file(const std::string &filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) throw std::runtime_error("Cannot open file for reading: " + filename);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}
inline void write_file(const std::string &filename, const std::vector<uint8_t> &data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) throw std::runtime_error("Cannot open file for writing: " + filename);
    file.write(reinterpret_cast<const char *>(data.data()), data.size());
}
inline void write_text(const std::string &filename, const std::string &data) {
    std::ofstream file(filename);
    if (!file) throw std::runtime_error("Cannot open file for writing (text): " + filename);
    file << data;
}
inline bool file_exists(const std::string &filename) {
    std::ifstream f(filename, std::ios::binary);
    return f.good();
}
inline mpz_class random_prime(int bits, gmp_randclass &rng) {
    mpz_class p;
    while (true) {
        p = rng.get_z_bits(bits);
        mpz_setbit(p.get_mpz_t(), bits - 1);
        mpz_setbit(p.get_mpz_t(), 0);
        if (mpz_probab_prime_p(p.get_mpz_t(), 25))
            return p;
    }
}
inline mpz_class modinv(const mpz_class &a, const mpz_class &m) {
    mpz_class inv;
    if (mpz_invert(inv.get_mpz_t(), a.get_mpz_t(), m.get_mpz_t()) == 0)
        throw std::runtime_error("No modular inverse exists");
    return inv;
}
inline mpz_class powm(const mpz_class &base, const mpz_class &exp, const mpz_class &mod) {
    mpz_class result;
    mpz_powm(result.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
    return result;
}
inline std::string bytes_to_hex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (auto b : data)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}
inline std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> data;
    for (size_t i = 0; i+1 < hex.length(); i += 2)
        data.push_back((uint8_t)std::stoi(hex.substr(i,2), nullptr, 16));
    return data;
}
} // namespace UTIL

// ----- Key Generation -----
inline KeyPair GenerateKeyPair(KeySize bits = KeySize::Bits2048) {
    int num_bits = static_cast<int>(bits);
    if (num_bits < 512) throw std::runtime_error("Key size too small.");
    gmp_randclass rng(gmp_randinit_mt);
    rng.seed(static_cast<unsigned long>(std::time(nullptr)));
    mpz_class p = UTIL::random_prime(num_bits / 2, rng);
    mpz_class q;
    do { q = UTIL::random_prime(num_bits / 2, rng); } while (q == p);
    mpz_class n = p * q;
    mpz_class phi = (p - 1) * (q - 1);
    mpz_class e = 65537;
    mpz_class d = UTIL::modinv(e, phi);
    mpz_class dP = d % (p - 1);
    mpz_class dQ = d % (q - 1);
    mpz_class qInv = UTIL::modinv(q, p);
    RSAPublicKey pub(n, e);
    RSAPrivateKey priv(n, e, d, p, q, dP, dQ, qInv);
    return {pub, priv};
}

// ----- Encryption/Decryption primitives -----
namespace INTERNAL {
inline std::vector<mpz_class> encrypt_blocks(const std::vector<uint8_t>& data, const RSAPublicKey& pub) {
    if (pub.n == 0 || pub.e == 0) throw std::runtime_error("Public key is not initialized.");
    std::vector<mpz_class> ciphertexts;
    for (uint8_t c : data)
        ciphertexts.push_back(UTIL::powm(c, pub.e, pub.n));
    return ciphertexts;
}
inline std::vector<uint8_t> decrypt_blocks(const std::vector<mpz_class>& cts, const RSAPrivateKey& priv) {
    if (priv.n == 0 || priv.d == 0) throw std::runtime_error("Private key is not initialized.");
    std::vector<uint8_t> message;
    for (const auto& c : cts)
        message.push_back(static_cast<uint8_t>(UTIL::powm(c, priv.d, priv.n).get_ui() & 0xFF));
    return message;
}
inline std::vector<uint8_t> cts_to_bytes(const std::vector<mpz_class>& cts, size_t mod_bytes) {
    std::vector<uint8_t> out;
    for (const auto& block : cts) {
        auto bytes = UTIL::mpz_to_bytes(block);
        if (bytes.size() < mod_bytes)
            bytes.insert(bytes.begin(), mod_bytes - bytes.size(), 0);
        out.insert(out.end(), bytes.begin(), bytes.end());
    }
    return out;
}
inline std::vector<mpz_class> bytes_to_cts(const std::vector<uint8_t>& raw, size_t mod_bytes) {
    std::vector<mpz_class> blocks;
    for (size_t i = 0; i < raw.size(); i += mod_bytes) {
        std::vector<uint8_t> sub(raw.begin() + i, raw.begin() + std::min(raw.size(), i + mod_bytes));
        blocks.push_back(UTIL::bytes_to_mpz(sub));
    }
    return blocks;
}
inline std::vector<uint8_t> decode_by_format(const std::string& in, OutputFormat fmt) {
    if (fmt == OutputFormat::Binary)
        return std::vector<uint8_t>(in.begin(), in.end());
    else if (fmt == OutputFormat::Hex)
        return UTIL::hex_to_bytes(in);
    else if (fmt == OutputFormat::Base64)
        return PEM_DER::base64_decode(in);
    throw std::runtime_error("Unknown OutputFormat for decoding input");
}
inline std::string encode_by_format(const std::vector<uint8_t>& in, OutputFormat fmt) {
    if (fmt == OutputFormat::Binary)
        return std::string(in.begin(), in.end());
    else if (fmt == OutputFormat::Hex)
        return UTIL::bytes_to_hex(in);
    else if (fmt == OutputFormat::Base64)
        return PEM_DER::base64_encode(in);
    throw std::runtime_error("Unknown OutputFormat for encoding output");
}
} // namespace INTERNAL

// ======= MESSAGE API =======
namespace MESSAGE {
inline std::string Encrypt(const std::string& message, const RSAPublicKey& pub, OutputFormat fmt) {
    if (message.empty()) throw std::runtime_error("Message is empty.");
    auto blocks = INTERNAL::encrypt_blocks(std::vector<uint8_t>(message.begin(), message.end()), pub);
    size_t mod_bytes = (mpz_sizeinbase(pub.n.get_mpz_t(), 2) + 7) / 8;
    auto as_bytes = INTERNAL::cts_to_bytes(blocks, mod_bytes);
    return INTERNAL::encode_by_format(as_bytes, fmt);
}
inline std::string Decrypt(const std::string& encoded, const RSAPrivateKey& priv, OutputFormat fmt) {
    auto raw = INTERNAL::decode_by_format(encoded, fmt);
    size_t mod_bytes = (mpz_sizeinbase(priv.n.get_mpz_t(), 2) + 7) / 8;
    auto blocks = INTERNAL::bytes_to_cts(raw, mod_bytes);
    auto message = INTERNAL::decrypt_blocks(blocks, priv);
    return std::string(message.begin(), message.end());
}
} // namespace MESSAGE

// ======= FILE API =======
namespace FILE {
inline void Encrypt(const std::string& inputFile, const std::string& outputFile,
             const RSAPublicKey& pub, OutputFormat fmt) {
    if (!UTIL::file_exists(inputFile))
        throw std::runtime_error("Input file does not exist: " + inputFile);
    auto data = UTIL::read_file(inputFile);
    if (data.empty()) throw std::runtime_error("Input file is empty: " + inputFile);
    auto blocks = INTERNAL::encrypt_blocks(data, pub);
    size_t mod_bytes = (mpz_sizeinbase(pub.n.get_mpz_t(), 2) + 7) / 8;
    auto as_bytes = INTERNAL::cts_to_bytes(blocks, mod_bytes);
    if (fmt == OutputFormat::Binary)
        UTIL::write_file(outputFile, as_bytes);
    else
        UTIL::write_text(outputFile, INTERNAL::encode_by_format(as_bytes, fmt));
}
inline void Decrypt(const std::string& inputFile, const std::string& outputFile,
             const RSAPrivateKey& priv, OutputFormat fmt) {
    if (!UTIL::file_exists(inputFile))
        throw std::runtime_error("Encrypted file does not exist: " + inputFile);
    std::vector<uint8_t> raw;
    if (fmt == OutputFormat::Binary)
        raw = UTIL::read_file(inputFile);
    else {
        std::ifstream file(inputFile);
        if (!file) throw std::runtime_error("Cannot open encrypted file: " + inputFile);
        std::ostringstream ss; ss << file.rdbuf();
        raw = INTERNAL::decode_by_format(ss.str(), fmt);
    }
    size_t mod_bytes = (mpz_sizeinbase(priv.n.get_mpz_t(), 2) + 7) / 8;
    auto blocks = INTERNAL::bytes_to_cts(raw, mod_bytes);
    auto message = INTERNAL::decrypt_blocks(blocks, priv);
    UTIL::write_file(outputFile, message);
}
} // namespace FILE

} // namespace RSA
