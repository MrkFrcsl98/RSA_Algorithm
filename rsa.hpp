#pragma once
#include <gmpxx.h>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <stdexcept>
#include <iomanip>
#include <iterator>
#include <ctime>
#include <type_traits>
#include <algorithm>
#include <stdint.h>

namespace RSA_Cipher {

enum class KeySize {
    Bits1024 = 1024,
    Bits2048 = 2048,
    Bits3072 = 3072,
    Bits4096 = 4096
};

enum class OutputFormat {
    HEX,
    BASE64,
    RAW,
};

class RSAUtils {
public:
    // GMP <-> bytes
    static std::vector<uint8_t> mpz_to_bytes(const mpz_class &value) {
        size_t count = (mpz_sizeinbase(value.get_mpz_t(), 2) + 7) / 8;
        std::vector<uint8_t> bytes(count ? count : 1, 0);
        mpz_export(bytes.data(), &count, 1, 1, 1, 0, value.get_mpz_t());
        if (bytes.empty()) bytes.push_back(0);
        while (bytes.size() > 1 && bytes[0] == 0)
            bytes.erase(bytes.begin());
        return bytes;
    }
    static mpz_class bytes_to_mpz(const std::vector<uint8_t> &bytes) {
        mpz_class value;
        mpz_import(value.get_mpz_t(), bytes.size(), 1, 1, 1, 0, bytes.data());
        return value;
    }
    // Base64 helpers
    static std::string base64_encode(const std::vector<uint8_t>& in) {
        static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        int val = 0, valb = -6;
        for (uint8_t c : in) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                out.push_back(b64[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) out.push_back(b64[((val << 8) >> (valb + 8)) & 0x3F]);
        while (out.size() % 4) out.push_back('=');
        return out;
    }
    static std::vector<uint8_t> base64_decode(const std::string& in) {
        static const std::string b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::vector<uint8_t> out;
        std::vector<int> T(256, -1);
        for (int i = 0; i < 64; i++) T[b64[i]] = i;
        int val = 0, valb = -8;
        for (uint8_t c : in) {
            if (T[c] == -1) break;
            val = (val << 6) + T[c];
            valb += 6;
            if (valb >= 0) {
                out.push_back(uint8_t((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return out;
    }
    // Hex helpers
    static std::string bytes_to_hex(const std::vector<uint8_t>& data) {
        std::ostringstream oss;
        for (auto b : data)
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        return oss.str();
    }
    static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hex.size(); i += 2)
            bytes.push_back((uint8_t)std::stoi(hex.substr(i, 2), nullptr, 16));
        return bytes;
    }
    // File helpers
    static std::vector<uint8_t> read_file(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file) throw std::runtime_error("Cannot open file for read: " + filename);
        return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    }
    static void write_file(const std::string& filename, const std::vector<uint8_t>& data) {
        std::ofstream file(filename, std::ios::binary);
        if (!file) throw std::runtime_error("Cannot open file for write: " + filename);
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
    }
    static bool file_exists(const std::string& filename) {
        std::ifstream f(filename, std::ios::binary);
        return f.good();
    }
    // Math
    static mpz_class random_prime(int bits, gmp_randclass& rng) {
        mpz_class p;
        while (true) {
            p = rng.get_z_bits(bits);
            mpz_setbit(p.get_mpz_t(), bits - 1);
            mpz_setbit(p.get_mpz_t(), 0);
            if (mpz_probab_prime_p(p.get_mpz_t(), 25))
                return p;
        }
    }
    static mpz_class modinv(const mpz_class& a, const mpz_class& m) {
        mpz_class inv;
        if (mpz_invert(inv.get_mpz_t(), a.get_mpz_t(), m.get_mpz_t()) == 0)
            throw std::runtime_error("No modular inverse exists");
        return inv;
    }
    static mpz_class powm(const mpz_class& base, const mpz_class& exp, const mpz_class& mod) {
        mpz_class result;
        mpz_powm(result.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
        return result;
    }
};

// -- Key Classes --

class RSAPublicKey {
public:
    mpz_class n, e;
    RSAPublicKey() = default;
    RSAPublicKey(const mpz_class& n_, const mpz_class& e_) : n(n_), e(e_) {}
};

class RSAPrivateKey {
public:
    mpz_class n, e, d;
    RSAPrivateKey() = default;
    RSAPrivateKey(const mpz_class& n_, const mpz_class& e_, const mpz_class& d_)
        : n(n_), e(e_), d(d_) {}
};

struct RSAKeyPair {
    RSAPublicKey public_key;
    RSAPrivateKey private_key;
};

class RSAKeyGenerator {
public:
    static RSAKeyPair generate(KeySize bits = KeySize::Bits2048) {
        int num_bits = static_cast<int>(bits);
        if (num_bits < 512) throw std::runtime_error("Key size too small");
        gmp_randclass rng(gmp_randinit_mt);
        rng.seed(static_cast<unsigned long>(std::time(nullptr)));

        mpz_class p = RSAUtils::random_prime(num_bits / 2, rng), q;
        do { q = RSAUtils::random_prime(num_bits / 2, rng); } while (q == p);
        mpz_class n = p * q;
        mpz_class phi = (p - 1) * (q - 1);
        mpz_class e = 65537;
        mpz_class d = RSAUtils::modinv(e, phi);

        return { RSAPublicKey(n, e), RSAPrivateKey(n, e, d) };
    }
};

// -- Encryption/Decryption Result Classes --

class RSAEncryptionResult {
    std::vector<mpz_class> ciphertext;
public:
    RSAEncryptionResult(std::vector<mpz_class>&& ct) : ciphertext(std::move(ct)) {}

    // Hex string, each block space-separated
    std::string asHex() const {
        std::ostringstream oss;
        for (size_t i = 0; i < ciphertext.size(); ++i) {
            if (i) oss << " ";
            oss << ciphertext[i].get_str(16);
        }
        return oss.str();
    }
    // Base64 of concatenated bytes of all blocks
    std::string asBase64() const {
        std::vector<uint8_t> all_bytes;
        for (const auto& block : ciphertext) {
            auto bytes = RSAUtils::mpz_to_bytes(block);
            all_bytes.insert(all_bytes.end(), bytes.begin(), bytes.end());
        }
        return RSAUtils::base64_encode(all_bytes);
    }
    // Raw bytes (concatenated blocks, no separators)
    std::vector<uint8_t> asRaw() const {
        std::vector<uint8_t> all_bytes;
        for (const auto& block : ciphertext) {
            auto bytes = RSAUtils::mpz_to_bytes(block);
            all_bytes.insert(all_bytes.end(), bytes.begin(), bytes.end());
        }
        return all_bytes;
    }
    // Vector of mpz_class blocks (for feed into decrypt)
    const std::vector<mpz_class>& asVector() const { return ciphertext; }
    // Save as hex to file
    void saveHexToFile(const std::string& filename) const {
        std::ofstream out(filename);
        if (!out) throw std::runtime_error("Cannot write ciphertext file: " + filename);
        out << asHex();
    }
    // Save as base64 to file
    void saveBase64ToFile(const std::string& filename) const {
        std::ofstream out(filename);
        if (!out) throw std::runtime_error("Cannot write ciphertext file: " + filename);
        out << asBase64();
    }
    // Save as raw bytes to file
    void saveRawToFile(const std::string& filename) const {
        RSAUtils::write_file(filename, asRaw());
    }
};

class RSADecryptionResult {
    std::vector<uint8_t> plaintext;
public:
    RSADecryptionResult(std::vector<uint8_t>&& pt) : plaintext(std::move(pt)) {}

    // As string
    std::string asString() const {
        return std::string(plaintext.begin(), plaintext.end());
    }
    // As hex
    std::string asHex() const {
        return RSAUtils::bytes_to_hex(plaintext);
    }
    // As base64
    std::string asBase64() const {
        return RSAUtils::base64_encode(plaintext);
    }
    // As raw vector
    const std::vector<uint8_t>& asVector() const { return plaintext; }
    // Save to file
    void saveToFile(const std::string& filename) const {
        RSAUtils::write_file(filename, plaintext);
    }
};

// -- Encryptor/Decryptor --

class RSAEncryptor {
    const RSAPublicKey& pub;
public:
    explicit RSAEncryptor(const RSAPublicKey& pub_) : pub(pub_) {}
    RSAEncryptionResult encrypt(const std::string& message_or_filename) const {
        if (RSAUtils::file_exists(message_or_filename)) {
            auto data = RSAUtils::read_file(message_or_filename);
            return encrypt(data);
        }
        std::vector<uint8_t> message(message_or_filename.begin(), message_or_filename.end());
        return encrypt(message);
    }
    RSAEncryptionResult encrypt(const std::vector<uint8_t>& message) const {
        std::vector<mpz_class> ciphertexts;
        for (uint8_t c : message)
            ciphertexts.push_back(RSAUtils::powm(c, pub.e, pub.n));
        return RSAEncryptionResult(std::move(ciphertexts));
    }
    // For decryptor to load from hex string
    static std::vector<mpz_class> hexToBlocks(const std::string& hex) {
        std::istringstream iss(hex);
        std::vector<mpz_class> res;
        std::string block;
        while (iss >> block) res.emplace_back(block, 16);
        return res;
    }
    // For decryptor to load from base64
    static std::vector<mpz_class> base64ToBlocks(const std::string& b64, size_t block_size) {
        auto all_bytes = RSAUtils::base64_decode(b64);
        std::vector<mpz_class> blocks;
        for(size_t i = 0; i < all_bytes.size(); i += block_size) {
            std::vector<uint8_t> sub(all_bytes.begin() + i, all_bytes.begin() + std::min(all_bytes.size(), i+block_size));
            blocks.push_back(RSAUtils::bytes_to_mpz(sub));
        }
        return blocks;
    }
};

class RSADecryptor {
    const RSAPrivateKey& priv;
public:
    explicit RSADecryptor(const RSAPrivateKey& priv_) : priv(priv_) {}
    RSADecryptionResult decrypt(const std::vector<mpz_class>& ciphertexts) const {
        std::vector<uint8_t> message;
        for (const auto& c : ciphertexts) {
            mpz_class m = RSAUtils::powm(c, priv.d, priv.n);
            message.push_back(static_cast<uint8_t>(m.get_ui() & 0xFF));
        }
        return RSADecryptionResult(std::move(message));
    }
    RSADecryptionResult decryptFromHex(const std::string& hex) const {
        return decrypt(RSAEncryptor::hexToBlocks(hex));
    }
    RSADecryptionResult decryptFromBase64(const std::string& b64, size_t block_size) const {
        return decrypt(RSAEncryptor::base64ToBlocks(b64, block_size));
    }
};

// -- File Handler (extended for storing/retrieving all formats) --

class RSAFileHandler {
public:
    // Encrypt file and save ciphertext in specified format
    static void encrypt_file(const std::string& in_filename, const std::string& out_filename, const RSAPublicKey& pub, const OutputFormat& format = OutputFormat::HEX) {
        RSAEncryptor enc(pub);
        auto result = enc.encrypt(in_filename);
        if (format == OutputFormat::HEX) result.saveHexToFile(out_filename);
        else if (format == OutputFormat::BASE64) result.saveBase64ToFile(out_filename);
        else if (format == OutputFormat::RAW) result.saveRawToFile(out_filename);
        else throw std::runtime_error("Unknown encryption file format!");
    }
    // Decrypt file and save plaintext as binary
 static void decrypt_file(const std::string& in_filename, const std::string& out_filename, const RSAPrivateKey& priv, const OutputFormat& format = OutputFormat::HEX, size_t block_size = 0) {
        RSADecryptor dec(priv);
        if (format == OutputFormat::HEX) {
            std::ifstream in(in_filename, std::ios::in);
            if (!in) throw std::runtime_error("Cannot open ciphertext file: " + in_filename);
            std::stringstream buffer;
            buffer << in.rdbuf();
            auto result = dec.decryptFromHex(buffer.str());
            result.saveToFile(out_filename);
        } else if (format == OutputFormat::BASE64) {
            if (block_size == 0) throw std::runtime_error("block_size required for base64 decryption");
            std::ifstream in(in_filename, std::ios::in);
            if (!in) throw std::runtime_error("Cannot open ciphertext file: " + in_filename);
            std::stringstream buffer;
            buffer << in.rdbuf();
            auto result = dec.decryptFromBase64(buffer.str(), block_size);
            result.saveToFile(out_filename);
        } else if (format == OutputFormat::RAW) {
            if (block_size == 0) throw std::runtime_error("block_size required for raw decryption");
            // RAW: Read the binary file and extract blocks directly
            auto all_bytes = RSAUtils::read_file(in_filename);
            std::vector<mpz_class> blocks;
            for (size_t i = 0; i < all_bytes.size(); i += block_size) {
                std::vector<uint8_t> sub(all_bytes.begin() + i, all_bytes.begin() + std::min(all_bytes.size(), i + block_size));
                blocks.push_back(RSAUtils::bytes_to_mpz(sub));
            }
            auto result = dec.decrypt(blocks);
            result.saveToFile(out_filename);
        } else {
            throw std::runtime_error("Unknown decryption file format!");
        }
    }

    // ====== Extensions for loading/storing ciphertext and plaintext ======

    // --- Ciphertext Loaders ---

    // Load ciphertext as vector<mpz_class> from hex file
    static std::vector<mpz_class> loadHexCiphertext(const std::string& filename) {
        std::ifstream in(filename);
        if (!in) throw std::runtime_error("Cannot open ciphertext file: " + filename);
        std::stringstream buffer;
        buffer << in.rdbuf();
        return RSAEncryptor::hexToBlocks(buffer.str());
    }

    // Load ciphertext as vector<mpz_class> from base64 file
    static std::vector<mpz_class> loadBase64Ciphertext(const std::string& filename, size_t block_size) {
        std::ifstream in(filename);
        if (!in) throw std::runtime_error("Cannot open ciphertext file: " + filename);
        std::stringstream buffer;
        buffer << in.rdbuf();
        return RSAEncryptor::base64ToBlocks(buffer.str(), block_size);
    }

    // Load ciphertext as vector<mpz_class> from raw binary file
    static std::vector<mpz_class> loadRawCiphertext(const std::string& filename, size_t block_size) {
        auto all_bytes = RSAUtils::read_file(filename);
        std::vector<mpz_class> blocks;
        for (size_t i = 0; i < all_bytes.size(); i += block_size) {
            std::vector<uint8_t> sub(all_bytes.begin() + i, all_bytes.begin() + std::min(all_bytes.size(), i+block_size));
            blocks.push_back(RSAUtils::bytes_to_mpz(sub));
        }
        return blocks;
    }

    // --- Plaintext Loaders ---

    // Load plaintext as vector<uint8_t> from binary file
    static std::vector<uint8_t> loadRawPlaintext(const std::string& filename) {
        return RSAUtils::read_file(filename);
    }

    // Load plaintext as vector<uint8_t> from hex file
    static std::vector<uint8_t> loadHexPlaintext(const std::string& filename) {
        std::ifstream in(filename);
        if (!in) throw std::runtime_error("Cannot open hex file: " + filename);
        std::stringstream buffer;
        buffer << in.rdbuf();
        return RSAUtils::hex_to_bytes(buffer.str());
    }

    // Load plaintext as vector<uint8_t> from base64 file
    static std::vector<uint8_t> loadBase64Plaintext(const std::string& filename) {
        std::ifstream in(filename);
        if (!in) throw std::runtime_error("Cannot open base64 file: " + filename);
        std::stringstream buffer;
        buffer << in.rdbuf();
        return RSAUtils::base64_decode(buffer.str());
    }

    // --- General Loader for Ciphertext based on OutputFormat ---
    static std::vector<mpz_class> loadCiphertext(const std::string& filename, OutputFormat format, size_t block_size = 0) {
        switch(format) {
            case OutputFormat::HEX:
                return loadHexCiphertext(filename);
            case OutputFormat::BASE64:
                if (block_size == 0) throw std::runtime_error("block_size required for base64");
                return loadBase64Ciphertext(filename, block_size);
            case OutputFormat::RAW:
                if (block_size == 0) throw std::runtime_error("block_size required for raw");
                return loadRawCiphertext(filename, block_size);
            default:
                throw std::runtime_error("Unknown format");
        }
    }

    // --- General Loader for Plaintext based on OutputFormat ---
    static std::vector<uint8_t> loadPlaintext(const std::string& filename, OutputFormat format) {
        switch(format) {
            case OutputFormat::HEX:
                return loadHexPlaintext(filename);
            case OutputFormat::BASE64:
                return loadBase64Plaintext(filename);
            case OutputFormat::RAW:
                return loadRawPlaintext(filename);
            default:
                throw std::runtime_error("Unknown format");
        }
    }
};

} // namespace RSA_Cipher
