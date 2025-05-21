#include "rsa.hpp"
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <vector>
#include <cstring>

using namespace RSA;

// ANSI color codes
const char* GREEN = "\033[32m";
const char* RED = "\033[31m";
const char* YELLOW = "\033[33m";
const char* RESET = "\033[0m";

void delay() { std::this_thread::sleep_for(std::chrono::milliseconds(300)); }

void print_result(const std::string& msg, bool ok, bool warning = false) {
    if(ok && !warning)
        std::cout << GREEN << msg << " [SUCCESS]" << RESET << std::endl;
    else if(ok && warning)
        std::cout << YELLOW << msg << " [WARNING]" << RESET << std::endl;
    else
        std::cout << RED << msg << " [FAILURE]" << RESET << std::endl;
    delay();
}

// Utility: Compare two files
bool files_equal(const std::string& f1, const std::string& f2) {
    std::ifstream a(f1, std::ios::binary), b(f2, std::ios::binary);
    std::istreambuf_iterator<char> ia(a), ib(b), end;
    return std::vector<char>(ia, end) == std::vector<char>(ib, end);
}

int main() {
    try {
        // ===== 1. Key Generation, Storage, and Loading =====
        std::cout << "Generating 2048-bit RSA key pair..." << std::endl; delay();
        KeyPair keys = GenerateKeyPair(KeySize::Bits2048);
        print_result("Key generation (2048 bits)", true);

        keys.public_key.save_pem("test_public.pem");
        keys.private_key.save_pem("test_private.pem");
        print_result("Saved public.pem and private.pem", true);

        bool loadedOK = false;
        try {
            RSAPublicKey pub = RSAPublicKey::load_pem("test_public.pem");
            RSAPrivateKey priv = RSAPrivateKey::load_pem("test_private.pem");
            loadedOK = (pub.n == keys.public_key.n) && (priv.n == keys.private_key.n);
        } catch (...) {}
        print_result("Loaded keys from files", loadedOK);

        // Try loading from non-existent file
        bool failLoad = false;
        try { (void)RSAPublicKey::load_pem("does_not_exist.pem"); }
        catch (...) { failLoad = true; }
        print_result("Loading from non-existent PEM fails", failLoad);

        // Test with 1024-bit key
        std::cout << "Generating 1024-bit RSA key pair..." << std::endl; delay();
        KeyPair keys1024 = GenerateKeyPair(KeySize::Bits1024);
        print_result("Key generation (1024 bits)", true);

        // ===== 2. Message Encryption/Decryption: Basic, Edge, Large, Unicode, Binary =====
        RSAPublicKey pub = RSAPublicKey::load_pem("test_public.pem");
        RSAPrivateKey priv = RSAPrivateKey::load_pem("test_private.pem");
        delay();

        // 2.1 Simple message
        std::string msg = "Hello, RSA!";
        auto enc = MESSAGE::Encrypt(msg, pub);
        auto dec = MESSAGE::Decrypt(enc.toFormat(OutputFormat::Binary), priv);
        print_result("Simple message roundtrip", dec.toString() == msg);

        // 2.2 Empty message
        bool caughtEmpty = false;
        try { MESSAGE::Encrypt("", pub); }
        catch (...) { caughtEmpty = true; }
        print_result("Encrypting empty message fails", caughtEmpty);

        // 2.3 Special characters
        std::string msg2 = "¡Hola! Привет! こんにちは!";
        auto enc2 = MESSAGE::Encrypt(msg2, pub);
        auto dec2 = MESSAGE::Decrypt(enc2.toFormat(OutputFormat::Binary), priv);
        print_result("Special chars message roundtrip", dec2.toString() == msg2);

        // 2.4 Large message (300 bytes)
        std::string large(300, 'A');
        auto enc3 = MESSAGE::Encrypt(large, pub);
        auto dec3 = MESSAGE::Decrypt(enc3, priv);
        print_result("Large message roundtrip", dec3.toString() == large);

        // 2.5 Binary data
        std::string binmsg = std::string("\0\1\2\3\4\5\6\7\0\xff", 10);
        auto enc4 = MESSAGE::Encrypt(binmsg, pub);
        auto dec4 = MESSAGE::Decrypt(enc4, priv);
        print_result("Binary data roundtrip", dec4.toString() == binmsg);

        // 2.6 Unicode edge (emoji)
        std::string emoji = "Test 🚀🔒";
        auto enc5 = MESSAGE::Encrypt(emoji, pub);
        auto dec5 = MESSAGE::Decrypt(enc5, priv);
        print_result("Emoji message roundtrip", dec5.toString() == emoji);

        // 2.7 Repeated encrypt/decrypt
        bool repeat_ok = true;
        std::string rmsg = "Repeat test!";
        for(int i=0;i<10;++i) {
            auto e = MESSAGE::Encrypt(rmsg, pub);
            auto d = MESSAGE::Decrypt(e, priv);
            if(d.toString() != rmsg) { repeat_ok = false; break; }
        }
        print_result("Repeated encrypt/decrypt", repeat_ok);

        // ===== 3. Output Formats: HEX, BASE64, BINARY =====
        // HEX
        auto encHex = enc.toFormat(OutputFormat::Hex);
        std::string hexStr = encHex.toString();
        auto decHex = MESSAGE::Decrypt(EncryptedResult(RSA::UTIL::hex_to_bytes(hexStr)), priv);
        print_result("HEX format roundtrip", decHex.toString() == msg);

        // BASE64
        auto encBase64x = enc.toFormat(OutputFormat::Base64);
        std::string b64Str = encBase64x.toString();
        auto decBase64 = MESSAGE::Decrypt(EncryptedResult(PEM_DER::base64_decode(b64Str)), priv);
        print_result("BASE64 format roundtrip", decBase64.toString() == msg);

        // BINARY
        auto binVec = enc.toFormat(OutputFormat::Binary).toVector();
        auto decBin = MESSAGE::Decrypt(EncryptedResult(binVec), priv);
        print_result("BINARY format roundtrip", decBin.toString() == msg);

        // ===== 4. File Encryption/Decryption: All Formats, Edge, Error Cases =====
        std::ofstream testfile("test_input.txt");
        testfile << "This is a test file for RSA file encryption!";
        testfile.close();
        print_result("Created test_input.txt", true);

        // Encrypt/Decrypt (Base64)
        RSA::FILE::Encrypt("test_input.txt", "enc_b64.txt", pub, OutputFormat::Base64);
        RSA::FILE::Decrypt("enc_b64.txt", "dec_b64.txt", priv, OutputFormat::Base64);
        print_result("File roundtrip (Base64)", files_equal("test_input.txt", "dec_b64.txt"));

        // Encrypt/Decrypt (Hex)
        RSA::FILE::Encrypt("test_input.txt", "enc_hex.txt", pub, OutputFormat::Hex);
        RSA::FILE::Decrypt("enc_hex.txt", "dec_hex.txt", priv, OutputFormat::Hex);
        print_result("File roundtrip (Hex)", files_equal("test_input.txt", "dec_hex.txt"));

        // Encrypt/Decrypt (Binary)
        RSA::FILE::Encrypt("test_input.txt", "enc_bin.bin", pub, OutputFormat::Binary);
        RSA::FILE::Decrypt("enc_bin.bin", "dec_bin.txt", priv, OutputFormat::Binary);
        print_result("File roundtrip (Binary)", files_equal("test_input.txt", "dec_bin.txt"));

        // Try encrypting non-existent file
        bool fileFail = false;
        try { RSA::FILE::Encrypt("no_file.txt", "out.txt", pub, OutputFormat::Binary); }
        catch (...) { fileFail = true; }
        print_result("Encrypt non-existent file fails", fileFail);

        // Try decrypting non-existent file
        bool fileFail2 = false;
        try { RSA::FILE::Decrypt("no_file.txt", "out.txt", priv, OutputFormat::Binary); }
        catch (...) { fileFail2 = true; }
        print_result("Decrypt non-existent file fails", fileFail2);

        // ===== 5. Error Handling: Wrong Key, Invalid Format, Invalid PEM =====
        KeyPair wrongKeys = GenerateKeyPair(KeySize::Bits1024);
        bool wrongKeyFail = false;
        try {
            auto badDec = MESSAGE::Decrypt(enc.toFormat(OutputFormat::Binary), wrongKeys.private_key);
            wrongKeyFail = (badDec.toString() != msg);
        } catch (...) { wrongKeyFail = true; }
        print_result("Decrypt with wrong key fails or yields incorrect result", wrongKeyFail);

        // Invalid format in decode_by_format
        bool badFormat = false;
        try {
            auto _ = INTERNAL::decode_by_format("test", static_cast<OutputFormat>(9999));
        } catch (...) { badFormat = true; }
        print_result("Decode by invalid format fails", badFormat);

        // Invalid PEM
        bool badPEM = false;
        try { RSAPublicKey::from_pem("NOT_A_PEM"); }
        catch (...) { badPEM = true; }
        print_result("Invalid PEM input fails", badPEM);

        // ===== 6. PEM Export/Import of Keys, Validate Equality =====
        std::string pubPEM = keys.public_key.to_pem();
        std::string privPEM = keys.private_key.to_pem();
        RSAPublicKey pub2 = RSAPublicKey::from_pem(pubPEM);
        RSAPrivateKey priv2 = RSAPrivateKey::from_pem(privPEM);
        print_result("PEM import/export (public key)", pub2.n == keys.public_key.n && pub2.e == keys.public_key.e);
        print_result("PEM import/export (private key)", priv2.n == keys.private_key.n && priv2.d == keys.private_key.d);

        std::cout << GREEN << "All tests completed!" << RESET << std::endl;
    } catch (const std::exception& ex) {
        std::cout << RED << "Exception occurred: " << ex.what() << RESET << std::endl;
    }
    return 0;
}
