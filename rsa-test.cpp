#include "rsa.hpp"
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>

using namespace RSA;
void delay() { std::this_thread::sleep_for(std::chrono::milliseconds(500)); }
void print_result(const std::string& msg, bool ok) {
    std::cout << msg << (ok ? " [SUCCESS]" : " [FAILURE]") << std::endl;
    delay();
}

int main() {
    try {
        // ===== 1. Key Generation, Storage, and Loading =====
        std::cout << "Generating 2048-bit RSA key pair..." << std::endl; delay();
        KeyPair keys = GenerateKeyPair(KeySize::Bits2048);
        print_result("Key generation", true);

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

        // ===== 2. Message Encryption/Decryption: Basic, Empty, Special, Large =====
        RSAPublicKey pub = RSAPublicKey::load_pem("test_public.pem");
        RSAPrivateKey priv = RSAPrivateKey::load_pem("test_private.pem");
        delay();

        // 2.1 Simple message
        std::string msg = "Hello, RSA!";
        auto enc = MESSAGE::Encrypt(msg, pub);
        std::string encBase64 = enc.toFormat(OutputFormat::Base64).toString();
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

        // 2.4 Large message (longer than modulus, should still work char-by-char)
        std::string large(300, 'A');
        auto enc3 = MESSAGE::Encrypt(large, pub);
        auto dec3 = MESSAGE::Decrypt(enc3, priv);
        print_result("Large message roundtrip", dec3.toString() == large);

        // ===== 3. Chaining Output Formats, toString, toVector, Roundtrip =====
        // HEX
        auto encHex = enc.toFormat(OutputFormat::Hex);
        std::string hexStr = encHex.toString();
        auto encFromHex = MESSAGE::Encrypt(msg, pub).toFormat(OutputFormat::Hex).toString();
        auto decHex = MESSAGE::Decrypt(EncryptedResult(RSA::UTIL::hex_to_bytes(encFromHex)), priv);
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

        // ===== 4. File Encryption/Decryption: All Formats, Error Cases =====
        std::ofstream testfile("test_input.txt");
        testfile << "This is a test file for RSA file encryption!";
        testfile.close();
        print_result("Created test_input.txt", true);

        // Encrypt/Decrypt (Base64)
        RSA::FILE::Encrypt("test_input.txt", "enc_b64.txt", pub, OutputFormat::Base64);
        RSA::FILE::Decrypt("enc_b64.txt", "dec_b64.txt", priv, OutputFormat::Base64);
        std::ifstream f1("dec_b64.txt");
        std::string r1((std::istreambuf_iterator<char>(f1)), {});
        print_result("File roundtrip (Base64)", r1 == "This is a test file for RSA file encryption!");

        // Encrypt/Decrypt (Hex)
        RSA::FILE::Encrypt("test_input.txt", "enc_hex.txt", pub, OutputFormat::Hex);
        RSA::FILE::Decrypt("enc_hex.txt", "dec_hex.txt", priv, OutputFormat::Hex);
        std::ifstream f2("dec_hex.txt");
        std::string r2((std::istreambuf_iterator<char>(f2)), {});
        print_result("File roundtrip (Hex)", r2 == "This is a test file for RSA file encryption!");

        // Encrypt/Decrypt (Binary)
        RSA::FILE::Encrypt("test_input.txt", "enc_bin.bin", pub, OutputFormat::Binary);
        RSA::FILE::Decrypt("enc_bin.bin", "dec_bin.txt", priv, OutputFormat::Binary);
        std::ifstream f3("dec_bin.txt");
        std::string r3((std::istreambuf_iterator<char>(f3)), {});
        print_result("File roundtrip (Binary)", r3 == "This is a test file for RSA file encryption!");

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

        // ===== 5. Error Handling: Wrong Key, Invalid Format =====
        // Generate a new, different keypair
        KeyPair wrongKeys = GenerateKeyPair(KeySize::Bits1024);
        bool wrongKeyFail = false;
        try {
            auto badDec = MESSAGE::Decrypt(enc.toFormat(OutputFormat::Binary), wrongKeys.private_key);
            // It may produce garbage, so check by comparing to original
            wrongKeyFail = (badDec.toString() != msg);
        } catch (...) { wrongKeyFail = true; }
        print_result("Decrypt with wrong key fails or yields incorrect result", wrongKeyFail);

        // Invalid format in decode_by_format
        bool badFormat = false;
        try {
            auto _ = INTERNAL::decode_by_format("test", static_cast<OutputFormat>(9999));
        } catch (...) { badFormat = true; }
        print_result("Decode by invalid format fails", badFormat);

        // ===== 6. PEM Export/Import of Keys, Validate Equality =====
        std::string pubPEM = keys.public_key.to_pem();
        std::string privPEM = keys.private_key.to_pem();
        RSAPublicKey pub2 = RSAPublicKey::from_pem(pubPEM);
        RSAPrivateKey priv2 = RSAPrivateKey::from_pem(privPEM);
        print_result("PEM import/export (public key)", pub2.n == keys.public_key.n && pub2.e == keys.public_key.e);
        print_result("PEM import/export (private key)", priv2.n == keys.private_key.n && priv2.d == keys.private_key.d);

        std::cout << "All tests completed!" << std::endl;
    } catch (const std::exception& ex) {
        std::cout << "Exception occurred: " << ex.what() << std::endl;
    }
    return 0;
}
