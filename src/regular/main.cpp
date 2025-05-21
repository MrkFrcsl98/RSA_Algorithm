
#include "rsa.hpp"
#include <iostream>
#include <fstream>

int main() {
    using namespace RSA;

    try {
        std::cout << "Generating RSA keypair..." << std::endl;
        KeyPair keys = GenerateKeyPair(KeySize::Bits2048);
        std::cout << "Keypair generated.\n";
        
        // Save keys
        keys.public_key.save_pem("public.pem");
        keys.private_key.save_pem("private.pem");
        std::cout << "Keys saved to 'public.pem' and 'private.pem'.\n";
        
        // Load keys
        RSAPublicKey pub_loaded = RSAPublicKey::load_pem("public.pem");
        RSAPrivateKey priv_loaded = RSAPrivateKey::load_pem("private.pem");
        std::cout << "Keys loaded from files.\n";
        
        // Encrypt and decrypt a message
        std::string message = "Hello, RSA!";
        std::cout << "Encrypting message: " << message << std::endl;
        auto encrypted = MESSAGE::Encrypt(message, pub_loaded);
        auto decrypted = MESSAGE::Decrypt(encrypted, priv_loaded);
        std::string decrypted_str = decrypted.toString();
        std::cout << "Decrypted message: " << decrypted_str << std::endl;
        if (decrypted_str == message)
            std::cout << "Message encryption/decryption: Success\n";
        else
            std::cout << "Message encryption/decryption: Failure\n";
        
        // Prepare a file for encryption
        const char* filename = "plain.txt";
        std::ofstream(filename) << "This is a test file for RSA encryption.";
        std::cout << "Test file '" << filename << "' created.\n";

        // Encrypt the file
        try {
            RSA::FILE::Encrypt(filename, "encrypted.bin", pub_loaded, OutputFormat::Binary);
            std::cout << "File encryption: Success\n";
        } catch (std::exception& e) {
            std::cout << "File encryption: Failure (" << e.what() << ")\n";
        }

        // Decrypt the file
        try {
            RSA::FILE::Decrypt("encrypted.bin", "decrypted.txt", priv_loaded, OutputFormat::Binary);
            std::cout << "File decryption: Success\n";

            // Compare the original and decrypted file
            std::ifstream orig(filename), dec("decrypted.txt");
            std::string orig_str((std::istreambuf_iterator<char>(orig)), std::istreambuf_iterator<char>());
            std::string dec_str((std::istreambuf_iterator<char>(dec)), std::istreambuf_iterator<char>());
            if (orig_str == dec_str)
                std::cout << "File content matches: Success\n";
            else
                std::cout << "File content does not match: Failure\n";
        } catch (std::exception& e) {
            std::cout << "File decryption: Failure (" << e.what() << ")\n";
        }
    } catch (std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
