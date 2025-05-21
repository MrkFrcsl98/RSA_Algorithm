#include "rsa.hpp"
#include <iostream>
#include <fstream>

int main() {
    using namespace RSA;

    // 1. Generate key pair
    const KeyPair kp = GenerateKeyPair(KeySize::Bits1024);

    // 2. Store keys
    kp.public_key.save_pem("public.pem");
    kp.private_key.save_pem("private.pem");

    // 3. Load keys from file
    const RSAPublicKey pub = RSAPublicKey::load_pem("public.pem");
    const RSAPrivateKey priv = RSAPrivateKey::load_pem("private.pem");

    // 4. Encrypt and decrypt a message
    const std::string msg = "Hello, RSA!";
    const std::string encrypted = MESSAGE::Encrypt(msg, pub).toFormat(OutputFormat::Base64).toString();
    const std::string decrypted = MESSAGE::Decrypt(encrypted, priv, OutputFormat::Base64);
    std::cout << "Original: " << msg << "\n";
    std::cout << "Encrypted (base64): " << encrypted << "\n";
    std::cout << "Decrypted: " << decrypted << "\n";

    // 5. Encrypt and decrypt a file
    std::ofstream("plain.txt") << "Secret file contents!"; // create a test file and write something into it...
    
    RSA::FILE::Encrypt("plain.txt", "enc.bin", pub, OutputFormat::Binary);
    RSA::FILE::Decrypt("enc.bin", "dec.txt", priv, OutputFormat::Binary);

}
