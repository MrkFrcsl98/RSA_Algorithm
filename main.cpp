#include "rsa.hpp"
#include <iostream>

int main() {
    using namespace RSA_Cipher;
    RSA rsa(4096); // Use 1024 or higher for real security

    std::string msg = "hello";
    std::vector<uint8_t> plain(msg.begin(), msg.end());
    auto ciphertexts = rsa.encrypt(plain);
    auto decrypted = rsa.decrypt(ciphertexts);
    std::string recovered(decrypted.begin(), decrypted.end());

    
    std::cout << rsa.get_public_key_pem();
    std::cout << rsa.get_private_key_pem();
    
    std::cout << "Decrypted: " << recovered << std::endl;
}
