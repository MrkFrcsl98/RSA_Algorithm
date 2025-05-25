#include "rsa.hpp"
#include <iostream>
#include <cassert>

int main() {
    
    RSA::KeyPair kp = RSA::GenerateKeyPair(RSA::KeySize::Bits1024);
    kp.public_key.save_x509_pem("public_x509.pem");
    kp.private_key.save_pem("private.pem");

    RSA::RSAPublicKey pub = RSA::RSAPublicKey::load_x509_pem("public_x509.pem");
    RSA::RSAPrivateKey priv = RSA::RSAPrivateKey::load_pem("private.pem");

    std::string msg = "hello x509";
    auto enc = RSA::MESSAGE::Encrypt(msg, pub);
    std::string dec = RSA::MESSAGE::Decrypt(enc, priv).toString();

    std::cout << dec << std::endl;
    assert(dec == msg);

    const std::string OAEP_LABEL("some label");
    RSA::FILE::Encrypt("plain.txt", "rsa_enc.bin", pub, RSA::OutputFormat::Binary, OAEP_LABEL);
    RSA::FILE::Decrypt("rsa_enc.bin", "rsa_dec.txt", priv, RSA::OutputFormat::Binary, OAEP_LABEL);

    return 0;
}
