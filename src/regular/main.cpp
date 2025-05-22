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
    return 0;
}
