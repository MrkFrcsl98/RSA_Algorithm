#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "rsa.h"

// Helper to print status
#define CHECK(x, msg) do { if (!(x)) { fprintf(stderr, "FAIL: %s\n", msg); exit(1); } } while(0)

int main() {
    RSAKeyPair kp;
    rsa_public_key_init(&kp.public_key);
    rsa_private_key_init(&kp.private_key);

    // Generate RSA keypair (2048 bits)
    rsa_generate_keypair(&kp, KEYSIZE_2048);
    printf("Keypair generated.\n");

    // Save in different formats
    CHECK(rsa_public_key_save_pem("pub.pem", &kp.public_key), "Saving public PEM");
    CHECK(rsa_private_key_save_pem("priv.pem", &kp.private_key), "Saving private PEM");

    char *pub_x509 = rsa_public_key_to_x509_pem(&kp.public_key);
    char *priv_pkcs8 = rsa_private_key_to_pkcs8_pem(&kp.private_key);
    CHECK(pub_x509 && priv_pkcs8, "Serialization to X.509/PKCS#8");

    CHECK(write_text("pub_x509.pem", pub_x509), "Writing X.509 PEM");
    CHECK(write_text("priv_pkcs8.pem", priv_pkcs8), "Writing PKCS#8 PEM");

    free(pub_x509);
    free(priv_pkcs8);

    // Encrypt a message (in-memory, without loading keys)
    const char *message = "Hello, RSA!";
    size_t mod_bytes = (mpz_sizeinbase(kp.public_key.n, 2) + 7) / 8;
    uint8_t *encrypted = (uint8_t*)malloc(mod_bytes);
    size_t encrypted_len = 0;

    CHECK(rsa_encrypt((const uint8_t *)message, strlen(message), &kp.public_key, encrypted, &encrypted_len), "Encrypt message");

    // Decrypt the message
    uint8_t *decrypted = (uint8_t*)malloc(mod_bytes);
    size_t decrypted_len = 0;
    CHECK(rsa_decrypt(encrypted, encrypted_len, &kp.private_key, decrypted, &decrypted_len), "Decrypt message");

    printf("Decrypted message: %.*s\n", (int)decrypted_len, decrypted);

    // Encrypt contents of plain.txt
    size_t plain_len = 0;
    uint8_t *plain_data = read_file("plain.txt", &plain_len);
    CHECK(plain_data, "Read plain.txt");

    // If too large for RSA, truncate or error
    if (plain_len > mod_bytes - 11) {
        printf("plain.txt too large for one RSA encryption block, truncating.\n");
        plain_len = mod_bytes - 11;
    }

    size_t encrypted_file_len = 0;
    CHECK(rsa_encrypt(plain_data, plain_len, &kp.public_key, encrypted, &encrypted_file_len), "Encrypt plain.txt");

    CHECK(write_file("encrypted.bin", encrypted, encrypted_file_len), "Write encrypted.bin");

    // Decrypt file
    uint8_t *enc_file_data = read_file("encrypted.bin", &encrypted_file_len);
    CHECK(enc_file_data, "Read encrypted.bin");
    uint8_t *decrypted_file = (uint8_t*)malloc(mod_bytes);
    size_t decrypted_file_len = 0;
    CHECK(rsa_decrypt(enc_file_data, encrypted_file_len, &kp.private_key, decrypted_file, &decrypted_file_len), "Decrypt encrypted.bin");

    CHECK(write_file("decrypted.txt", decrypted_file, decrypted_file_len), "Write decrypted.txt");

    // Cleanup
    free(encrypted);
    free(decrypted);
    free(plain_data);
    free(enc_file_data);
    free(decrypted_file);
    rsa_public_key_clear(&kp.public_key);
    rsa_private_key_clear(&kp.private_key);

    printf("Demo completed successfully.\n");
    return 0;
}
