#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsa.h"

#define PUBKEY_FILE "public_x509.pem"
#define PRIVKEY_FILE "private_pkcs8.pem"
#define ENCRYPTED_FILE "encrypted.bin"
#define DECRYPTED_FILE "decrypted.txt"
#define FILENAME "plain.txt"
#define MSG "Hello, world! This is an RSA test."

int main(void) {
    rsa_public_key pub;
    rsa_private_key priv;

    printf("Generating RSA keypair...\n");
    rsa_generate_keypair(&pub, &priv, 2048);

    printf("Saving public key (X.509 PEM)...\n");
    if (!rsa_save_public_x509_pem(PUBKEY_FILE, &pub)) {
        fprintf(stderr, "Failed to save public key!\n");
        return 1;
    }

    printf("Saving private key (PKCS#8 PEM)...\n");
    if (!rsa_save_private_pkcs8_pem(PRIVKEY_FILE, &priv)) {
        fprintf(stderr, "Failed to save private key!\n");
        return 1;
    }

    // Clear keys
    rsa_clear_public(&pub);
    rsa_clear_private(&priv);

    printf("Loading public key from PEM...\n");
    if (!rsa_load_public_x509_pem(PUBKEY_FILE, &pub)) {
        fprintf(stderr, "Failed to load public key!\n");
        return 1;
    }
    printf("Loading private key from PEM...\n");
    if (!rsa_load_private_pkcs8_pem(PRIVKEY_FILE, &priv)) {
        fprintf(stderr, "Failed to load private key!\n");
        return 1;
    }

    // --- Encrypt/Decrypt a file ---
    FILE *f = fopen(FILENAME, "w");
    fputs("This is a test file for RSA encryption!!!\n", f);
    fclose(f);

    printf("Encrypting file...\n");
    if (!rsa_encrypt_file(FILENAME, ENCRYPTED_FILE, &pub)) {
        fprintf(stderr, "Failed to encrypt file!\n");
        return 1;
    }

    printf("Decrypting file...\n");
    if (!rsa_decrypt_file(ENCRYPTED_FILE, DECRYPTED_FILE, &priv)) {
        fprintf(stderr, "Failed to decrypt file!\n");
        return 1;
    }

    // --- Encrypt/Decrypt a message ---
    printf("Encrypting and decrypting a message...\n");

    mpz_t m, c, m_dec;
    mpz_inits(m, c, m_dec, NULL);

    // Convert message to mpz
    mpz_import(m, strlen(MSG), 1, 1, 1, 0, MSG);

    // Encrypt
    rsa_encrypt(c, m, &pub);

    // Decrypt
    rsa_decrypt(m_dec, c, &priv);

    // Convert back to string
    size_t msg_len;
    char *decrypted_msg = (char*)malloc(strlen(MSG) + 1);
    mpz_export(decrypted_msg, &msg_len, 1, 1, 1, 0, m_dec);
    decrypted_msg[msg_len] = '\0';

    printf("Original message: \"%s\"\n", MSG);
    printf("Decrypted message: \"%s\"\n", decrypted_msg);

    free(decrypted_msg);
    mpz_clears(m, c, m_dec, NULL);

    rsa_clear_public(&pub);
    rsa_clear_private(&priv);

    printf("Demo complete!\n");
    return 0;
}
