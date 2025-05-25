#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

#define KEY_BITS 2048
#define PLAINTEXT_FILE "plain.txt"
#define PUBKEY_FILE "public.pem"
#define PRIVKEY_FILE "private.pem"
#define ENCRYPTED_FILE "encrypted.bin"
#define DECRYPTED_FILE "decrypted.txt"

#define ANSI_COLOR_GREEN  "\033[1;32m"
#define ANSI_COLOR_RED    "\033[1;31m"
#define ANSI_COLOR_YELLOW "\033[1;33m"
#define ANSI_COLOR_RESET  "\033[0m"

void print_success(const char *fmt, ...) {
    va_list args;
    printf(ANSI_COLOR_GREEN "[SUCCESS] " ANSI_COLOR_RESET);
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

void print_error(const char *fmt, ...) {
    va_list args;
    printf(ANSI_COLOR_RED "[ERROR]   " ANSI_COLOR_RESET);
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

void print_info(const char *fmt, ...) {
    va_list args;
    printf(ANSI_COLOR_YELLOW "[INFO]    " ANSI_COLOR_RESET);
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

static void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; ++i)
        printf("%02x", buf[i]);
    printf("\n");
}

int main(void) {
    int status = 0;
    rsa_public_key pub, pub2, pub3, pub4, pub_oaep;
    rsa_private_key priv, priv2, priv3, priv4, priv_oaep;
    mpz_t m, c, m2, ciphertext;
    char buffer[1024] = {0};
    char decbuf[1024] = {0};
    unsigned char derbuf[4096];
    size_t derlen = 0, count = 0;
    FILE *f = NULL;

    // OAEP variables
    const uint8_t oaep_label[] = "OAEP Label";
    int bits = 1024;
    const char *oaep_msg = "Message with OAEP!";
    size_t oaep_msg_len = 0, clen = 0, cbuflen = 0, decrypted_len = 0;
    uint8_t *cbuf = NULL;
    uint8_t decrypted[512];

    // --- Key Generation ---
    print_info("Generating %d-bit RSA keypair...\n", KEY_BITS);
    rsa_generate_keypair(&pub, &priv, KEY_BITS);
    print_success("Keypair generated\n");

    // --- Save keys to PEM files (X.509/PKCS#8) ---
    status = rsa_save_public_x509_pem(PUBKEY_FILE, &pub);
    status ? print_success("Saved public key to %s\n", PUBKEY_FILE) : print_error("Saving public key to %s\n", PUBKEY_FILE);

    status = rsa_save_private_pkcs8_pem(PRIVKEY_FILE, &priv);
    status ? print_success("Saved private key to %s\n", PRIVKEY_FILE) : print_error("Saving private key to %s\n", PRIVKEY_FILE);

    // --- Reload keys from files ---
    status = rsa_load_public_x509_pem(PUBKEY_FILE, &pub2);
    status ? print_success("Loaded public key from %s\n", PUBKEY_FILE) : print_error("Loading public key from %s\n", PUBKEY_FILE);

    status = rsa_load_private_pkcs8_pem(PRIVKEY_FILE, &priv2);
    status ? print_success("Loaded private key from %s\n", PRIVKEY_FILE) : print_error("Loading private key from %s\n", PRIVKEY_FILE);

    // --- Prepare message ---
    const char *message = "Hello, RSA world!";
    mpz_inits(m, c, m2, NULL);
    mpz_import(m, strlen(message), 1, 1, 1, 0, message);

    // --- Encrypt with public key ---
    print_info("Encrypting message with public key...\n");
    rsa_encrypt(c, m, &pub2);
    print_success("Message encrypted\n");

    // --- Decrypt with private key ---
    print_info("Decrypting message with private key...\n");
    rsa_decrypt(m2, c, &priv2);
    print_success("Message decrypted\n");

    // --- Export decrypted message ---
    memset(buffer, 0, sizeof(buffer));
    count = 0;
    mpz_export(buffer, &count, 1, 1, 1, 0, m2);
    buffer[count] = '\0';
    print_info("Original message:  '%s'\n", message);
    print_info("Decrypted message: '%s'\n", buffer);

    if (memcmp(message, buffer, strlen(message)) == 0) {
        print_success("RSA encrypt/decrypt match\n");
    } else {
        print_error("RSA encrypt/decrypt mismatch\n");
    }

    // --- File encryption/decryption demo ---
    print_info("Writing plaintext to file '%s'...\n", PLAINTEXT_FILE);
    f = fopen(PLAINTEXT_FILE, "w");
    if (f) {
        fwrite(message, 1, strlen(message), f);
        fclose(f);
        print_success("Plaintext written\n");
    } else {
        print_error("Failed to write plaintext file\n");
    }

    // Encrypt file
    print_info("Encrypting file '%s' -> '%s'...\n", PLAINTEXT_FILE, ENCRYPTED_FILE);
    status = rsa_encrypt_file(PLAINTEXT_FILE, ENCRYPTED_FILE, &pub2);
    status ? print_success("File encrypted to %s\n", ENCRYPTED_FILE) : print_error("File encryption to %s\n", ENCRYPTED_FILE);

    // Decrypt file
    print_info("Decrypting file '%s' -> '%s'...\n", ENCRYPTED_FILE, DECRYPTED_FILE);
    status = rsa_decrypt_file(ENCRYPTED_FILE, DECRYPTED_FILE, &priv2);
    status ? print_success("File decrypted to %s\n", DECRYPTED_FILE) : print_error("File decryption to %s\n", DECRYPTED_FILE);

    // Verify file content
    memset(decbuf, 0, sizeof(decbuf));
    f = fopen(DECRYPTED_FILE, "r");
    if (f) {
        size_t n = fread(decbuf, 1, sizeof(decbuf) - 1, f);
        fclose(f);
        decbuf[n] = 0;
        print_info("Decrypted file content: '%s'\n", decbuf);
        if (strcmp(message, decbuf) == 0)
            print_success("File encrypt/decrypt match\n");
        else
            print_error("File encrypt/decrypt mismatch\n");
    } else {
        print_error("Failed to read decrypted file\n");
    }

    // --- Try all PEM, DER, and classic save/load operations ---
    print_info("Testing all key save/load operations...\n");
    status = rsa_save_public(PUBKEY_FILE ".classic", &pub);
    status ? print_success("Classic public key saved\n") : print_error("Classic public key save\n");

    status = rsa_save_private(PRIVKEY_FILE ".classic", &priv);
    status ? print_success("Classic private key saved\n") : print_error("Classic private key save\n");

    status = rsa_load_public(PUBKEY_FILE ".classic", &pub3);
    status ? print_success("Classic public key loaded\n") : print_error("Classic public key load\n");

    status = rsa_load_private(PRIVKEY_FILE ".classic", &priv3);
    status ? print_success("Classic private key loaded\n") : print_error("Classic private key load\n");

    // Test DER serialization
    derlen = rsa_serialize_public_der(&pub, derbuf, sizeof(derbuf));
    derlen ? print_success("Public DER serialization (%zu bytes)\n", derlen) : print_error("Public DER serialization\n");

    status = rsa_deserialize_public_der(&pub4, derbuf, derlen);
    status ? print_success("Public DER deserialization\n") : print_error("Public DER deserialization\n");

    derlen = rsa_serialize_private_der(&priv, derbuf, sizeof(derbuf));
    derlen ? print_success("Private DER serialization (%zu bytes)\n", derlen) : print_error("Private DER serialization\n");

    status = rsa_deserialize_private_der(&priv4, derbuf, derlen);
    status ? print_success("Private DER deserialization\n") : print_error("Private DER deserialization\n");

    // --- OAEP demo ---
    print_info("Testing RSA-OAEP encryption/decryption...\n");
    rsa_generate_keypair(&pub_oaep, &priv_oaep, bits);

    oaep_msg_len = strlen(oaep_msg);
    mpz_init(ciphertext);

    if (!rsa_encrypt_oaep(ciphertext, (const uint8_t *)oaep_msg, oaep_msg_len, &pub_oaep, oaep_label, sizeof(oaep_label) - 1)) {
        print_error("OAEP Encryption failed!\n");
        goto cleanup;
    }

    // Print ciphertext as hex
    print_info("OAEP ciphertext (hex): ");
    clen = (mpz_sizeinbase(pub_oaep.n, 2) + 7) / 8;
    cbuf = (uint8_t *)calloc(1, clen);
    if (!cbuf) {
        print_error("Allocation failed for cbuf\n");
        goto cleanup;
    }
    mpz_export(cbuf, &cbuflen, 1, 1, 1, 0, ciphertext);
    if (cbuflen < clen) {
        memmove(cbuf + (clen - cbuflen), cbuf, cbuflen);
        memset(cbuf, 0, clen - cbuflen);
    }
    print_hex(cbuf, clen);

    decrypted_len = 0;
    if (!rsa_decrypt_oaep(decrypted, &decrypted_len, ciphertext, &priv_oaep, oaep_label, sizeof(oaep_label) - 1)) {
        print_error("OAEP Decryption failed!\n");
        goto cleanup;
    }

    print_info("OAEP original message: %s\n", oaep_msg);
    print_info("OAEP decrypted message: %.*s\n", (int)decrypted_len, decrypted);

    if (decrypted_len == strlen(oaep_msg) && memcmp(oaep_msg, decrypted, decrypted_len) == 0)
        print_success("OAEP encrypt/decrypt match\n");
    else
        print_error("OAEP encrypt/decrypt mismatch\n");

cleanup:
    if (cbuf) free(cbuf);
    mpz_clear(ciphertext);
    rsa_clear_public(&pub_oaep);
    rsa_clear_private(&priv_oaep);

    // --- Final Cleanup ---
    rsa_clear_public(&pub);
    rsa_clear_private(&priv);
    rsa_clear_public(&pub2);
    rsa_clear_private(&priv2);
    rsa_clear_public(&pub3);
    rsa_clear_private(&priv3);
    rsa_clear_public(&pub4);
    rsa_clear_private(&priv4);
    mpz_clears(m, c, m2, NULL);

    print_success("Test complete.\n");
    return 0;
}
