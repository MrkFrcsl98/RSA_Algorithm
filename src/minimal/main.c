#include "rsa.h"
#include <stdio.h>
#include <string.h>

#define PUBKEY_FILE "pub.pem"
#define PRIVKEY_FILE "priv.pem"
#define PLAINTEXT_FILE "plain.txt"
#define ENCRYPTED_FILE "enc.bin"
#define DECRYPTED_FILE "dec.txt"
#define KEY_BITS 2048

int main() {
    int status = 0;

    // --- Key Generation ---
    rsa_public_key pub;
    rsa_private_key priv;
    printf("[*] Generating %d-bit RSA keypair...\n", KEY_BITS);
    rsa_generate_keypair(&pub, &priv, KEY_BITS);
    printf("[OK] Keypair generated\n");

    // --- Save keys to PEM files (X.509/PKCS#8) ---
    status = rsa_save_public_x509_pem(PUBKEY_FILE, &pub);
    printf("%s public key to %s\n", status ? "[OK]" : "[FAIL]", PUBKEY_FILE);

    status = rsa_save_private_pkcs8_pem(PRIVKEY_FILE, &priv);
    printf("%s private key to %s\n", status ? "[OK]" : "[FAIL]", PRIVKEY_FILE);

    rsa_public_key pub2;
    rsa_private_key priv2;
    status = rsa_load_public_x509_pem(PUBKEY_FILE, &pub2);
    printf("%s loading public key from %s\n", status ? "[OK]" : "[FAIL]", PUBKEY_FILE);

    status = rsa_load_private_pkcs8_pem(PRIVKEY_FILE, &priv2);
    printf("%s loading private key from %s\n", status ? "[OK]" : "[FAIL]", PRIVKEY_FILE);

    // --- Prepare message ---
    const char *message = "Hello, RSA world!";
    mpz_t m, c, m2;
    mpz_inits(m, c, m2, NULL);
    mpz_import(m, strlen(message), 1, 1, 1, 0, message);

    // --- Encrypt with public key ---
    printf("[*] Encrypting message with public key...\n");
    rsa_encrypt(c, m, &pub2);
    printf("[OK] Message encrypted\n");

    // --- Decrypt with private key ---
    printf("[*] Decrypting message with private key...\n");
    rsa_decrypt(m2, c, &priv2);
    printf("[OK] Message decrypted\n");

    // --- Export decrypted message ---
    char buffer[1024] = {0};
    size_t count = 0;
    mpz_export(buffer, &count, 1, 1, 1, 0, m2);
    buffer[count] = '\0';
    printf("[*] Original message:  '%s'\n", message);
    printf("[*] Decrypted message: '%s'\n", buffer);

    if (memcmp(message, buffer, strlen(message)) == 0) {
        printf("[OK] RSA encrypt/decrypt\n");
    } else {
        printf("[FAIL] RSA encrypt/decrypt\n");
    }

    // --- File encryption/decryption demo ---
    printf("[*] Writing plaintext to file '%s'...\n", PLAINTEXT_FILE);
    FILE *f = fopen(PLAINTEXT_FILE, "w");
    if (f) {
        fwrite(message, 1, strlen(message), f);
        fclose(f);
        printf("[OK] Plaintext written\n");
    } else {
        printf("[FAIL] Failed to write plaintext file\n");
    }

    // Encrypt file
    printf("[*] Encrypting file '%s' -> '%s'...\n", PLAINTEXT_FILE, ENCRYPTED_FILE);
    status = rsa_encrypt_file(PLAINTEXT_FILE, ENCRYPTED_FILE, &pub2);
    printf("%s file encryption to %s\n", status ? "[OK]" : "[FAIL]", ENCRYPTED_FILE);

    // Decrypt file
    printf("[*] Decrypting file '%s' -> '%s'...\n", ENCRYPTED_FILE, DECRYPTED_FILE);
    status = rsa_decrypt_file(ENCRYPTED_FILE, DECRYPTED_FILE, &priv2);
    printf("%s file decryption to %s\n", status ? "[OK]" : "[FAIL]", DECRYPTED_FILE);

    // Verify file content
    char decbuf[1024] = {0};
    f = fopen(DECRYPTED_FILE, "r");
    if (f) {
        size_t n = fread(decbuf, 1, sizeof(decbuf)-1, f);
        fclose(f);
        decbuf[n] = 0;
        printf("[*] Decrypted file content: '%s'\n", decbuf);
        if (strcmp(message, decbuf) == 0)
            printf("[OK] File encrypt/decrypt\n");
        else
            printf("[FAIL] File encrypt/decrypt\n");
    } else {
        printf("[FAIL] Failed to read decrypted file\n");
    }

    // --- Try all PEM, DER, and classic save/load operations ---
    printf("[*] Testing all key save/load operations...\n");
    status = rsa_save_public(PUBKEY_FILE ".classic", &pub);
    printf("%s classic public key save\n", status ? "[OK]" : "[FAIL]");

    status = rsa_save_private(PRIVKEY_FILE ".classic", &priv);
    printf("%s classic private key save\n", status ? "[OK]" : "[FAIL]");

    rsa_public_key pub3;
    rsa_private_key priv3;
    status = rsa_load_public(PUBKEY_FILE ".classic", &pub3);
    printf("%s classic public key load\n", status ? "[OK]" : "[FAIL]");

    status = rsa_load_private(PRIVKEY_FILE ".classic", &priv3);
    printf("%s classic private key load\n", status ? "[OK]" : "[FAIL]");

    // Test DER serialization
    unsigned char derbuf[4096];
    size_t derlen;
    derlen = rsa_serialize_public_der(&pub, derbuf, sizeof(derbuf));
    printf("%s public DER serialization (%zu bytes)\n", derlen ? "[OK]" : "[FAIL]", derlen);

    rsa_public_key pub4;
    status = rsa_deserialize_public_der(&pub4, derbuf, derlen);
    printf("%s public DER deserialization\n", status ? "[OK]" : "[FAIL]");

    derlen = rsa_serialize_private_der(&priv, derbuf, sizeof(derbuf));
    printf("%s private DER serialization (%zu bytes)\n", derlen ? "[OK]" : "[FAIL]", derlen);

    rsa_private_key priv4;
    status = rsa_deserialize_private_der(&priv4, derbuf, derlen);
    printf("%s private DER deserialization\n", status ? "[OK]" : "[FAIL]");

    // --- Cleanup ---
    rsa_clear_public(&pub);
    rsa_clear_private(&priv);
    rsa_clear_public(&pub2);
    rsa_clear_private(&priv2);
    rsa_clear_public(&pub3);
    rsa_clear_private(&priv3);
    rsa_clear_public(&pub4);
    rsa_clear_private(&priv4);
    mpz_clears(m, c, m2, NULL);

    printf("[OK] Test complete.\n");
    return 0;
}
