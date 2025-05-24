#include "rsa.h"
#include <stdio.h>
#include <string.h>

#define KEY_BITS 2048
#define PLAINTEXT_FILE "plain.txt"
#define PUBKEY_FILE "public.pem"
#define PRIVKEY_FILE "private.pem"
#define ENCRYPTED_FILE "encrypted.bin"
#define DECRYPTED_FILE "decrypted.txt"
#define MSG "TEsting Rsa Encryption!"

void print_hex(const uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len; ++i)
    printf("%02x", buf[i]);
  printf("\n");
}

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
    size_t n = fread(decbuf, 1, sizeof(decbuf) - 1, f);
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

  {
    const uint8_t oaep_label[] = "OAEP Label";
    // 1. Key generation
    rsa_public_key pub;
    rsa_private_key priv;
    int bits = 1024; // RSA key size in bits (2048+ recommended for real use)
    rsa_generate_keypair(&pub, &priv, bits);

    // 2. Message to encrypt
    const char *message = "Message with OAEP!";
    size_t msg_len = strlen(message);

    // 3. OAEP encode + RSA encrypt
    mpz_t ciphertext;
    mpz_init(ciphertext);
    if (!rsa_encrypt_oaep(ciphertext, (const uint8_t *)message, msg_len, &pub, oaep_label, sizeof(oaep_label) - 1)) {
      printf("[FAIL] Encryption failed!\n");
      return 1;
    }

    // Print ciphertext as hex
    printf("[*] Ciphertext (hex): ");
    size_t clen = (mpz_sizeinbase(pub.n, 2) + 7) / 8;
    uint8_t *cbuf = (uint8_t *)malloc(clen);
    size_t cbuflen;
    mpz_export(cbuf, &cbuflen, 1, 1, 1, 0, ciphertext);
    // Left pad if necessary
    if (cbuflen < clen) {
      memmove(cbuf + (clen - cbuflen), cbuf, cbuflen);
      memset(cbuf, 0, clen - cbuflen);
    }
    print_hex(cbuf, clen);

    // 4. RSA decrypt + OAEP decode
    uint8_t decrypted[512];
    size_t decrypted_len;
    if (!rsa_decrypt_oaep(decrypted, &decrypted_len, ciphertext, &priv, oaep_label, sizeof(oaep_label) - 1)) {
      printf("[FAIL] Decryption failed!\n");
      return 1;
    }

    // 5. Print results
    printf("[*] Original message: %s\n", message);
    printf("[*] Decrypted message: %.*s\n", (int)decrypted_len, decrypted);

    // Cleanup
    mpz_clear(ciphertext);
    rsa_clear_public(&pub);
    rsa_clear_private(&priv);
    free(cbuf);
  }

  printf("[OK] Test complete.\n");
  return 0;
}
