#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "rsa.h"

int main() {
    // 1. Generate Keypair
    RSAKeyPair kp;
    rsa_public_key_init(&kp.public_key);
    rsa_private_key_init(&kp.private_key);

    printf("Generating RSA keypair (1024 bits)...\n");
    rsa_generate_keypair(&kp, KEYSIZE_1024);

    // 2. Print and Save Keys as PEM
    char* pub_pem = rsa_public_key_to_pem(&kp.public_key);
    char* priv_pem = rsa_private_key_to_pem(&kp.private_key);

    printf("\nPublic Key (PEM):\n%s\n", pub_pem);
    printf("Private Key (PEM):\n%s\n", priv_pem);

    const int save_pubpem = rsa_public_key_save_pem("public.pem", &kp.public_key);
    const int save_privpem = rsa_private_key_save_pem("private.pem", &kp.private_key);

    // 3. Encrypt Message
    const char* message = "Hello, RSA World!";
    size_t msglen = strlen(message);
    size_t mod_bytes = (mpz_sizeinbase(kp.public_key.n, 2) + 7) / 8;
    uint8_t* ciphertext = (uint8_t*)malloc(mod_bytes);
    size_t clen = 0;
    if (!rsa_encrypt((const uint8_t*)message, msglen, &kp.public_key, ciphertext, &clen)) {
        fprintf(stderr, "Encryption failed.\n");
        return 1;
    }
    char* hex_enc = bytes_to_hex(ciphertext, clen);

    printf("\nOriginal message: %s\n", message);
    printf("Encrypted (hex): %s\n", hex_enc);

    // 4. Decrypt Message
    uint8_t* decrypted = (uint8_t*)malloc(mod_bytes);
    size_t dlen = 0;
    if (!rsa_decrypt(ciphertext, clen, &kp.private_key, decrypted, &dlen)) {
        fprintf(stderr, "Decryption failed.\n");
        return 1;
    }
    char* decrypted_str = (char*)malloc(dlen + 1);
    memcpy(decrypted_str, decrypted, dlen);
    decrypted_str[dlen] = '\0';

    printf("Decrypted message: %s\n", decrypted_str);

    // Cleanup
    free(ciphertext); 
    free(hex_enc); 
    free(decrypted); 
    free(decrypted_str);
    free(pub_pem); 
    free(priv_pem);
    rsa_public_key_clear(&kp.public_key);
    rsa_private_key_clear(&kp.private_key);

    return 0;
}
