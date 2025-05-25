#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define COLOR_RED    "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_GREEN  "\033[32m"
#define COLOR_CYAN   "\033[36m"
#define COLOR_RESET  "\033[0m"

enum pemtype_pub { PUB_PKCS1, PUB_X509 };
enum pemtype_priv { PRIV_PKCS1, PRIV_PKCS8 };

int valid_key_size(int bits) {
    return bits == 1024 || bits == 2048 || bits == 3072 || bits == 4096;
}
int is_valid_filename(const char *fname) {
    if (!fname || !*fname) return 0;
    while (*fname) {
        if (!isprint((unsigned char)*fname) || strchr(":*?\"<>|", *fname)) return 0;
        fname++;
    }
    return 1;
}
void print_usage(int no_color) {
    if (!no_color) printf(COLOR_CYAN);
    puts(
"Usage:\n"
"  rsa_cli genkey --pub <public.pem> --priv <private.pem> [--bits <key size>] [--pem-type pkcs1|x509] [options]\n"
"  rsa_cli encrypt --pub <public.pem> --in <msg> --out <encrypted> [--msg] [options]\n"
"  rsa_cli decrypt --priv <private.pem> --in <encrypted> --out <decrypted> [--msg] [options]\n"
"Options:\n"
"  --pub         Public key PEM file\n"
"  --priv        Private key PEM file\n"
"  --in          Input file or message (with --msg)\n"
"  --out         Output file\n"
"  --bits        Key size: 1024, 2048, 3072, 4096 (default: 1024)\n"
"  --pem-type    For genkey: pkcs1 (default) or x509 (public key)\n"
"  --msg         Operate on a short message instead of file\n"
"  --force       Overwrite output files without prompt\n"
"  --quick       No prompts, use defaults when missing\n"
"  --no-color    Disable colored output\n"
"  --help        Show this help\n"
    );
    if (!no_color) printf(COLOR_RESET);
}
void print_error(const char *msg, int no_color) {
    if (!no_color) printf(COLOR_RED);
    printf("[ERROR] %s\n", msg);
    if (!no_color) printf(COLOR_RESET);
}
void print_success(const char *msg, int no_color) {
    if (!no_color) printf(COLOR_GREEN);
    printf("[SUCCESS] %s\n", msg);
    if (!no_color) printf(COLOR_RESET);
}
void print_warning(const char *msg, int no_color) {
    if (!no_color) printf(COLOR_YELLOW);
    printf("[WARNING] %s\n", msg);
    if (!no_color) printf(COLOR_RESET);
}
int file_exists(const char *fname) {
    FILE *f = fopen(fname, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}
int confirm_prompt(const char *question, int default_yes, int quick, int no_color) {
    if (quick) return 1;
    if (!no_color) printf(COLOR_YELLOW);
    printf("%s [%c/%c]: ", question, default_yes ? 'Y' : 'y', default_yes ? 'n' : 'N');
    if (!no_color) printf(COLOR_RESET);
    char resp[16] = {0};
    fgets(resp, sizeof(resp), stdin);
    if (resp[0] == '\n' || resp[0] == 0) return default_yes;
    return (tolower(resp[0]) == 'y');
}
void prompt_str(const char *q, char *dst, size_t max, const char *def, int quick, int no_color) {
    if (quick && def) { strncpy(dst, def, max-1); dst[max-1]=0; return; }
    if (!no_color) printf(COLOR_YELLOW);
    printf("%s [%s]: ", q, def ? def : "");
    if (!no_color) printf(COLOR_RESET);
    if (!fgets(dst, max, stdin) || dst[0]=='\n') { strncpy(dst, def, max-1); dst[max-1]=0; }
    else dst[strcspn(dst, "\n")] = 0;
}
int prompt_int(const char *q, int def, int quick, int no_color) {
    char buf[32];
    if (quick) return def;
    if (!no_color) printf(COLOR_YELLOW);
    printf("%s [%d]: ", q, def);
    if (!no_color) printf(COLOR_RESET);
    if (!fgets(buf, sizeof(buf), stdin) || buf[0]=='\n') return def;
    return atoi(buf);
}
enum pemtype_pub parse_pub_pemtype(const char *arg) {
    if (!arg) return PUB_PKCS1;
    return (strcmp(arg, "x509")==0) ? PUB_X509 : PUB_PKCS1;
}
enum pemtype_priv parse_priv_pemtype(const char *arg) {
    if (!arg) return PRIV_PKCS1;
    return (strcmp(arg, "pkcs8")==0) ? PRIV_PKCS8 : PRIV_PKCS1;
}
enum pemtype_pub autodetect_pubkey_type(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) return PUB_PKCS1;
    char line[128];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return PUB_PKCS1; }
    fclose(f);
    if (strstr(line, "BEGIN PUBLIC KEY")) return PUB_X509;
    if (strstr(line, "BEGIN RSA PUBLIC KEY")) return PUB_PKCS1;
    return PUB_PKCS1;
}
enum pemtype_priv autodetect_privkey_type(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) return PRIV_PKCS1;
    char line[128];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return PRIV_PKCS1; }
    fclose(f);
    if (strstr(line, "BEGIN PRIVATE KEY")) return PRIV_PKCS8;
    if (strstr(line, "BEGIN RSA PRIVATE KEY")) return PRIV_PKCS1;
    return PRIV_PKCS1;
}

int main(int argc, char **argv) {
    int no_color = 0, quick = 0, force = 0, msgmode = 0;
    char pubfile[256] = "", privfile[256] = "", infile[4096] = "", outfile[256] = "", pemtype_str[16] = "";
    int bits = 0;
    enum pemtype_pub pub_pemtype = PUB_PKCS1;
    enum pemtype_priv priv_pemtype = PRIV_PKCS1;

    if (argc < 2) { print_usage(no_color); return 0; }
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) { print_usage(no_color); return 0; }

    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--pub") == 0 && i+1 < argc) strncpy(pubfile, argv[++i], sizeof(pubfile)-1);
        else if (strcmp(argv[i], "--priv") == 0 && i+1 < argc) strncpy(privfile, argv[++i], sizeof(privfile)-1);
        else if (strcmp(argv[i], "--in") == 0 && i+1 < argc) strncpy(infile, argv[++i], sizeof(infile)-1);
        else if (strcmp(argv[i], "--out") == 0 && i+1 < argc) strncpy(outfile, argv[++i], sizeof(outfile)-1);
        else if (strcmp(argv[i], "--bits") == 0 && i+1 < argc) bits = atoi(argv[++i]);
        else if (strcmp(argv[i], "--pem-type") == 0 && i+1 < argc) strncpy(pemtype_str, argv[++i], sizeof(pemtype_str)-1);
        else if (strcmp(argv[i], "--msg") == 0) msgmode = 1;
        else if (strcmp(argv[i], "--no-color") == 0) no_color = 1;
        else if (strcmp(argv[i], "--quick") == 0) quick = 1;
        else if (strcmp(argv[i], "--force") == 0) force = 1;
        else if (strcmp(argv[i], "--help") == 0) { print_usage(no_color); return 0; }
        else print_warning("Unknown argument", no_color);
    }
    pub_pemtype = parse_pub_pemtype(pemtype_str);
    priv_pemtype = parse_priv_pemtype(pemtype_str);

    if (strcmp(argv[1], "genkey")==0) {
        while (!is_valid_filename(pubfile))
            prompt_str("Enter public key file", pubfile, sizeof(pubfile), "public.pem", quick, no_color);
        while (!is_valid_filename(privfile))
            prompt_str("Enter private key file", privfile, sizeof(privfile), "private.pem", quick, no_color);
        while (!valid_key_size(bits))
            bits = prompt_int("Enter key size (1024/2048/3072/4096)", 1024, quick, no_color);

        while (!pemtype_str[0] && !quick) {
            prompt_str("Select PEM type for public/private key (pkcs1 or x509)", pemtype_str, sizeof(pemtype_str), "pkcs1", quick, no_color);
            pub_pemtype = parse_pub_pemtype(pemtype_str);
            priv_pemtype = (pub_pemtype == PUB_X509) ? PRIV_PKCS8 : PRIV_PKCS1;
        }
        if (pub_pemtype == PUB_X509) priv_pemtype = PRIV_PKCS8;

        if ((file_exists(pubfile) || file_exists(privfile)) && !force) {
            print_warning("One or both key files exist.", no_color);
            if (!confirm_prompt("Overwrite?", 1, quick, no_color)) return 1;
        }
        rsa_public_key pub;
        rsa_private_key priv;
        rsa_generate_keypair(&pub, &priv, bits);

        int ok1 = (pub_pemtype==PUB_X509) ? rsa_save_public_x509_pem(pubfile, &pub) : rsa_save_public_pem(pubfile, &pub);
        int ok2 = (priv_pemtype==PRIV_PKCS8) ? rsa_save_private_pkcs8_pem(privfile, &priv) : rsa_save_private_pem(privfile, &priv);
        rsa_clear_public(&pub); rsa_clear_private(&priv);
        if (!ok1 || !ok2) { print_error("Failed to save keys.", no_color); return 1; }
        print_success("Keypair generated.", no_color);
        return 0;
    }
    // Encryption
    if (strcmp(argv[1], "encrypt")==0) {
        while (!is_valid_filename(pubfile) || !file_exists(pubfile))
            prompt_str("Enter public key file", pubfile, sizeof(pubfile), "public.pem", quick, no_color);
        if (!pemtype_str[0])
            pub_pemtype = autodetect_pubkey_type(pubfile);
        while (!is_valid_filename(outfile))
            prompt_str("Enter output file", outfile, sizeof(outfile), "encrypted.bin", quick, no_color);
        if (file_exists(outfile) && !force) {
            print_warning("Output file exists.", no_color);
            if (!confirm_prompt("Overwrite?", 1, quick, no_color)) return 1;
        }
        int success = 0;
        rsa_public_key pub;
        int ok = (pub_pemtype==PUB_X509) ? rsa_load_public_x509_pem(pubfile, &pub) : rsa_load_public_pem(pubfile, &pub);
        if (!ok) { print_error("Failed to load public key.", no_color); return 1; }
        while (!msgmode && (!is_valid_filename(infile) || !file_exists(infile)))
            prompt_str("Enter input file", infile, sizeof(infile), "to_encrypt.txt", quick, no_color);
        while (msgmode && !infile[0])
            prompt_str("Enter message to encrypt", infile, sizeof(infile), "", quick, no_color);

        unsigned char *plain = NULL;
        size_t plainlen = 0;
        if (msgmode) {
            plainlen = strlen(infile);
            plain = (unsigned char*)malloc(plainlen);
            memcpy(plain, infile, plainlen);
        } else {
            FILE *fin = fopen(infile, "rb");
            if (!fin) { print_error("Failed to open input file.", no_color); rsa_clear_public(&pub); return 1; }
            fseek(fin, 0, SEEK_END); long flen = ftell(fin); rewind(fin);
            if (flen <= 0) { fclose(fin); print_error("Input file empty or error.", no_color); rsa_clear_public(&pub); return 1; }
            plainlen = (size_t)flen;
            plain = (unsigned char*)malloc(plainlen);
            fread(plain, 1, plainlen, fin); fclose(fin);
        }

        mpz_t c; mpz_init(c);
        if (!rsa_encrypt_oaep(c, plain, plainlen, &pub, NULL, 0)) {
            print_error("Encryption failed.", no_color);
            free(plain); mpz_clear(c); rsa_clear_public(&pub); return 1;
        }
        free(plain);

        size_t clen;
        size_t nbytes = (mpz_sizeinbase(pub.n, 2)+7)/8;
        unsigned char *cbuf = (unsigned char*)malloc(nbytes);
        memset(cbuf, 0, nbytes);
        mpz_export(cbuf, &clen, 1, 1, 1, 0, c);

        FILE *f = fopen(outfile, "wb");
        if (f) { fwrite(cbuf, 1, clen, f); fclose(f); success=1; }
        free(cbuf); mpz_clear(c); rsa_clear_public(&pub);

        if (!success) { print_error("Encryption failed.", no_color); return 1; }
        print_success("Encrypted!", no_color);
        return 0;
    }
    // Decryption
    if (strcmp(argv[1], "decrypt")==0) {
        while (!is_valid_filename(privfile) || !file_exists(privfile))
            prompt_str("Enter private key file", privfile, sizeof(privfile), "private.pem", quick, no_color);
        if (!pemtype_str[0])
            priv_pemtype = autodetect_privkey_type(privfile);
        while (!is_valid_filename(outfile))
            prompt_str("Enter output file", outfile, sizeof(outfile), "decrypted.txt", quick, no_color);
        if (file_exists(outfile) && !force) {
            print_warning("Output file exists.", no_color);
            if (!confirm_prompt("Overwrite?", 1, quick, no_color)) return 1;
        }
        int success = 0;
        rsa_private_key priv;
        int ok = (priv_pemtype==PRIV_PKCS8) ? rsa_load_private_pkcs8_pem(privfile, &priv) : rsa_load_private_pem(privfile, &priv);
        if (!ok) { print_error("Failed to load private key.", no_color); return 1; }

        while (!msgmode && (!is_valid_filename(infile) || !file_exists(infile)))
            prompt_str("Enter input file", infile, sizeof(infile), "encrypted.bin", quick, no_color);
        while (msgmode && !infile[0])
            prompt_str("Enter encrypted message to decrypt", infile, sizeof(infile), "", quick, no_color);

        unsigned char *encbuf = NULL;
        size_t enclen = 0;

        if (msgmode) {
            FILE *f = fopen(infile, "rb");
            if (f) {
                fseek(f, 0, SEEK_END); enclen = ftell(f); rewind(f);
                encbuf = (unsigned char*)malloc(enclen);
                fread(encbuf, 1, enclen, f); fclose(f);
            } else { print_error("Input file not found.", no_color); rsa_clear_private(&priv); return 1; }
        } else {
            FILE *f = fopen(infile, "rb");
            if (!f) { print_error("Input file not found.", no_color); rsa_clear_private(&priv); return 1; }
            fseek(f, 0, SEEK_END); enclen = ftell(f); rewind(f);
            encbuf = (unsigned char*)malloc(enclen);
            fread(encbuf, 1, enclen, f); fclose(f);
        }

        mpz_t c; mpz_init(c);
        mpz_import(c, enclen, 1, 1, 1, 0, encbuf);
        free(encbuf);

        unsigned char outbuf[4096];
        size_t outlen = 0;
        if (!rsa_decrypt_oaep(outbuf, &outlen, c, &priv, NULL, 0)) {
            print_error("Decryption failed.", no_color);
            mpz_clear(c); rsa_clear_private(&priv); return 1;
        }
        mpz_clear(c); rsa_clear_private(&priv);

        FILE *f = fopen(outfile, "wb");
        if (f) { fwrite(outbuf, 1, outlen, f); fclose(f); success=1; }

        if (!success) { print_error("Decryption failed.", no_color); return 1; }
        print_success("Decrypted!", no_color);
        return 0;
    }
    print_usage(no_color);
    return 0;
}
