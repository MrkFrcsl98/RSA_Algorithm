#include "rsa.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>

// Color codes
std::string COLOR_RED    = "\033[31m";
std::string COLOR_YELLOW = "\033[33m";
std::string COLOR_GREEN  = "\033[32m";
std::string COLOR_CYAN   = "\033[36m";
std::string COLOR_RESET  = "\033[0m";

// Utilities
bool file_exists(const std::string& fname) {
    std::ifstream f(fname, std::ios::binary);
    return f.good();
}
bool valid_key_size(int bits) {
    return bits == 1024 || bits == 2048 || bits == 3072 || bits == 4096;
}
bool is_valid_filename(const std::string& fname) {
    if (fname.empty()) return false;
    for (char c : fname)
        if (!isprint(static_cast<unsigned char>(c)) || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|')
            return false;
    return true;
}
bool is_valid_message(const std::string& msg) {
    return !msg.empty();
}
RSA::OutputFormat parse_format(const std::string& v, bool& ok) {
    if (v == "hex") { ok = true; return RSA::OutputFormat::Hex; }
    if (v == "base64") { ok = true; return RSA::OutputFormat::Base64; }
    if (v == "binary") { ok = true; return RSA::OutputFormat::Binary; }
    ok = false;
    return RSA::OutputFormat::Binary;
}

// Prompts
std::string prompt(const std::string& question, const std::string& defaultValue = "", bool no_color = false) {
    if (!no_color) std::cout << COLOR_YELLOW;
    std::cout << question;
    if (!defaultValue.empty()) std::cout << " [" << defaultValue << "]";
    std::cout << ": ";
    if (!no_color) std::cout << COLOR_RESET;
    std::string resp;
    std::getline(std::cin, resp);
    if (resp.empty()) return defaultValue;
    return resp;
}
bool confirm_prompt(const std::string& message, bool defaultYes = true, bool quick = false, bool no_color = false) {
    if (quick) return true;
    if (!no_color) std::cout << COLOR_YELLOW;
    std::cout << message << (defaultYes ? " [Y/n]: " : " [y/N]: ");
    if (!no_color) std::cout << COLOR_RESET;
    std::string resp;
    std::getline(std::cin, resp);
    std::transform(resp.begin(), resp.end(), resp.begin(), ::tolower);
    if (resp.empty()) return defaultYes;
    return (resp == "y" || resp == "yes");
}
void print_error(const std::string& msg, bool no_color = false) {
    if (!no_color) std::cout << COLOR_RED;
    std::cout << "[ERROR] " << msg;
    if (!no_color) std::cout << COLOR_RESET;
    std::cout << "\n";
}
void print_warning(const std::string& msg, bool no_color = false) {
    if (!no_color) std::cout << COLOR_YELLOW;
    std::cout << "[WARNING] " << msg;
    if (!no_color) std::cout << COLOR_RESET;
    std::cout << "\n";
}
void print_success(const std::string& msg, bool no_color = false) {
    if (!no_color) std::cout << COLOR_GREEN;
    std::cout << "[SUCCESS] " << msg;
    if (!no_color) std::cout << COLOR_RESET;
    std::cout << "\n";
}
void print_usage(bool no_color = false) {
    if (!no_color) std::cout << COLOR_CYAN;
    std::cout <<
R"(Usage:
  rsa_cli genkey --pub <public.pem> --priv <private.pem> [--bits <key size>] [options]
  rsa_cli encrypt --pub <public.pem> --in <input file|msg> --out <encrypted.bin> [--format hex|base64|binary] [--msg] [options]
  rsa_cli decrypt --priv <private.pem> --in <encrypted.bin> --out <decrypted.txt> [--format hex|base64|binary] [--msg] [options]
Options:
  --pub       Path to RSA public key (PEM) [public.pem]
  --priv      Path to RSA private key (PEM) [private.pem]
  --in        Input file (for --msg, input is a string, not a file)
  --out       Output file (for --msg, output is written as text)
  --bits      Key size: 1024, 2048, 3072, 4096. Default: 1024
  --format    Output format: hex, base64, or binary. Default: binary
  --msg       Operate on message string instead of file
  --quick     No confirmation prompts (except errors/missing)
  --force     Force overwrite of any output files without prompt
  --no-color  Disable colored output
  --help      Show this help and exit
  --version   Print version info and continue
Examples:
  rsa_cli genkey --pub public.pem --priv private.pem --bits 2048 --quick
  rsa_cli encrypt --pub public.pem --in my.txt --out encrypted.bin --format binary
  rsa_cli encrypt --pub public.pem --in "Secret" --out encrypted.bin --format hex --msg
  rsa_cli decrypt --priv private.pem --in encrypted.bin --out decrypted.txt --format binary
  rsa_cli decrypt --priv private.pem --in "..." --out decrypted.txt --format hex --msg
)";
    if (!no_color) std::cout << COLOR_RESET;
}

void print_verbose_help(bool no_color = false) {
    if (!no_color) std::cout << COLOR_CYAN;
    std::cout << R"(
RSA CLI - Help
-----------------------
This tool allows you to generate RSA key pairs, encrypt files or messages, and decrypt them.

Commands:
  genkey     Generate a new RSA keypair.
  encrypt    Encrypt a file or message using a public key.
  decrypt    Decrypt an encrypted file or message using a private key.

Options:
  --pub <file>
      Path to the RSA public key in PEM format.
      Used for encryption and key generation.
      Default: public.pem

  --priv <file>
      Path to the RSA private key in PEM format.
      Used for decryption and key generation.
      Default: private.pem

  --in <file|message>
      File to read input data from. For --msg, this is treated as the message/text.
      For encryption, this is the plaintext file/message.
      For decryption, this is the encrypted file/message.

  --out <file>
      File to write output data to.
      For encryption, this is the encrypted result file.
      For decryption, this is the decrypted output file or message.

  --bits <size>
      RSA key size in bits. Supported values: 1024, 2048, 3072, 4096.
      Default: 1024

  --format <format>
      Format for encrypted or decrypted output.
      Allowed: binary (default), base64, hex

  --msg
      Treat --in as a text message instead of a file.
      Use this to encrypt or decrypt short messages directly from the command line.

  --quick
      Suppresses all confirmation prompts except for errors or missing/invalid arguments.
      Useful for scripting or automation.

  --force
      Overwrite output files without prompting, even if they already exist.

  --no-color
      Disables colored output.

  --help
      Show this detailed help and exit.

  --version
      Print the program version at the start of output (does not exit).

Examples:
  rsa_cli genkey --pub public.pem --priv private.pem --bits 2048 --quick
      # Generates a 2048-bit keypair with no interactive prompts.

  rsa_cli encrypt --pub public.pem --in my.txt --out encrypted.bin --format binary
      # Encrypts 'my.txt' using 'public.pem' and writes binary output.

  rsa_cli encrypt --pub public.pem --in "Secret" --out encrypted.bin --format hex --msg
      # Encrypts the message "Secret" (not a file!) and outputs the result in hex.

  rsa_cli decrypt --priv private.pem --in encrypted.bin --out decrypted.txt --format binary
      # Decrypts the file 'encrypted.bin' using 'private.pem'.

  rsa_cli decrypt --priv private.pem --in "..." --out decrypted.txt --format hex --msg
      # Decrypts the hex-encoded message (from --in) using 'private.pem'.

)";
    if (!no_color) std::cout << COLOR_RESET;
}

int main(int argc, char* argv[]) {
    std::string version = "1.1.0";
    bool quick = false, force = false, no_color = false;
    bool verbose_help = false, show_version = false;

    // Argument variables
    std::string pubfile, privfile, infile, outfile, format_str;
    int bits = 0;
    bool msgmode = false;

    // Pre-scan for --version and --help anywhere
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--version") show_version = true;
        if (arg == "--help") verbose_help = true;
        if (arg == "--no-color") no_color = true;
    }
    if (no_color) {
        COLOR_RED = COLOR_YELLOW = COLOR_GREEN = COLOR_CYAN = COLOR_RESET = "";
    }
    if (show_version) {
        std::cout << "rsa_cli version " << version << std::endl;
    }
    if (verbose_help) {
        print_verbose_help(no_color);
        return 0;
    }
    if (argc < 2) {
        print_usage(no_color);
        return 0;
    }
    std::string command = argv[1];

    // Parse CLI args (flags and provided values)
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--pub" && i + 1 < argc) pubfile = argv[++i];
        else if (arg == "--priv" && i + 1 < argc) privfile = argv[++i];
        else if (arg == "--in" && i + 1 < argc) infile = argv[++i];
        else if (arg == "--out" && i + 1 < argc) outfile = argv[++i];
        else if (arg == "--bits" && i + 1 < argc) bits = std::atoi(argv[++i]);
        else if (arg == "--format" && i + 1 < argc) format_str = argv[++i];
        else if (arg == "--msg") msgmode = true;
        else if (arg == "--quick") quick = true;
        else if (arg == "--force") force = true;
        else if (arg == "--no-color") {/*already handled*/}
        else if (arg == "--help" || arg == "--version") {/*already handled*/}
        else { print_warning("Unknown or incomplete argument: " + arg, no_color); }
    }

    // ====== GENKEY ======
    if (command == "genkey") {
        while (!is_valid_filename(pubfile)) {
            pubfile = prompt("Enter public key file", "public.pem", no_color);
        }
        while (!is_valid_filename(privfile)) {
            privfile = prompt("Enter private key file", "private.pem", no_color);
        }
        while (!valid_key_size(bits)) {
            std::string bits_str = prompt("Enter key size", "1024", no_color);
            try { bits = std::stoi(bits_str); }
            catch (...) { print_error("Not a number!", no_color); bits = 0; }
        }
        if ((file_exists(pubfile) || file_exists(privfile)) && !force) {
            print_warning("One or both key files already exist.", no_color);
            if (!confirm_prompt("Overwrite?", true, quick, no_color)) { print_warning("Operation cancelled.", no_color); return 0; }
        }
        if (!quick) {
            std::cout << COLOR_YELLOW
                    << "You are about to generate an RSA keypair:\n"
                    << "  Public key: " << pubfile << "\n"
                    << "  Private key: " << privfile << "\n"
                    << "  Key size: " << bits << "\n"
                    << COLOR_RESET;
            if (!confirm_prompt("Proceed?", true, quick, no_color)) { print_warning("Operation cancelled.", no_color); return 0; }
        }
        try {
            RSA::KeyPair kp = RSA::GenerateKeyPair(static_cast<RSA::KeySize>(bits));
            kp.public_key.save_pem(pubfile);
            kp.private_key.save_pem(privfile);
            print_success("Keys saved to " + pubfile + " and " + privfile, no_color);
        } catch (const std::exception& ex) {
            print_error("Key generation failed: " + std::string(ex.what()), no_color);
        }
        return 0;
    }

    // ===== ENCRYPT/DECRYPT =====
    bool encrypt = (command == "encrypt");
    bool decrypt = (command == "decrypt");
    if (encrypt || decrypt) {
        if (encrypt) {
            while (!is_valid_filename(pubfile) || !file_exists(pubfile)) {
                pubfile = prompt("Enter public key file", "public.pem", no_color);
                if (!file_exists(pubfile)) print_error("File not found!", no_color);
            }
        } else {
            while (!is_valid_filename(privfile) || !file_exists(privfile)) {
                privfile = prompt("Enter private key file", "private.pem", no_color);
                if (!file_exists(privfile)) print_error("File not found!", no_color);
            }
        }
        if (!msgmode) {
            std::string defIn = encrypt ? "to_encrypt.txt" : "encrypted.bin";
            while (!is_valid_filename(infile) || !file_exists(infile)) {
                infile = prompt("Enter input file", defIn, no_color);
                if (!file_exists(infile)) print_error("File not found!", no_color);
            }
        } else {
            while (!is_valid_message(infile)) {
                infile = prompt("Enter message to " + std::string(encrypt ? "encrypt" : "decrypt"), "", no_color);
            }
        }
        std::string defOut = encrypt ? "encrypted.bin" : "decrypted.txt";
        while (!is_valid_filename(outfile)) {
            outfile = prompt("Enter output file", defOut, no_color);
        }
        while (true) {
            if (format_str.empty()) format_str = "binary";
            bool fmtok = false;
            RSA::OutputFormat fmt = parse_format(format_str, fmtok);
            if (!fmtok) {
                format_str = prompt("Enter output format (hex|base64|binary)", "binary", no_color);
            } else break;
        }
        bool fmtok2 = false;
        RSA::OutputFormat fmt = parse_format(format_str, fmtok2);

        if (file_exists(outfile) && !force) {
            print_warning("Output file already exists.", no_color);
            if (!confirm_prompt("Overwrite?", true, quick, no_color)) { print_warning("Operation cancelled.", no_color); return 0; }
        }
        if (!quick) {
            std::cout << COLOR_YELLOW
                    << (encrypt ? "You are about to encrypt:\n" : "You are about to decrypt:\n")
                    << (encrypt ? "  Public key: " + pubfile + "\n" : "  Private key: " + privfile + "\n")
                    << "  Input: " << infile << (msgmode ? " (message mode)" : " (file mode)") << "\n"
                    << "  Output: " << outfile << "\n"
                    << "  Format: " << format_str << "\n"
                    << COLOR_RESET;
            if (!confirm_prompt("Proceed?", true, quick, no_color)) { print_warning("Operation cancelled.", no_color); return 0; }
        }
        try {
            if (encrypt) {
                RSA::RSAPublicKey pub = RSA::RSAPublicKey::load_pem(pubfile);
                if (msgmode) {
                    std::string message = infile;
                    auto enc = RSA::MESSAGE::Encrypt(message, pub).toFormat(fmt);
                    std::ofstream out(outfile, std::ios::out | std::ios::binary);
                    out << enc.toString(); out.close();
                } else {
                    RSA::FILE::Encrypt(infile, outfile, pub, fmt);
                }
                print_success("Encryption OK. Output: " + outfile, no_color);
            } else if (decrypt) {
                RSA::RSAPrivateKey priv = RSA::RSAPrivateKey::load_pem(privfile);
                if (msgmode) {
                    std::string encdata = infile;
                    RSA::EncryptedResult encres(
                        (fmt == RSA::OutputFormat::Hex) ? RSA::UTIL::hex_to_bytes(encdata) :
                        (fmt == RSA::OutputFormat::Base64) ? PEM_DER::base64_decode(encdata) :
                        std::vector<uint8_t>(encdata.begin(), encdata.end())
                    );
                    auto dec = RSA::MESSAGE::Decrypt(encres, priv);
                    std::ofstream out(outfile, std::ios::out | std::ios::binary);
                    out << dec.toString();
                    out.close();
                } else {
                    RSA::FILE::Decrypt(infile, outfile, priv, fmt);
                }
                print_success("Decryption OK. Output: " + outfile, no_color);
            }
        } catch (const std::exception& ex) {
            print_error(std::string(encrypt ? "Encryption" : "Decryption") + " failed: " + ex.what(), no_color);
        }
        return 0;
    }

    print_usage(no_color);
    return 0;
}
