#include "rsa.hpp"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <thread>
#include <chrono>
#include <iomanip>

using namespace RSA;
namespace fs = std::filesystem;

// ANSI color codes for clear output
const char* GREEN = "\033[32m";
const char* RED = "\033[31m";
const char* YELLOW = "\033[33m";
const char* CYAN = "\033[36m";
const char* BOLD = "\033[1m";
const char* RESET = "\033[0m";

void delay() {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

void print_result(const std::string& msg, bool ok, bool warn = false) {
    if(ok && !warn)
        std::cout << GREEN << msg << " [PASS]" << RESET << std::endl;
    else if(ok && warn)
        std::cout << YELLOW << msg << " [SKIPPED]" << RESET << std::endl;
    else
        std::cout << RED << msg << " [FAIL]" << RESET << std::endl;
    delay();
}

void print_step(const std::string& msg) {
    std::cout << CYAN << "[*] " << msg << RESET << std::endl;
    delay();
}

bool files_equal(const std::string& f1, const std::string& f2) {
    std::ifstream a(f1, std::ios::binary), b(f2, std::ios::binary);
    std::istreambuf_iterator<char> ia(a), ib(b), end;
    return std::vector<char>(ia, end) == std::vector<char>(ib, end);
}

void write_binary(const std::string& path, const std::vector<char>& data) {
    std::ofstream out(path, std::ios::binary); out.write(data.data(), data.size());
}

size_t get_max_rsa_block_size(int key_bits) {
    return key_bits / 8 - 11;
}

struct TestFile {
    std::string fname;
    std::string desc;
    size_t size;
};

struct TestOp {
    std::string filename;
    std::string desc;
    int keybits;
    std::string format;
    size_t size;
};

int main() {
    const std::string base_dir = "rsa-test-results";
    std::vector<int> key_sizes = {1024, 2048, 3072, 4096};

    // NOTICE: Display up front that some warnings/skips are normal
    std::cout << BOLD << YELLOW <<
        "\n=====================================================================================\n"
        "NOTE: Some warnings [SKIPPED] will be shown during testing. This is expected!\n"
        "      RSA can only encrypt small payloads directly. Empty files and very large files\n"
        "      are included to demonstrate this and will generate warnings/skips, not failures.\n"
        "      These are NOT bugs, but intentional for educational/diagnostic purposes.\n"
        "=====================================================================================\n" << RESET << std::endl;
    delay();

    // Prepare test files
    print_step("Preparing a clean test directory...");
    try {
        if(fs::exists(base_dir)) fs::remove_all(base_dir);
        fs::create_directory(base_dir);
        print_result("Test directory created", true);
    } catch (...) {
        print_result("Failed to create test directory", false);
        return 1;
    }

    print_step("Creating a variety of test files...");
    std::vector<TestFile> test_files;

    // Small ASCII text
    {
        std::string ascii_text = "Hello, RSA Test!\nEnd of ASCII file.\n";
        std::string path = base_dir + "/ascii.txt";
        std::cout << CYAN << "  - Creating file: ascii.txt (Simple ASCII text, "
                  << ascii_text.size() << " bytes)" << RESET << std::endl;
        std::ofstream f(path); f << ascii_text; f.close();
        test_files.push_back({"ascii.txt", "Simple ASCII text", ascii_text.size()});
        delay();
    }
    // Unicode text
    {
        std::string unicode_text(reinterpret_cast<const char*>(u8"Привет, мир!\nこんにちは世界\n¡Hola mundo!\n"));
        std::string path = base_dir + "/unicode.txt";
        std::cout << CYAN << "  - Creating file: unicode.txt (Unicode text file, "
                  << unicode_text.size() << " bytes)" << RESET << std::endl;
        std::ofstream f(path); f << unicode_text; f.close();
        test_files.push_back({"unicode.txt", "Unicode text file", unicode_text.size()});
        delay();
    }
    // Small binary file
    {
        std::string path = base_dir + "/binary.bin";
        std::vector<char> bin(64);
        for(size_t i=0;i<bin.size();++i) bin[i] = static_cast<char>(i%256);
        std::cout << CYAN << "  - Creating file: binary.bin (Binary file, 64 bytes)" << RESET << std::endl;
        write_binary(path, bin);
        test_files.push_back({"binary.bin", "Binary file", bin.size()});
        delay();
    }
    // Empty file (will cause [SKIPPED] warning)
    {
        std::string path = base_dir + "/empty.txt";
        std::cout << CYAN << "  - Creating file: empty.txt (Empty file, 0 bytes) "
                  << YELLOW << "[This will be SKIPPED during tests]" << RESET << std::endl;
        std::ofstream f(path); f.close();
        test_files.push_back({"empty.txt", "Empty file", 0});
        delay();
    }
    // Large file (will cause [SKIPPED] warning)
    {
        std::string path = base_dir + "/long.txt";
        std::string block = "0123456789abcdef";
        size_t file_size = block.size() * 1024 * 10;
        std::cout << CYAN << "  - Creating file: long.txt (Long file, "
                  << file_size << " bytes) "
                  << YELLOW << "[This will be SKIPPED during tests]" << RESET << std::endl;
        std::ofstream f(path);
        for(int i=0;i<1024*10;++i) f << block;
        f.close();
        test_files.push_back({"long.txt", "Long file (160KB, will be SKIPPED for direct RSA)", file_size});
        delay();
    }
    print_result("Test files created", true);

    // Pre-compute number of tests that will be performed (excluding large/empty files)
    std::vector<TestOp> test_ops;
    for(int sz : key_sizes) {
        size_t max_block = get_max_rsa_block_size(sz);
        for(const auto& tf : test_files) {
            // Skip large files and empty files
            if (tf.size > max_block || tf.size == 0) continue;
            for(auto fmt : {"BIN", "HEX", "B64"}) {
                test_ops.push_back({tf.fname, tf.desc, sz, fmt, tf.size});
            }
        }
    }
    int total_tests = static_cast<int>(test_ops.size());

    std::cout << BOLD << CYAN
        << "\n########################################################\n"
        << "#         RSA Algorithm Comprehensive Test Suite        #\n"
        << "########################################################\n"
        << "# Key sizes: 1024, 2048, 3072, 4096 bits\n"
        << "# Test files: ASCII, Unicode, binary, empty, large\n"
        << "# Output formats: BIN, HEX, B64\n"
        << "#\n"
        << "# " << total_tests << " actual encryption/decryption tests will be performed.\n"
        << "########################################################\n" << RESET << std::endl;
    delay();

    int test_passed = 0, test_failed = 0, test_skipped = 0, test_count = 0;

    // 3. For each key size
    for(int sz : key_sizes) {
        std::cout << BOLD << CYAN << "\n--- Testing with RSA key size: " << sz << " bits ---" << RESET << std::endl;
        delay();
        std::string key_name = "rsa" + std::to_string(sz);
        size_t max_block = get_max_rsa_block_size(sz);

        print_step("Generating RSA keypair...");
        KeyPair keys;
        try {
            keys = GenerateKeyPair(static_cast<KeySize>(sz));
            print_result("Key generation", true);
        } catch (...) {
            print_result("Key generation", false);
            continue;
        }

        // Save/load keys
        std::string pub_pem = base_dir + "/" + key_name + "_pub.pem";
        std::string priv_pem = base_dir + "/" + key_name + "_priv.pem";
        try {
            keys.public_key.save_pem(pub_pem.c_str());
            keys.private_key.save_pem(priv_pem.c_str());
            RSAPublicKey pub2 = RSAPublicKey::load_pem(pub_pem.c_str());
            RSAPrivateKey priv2 = RSAPrivateKey::load_pem(priv_pem.c_str());
            bool eq = (pub2.n == keys.public_key.n && priv2.n == keys.private_key.n);
            print_result("Key save/load roundtrip", eq);
        } catch (...) {
            print_result("Key save/load", false);
            continue;
        }

        for(const auto& tf : test_files) {
            std::string input_path = base_dir + "/" + tf.fname;
            std::cout << BOLD << CYAN << "\n--> File: " << tf.fname << " (" << tf.desc << "), Size: " << tf.size << " bytes" << RESET << std::endl;
            delay();

            // Large file skip
            if (tf.size > max_block) {
                print_result("SKIPPED: File size exceeds max direct RSA payload (" + std::to_string(max_block) + " bytes). Not an error; use hybrid encryption for large files.", true, true);
                ++test_skipped;
                continue;
            }
            // Empty file skip
            if (tf.size == 0) {
                print_result("SKIPPED: File is empty. Nothing to encrypt. This is normal.", true, true);
                ++test_skipped;
                continue;
            }

            for(auto fmt : {OutputFormat::Binary, OutputFormat::Hex, OutputFormat::Base64}) {
                std::string fmt_name = (fmt == OutputFormat::Binary) ? "BIN" : (fmt == OutputFormat::Hex) ? "HEX" : "B64";
                std::string enc_path = base_dir + "/" + tf.fname + "." + key_name + ".enc." + fmt_name;
                std::string dec_path = base_dir + "/" + tf.fname + "." + key_name + ".dec.txt";
                ++test_count;
                std::cout << CYAN << "  [" << test_count << "/" << total_tests << "] "
                          << "Encrypting and decrypting '" << tf.fname
                          << "' (" << tf.size << " bytes) using key " << sz
                          << " bits, format " << fmt_name << "..." << RESET << std::endl;
                delay();

                bool encrypt_ok = false;
                bool decrypt_ok = false;
                bool identical = false;

                // Encryption
                try {
                    RSA::FILE::Encrypt(input_path, enc_path, keys.public_key, fmt);
                    encrypt_ok = true;
                    print_result("    Encryption (" + fmt_name + ")", true);
                } catch (const std::exception& ex) {
                    print_result(std::string("    Encryption failed: ") + ex.what(), false);
                } catch (...) {
                    print_result("    Encryption failed (unknown error)", false);
                }

                // Decryption (only if encryption passed)
                if (encrypt_ok) {
                    try {
                        RSA::FILE::Decrypt(enc_path, dec_path, keys.private_key, fmt);
                        decrypt_ok = true;
                        print_result("    Decryption (" + fmt_name + ")", true);
                        identical = files_equal(input_path, dec_path);
                        if(identical) {
                            print_result("    File content matches original!", true);
                            ++test_passed;
                        } else {
                            print_result("    File content does NOT match original!", false);
                            ++test_failed;
                        }
                    } catch (const std::exception& ex) {
                        print_result(std::string("    Decryption failed: ") + ex.what(), false);
                        ++test_failed;
                    } catch (...) {
                        print_result("    Decryption failed (unknown error)", false);
                        ++test_failed;
                    }
                } else {
                    print_result("    Decryption skipped due to encryption failure", false, true);
                    ++test_failed;
                }
            }
        }
    }

    // Final summary
    std::cout << BOLD << CYAN << "\n########################################################\n"
              << "#                   TEST SUMMARY                       #\n"
              << "########################################################\n"
              << "# Tests run     : " << test_count << "/" << total_tests << "\n"
              << "# Passed        : " << test_passed << "\n"
              << "# Failed        : " << test_failed << "\n"
              << "# Skipped       : " << test_skipped << "\n"
              << "########################################################\n" << RESET << std::endl;

    if(test_failed == 0)
        std::cout << GREEN << BOLD << "ALL TESTS PASSED!" << RESET << std::endl;
    else
        std::cout << RED << BOLD << "SOME TESTS FAILED. Please check output above." << RESET << std::endl;

    std::cout << YELLOW << "Results and generated files are in the '" << base_dir << "' directory." << RESET << std::endl;
    std::cout << CYAN << "Note: Skipped cases for empty or large files are normal. RSA is only for small payloads." << RESET << std::endl;

    return 0;
}
