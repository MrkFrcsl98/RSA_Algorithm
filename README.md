# RSA_Algorithm

**RSA (Rivest–Shamir–Adleman) Asymmetric Encryption Algorithm Implementation — Educational Purposes**


## Table of Contents

- [Overview](#overview)
- [Directory Structure](#directory-structure)
- [Features](#features)
- [Dependencies](#dependencies)
- [Build Instructions](#build-instructions)
- [Usage Examples](#usage-examples)
  - [C++ Example Code](#c-example-code)
  - [Command-Line Tool Usage](#command-line-tool-usage)
- [File/Code Structure](#filecode-structure)
- [Testing](#testing)
- [OS Compatibility & Warnings](#os-compatibility--warnings)
- [Security Notes](#security-notes)
- [License](#license)

---

## Overview

This project provides a modern, header-only C++ implementation of the RSA cryptosystem. It is designed for learning and experimentation, featuring:

- Key generation (configurable size)
- PEM/DER encoding for key storage/interop
- Message and file encryption/decryption with selectable output formats
- A CLI tool for practical usage
- Comprehensive test suite

**Note:** This implementation is for educational purposes only and should NOT be used in production settings.

---

## Directory Structure

```
RSA_Algorithm/
  ├── src/
  │     ├── rsa.hpp        # Core RSA logic (header-only)
  │     └── main.cpp       # Example usage program
  ├── bin/
  │     └── rsa_cli.cpp    # Command-line interface tool
  ├── tests/
  │     └── rsa_test.cpp   # Automated test suite
  └── README.md
```

---

## Features

- **Key generation:** Choose from 1024, 2048, 3072, or 4096 bits
- **PEM/DER key serialization:** Compatible with OpenSSL
- **Multiple output formats:** Binary, hex, and base64
- **File and message encryption/decryption**
- **Robust error handling** and user feedback (colored output in CLI)
- **Cross-platform (see OS notes below)**

---

## Dependencies

- **C++17 or later**
- **GMP** (GNU Multiple Precision Arithmetic Library) and **gmpxx** (C++ bindings)
  - Install with:  
    - Ubuntu/Debian: `sudo apt-get install libgmp-dev libgmpxx-dev`
    - macOS (Homebrew): `brew install gmp`
- Standard C++17 library
- (For tests) C++17 filesystem API

---

## Build Instructions

### Compile the Command-Line Tool

```sh
g++ -std=c++17 -lgmp -lgmpxx -o rsa_cli bin/rsa_cli.cpp
```

### Compile the Example

```sh
g++ -std=c++17 -lgmp -lgmpxx -o rsa_example src/main.cpp
```

### Compile and Run the Tests

```sh
g++ -std=c++17 -lgmp -lgmpxx -o rsa_test tests/rsa_test.cpp
./rsa_test
```

---

## Usage Examples

### C++ Example Code

#### Generate Keys, Encrypt, and Decrypt a Message


---

## Examples: Using the RSA_Algorithm Library

### 1. Generate and Save Keys to PEM Files

```cpp
#include "rsa.hpp"

int main() {
    // Generate a 2048-bit key pair (in memory)
    RSA::KeyPair keys = RSA::GenerateKeyPair(RSA::KeySize::Bits2048);

    // Save keys to PEM files
    keys.public_key.save_pem("public.pem");
    keys.private_key.save_pem("private.pem");
}
```

---

### 2. Encrypt and Decrypt a String Message (Both File and In-Memory Keys)

```cpp
#include "rsa.hpp"
#include <iostream>

int main() {
    std::string message = "Hello, RSA!";

    // --- Option 1: Use keys directly after generation (in-memory) ---
    RSA::KeyPair keys = RSA::GenerateKeyPair(RSA::KeySize::Bits1024);

    std::string encrypted_inline = RSA::MESSAGE::Encrypt(message, keys.public_key)
                                      .toFormat(RSA::OutputFormat::Base64)
                                      .toString();
    std::string decrypted_inline = RSA::MESSAGE::Decrypt(encrypted_inline, keys.private_key, RSA::OutputFormat::Base64);

    std::cout << "[Inline] Decrypted: " << decrypted_inline << std::endl; // Output: Hello, RSA!

    // --- Option 2: Load keys from PEM files ---
    // (Assuming PEM files exist, e.g., from the previous example)
    auto pub = RSA::RSAPublicKey::load_pem("public.pem");
    auto priv = RSA::RSAPrivateKey::load_pem("private.pem");

    std::string encrypted_file = RSA::MESSAGE::Encrypt(message, pub)
                                     .toFormat(RSA::OutputFormat::Base64)
                                     .toString();
    std::string decrypted_file = RSA::MESSAGE::Decrypt(encrypted_file, priv, RSA::OutputFormat::Base64);

    std::cout << "[PEM file] Decrypted: " << decrypted_file << std::endl; // Output: Hello, RSA!
}
```

---

### 3. Encrypt and Decrypt a File (Both File and In-Memory Keys)

```cpp
#include "rsa.hpp"

int main() {
    // --- Option 1: Use keys just generated (in-memory) ---
    RSA::KeyPair keys = RSA::GenerateKeyPair(RSA::KeySize::Bits1024);

    // Encrypt and decrypt using in-memory keys
    RSA::FILE::Encrypt("plain.txt", "enc.bin", keys.public_key, RSA::OutputFormat::Binary);
    RSA::FILE::Decrypt("enc.bin", "dec.txt", keys.private_key, RSA::OutputFormat::Binary);

    // --- Option 2: Use keys loaded from PEM files ---
    auto pub = RSA::RSAPublicKey::load_pem("public.pem");
    auto priv = RSA::RSAPrivateKey::load_pem("private.pem");

    RSA::FILE::Encrypt("plain.txt", "enc2.bin", pub, RSA::OutputFormat::Binary);
    RSA::FILE::Decrypt("enc2.bin", "dec2.txt", priv, RSA::OutputFormat::Binary);
}
```

---

### 4. Encrypt to Hex or Base64, Decrypt from Hex or Base64

```cpp
#include "rsa.hpp"
#include <iostream>

int main() {
    std::string message = "Format test!";
    RSA::KeyPair keys = RSA::GenerateKeyPair(RSA::KeySize::Bits1024);

    // Encrypt to hex
    std::string hex_cipher = RSA::MESSAGE::Encrypt(message, keys.public_key)
                                .toFormat(RSA::OutputFormat::Hex)
                                .toString();
    std::string hex_plain = RSA::MESSAGE::Decrypt(hex_cipher, keys.private_key, RSA::OutputFormat::Hex);

    // Encrypt to base64
    std::string b64_cipher = RSA::MESSAGE::Encrypt(message, keys.public_key)
                                .toFormat(RSA::OutputFormat::Base64)
                                .toString();
    std::string b64_plain = RSA::MESSAGE::Decrypt(b64_cipher, keys.private_key, RSA::OutputFormat::Base64);

    std::cout << "Hex decrypted: " << hex_plain << std::endl;
    std::cout << "Base64 decrypted: " << b64_plain << std::endl;
}
```

---

### 5. Quick Reference — Loading Keys

```cpp
// To use keys immediately after generation:
RSA::KeyPair keys = RSA::GenerateKeyPair(RSA::KeySize::Bits2048);
// Use keys.public_key and keys.private_key directly.

// To use keys stored in files:
auto pub = RSA::RSAPublicKey::load_pem("public.pem");
auto priv = RSA::RSAPrivateKey::load_pem("private.pem");
// Use pub and priv as above.
```

---

**Tip:**  
- You can use keys immediately after generating them (in-memory), or save them to PEM files and later load them from disk as needed.
- Both approaches are supported throughout the API for flexibility.


### Command-Line Tool Usage

#### Key Generation

```sh
./rsa_cli genkey --pub public.pem --priv private.pem --bits 2048 --quick
```

#### Encrypt a Message

```sh
./rsa_cli encrypt --pub public.pem --in "Secret Message" --out encrypted.b64 --format base64 --msg
```

#### Encrypt a File

```sh
./rsa_cli encrypt --pub public.pem --in myfile.txt --out encrypted.bin --format binary
```

#### Decrypt a Message

```sh
./rsa_cli decrypt --priv private.pem --in encrypted.b64 --out message.txt --format base64 --msg
```

#### Decrypt a File

```sh
./rsa_cli decrypt --priv private.pem --in encrypted.bin --out myfile_decrypted.txt --format binary
```

#### Help

```sh
./rsa_cli --help
```

---

## File/Code Structure

### `src/rsa.hpp`

- **PEM_DER namespace:** ASN.1 DER and PEM/base64 encode/decode routines.
- **RSA namespace:** Key classes, utility functions, key generation, and message/file APIs.
  - `RSAPublicKey` and `RSAPrivateKey`: Key containers with PEM/DER serialization.
  - `KeyPair`: Bundles public and private keys.
  - `GenerateKeyPair`: Securely generates new key pairs.
  - `MESSAGE` namespace: Message encryption/decryption.
  - `FILE` namespace: File encryption/decryption with output format support.

### `src/main.cpp`

- Example program:
  - Generates keys, saves/loads keys from PEM files.
  - Demonstrates message and file encryption/decryption.

### `bin/rsa_cli.cpp`

- Fully-featured CLI for real-world use.
- Interactive prompts, colorized output, robust error handling.
- Supports key generation, encryption, and decryption of files and messages.
- Multiple output/input formats (binary, hex, base64).

### `tests/rsa_test.cpp`

- Automated test suite:
  - Tests all key sizes, file types, and output formats.
  - Reports results with color-coded output and statistics.
  - Demonstrates practical/educational limitations (e.g., RSA cannot encrypt large files directly).

---

## Testing

Run the test suite with:

```sh
./rsa_test
```

- Generates various files (text, binary, empty, large).
- Validates correct round-trip encryption/decryption.
- Highlights edge cases (empty/large files skipped with warnings).

---

## OS Compatibility & Warnings

- **Tested on:** Linux (Ubuntu), macOS.  
  Should work on any OS with C++17 and GMP support.
- **Windows:**  
  - GMP library must be installed and properly linked.  
  - Filesystem and colored output might behave differently or require modifications.
  - Use MSYS2/MinGW or WSL for best experience.
- **Filesystem/Paths:**  
  Use forward slashes `/` for cross-platform compatibility or adjust paths as necessary.

---

## Security Notes

- **Educational use only:**  
  This code is NOT hardened for production and omits cryptographic best practices (e.g., no padding, no OAEP/PKCS#1).
- **Direct RSA is insecure for large data:**  
  Encrypting large files or data directly with RSA is not secure or practical. Use hybrid cryptography (e.g., AES for data, RSA for keys) in real applications.
- **No side-channel protection:**  
  The code does not attempt to mitigate timing or power analysis attacks.
- **Key/Message Handling:**  
  Always protect your private keys and sensitive data.  
  Do not use small key sizes (e.g., 1024 bits) for anything other than demo/learning.
- **GMP dependency:**  
  GMP is a reliable, widely-used library, but always keep dependencies up-to-date and review their security advisories.

---

## License

MIT License (see [LICENSE](LICENSE) file).

---

**For questions, improvements, or bug reports, please open an issue or pull request!**

---

**Warning:**  
Do NOT use this implementation for protecting real secrets or in production systems. For professional cryptography, use vetted libraries and protocols.

---
