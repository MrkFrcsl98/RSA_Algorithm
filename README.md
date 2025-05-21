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

```cpp
#include "rsa.hpp"
#include <iostream>

int main() {
    using namespace RSA;

    // Generate a key pair (1024 bits)
    KeyPair keys = GenerateKeyPair(KeySize::Bits1024);

    // Save keys to PEM files
    keys.public_key.save_pem("public.pem");
    keys.private_key.save_pem("private.pem");

    // Load keys from PEM files
    RSAPublicKey pub = RSAPublicKey::load_pem("public.pem");
    RSAPrivateKey priv = RSAPrivateKey::load_pem("private.pem");

    // Encrypt a message
    std::string message = "Hello, RSA!";
    std::string encrypted = MESSAGE::Encrypt(message, pub)
                                .toFormat(OutputFormat::Base64)
                                .toString();

    // Decrypt the message
    std::string decrypted = MESSAGE::Decrypt(encrypted, priv, OutputFormat::Base64);

    std::cout << "Original:   " << message << "\n";
    std::cout << "Encrypted:  " << encrypted << "\n";
    std::cout << "Decrypted:  " << decrypted << "\n";
}
```

#### File Encryption/Decryption

```cpp
// Encrypt a file
RSA::FILE::Encrypt("plain.txt", "enc.bin", pub, OutputFormat::Binary);

// Decrypt the file
RSA::FILE::Decrypt("enc.bin", "dec.txt", priv, OutputFormat::Binary);
```

---

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
