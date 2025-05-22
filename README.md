# RSA_Algorithm

**RSA (Rivest–Shamir–Adleman) Asymmetric Encryption Algorithm Implementation — Educational Purposes**

---

## Table of Contents

- [Overview](#overview)
- [What is RSA? (History and Detailed Explanation)](#what-is-rsa-history-and-detailed-explanation)
- [Directory Structure](#directory-structure)
- [Features](#features)
- [Dependencies](#dependencies)
- [Build Instructions](#build-instructions)
- [Usage Examples](#usage-examples)
- [Command-Line Interface: rsa_cli](#command-line-interface-rsa_cli)
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
- **Supports both PKCS#1 and PKCS#8/X.509 PEM key types for RSA keys**
- Message and file encryption/decryption with selectable output formats
- A CLI tool for practical usage
- Comprehensive test suite

**Note:** This implementation is for educational purposes only and should NOT be used in production settings.

---

## What is RSA? (History and Detailed Explanation)

### Historical Background

RSA stands for Rivest–Shamir–Adleman, named after its inventors Ron Rivest, Adi Shamir, and Leonard Adleman. The algorithm was first publicly described in 1977 by these three MIT researchers. It provided the first practical implementation of public-key cryptography, a concept invented by Whitfield Diffie and Martin Hellman in 1976.

The publication of RSA revolutionized the field of cryptography by introducing the concept of practical public-key cryptography, which underpins much of modern digital security, including secure web browsing, digital signatures, and secure email.

### Why is RSA Important?

Prior to RSA and public-key cryptography, all secure communication required that both parties share a secret key in advance—a major problem for large-scale or spontaneous secure communications. RSA allows two parties to establish secure communications over an insecure channel without needing to share a secret in advance.

### The Mathematics of RSA (Obsessive Details)

RSA is based on the mathematical difficulty of factoring the product of two large prime numbers. The security of RSA relies on the fact that, while it is easy to multiply two large primes together, it is computationally infeasible to factor their product back into the original primes for suitably large numbers.

#### RSA Key Generation Steps

1. **Select Two Large Prime Numbers (`p` and `q`):**
   - These should be chosen randomly and kept secret. Typical key sizes use primes hundreds of digits long (1024, 2048, or 4096 bits).
   - The security of RSA increases with the size of these primes.

2. **Compute the Modulus (`n`):**
   - `n = p * q`
   - The modulus `n` is used as part of both the public and private keys.

3. **Calculate Euler's Totient Function (`φ(n)`):**
   - `φ(n) = (p - 1) * (q - 1)`
   - Euler's Totient Function counts the positive integers up to `n` that are relatively prime to `n`.

4. **Choose Public Exponent (`e`):**
   - `e` must be an integer such that `1 < e < φ(n)` and `gcd(e, φ(n)) = 1` (i.e., `e` and `φ(n)` are coprime).
   - Common choices for `e` are 65537, 17, or 3 because they make encryption efficient while maintaining security.

5. **Compute Private Exponent (`d`):**
   - `d` is the modular multiplicative inverse of `e` modulo `φ(n)`, i.e., `d ≡ e⁻¹ mod φ(n)`.
   - This means `(d * e) mod φ(n) = 1`.
   - `d` must be kept secret.

6. **Public and Private Keys:**
   - **Public Key:** The pair `(n, e)`
   - **Private Key:** The pair `(n, d)` (with knowledge of `p` and `q` also considered part of the private key in practical implementations for optimization)

#### RSA Encryption and Decryption

- **Encryption:** Given a plaintext message `m` (represented as an integer `0 ≤ m < n`), compute ciphertext `c`:
  - `c = m^e mod n`
- **Decryption:** Given ciphertext `c`, compute plaintext `m`:
  - `m = c^d mod n`

**Note:** In practice, messages larger than `n` must be split, padded, or handled with hybrid cryptography. Direct use of RSA is not secure for encrypting large data or arbitrary messages (see "Security Notes" below).

#### Why is RSA Secure?

The security of RSA depends on the practical difficulty of factoring the large number `n` back into its prime components `p` and `q`. If an attacker could factor `n`, they could compute `φ(n)` and thus recover the private key `d`. For large enough `n`, this is believed to be infeasible with current technology.

#### Digital Signatures with RSA

Besides encryption, RSA can be used for digital signatures:
- The sender "signs" a message by computing `s = m^d mod n` with their private key.
- The recipient verifies the signature by computing `m = s^e mod n` with the sender's public key.

This allows verification of both authenticity (only the private key holder could have signed) and integrity of the original message.

#### Limitations and Attacks

- **Padding Oracle/Chosen Ciphertext Attacks:** Raw RSA is vulnerable to several attacks if used without proper padding schemes (e.g., PKCS#1 v1.5, OAEP).
- **Key Size:** Increasing computational power makes longer keys necessary. 1024-bit keys are no longer considered secure.
- **Side-channel Attacks:** Timing or power analysis can leak information if not properly mitigated.
- **Quantum Computers:** Shor's algorithm could break RSA if a sufficiently large quantum computer is ever built.

#### Summary Table

| Step           | Symbol  | Description                                                                |
|----------------|---------|----------------------------------------------------------------------------|
| Choose Primes  | p, q    | Large, random primes                                                       |
| Compute Modulus| n       | n = p * q                                                                  |
| Totient        | φ(n)    | φ(n) = (p-1)*(q-1)                                                         |
| Public Exponent| e       | 1 < e < φ(n), gcd(e, φ(n))=1                                               |
| Private Exp.   | d       | d ≡ e⁻¹ mod φ(n)                                                           |
| Public Key     | (n, e)  | Distributed openly                                                         |
| Private Key    | (n, d)  | Kept secret                                                                |
| Encrypt        | c       | c = m^e mod n                                                              |
| Decrypt        | m       | m = c^d mod n                                                              |

#### References

- [Original RSA Paper (1978)](https://people.csail.mit.edu/rivest/Rsapaper.pdf)
- [Wikipedia: RSA (cryptosystem)](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [Practical Cryptography for Developers](https://cryptobook.nakov.com/asymmetric-key-ciphers/rsa-encrypt-decrypt-examples)

---

## Directory Structure

- `src/` — Main C++ source code and headers
- `bin/` — Command-line interface (CLI) implementation
- `tests/` — Test suite
- `examples/` — Example programs (if present)
- `README.md` — Project documentation
- `LICENSE` — License file

## Features

- **Key generation:** Choose from 1024, 2048, 3072, or 4096 bits
- **PEM/DER key serialization:** Compatible with OpenSSL
- **Supports both PKCS#1 and PKCS#8/X.509 key formats for PEM files**
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

Here are updated usage examples using the actual API function names from your rsa.hpp file, covering PEM, PKCS#8, X.509 formats, and encryption/decryption for both messages and files:

---

## Usage Examples

### 1. Generate and Save Keys (PEM, PKCS#8, X.509)

```cpp
#include "rsa.hpp"

int main() {
    // Generate a 2048-bit key pair
    RSA::KeyPair keys = RSA::GenerateKeyPair(RSA::KeySize::Bits2048);

    // Save as PEM (PKCS#1 for private, PKCS#1 for public)
    keys.public_key.save_pem("public.pem");
    keys.private_key.save_pem("private.pem");

    // Save private key as PKCS#8 (X.509 format)
    keys.private_key.save_pkcs8_pem("private_pkcs8.pem");

    // Save public key as X.509 SubjectPublicKeyInfo
    keys.public_key.save_x509_pem("public_x509.pem");
}
```

---

### 2. Load Keys in Various Formats

```cpp
#include "rsa.hpp"

int main() {
    // Load public key (PKCS#1 PEM)
    auto pub1 = RSA::RSAPublicKey::load_pem("public.pem");
    // Load public key (X.509 PEM)
    auto pub2 = RSA::RSAPublicKey::load_x509_pem("public_x509.pem");

    // Load private key (PKCS#1 PEM)
    auto priv1 = RSA::RSAPrivateKey::load_pem("private.pem");
    // Load private key (PKCS#8 PEM)
    auto priv2 = RSA::RSAPrivateKey::load_pkcs8_pem("private_pkcs8.pem");
}
```

---

### 3. Encrypt and Decrypt a String Message

```cpp
#include "rsa.hpp"
#include <iostream>

int main() {
    std::string message = "Hello, RSA!";

    // In-memory keys
    RSA::KeyPair keys = RSA::GenerateKeyPair(RSA::KeySize::Bits1024);

    // Encrypt with public, decrypt with private (in-memory)
    std::string encrypted = RSA::MESSAGE::Encrypt(message, keys.public_key)
                                .toFormat(RSA::OutputFormat::Base64)
                                .toString();
    std::string decrypted = RSA::MESSAGE::Decrypt(encrypted, keys.private_key, RSA::OutputFormat::Base64);

    std::cout << "Decrypted: " << decrypted << std::endl;

    // Using loaded keys (X.509 public, PKCS#8 private)
    auto pub = RSA::RSAPublicKey::load_x509_pem("public_x509.pem");
    auto priv = RSA::RSAPrivateKey::load_pkcs8_pem("private_pkcs8.pem");

    std::string encrypted2 = RSA::MESSAGE::Encrypt(message, pub)
                                 .toFormat(RSA::OutputFormat::Base64)
                                 .toString();
    std::string decrypted2 = RSA::MESSAGE::Decrypt(encrypted2, priv, RSA::OutputFormat::Base64);

    std::cout << "Decrypted (X.509/PKCS#8): " << decrypted2 << std::endl;
}
```

---

### 4. Encrypt and Decrypt a File (All Key Formats)

```cpp
#include "rsa.hpp"

int main() {
    // Load keys
    auto pub = RSA::RSAPublicKey::load_x509_pem("public_x509.pem");
    auto priv = RSA::RSAPrivateKey::load_pkcs8_pem("private_pkcs8.pem");

    // Encrypt file
    RSA::FILE::Encrypt("plain.txt", "enc.bin", pub, RSA::OutputFormat::Binary);

    // Decrypt file
    RSA::FILE::Decrypt("enc.bin", "dec.txt", priv, RSA::OutputFormat::Binary);
}
```

---

### 5. Encrypt to Hex or Base64, Decrypt from Hex or Base64

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

### 6. Quick Reference — Loading Keys (All Formats)

```cpp
// Generate keys
RSA::KeyPair keys = RSA::GenerateKeyPair(RSA::KeySize::Bits2048);

// Load public key
auto pub_pem  = RSA::RSAPublicKey::load_pem("public.pem");
auto pub_x509 = RSA::RSAPublicKey::load_x509_pem("public_x509.pem");

// Load private key
auto priv_pem   = RSA::RSAPrivateKey::load_pem("private.pem");
auto priv_pkcs8 = RSA::RSAPrivateKey::load_pkcs8_pem("private_pkcs8.pem");
```

---

---

## Command-Line Interface: rsa_cli

The project includes a robust CLI tool, `rsa_cli`, for generating keys, encrypting, and decrypting messages or files.  
It handles user prompts, colored output, and supports all core library functionality.

### CLI Usage

```sh
./rsa_cli <command> [options]
```

#### Main Commands

- `genkey`    Generate RSA key pair and save in PEM format.
- `encrypt`   Encrypt a message or file.
- `decrypt`   Decrypt a message or file.

### Flags and Arguments Table

| Command   | Required Flags                                      | Optional Flags & Arguments                                                                                                    | Description                                 |
|-----------|-----------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------|
| genkey    | `--pub <pub.pem>`<br>`--priv <priv.pem>`            | `--bits <size>`<br>`--pem-type <pkcs1\|x509>`<br>`--quick`<br>`--force`<br>`--no-color`                                      | Generate RSA keypair                        |
| encrypt   | `--pub <pub.pem>`<br>`--in <file\|msg>`<br>`--out <file>` | `--format <binary\|base64\|hex>`<br>`--pem-type <pkcs1\|x509>`<br>`--msg`<br>`--quick`<br>`--force`<br>`--no-color` | Encrypt file or message          |
| decrypt   | `--priv <priv.pem>`<br>`--in <file\|msg>`<br>`--out <file>`| `--format <binary\|base64\|hex>`<br>`--pem-type <pkcs1\|x509>`<br>`--msg`<br>`--quick`<br>`--force`<br>`--no-color` | Decrypt file or message         |
|           |                                                     | `--help`<br>`--version`                                                                                                      | Show help/version info                      |

#### Flag Descriptions

- `--pub <file>`: Path to the public key (for encrypt/genkey)
- `--priv <file>`: Path to the private key (for decrypt/genkey)
- `--in <file>`: Input file (for `--msg`, input is a message string)
- `--out <file>`: Output file
- `--bits <size>`: Key size (1024, 2048, 3072, 4096; default: 1024)
- `--format <type>`: Output format (`binary`, `base64`, or `hex`; default: binary)
- `--pem-type <pkcs1|x509>`: **PEM key encoding type; choose between `pkcs1` (traditional RSA) or `x509` (PKCS#8/X.509). Default: `pkcs1`.**
- `--msg`: Treat input as a string message instead of a file
- `--quick`: Suppress confirmation prompts
- `--force`: Overwrite existing output files without prompting
- `--no-color`: Disable colored output
- `--help`: Show help and exit
- `--version`: Print the CLI version

#### CLI Usage Examples

**Generate a key pair (default PKCS#1):**
```sh
./rsa_cli genkey --pub public.pem --priv private.pem --bits 2048 --quick
```

**Generate a key pair with X.509/PKCS#8 encoding:**
```sh
./rsa_cli genkey --pub public.pem --priv private.pem --bits 2048 --pem-type x509 --quick
```

**Encrypt a file as binary using a specific PEM type:**
```sh
./rsa_cli encrypt --pub public.pem --in myfile.txt --out encrypted.bin --format binary --pem-type pkcs1
```

**Decrypt a file with X.509/PKCS#8:**
```sh
./rsa_cli decrypt --priv private.pem --in encrypted.bin --out decrypted.txt --format binary --pem-type x509
```

**Encrypt a message to base64:**
```sh
./rsa_cli encrypt --pub public.pem --in "my secret" --out encrypted.b64 --format base64 --msg
```

**Decrypt a base64 message:**
```sh
./rsa_cli decrypt --priv private.pem --in "base64ciphertext" --out message.txt --format base64 --msg
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
