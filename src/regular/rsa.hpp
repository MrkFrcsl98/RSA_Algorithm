#pragma once
#include <algorithm>
#include <cctype>
#include <ctime>
#include <fstream>
#include <gmpxx.h>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <type_traits>
#include <vector>

// ===== PEM_DER utilities (ASN.1 DER, Base64, PEM) =====
namespace PEM_DER {
inline std::vector<uint8_t> encode_integer(const mpz_class &x) {
  std::vector<uint8_t> bytes;
  size_t count = (mpz_sizeinbase(x.get_mpz_t(), 2) + 7) / 8;
  if (count == 0)
    count = 1;
  bytes.resize(count);
  mpz_export(bytes.data(), &count, 1, 1, 1, 0, x.get_mpz_t());
  if (bytes[0] & 0x80)
    bytes.insert(bytes.begin(), 0x00);
  std::vector<uint8_t> out = {0x02};
  if (bytes.size() < 128) {
    out.push_back(uint8_t(bytes.size()));
  } else {
    std::vector<uint8_t> len;
    size_t lenval = bytes.size();
    while (lenval) {
      len.insert(len.begin(), lenval & 0xFF);
      lenval >>= 8;
    }
    out.push_back(0x80 | len.size());
    out.insert(out.end(), len.begin(), len.end());
  }
  out.insert(out.end(), bytes.begin(), bytes.end());
  return out;
}
inline std::vector<uint8_t> encode_sequence(const std::vector<std::vector<uint8_t>> &fields) {
  std::vector<uint8_t> seq_data;
  for (const auto &f : fields)
    seq_data.insert(seq_data.end(), f.begin(), f.end());
  std::vector<uint8_t> out = {0x30};
  if (seq_data.size() < 128) {
    out.push_back(uint8_t(seq_data.size()));
  } else {
    std::vector<uint8_t> len;
    size_t lenval = seq_data.size();
    while (lenval) {
      len.insert(len.begin(), lenval & 0xFF);
      lenval >>= 8;
    }
    out.push_back(0x80 | len.size());
    out.insert(out.end(), len.begin(), len.end());
  }
  out.insert(out.end(), seq_data.begin(), seq_data.end());
  return out;
}
inline mpz_class decode_integer(const std::vector<uint8_t> &der, size_t &idx) {
  if (der[idx++] != 0x02)
    throw std::runtime_error("ASN.1: expected INTEGER");
  size_t len = der[idx++];
  if (len & 0x80) {
    size_t n = len & 0x7F;
    len = 0;
    for (size_t i = 0; i < n; ++i)
      len = (len << 8) | der[idx++];
  }
  std::vector<uint8_t> bytes(der.begin() + idx, der.begin() + idx + len);
  idx += len;
  if (bytes.size() > 1 && bytes[0] == 0x00)
    bytes.erase(bytes.begin());
  mpz_class val;
  mpz_import(val.get_mpz_t(), bytes.size(), 1, 1, 1, 0, bytes.data());
  return val;
}
inline void decode_sequence(const std::vector<uint8_t> &der, size_t &idx, size_t &seq_end) {
  if (der[idx++] != 0x30)
    throw std::runtime_error("ASN.1: expected SEQUENCE");
  size_t len = der[idx++];
  if (len & 0x80) {
    size_t n = len & 0x7F;
    len = 0;
    for (size_t i = 0; i < n; ++i)
      len = (len << 8) | der[idx++];
  }
  seq_end = idx + len;
}
inline std::string base64_encode(const std::vector<uint8_t> &in) {
  static const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  int val = 0, valb = -6;
  for (uint8_t c : in) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      out.push_back(b64[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6)
    out.push_back(b64[((val << 8) >> (valb + 8)) & 0x3F]);
  while (out.size() % 4)
    out.push_back('=');
  return out;
}
inline std::vector<uint8_t> base64_decode(const std::string &in) {
  static const std::string b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::vector<uint8_t> out;
  std::vector<int> T(256, -1);
  for (int i = 0; i < 64; i++)
    T[b64[i]] = i;
  int val = 0, valb = -8;
  for (uint8_t c : in) {
    if (T[c] == -1)
      continue;
    val = (val << 6) + T[c];
    valb += 6;
    if (valb >= 0) {
      out.push_back(uint8_t((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return out;
}
inline std::string pem_wrap(const std::string &base64, const std::string &type) {
  std::ostringstream oss;
  oss << "-----BEGIN " << type << "-----\n";
  for (size_t i = 0; i < base64.size(); i += 64)
    oss << base64.substr(i, 64) << "\n";
  oss << "-----END " << type << "-----\n";
  return oss.str();
}
inline std::string strip_pem(const std::string &pem) {
  auto begin = pem.find("-----BEGIN");
  if (begin == std::string::npos)
    throw std::runtime_error("Invalid PEM: no BEGIN");
  begin = pem.find('\n', begin);
  auto end = pem.find("-----END");
  if (end == std::string::npos)
    throw std::runtime_error("Invalid PEM: no END");
  std::string b64 = pem.substr(begin + 1, end - begin - 1);
  std::string out;
  for (char c : b64)
    if (isalnum(c) || c == '+' || c == '/' || c == '=')
      out += c;
  return out;
}
} // namespace PEM_DER

// ===== X.509 SubjectPublicKeyInfo helpers =====
namespace X509 {
inline std::vector<uint8_t> oid_rsaEncryption() { return {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01}; }
inline std::vector<uint8_t> encode_null() { return {0x05, 0x00}; }
inline std::vector<uint8_t> encode_algorithm_identifier() {
  auto oid = oid_rsaEncryption();
  auto nul = encode_null();
  std::vector<std::vector<uint8_t>> fields = {oid, nul};
  return PEM_DER::encode_sequence(fields);
}
inline std::vector<uint8_t> encode_bitstring(const std::vector<uint8_t> &bytes) {
  std::vector<uint8_t> out = {0x03};
  size_t len = bytes.size() + 1;
  if (len < 128)
    out.push_back(uint8_t(len));
  else {
    std::vector<uint8_t> lenvec;
    size_t l = len;
    while (l) {
      lenvec.insert(lenvec.begin(), l & 0xFF);
      l >>= 8;
    }
    out.push_back(0x80 | lenvec.size());
    out.insert(out.end(), lenvec.begin(), lenvec.end());
  }
  out.push_back(0x00); // unused bits
  out.insert(out.end(), bytes.begin(), bytes.end());
  return out;
}
inline std::vector<uint8_t> encode_subjectpublickeyinfo(const std::vector<uint8_t> &pkcs1_pub_der) {
  std::vector<std::vector<uint8_t>> fields = {encode_algorithm_identifier(), encode_bitstring(pkcs1_pub_der)};
  return PEM_DER::encode_sequence(fields);
}
inline std::vector<uint8_t> decode_subjectpublickeyinfo(const std::vector<uint8_t> &der) {
  size_t idx = 0, seq_end = 0;
  PEM_DER::decode_sequence(der, idx, seq_end);
  PEM_DER::decode_sequence(der, idx, seq_end); // AlgorithmIdentifier
  if (der[idx++] != 0x06)
    throw std::runtime_error("Expected OID in AlgorithmIdentifier");
  uint8_t oid_len = der[idx++];
  if (oid_len != 9 || !std::equal(der.begin() + idx, der.begin() + idx + oid_len, oid_rsaEncryption().begin() + 2))
    throw std::runtime_error("Expected rsaEncryption OID");
  idx += oid_len;
  if (der[idx++] != 0x05 || der[idx++] != 0x00)
    throw std::runtime_error("Expected NULL in AlgorithmIdentifier");
  if (der[idx++] != 0x03)
    throw std::runtime_error("Expected BIT STRING for public key");
  size_t len = der[idx++];
  if (len & 0x80) {
    size_t n = len & 0x7F;
    len = 0;
    for (size_t i = 0; i < n; ++i)
      len = (len << 8) | der[idx++];
  }
  if (der[idx++] != 0x00)
    throw std::runtime_error("Expected 0 unused bits in BIT STRING");
  std::vector<uint8_t> pkcs1_der(der.begin() + idx, der.begin() + idx + len - 1);
  return pkcs1_der;
}
} // namespace X509

// ================= RSA Core =====================
namespace RSA {

namespace RSA_Internal {

class SHA256 {
  uint32_t h[8], datalen;
  uint64_t bitlen;
  uint8_t data[64];
  static constexpr uint32_t k[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
                                     0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
                                     0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
                                     0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                                     0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
                                     0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
  static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
  static void to_bytes(uint32_t val, uint8_t *bytes) {
    bytes[0] = (val >> 24) & 0xff;
    bytes[1] = (val >> 16) & 0xff;
    bytes[2] = (val >> 8) & 0xff;
    bytes[3] = val & 0xff;
  }
  static uint32_t to_uint32(const uint8_t *bytes) { return (uint32_t(bytes[0]) << 24) | (uint32_t(bytes[1]) << 16) | (uint32_t(bytes[2]) << 8) | (uint32_t(bytes[3])); }
  void transform() {
    uint32_t m[64], a, b, c, d, e, f, g, h_;
    for (int i = 0; i < 16; ++i)
      m[i] = to_uint32(data + i * 4);
    for (int i = 16; i < 64; ++i)
      m[i] = (rotr(m[i - 2], 17) ^ rotr(m[i - 2], 19) ^ (m[i - 2] >> 10)) + m[i - 7] + (rotr(m[i - 15], 7) ^ rotr(m[i - 15], 18) ^ (m[i - 15] >> 3)) + m[i - 16];
    a = h[0];
    b = h[1];
    c = h[2];
    d = h[3];
    e = h[4];
    f = h[5];
    g = h[6];
    h_ = h[7];
    for (int i = 0; i < 64; ++i) {
      uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      uint32_t ch = (e & f) ^ ((~e) & g);
      uint32_t temp1 = h_ + S1 + ch + k[i] + m[i];
      uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      uint32_t temp2 = S0 + maj;
      h_ = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += h_;
  }

public:
  SHA256() { reset(); }
  void reset() {
    h[0] = 0x6a09e667;
    h[1] = 0xbb67ae85;
    h[2] = 0x3c6ef372;
    h[3] = 0xa54ff53a;
    h[4] = 0x510e527f;
    h[5] = 0x9b05688c;
    h[6] = 0x1f83d9ab;
    h[7] = 0x5be0cd19;
    datalen = 0;
    bitlen = 0;
  }
  void update(const uint8_t *dataIn, size_t len) {
    for (size_t i = 0; i < len; ++i) {
      data[datalen++] = dataIn[i];
      if (datalen == 64) {
        transform();
        bitlen += 512;
        datalen = 0;
      }
    }
  }
  void update(const std::vector<uint8_t> &in) { update(in.data(), in.size()); }
  void update(const std::string &in) { update((const uint8_t *)in.data(), in.size()); }
  std::vector<uint8_t> digest() {
    uint64_t bitlen_ = bitlen + datalen * 8;
    data[datalen++] = 0x80;
    if (datalen > 56) {
      while (datalen < 64)
        data[datalen++] = 0;
      transform();
      datalen = 0;
    }
    while (datalen < 56)
      data[datalen++] = 0;
    for (int i = 7; i >= 0; --i)
      data[datalen++] = (bitlen_ >> (i * 8)) & 0xFF;
    transform();
    std::vector<uint8_t> out(32);
    for (int i = 0; i < 8; ++i)
      to_bytes(h[i], &out[i * 4]);
    return out;
  }
  static std::vector<uint8_t> hash(const std::vector<uint8_t> &in) {
    SHA256 sha;
    sha.update(in);
    return sha.digest();
  }
  static std::vector<uint8_t> hash(const std::string &in) {
    SHA256 sha;
    sha.update(in);
    return sha.digest();
  }
};

// ================= MGF1 using SHA-256 =================
inline std::vector<uint8_t> MGF1_SHA256(const std::vector<uint8_t> &seed, size_t length) {
  std::vector<uint8_t> mask;
  for (uint32_t i = 0; mask.size() < length; ++i) {
    std::vector<uint8_t> cnt = {uint8_t(i >> 24), uint8_t(i >> 16), uint8_t(i >> 8), uint8_t(i)};
    std::vector<uint8_t> data(seed);
    data.insert(data.end(), cnt.begin(), cnt.end());
    auto h = SHA256::hash(data);
    mask.insert(mask.end(), h.begin(), h.end());
  }
  mask.resize(length);
  return mask;
}

// ================= OAEP Padding w/ SHA-256 =================
inline std::vector<uint8_t> OAEP_encode(const std::vector<uint8_t> &message, size_t k, const std::vector<uint8_t> &label = {}) {
  const size_t hLen = 32; // SHA-256 output size
  if (message.size() > k - 2 * hLen - 2)
    throw std::runtime_error("Message too long for OAEP");
  std::vector<uint8_t> lHash = SHA256::hash(label);
  std::vector<uint8_t> PS(k - message.size() - 2 * hLen - 2, 0x00);
  std::vector<uint8_t> DB; // DB = lHash || PS || 0x01 || M
  DB.insert(DB.end(), lHash.begin(), lHash.end());
  DB.insert(DB.end(), PS.begin(), PS.end());
  DB.push_back(0x01);
  DB.insert(DB.end(), message.begin(), message.end());
  // Generate a random seed
  std::vector<uint8_t> seed(hLen);
  for (auto &b : seed)
    b = uint8_t(rand() % 256); // (Replace with cryptographic RNG in production)
  // Mask DB and seed
  std::vector<uint8_t> dbMask = MGF1_SHA256(seed, k - hLen - 1);
  std::vector<uint8_t> maskedDB(DB.size());
  for (size_t i = 0; i < DB.size(); ++i)
    maskedDB[i] = DB[i] ^ dbMask[i];
  std::vector<uint8_t> seedMask = MGF1_SHA256(maskedDB, hLen);
  std::vector<uint8_t> maskedSeed(hLen);
  for (size_t i = 0; i < hLen; ++i)
    maskedSeed[i] = seed[i] ^ seedMask[i];
  // Output: 0x00 || maskedSeed || maskedDB
  std::vector<uint8_t> EM;
  EM.push_back(0x00);
  EM.insert(EM.end(), maskedSeed.begin(), maskedSeed.end());
  EM.insert(EM.end(), maskedDB.begin(), maskedDB.end());
  return EM;
}

inline std::vector<uint8_t> OAEP_decode(const std::vector<uint8_t> &EM, size_t k, const std::vector<uint8_t> &label = {}) {
  const size_t hLen = 32;
  if (EM.size() != k)
    throw std::runtime_error("Decryption error: OAEP length mismatch");
  uint8_t first_byte = EM[0];
  std::vector<uint8_t> maskedSeed(EM.begin() + 1, EM.begin() + 1 + hLen);
  std::vector<uint8_t> maskedDB(EM.begin() + 1 + hLen, EM.end());
  std::vector<uint8_t> seedMask = RSA_Internal::MGF1_SHA256(maskedDB, hLen);
  std::vector<uint8_t> seed(hLen);
  for (size_t i = 0; i < hLen; ++i)
    seed[i] = maskedSeed[i] ^ seedMask[i];
  std::vector<uint8_t> dbMask = RSA_Internal::MGF1_SHA256(seed, k - hLen - 1);
  std::vector<uint8_t> DB(maskedDB.size());
  for (size_t i = 0; i < DB.size(); ++i)
    DB[i] = maskedDB[i] ^ dbMask[i];
  std::vector<uint8_t> lHash = RSA_Internal::SHA256::hash(label);

  // Constant-time lHash comparison
  uint8_t lHash_mismatch = 0;
  for (size_t i = 0; i < hLen; ++i)
    lHash_mismatch |= (lHash[i] ^ DB[i]);

  // Constant-time search for 0x01 delimiter after PS
  size_t msg_start = hLen;
  uint8_t found_delim = 0;
  for (size_t i = hLen; i < DB.size(); ++i) {
    uint8_t is_one = (DB[i] == 0x01);
    msg_start = is_one && !found_delim ? i + 1 : msg_start;
    found_delim |= is_one;
  }

  // If any error, set fail
  uint8_t fail = lHash_mismatch | (first_byte != 0) | (!found_delim);

  // Produce dummy message if fail
  std::vector<uint8_t> result(DB.begin() + msg_start, DB.end());
  if (fail) {
    // Return a vector of zeroes of max allowed length (leaks nothing)
    result.assign(DB.size() - hLen, 0);
  }
  return result;
}

} // namespace RSA_Internal

enum class KeySize { Bits1024 = 1024, Bits2048 = 2048, Bits3072 = 3072, Bits4096 = 4096 };
enum class OutputFormat { Binary, Hex, Base64 };

// ----- Key classes -----
class RSAPublicKey {
public:
  mpz_class n, e;
  RSAPublicKey() : n(0), e(0) {}
  RSAPublicKey(const mpz_class &n_, const mpz_class &e_) : n(n_), e(e_) {}
  std::vector<uint8_t> to_der() const {
    std::vector<std::vector<uint8_t>> fields = {PEM_DER::encode_integer(n), PEM_DER::encode_integer(e)};
    return PEM_DER::encode_sequence(fields);
  }
  std::string to_pem() const { return PEM_DER::pem_wrap(PEM_DER::base64_encode(to_der()), "RSA PUBLIC KEY"); }
  static RSAPublicKey from_der(const std::vector<uint8_t> &der) {
    size_t idx = 0, seq_end = 0;
    PEM_DER::decode_sequence(der, idx, seq_end);
    mpz_class n = PEM_DER::decode_integer(der, idx);
    mpz_class e = PEM_DER::decode_integer(der, idx);
    return RSAPublicKey(n, e);
  }
  static RSAPublicKey from_pem(const std::string &pem) {
    auto der = PEM_DER::base64_decode(PEM_DER::strip_pem(pem));
    return from_der(der);
  }
  void save_pem(const std::string &filename) const { std::ofstream(filename) << to_pem(); }
  static RSAPublicKey load_pem(const std::string &filename) {
    std::ifstream f(filename);
    if (!f)
      throw std::runtime_error("Cannot open public PEM: " + filename);
    std::ostringstream ss;
    ss << f.rdbuf();
    return from_pem(ss.str());
  }

  // ===== X.509 additions for public key support =====
  std::vector<uint8_t> to_x509_der() const { return X509::encode_subjectpublickeyinfo(to_der()); }
  std::string to_x509_pem() const { return PEM_DER::pem_wrap(PEM_DER::base64_encode(to_x509_der()), "PUBLIC KEY"); }
  static RSAPublicKey from_x509_der(const std::vector<uint8_t> &der) {
    auto pkcs1_der = X509::decode_subjectpublickeyinfo(der);
    return from_der(pkcs1_der);
  }
  static RSAPublicKey from_x509_pem(const std::string &pem) {
    auto der = PEM_DER::base64_decode(PEM_DER::strip_pem(pem));
    return from_x509_der(der);
  }
  void save_x509_pem(const std::string &filename) const { std::ofstream(filename) << to_x509_pem(); }
  static RSAPublicKey load_x509_pem(const std::string &filename) {
    std::ifstream f(filename);
    if (!f)
      throw std::runtime_error("Cannot open X.509 PEM: " + filename);
    std::ostringstream ss;
    ss << f.rdbuf();
    return from_x509_pem(ss.str());
  }
};

class RSAPrivateKey {
public:
  mpz_class n, e, d, p, q, dP, dQ, qInv;
  RSAPrivateKey() : n(0), e(0), d(0), p(0), q(0), dP(0), dQ(0), qInv(0) {}
  RSAPrivateKey(const mpz_class &n_, const mpz_class &e_, const mpz_class &d_, const mpz_class &p_, const mpz_class &q_, const mpz_class &dP_, const mpz_class &dQ_,
                const mpz_class &qInv_)
      : n(n_), e(e_), d(d_), p(p_), q(q_), dP(dP_), dQ(dQ_), qInv(qInv_) {}
  std::vector<uint8_t> to_der() const {
    std::vector<std::vector<uint8_t>> fields = {PEM_DER::encode_integer(0),  PEM_DER::encode_integer(n),  PEM_DER::encode_integer(e),
                                                PEM_DER::encode_integer(d),  PEM_DER::encode_integer(p),  PEM_DER::encode_integer(q),
                                                PEM_DER::encode_integer(dP), PEM_DER::encode_integer(dQ), PEM_DER::encode_integer(qInv)};
    return PEM_DER::encode_sequence(fields);
  }
  std::string to_pem() const { return PEM_DER::pem_wrap(PEM_DER::base64_encode(to_der()), "RSA PRIVATE KEY"); }
  static RSAPrivateKey from_der(const std::vector<uint8_t> &der) {
    size_t idx = 0, seq_end = 0;
    PEM_DER::decode_sequence(der, idx, seq_end);
    (void)PEM_DER::decode_integer(der, idx); // version
    mpz_class n = PEM_DER::decode_integer(der, idx);
    mpz_class e = PEM_DER::decode_integer(der, idx);
    mpz_class d = PEM_DER::decode_integer(der, idx);
    mpz_class p = PEM_DER::decode_integer(der, idx);
    mpz_class q = PEM_DER::decode_integer(der, idx);
    mpz_class dP = PEM_DER::decode_integer(der, idx);
    mpz_class dQ = PEM_DER::decode_integer(der, idx);
    mpz_class qInv = PEM_DER::decode_integer(der, idx);
    return RSAPrivateKey(n, e, d, p, q, dP, dQ, qInv);
  }
  static RSAPrivateKey from_pem(const std::string &pem) {
    auto der = PEM_DER::base64_decode(PEM_DER::strip_pem(pem));
    return from_der(der);
  }
  void save_pem(const std::string &filename) const { std::ofstream(filename) << to_pem(); }
  static RSAPrivateKey load_pem(const std::string &filename) {
    std::ifstream f(filename);
    if (!f)
      throw std::runtime_error("Cannot open private PEM: " + filename);
    std::ostringstream ss;
    ss << f.rdbuf();
    return from_pem(ss.str());
  }
};

struct KeyPair {
  RSAPublicKey public_key;
  RSAPrivateKey private_key;
};

namespace UTIL {
inline std::vector<uint8_t> mpz_to_bytes(const mpz_class &value) {
  size_t count = (mpz_sizeinbase(value.get_mpz_t(), 2) + 7) / 8;
  std::vector<uint8_t> bytes(count ? count : 1, 0);
  mpz_export(bytes.data(), &count, 1, 1, 1, 0, value.get_mpz_t());
  if (bytes.empty())
    bytes.push_back(0);
  while (bytes.size() > 1 && bytes[0] == 0)
    bytes.erase(bytes.begin());
  return bytes;
}
inline mpz_class bytes_to_mpz(const std::vector<uint8_t> &bytes) {
  mpz_class value;
  mpz_import(value.get_mpz_t(), bytes.size(), 1, 1, 1, 0, bytes.data());
  return value;
}
inline std::vector<uint8_t> read_file(const std::string &filename) {
  std::ifstream file(filename, std::ios::binary);
  if (!file)
    throw std::runtime_error("Cannot open file for reading: " + filename);
  return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}
inline void write_file(const std::string &filename, const std::vector<uint8_t> &data) {
  std::ofstream file(filename, std::ios::binary);
  if (!file)
    throw std::runtime_error("Cannot open file for writing: " + filename);
  file.write(reinterpret_cast<const char *>(data.data()), data.size());
}
inline void write_text(const std::string &filename, const std::string &data) {
  std::ofstream file(filename);
  if (!file)
    throw std::runtime_error("Cannot open file for writing (text): " + filename);
  file << data;
}
inline bool file_exists(const std::string &filename) {
  std::ifstream f(filename, std::ios::binary);
  return f.good();
}
inline mpz_class random_prime(int bits, gmp_randclass &rng) {
  mpz_class p;
  while (true) {
    p = rng.get_z_bits(bits);
    mpz_setbit(p.get_mpz_t(), bits - 1);
    mpz_setbit(p.get_mpz_t(), 0);
    if (mpz_probab_prime_p(p.get_mpz_t(), 25))
      return p;
  }
}
inline mpz_class modinv(const mpz_class &a, const mpz_class &m) {
  mpz_class inv;
  if (mpz_invert(inv.get_mpz_t(), a.get_mpz_t(), m.get_mpz_t()) == 0)
    throw std::runtime_error("No modular inverse exists");
  return inv;
}
inline mpz_class powm(const mpz_class &base, const mpz_class &exp, const mpz_class &mod) {
  mpz_class result;
  mpz_powm(result.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
  return result;
}
inline std::string bytes_to_hex(const std::vector<uint8_t> &data) {
  std::ostringstream oss;
  for (auto b : data)
    oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
  return oss.str();
}
inline std::vector<uint8_t> hex_to_bytes(const std::string &hex) {
  std::vector<uint8_t> data;
  for (size_t i = 0; i + 1 < hex.length(); i += 2)
    data.push_back((uint8_t)std::stoi(hex.substr(i, 2), nullptr, 16));
  return data;
}
} // namespace UTIL

inline KeyPair GenerateKeyPair(KeySize bits = KeySize::Bits2048) {
  int num_bits = static_cast<int>(bits);
  if (num_bits < 512)
    throw std::runtime_error("Key size too small.");
  gmp_randclass rng(gmp_randinit_mt);
  rng.seed(static_cast<unsigned long>(std::time(nullptr)));
  mpz_class p = UTIL::random_prime(num_bits / 2, rng);
  mpz_class q;
  do {
    q = UTIL::random_prime(num_bits / 2, rng);
  } while (q == p);
  mpz_class n = p * q;
  mpz_class phi = (p - 1) * (q - 1);
  mpz_class e = 65537;
  mpz_class d = UTIL::modinv(e, phi);
  mpz_class dP = d % (p - 1);
  mpz_class dQ = d % (q - 1);
  mpz_class qInv = UTIL::modinv(q, p);
  RSAPublicKey pub(n, e);
  RSAPrivateKey priv(n, e, d, p, q, dP, dQ, qInv);
  return {pub, priv};
}

namespace RSA_Internal {
inline std::vector<mpz_class> encrypt_blocks(const std::vector<uint8_t> &data, const RSAPublicKey &pub) {
  if (pub.n == 0 || pub.e == 0)
    throw std::runtime_error("Public key is not initialized.");
  std::vector<mpz_class> ciphertexts;
  for (uint8_t c : data)
    ciphertexts.push_back(UTIL::powm(c, pub.e, pub.n));
  return ciphertexts;
}
inline std::vector<uint8_t> decrypt_blocks(const std::vector<mpz_class> &cts, const RSAPrivateKey &priv) {
  if (priv.n == 0 || priv.d == 0)
    throw std::runtime_error("Private key is not initialized.");
  std::vector<uint8_t> message;
  for (const auto &c : cts)
    message.push_back(static_cast<uint8_t>(UTIL::powm(c, priv.d, priv.n).get_ui() & 0xFF));
  return message;
}
inline std::vector<uint8_t> cts_to_bytes(const std::vector<mpz_class> &cts, size_t mod_bytes) {
  std::vector<uint8_t> out;
  for (const auto &block : cts) {
    auto bytes = UTIL::mpz_to_bytes(block);
    if (bytes.size() < mod_bytes)
      bytes.insert(bytes.begin(), mod_bytes - bytes.size(), 0);
    out.insert(out.end(), bytes.begin(), bytes.end());
  }
  return out;
}
inline std::vector<mpz_class> bytes_to_cts(const std::vector<uint8_t> &raw, size_t mod_bytes) {
  std::vector<mpz_class> blocks;
  for (size_t i = 0; i < raw.size(); i += mod_bytes) {
    std::vector<uint8_t> sub(raw.begin() + i, raw.begin() + std::min(raw.size(), i + mod_bytes));
    blocks.push_back(UTIL::bytes_to_mpz(sub));
  }
  return blocks;
}
inline std::vector<uint8_t> decode_by_format(const std::string &in, OutputFormat fmt) {
  if (fmt == OutputFormat::Binary)
    return std::vector<uint8_t>(in.begin(), in.end());
  else if (fmt == OutputFormat::Hex)
    return UTIL::hex_to_bytes(in);
  else if (fmt == OutputFormat::Base64)
    return PEM_DER::base64_decode(in);
  throw std::runtime_error("Unknown OutputFormat for decoding input");
}
inline std::string encode_by_format(const std::vector<uint8_t> &in, OutputFormat fmt) {
  if (fmt == OutputFormat::Binary)
    return std::string(in.begin(), in.end());
  else if (fmt == OutputFormat::Hex)
    return UTIL::bytes_to_hex(in);
  else if (fmt == OutputFormat::Base64)
    return PEM_DER::base64_encode(in);
  throw std::runtime_error("Unknown OutputFormat for encoding output");
}
} // namespace RSA_Internal

class EncryptedResult {
  std::vector<uint8_t> raw;
  OutputFormat format;

public:
  EncryptedResult(std::vector<uint8_t> rawData) : raw(std::move(rawData)), format(OutputFormat::Binary) {}
  EncryptedResult &toFormat(OutputFormat fmt) {
    format = fmt;
    return *this;
  }
  std::string toString() const {
    switch (format) {
    case OutputFormat::Hex:
      return UTIL::bytes_to_hex(raw);
    case OutputFormat::Base64:
      return PEM_DER::base64_encode(raw);
    case OutputFormat::Binary:
    default:
      return std::string(raw.begin(), raw.end());
    }
  }
  std::vector<uint8_t> toVector() const { return raw; }
  OutputFormat getFormat() const { return format; }
};

class DecryptedResult {
  std::vector<uint8_t> raw;

public:
  DecryptedResult(std::vector<uint8_t> rawData) : raw(std::move(rawData)) {}
  std::string toString() const { return std::string(raw.begin(), raw.end()); }
  std::vector<uint8_t> toVector() const { return raw; }
};

namespace MESSAGE {

inline EncryptedResult Encrypt(const std::string &message, const RSAPublicKey &pub, const std::vector<uint8_t> &label = {}) {
  if (message.empty())
    throw std::runtime_error("Message is empty.");
  size_t mod_bytes = (mpz_sizeinbase(pub.n.get_mpz_t(), 2) + 7) / 8;
  auto padded = RSA_Internal::OAEP_encode(std::vector<uint8_t>(message.begin(), message.end()), mod_bytes, label);
  mpz_class m = UTIL::bytes_to_mpz(padded);
  if (m >= pub.n)
    throw std::runtime_error("OAEP: message representative out of range");
  mpz_class c = UTIL::powm(m, pub.e, pub.n);
  auto block = UTIL::mpz_to_bytes(c);
  if (block.size() < mod_bytes)
    block.insert(block.begin(), mod_bytes - block.size(), 0);
  return EncryptedResult(block);
}

inline DecryptedResult Decrypt(const EncryptedResult &enc, const RSAPrivateKey &priv, const std::vector<uint8_t> &label = {}) {
  auto raw = enc.toVector();
  size_t mod_bytes = (mpz_sizeinbase(priv.n.get_mpz_t(), 2) + 7) / 8;
  if (raw.size() != mod_bytes)
    throw std::runtime_error("Ciphertext size mismatch.");
  mpz_class c = UTIL::bytes_to_mpz(raw);
  mpz_class m = UTIL::powm(c, priv.d, priv.n);
  auto em = UTIL::mpz_to_bytes(m);
  if (em.size() < mod_bytes)
    em.insert(em.begin(), mod_bytes - em.size(), 0);
  auto msg = RSA_Internal::OAEP_decode(em, mod_bytes, label);
  return DecryptedResult(msg);
}

} // namespace MESSAGE

namespace FILE {

// OAEP max message length for a given modulus size
inline size_t oaep_max_message_len(size_t mod_bytes) {
  return mod_bytes - 2 * 32 - 2; // 32 = SHA-256 output size
}

// CONSTANT-TIME OAEP DECODE
inline std::vector<uint8_t> OAEP_decode_ct(const std::vector<uint8_t> &EM, size_t k, const std::string &label = "") {
  const size_t hLen = 32;
  if (EM.size() != k)
    throw std::runtime_error("Decryption error: OAEP length mismatch");
  uint8_t first_byte = EM[0];
  std::vector<uint8_t> maskedSeed(EM.begin() + 1, EM.begin() + 1 + hLen);
  std::vector<uint8_t> maskedDB(EM.begin() + 1 + hLen, EM.end());
  std::vector<uint8_t> seedMask = RSA_Internal::MGF1_SHA256(maskedDB, hLen);
  std::vector<uint8_t> seed(hLen);
  for (size_t i = 0; i < hLen; ++i)
    seed[i] = maskedSeed[i] ^ seedMask[i];
  std::vector<uint8_t> dbMask = RSA_Internal::MGF1_SHA256(seed, k - hLen - 1);
  std::vector<uint8_t> DB(maskedDB.size());
  for (size_t i = 0; i < DB.size(); ++i)
    DB[i] = maskedDB[i] ^ dbMask[i];
  std::vector<uint8_t> lHash = RSA_Internal::SHA256::hash(label);

  // Constant-time lHash comparison
  uint8_t lHash_mismatch = 0;
  for (size_t i = 0; i < hLen; ++i)
    lHash_mismatch |= (lHash[i] ^ DB[i]);

  // Constant-time search for 0x01 delimiter after PS
  size_t msg_start = hLen;
  uint8_t found_delim = 0;
  for (size_t i = hLen; i < DB.size(); ++i) {
    uint8_t is_one = (DB[i] == 0x01);
    msg_start = is_one && !found_delim ? i + 1 : msg_start;
    found_delim |= is_one;
  }

  // If any error, set fail
  uint8_t fail = lHash_mismatch | (first_byte != 0) | (!found_delim);

  // Produce dummy message if fail
  std::vector<uint8_t> result(DB.begin() + msg_start, DB.end());
  if (fail) {
    // Return a vector of zeroes of max allowed length (leaks nothing)
    result.assign(DB.size() - hLen, 0);
  }
  return result;
}

// OAEP file encryption (with string label)
inline void Encrypt(const std::string &inputFile, const std::string &outputFile, const RSAPublicKey &pub, OutputFormat fmt, const std::string &oaep_label = "") {
  if (!UTIL::file_exists(inputFile))
    throw std::runtime_error("Input file does not exist: " + inputFile);
  auto data = UTIL::read_file(inputFile);
  if (data.empty())
    throw std::runtime_error("Input file is empty: " + inputFile);

  size_t mod_bytes = (mpz_sizeinbase(pub.n.get_mpz_t(), 2) + 7) / 8;
  size_t max_msg_len = oaep_max_message_len(mod_bytes);

  std::vector<uint8_t> out;
  for (size_t i = 0; i < data.size(); i += max_msg_len) {
    size_t chunk_len = std::min(max_msg_len, data.size() - i);
    std::vector<uint8_t> chunk(data.begin() + i, data.begin() + i + chunk_len);
    auto padded = RSA_Internal::OAEP_encode(chunk, mod_bytes, std::vector<uint8_t>(oaep_label.begin(), oaep_label.end()));
    mpz_class m = RSA::UTIL::bytes_to_mpz(padded);
    if (m >= pub.n)
      throw std::runtime_error("OAEP: message representative out of range");
    mpz_class c = RSA::UTIL::powm(m, pub.e, pub.n);
    auto block = RSA::UTIL::mpz_to_bytes(c);
    if (block.size() < mod_bytes)
      block.insert(block.begin(), mod_bytes - block.size(), 0);
    out.insert(out.end(), block.begin(), block.end());
  }

  if (fmt == OutputFormat::Binary)
    UTIL::write_file(outputFile, out);
  else if (fmt == OutputFormat::Hex)
    UTIL::write_text(outputFile, UTIL::bytes_to_hex(out));
  else if (fmt == OutputFormat::Base64)
    UTIL::write_text(outputFile, PEM_DER::base64_encode(out));
}

// OAEP file decryption with RSA blinding and constant-time OAEP decode
inline void Decrypt(const std::string &inputFile, const std::string &outputFile, const RSAPrivateKey &priv, OutputFormat fmt, const std::string &oaep_label = "") {
  if (!UTIL::file_exists(inputFile))
    throw std::runtime_error("Encrypted file does not exist: " + inputFile);

  std::vector<uint8_t> raw;
  if (fmt == OutputFormat::Binary)
    raw = UTIL::read_file(inputFile);
  else {
    std::ifstream file(inputFile);
    if (!file)
      throw std::runtime_error("Cannot open encrypted file: " + inputFile);
    std::ostringstream ss;
    ss << file.rdbuf();
    if (fmt == OutputFormat::Hex)
      raw = UTIL::hex_to_bytes(ss.str());
    else if (fmt == OutputFormat::Base64)
      raw = PEM_DER::base64_decode(ss.str());
  }

  size_t mod_bytes = (mpz_sizeinbase(priv.n.get_mpz_t(), 2) + 7) / 8;
  if (raw.size() % mod_bytes != 0)
    throw std::runtime_error("Ciphertext size is not a multiple of modulus size.");

  std::vector<uint8_t> message;
  for (size_t i = 0; i < raw.size(); i += mod_bytes) {
    std::vector<uint8_t> block(raw.begin() + i, raw.begin() + i + mod_bytes);
    // RSA blinding
    mpz_class c = RSA::UTIL::bytes_to_mpz(block);
    gmp_randclass rng(gmp_randinit_mt);
    rng.seed(static_cast<unsigned long>(std::time(nullptr)) ^ (uintptr_t)&block ^ i);
    mpz_class r, g;
    do {
      r = rng.get_z_range(priv.n - 2) + 1;
      mpz_gcd(g.get_mpz_t(), r.get_mpz_t(), priv.n.get_mpz_t());
    } while (g != 1);
    mpz_class r_e = RSA::UTIL::powm(r, priv.e, priv.n);
    mpz_class c_blind = (c * r_e) % priv.n;
    mpz_class m_blind = RSA::UTIL::powm(c_blind, priv.d, priv.n);
    mpz_class r_inv = RSA::UTIL::modinv(r, priv.n);
    mpz_class m = (m_blind * r_inv) % priv.n;

    auto em = RSA::UTIL::mpz_to_bytes(m);
    if (em.size() < mod_bytes)
      em.insert(em.begin(), mod_bytes - em.size(), 0);
    auto chunk = OAEP_decode_ct(em, mod_bytes, oaep_label);
    message.insert(message.end(), chunk.begin(), chunk.end());
  }

  UTIL::write_file(outputFile, message);
}

} // namespace FILE

} // namespace RSA
