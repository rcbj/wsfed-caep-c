// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "json.hpp"

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <memory>
#include <string>
#include <vector>

namespace iya::wsfed {

struct PKey {
  EVP_PKEY *key = nullptr;
  explicit PKey(EVP_PKEY *k = nullptr) : key(k) {}
  ~PKey() {
    if (key) EVP_PKEY_free(key);
  }
  PKey(const PKey &) = delete;
  PKey &operator=(const PKey &) = delete;
};

struct Cert {
  X509 *cert = nullptr;
  explicit Cert(X509 *c = nullptr) : cert(c) {}
  ~Cert() {
    if (cert) X509_free(cert);
  }
  Cert(const Cert &) = delete;
  Cert &operator=(const Cert &) = delete;
};

std::shared_ptr<PKey> load_private_key(const std::string &pem);
std::shared_ptr<Cert> load_certificate(const std::string &pem);
bool key_matches(const PKey &key, const Cert &cert);
std::string cert_pem(X509 *cert);
std::string private_pem(EVP_PKEY *key);
std::string cert_common_name(X509 *cert);

KeyPairPem create_self_signed(const std::string &common_name, int days, int bits);

std::vector<unsigned char> sha256_bytes(const std::string &data);
std::vector<unsigned char> sha384_bytes(const std::string &data);
std::vector<unsigned char> sha512_bytes(const std::string &data);
std::vector<unsigned char> digest_bytes(const std::string &name, const std::string &data);

std::vector<unsigned char> rsa_sign_pkcs1(EVP_PKEY *key, const EVP_MD *md, const unsigned char *digest, size_t len);
bool rsa_verify_pkcs1(EVP_PKEY *key, const EVP_MD *md, const unsigned char *digest, size_t dlen,
                      const unsigned char *sig, size_t slen);
bool rsa_verify_pss(EVP_PKEY *key, const EVP_MD *md, const unsigned char *digest, size_t dlen,
                    const unsigned char *sig, size_t slen);
std::vector<unsigned char> rsa_oaep_decrypt(EVP_PKEY *key, const std::string &hash_name,
                                            const unsigned char *in, size_t len);

std::string aes_gcm_decrypt(const unsigned char *key, size_t key_len, const unsigned char *raw, size_t raw_len);
std::string aes_cbc_decrypt(const unsigned char *key, size_t key_len, const unsigned char *raw, size_t raw_len);

EVP_PKEY *jwk_public(const Json &jwk);
bool jws_verify_key(EVP_PKEY *key, const std::string &alg, const std::string &data, const std::vector<unsigned char> &sig);

}  // namespace iya::wsfed
