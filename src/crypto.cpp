// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "crypto.hpp"

#include "b64.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>

#include <cstring>
#include <ctime>

namespace iya::wsfed {
namespace {

std::string ossl_error() {
  char buf[256];
  unsigned long e = ERR_get_error();
  if (!e) return "openssl error";
  ERR_error_string_n(e, buf, sizeof buf);
  return buf;
}

const EVP_MD *md_by_name(const std::string &name) {
  if (name == "sha256") return EVP_sha256();
  if (name == "sha384") return EVP_sha384();
  if (name == "sha512") return EVP_sha512();
  return EVP_sha1();
}

std::vector<unsigned char> bn_bytes(const BIGNUM *bn) {
  std::vector<unsigned char> out(static_cast<size_t>(BN_num_bytes(bn)));
  if (!out.empty()) BN_bn2bin(bn, out.data());
  if (out.empty()) out.push_back(0);
  return out;
}

}  // namespace

std::shared_ptr<PKey> load_private_key(const std::string &pem) {
  if (pem.find("-----BEGIN ") == std::string::npos) {
    fail("config", "the private key or certificate cannot be read: not a PEM");
  }
  BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!bio) fail("config", "the private key or certificate cannot be read: not a PEM");
  EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  if (!key) {
    std::string detail = ossl_error();
    fail("config", "the private key or certificate cannot be read: " + detail);
  }
  if (!EVP_PKEY_is_a(key, "RSA")) {
    EVP_PKEY_free(key);
    fail("config", "the private key is not RSA; an RSA key is required");
  }
  return std::make_shared<PKey>(key);
}

std::shared_ptr<Cert> load_certificate(const std::string &pem) {
  if (pem.find("-----BEGIN ") == std::string::npos) {
    fail("config", "the private key or certificate cannot be read: not a PEM");
  }
  BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!bio) fail("config", "the private key or certificate cannot be read: not a PEM");
  X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  if (!cert) {
    std::string detail = ossl_error();
    fail("config", "the private key or certificate cannot be read: " + detail);
  }
  return std::make_shared<Cert>(cert);
}

bool key_matches(const PKey &key, const Cert &cert) {
  EVP_PKEY *pub = X509_get_pubkey(cert.cert);
  if (!pub) return false;
  bool ok = EVP_PKEY_eq(key.key, pub) == 1;
  EVP_PKEY_free(pub);
  return ok;
}

std::string cert_pem(X509 *cert) {
  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(bio, cert);
  char *data = nullptr;
  long len = BIO_get_mem_data(bio, &data);
  std::string out(data, data && len > 0 ? static_cast<size_t>(len) : 0);
  BIO_free(bio);
  return out;
}

std::string private_pem(EVP_PKEY *key) {
  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr);
  char *data = nullptr;
  long len = BIO_get_mem_data(bio, &data);
  std::string out(data, data && len > 0 ? static_cast<size_t>(len) : 0);
  BIO_free(bio);
  return out;
}

std::string cert_common_name(X509 *cert) {
  X509_NAME *name = X509_get_subject_name(cert);
  if (!name) return "";
  int idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
  if (idx < 0) return "";
  X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, idx);
  ASN1_STRING *str = X509_NAME_ENTRY_get_data(entry);
  unsigned char *utf = nullptr;
  int n = ASN1_STRING_to_UTF8(&utf, str);
  std::string out;
  if (n >= 0 && utf) out.assign(reinterpret_cast<char *>(utf), static_cast<size_t>(n));
  if (utf) OPENSSL_free(utf);
  return out;
}

KeyPairPem create_self_signed(const std::string &common_name, int days, int bits) {
  if (days <= 0) days = 1095;
  if (bits == 0) bits = 3072;
  EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, bits) <= 0) {
    if (kctx) EVP_PKEY_CTX_free(kctx);
    fail("config", "a key could not be generated");
  }
  EVP_PKEY *pkey = nullptr;
  if (EVP_PKEY_keygen(kctx, &pkey) <= 0) {
    EVP_PKEY_CTX_free(kctx);
    fail("config", "a key could not be generated");
  }
  EVP_PKEY_CTX_free(kctx);

  X509 *cert = X509_new();
  X509_set_version(cert, 2);
  unsigned char serial[16];
  if (RAND_bytes(serial, sizeof serial) != 1) {
    X509_free(cert);
    EVP_PKEY_free(pkey);
    fail("config", "a key could not be generated");
  }
  serial[0] &= 0x7F;
  if (serial[0] == 0) serial[0] = 1;
  BIGNUM *bn = BN_bin2bn(serial, sizeof serial, nullptr);
  ASN1_INTEGER *ai = BN_to_ASN1_INTEGER(bn, nullptr);
  X509_set_serialNumber(cert, ai);
  ASN1_INTEGER_free(ai);
  BN_free(bn);

  time_t not_before = time(nullptr) - 60;
  X509_gmtime_adj(X509_getm_notBefore(cert), not_before - time(nullptr));
  X509_gmtime_adj(X509_getm_notAfter(cert), not_before - time(nullptr) + static_cast<long>(days) * 86400L);

  X509_set_pubkey(cert, pkey);
  X509_NAME *name = X509_get_subject_name(cert);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8, reinterpret_cast<const unsigned char *>(common_name.data()),
                             static_cast<int>(common_name.size()), -1, 0);
  X509_set_issuer_name(cert, name);

  unsigned char *pkcs1 = nullptr;
  int pkcs1_len = i2d_PublicKey(pkey, &pkcs1);
  if (pkcs1_len <= 0 || !pkcs1) {
    X509_free(cert);
    EVP_PKEY_free(pkey);
    fail("config", "a key could not be generated");
  }
  unsigned char ski[SHA_DIGEST_LENGTH];
  SHA1(pkcs1, static_cast<size_t>(pkcs1_len), ski);
  OPENSSL_free(pkcs1);

  ASN1_OCTET_STRING *oct = ASN1_OCTET_STRING_new();
  ASN1_OCTET_STRING_set(oct, ski, SHA_DIGEST_LENGTH);
  X509_EXTENSION *skid = X509V3_EXT_i2d(NID_subject_key_identifier, 0, oct);
  X509_add_ext(cert, skid, -1);
  X509_EXTENSION_free(skid);

  AUTHORITY_KEYID *akid = AUTHORITY_KEYID_new();
  akid->keyid = ASN1_OCTET_STRING_dup(oct);
  X509_EXTENSION *ak = X509V3_EXT_i2d(NID_authority_key_identifier, 0, akid);
  X509_add_ext(cert, ak, -1);
  X509_EXTENSION_free(ak);
  AUTHORITY_KEYID_free(akid);
  ASN1_OCTET_STRING_free(oct);

  X509V3_CTX v3;
  X509V3_set_ctx(&v3, cert, cert, nullptr, nullptr, 0);
  X509_EXTENSION *bc = X509V3_EXT_conf_nid(nullptr, &v3, NID_basic_constraints, "critical,CA:FALSE");
  if (bc) {
    X509_add_ext(cert, bc, -1);
    X509_EXTENSION_free(bc);
  }
  X509_EXTENSION *ku = X509V3_EXT_conf_nid(nullptr, &v3, NID_key_usage, "critical,digitalSignature,keyEncipherment");
  if (ku) {
    X509_add_ext(cert, ku, -1);
    X509_EXTENSION_free(ku);
  }

  if (X509_sign(cert, pkey, EVP_sha256()) == 0) {
    X509_free(cert);
    EVP_PKEY_free(pkey);
    fail("config", "a key could not be generated");
  }
  KeyPairPem pair;
  pair.private_key_pem = private_pem(pkey);
  pair.certificate_pem = cert_pem(cert);
  pair.common_name = cert_common_name(cert);
  X509_free(cert);
  EVP_PKEY_free(pkey);
  return pair;
}

static std::vector<unsigned char> hash_data(const EVP_MD *md, const std::string &data) {
  std::vector<unsigned char> out(EVP_MD_size(md));
  unsigned int len = 0;
  EVP_Digest(data.data(), data.size(), out.data(), &len, md, nullptr);
  out.resize(len);
  return out;
}

std::vector<unsigned char> sha256_bytes(const std::string &data) { return hash_data(EVP_sha256(), data); }
std::vector<unsigned char> sha384_bytes(const std::string &data) { return hash_data(EVP_sha384(), data); }
std::vector<unsigned char> sha512_bytes(const std::string &data) { return hash_data(EVP_sha512(), data); }

std::vector<unsigned char> digest_bytes(const std::string &name, const std::string &data) {
  if (name == "sha256") return sha256_bytes(data);
  if (name == "sha384") return sha384_bytes(data);
  if (name == "sha512") return sha512_bytes(data);
  fail("signature", "unsupported digest");
}

std::vector<unsigned char> rsa_sign_pkcs1(EVP_PKEY *key, const EVP_MD *md, const unsigned char *digest, size_t len) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, nullptr);
  if (!ctx || EVP_PKEY_sign_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
      EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0) {
    if (ctx) EVP_PKEY_CTX_free(ctx);
    fail("signature", "the signature could not be produced");
  }
  size_t siglen = 0;
  if (EVP_PKEY_sign(ctx, nullptr, &siglen, digest, len) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    fail("signature", "the signature could not be produced");
  }
  std::vector<unsigned char> sig(siglen);
  if (EVP_PKEY_sign(ctx, sig.data(), &siglen, digest, len) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    fail("signature", "the signature could not be produced");
  }
  sig.resize(siglen);
  EVP_PKEY_CTX_free(ctx);
  return sig;
}

bool rsa_verify_pkcs1(EVP_PKEY *key, const EVP_MD *md, const unsigned char *digest, size_t dlen,
                      const unsigned char *sig, size_t slen) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, nullptr);
  if (!ctx || EVP_PKEY_verify_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
      EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0) {
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return false;
  }
  int rc = EVP_PKEY_verify(ctx, sig, slen, digest, dlen);
  EVP_PKEY_CTX_free(ctx);
  return rc == 1;
}

bool rsa_verify_pss(EVP_PKEY *key, const EVP_MD *md, const unsigned char *digest, size_t dlen,
                    const unsigned char *sig, size_t slen) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, nullptr);
  if (!ctx || EVP_PKEY_verify_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
      EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0 ||
      EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, EVP_MD_size(md)) <= 0) {
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return false;
  }
  int rc = EVP_PKEY_verify(ctx, sig, slen, digest, dlen);
  EVP_PKEY_CTX_free(ctx);
  return rc == 1;
}

std::vector<unsigned char> rsa_oaep_decrypt(EVP_PKEY *key, const std::string &hash_name, const unsigned char *in,
                                            size_t len) {
  const EVP_MD *md = md_by_name(hash_name);
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, nullptr);
  if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
      EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0 || EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0) {
    if (ctx) EVP_PKEY_CTX_free(ctx);
    fail("decryption", "the content key could not be unwrapped with this relying party's key");
  }
  size_t outlen = 0;
  if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, in, len) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    fail("decryption", "the content key could not be unwrapped with this relying party's key");
  }
  std::vector<unsigned char> out(outlen);
  if (EVP_PKEY_decrypt(ctx, out.data(), &outlen, in, len) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    fail("decryption", "the content key could not be unwrapped with this relying party's key");
  }
  out.resize(outlen);
  EVP_PKEY_CTX_free(ctx);
  return out;
}

std::string aes_gcm_decrypt(const unsigned char *key, size_t key_len, const unsigned char *raw, size_t raw_len) {
  if (raw_len < 12 + 16) fail("decryption", "the ciphertext is too short");
  const EVP_CIPHER *cipher = key_len == 16 ? EVP_aes_128_gcm() : key_len == 24 ? EVP_aes_192_gcm() : EVP_aes_256_gcm();
  if ((key_len == 16 && cipher) || key_len == 24 || key_len == 32) {
  } else {
    fail("decryption", "the content could not be decrypted");
  }
  if (key_len == 16) cipher = EVP_aes_128_gcm();
  else if (key_len == 24) cipher = EVP_aes_192_gcm();
  else if (key_len == 32) cipher = EVP_aes_256_gcm();
  else fail("decryption", "the content could not be decrypted");
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  std::string plain;
  bool ok = ctx && EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, raw) == 1;
  size_t ct_len = raw_len - 12 - 16;
  const unsigned char *ct = raw + 12;
  const unsigned char *tag = raw + raw_len - 16;
  std::vector<unsigned char> out(ct_len);
  int len = 0;
  int final_len = 0;
  ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char *>(tag)) == 1 &&
       EVP_DecryptUpdate(ctx, out.data(), &len, ct, static_cast<int>(ct_len)) == 1 &&
       EVP_DecryptFinal_ex(ctx, out.data() + len, &final_len) == 1;
  if (ctx) EVP_CIPHER_CTX_free(ctx);
  if (!ok) fail("decryption", "the content could not be decrypted");
  return std::string(reinterpret_cast<char *>(out.data()), static_cast<size_t>(len + final_len));
}

std::string aes_cbc_decrypt(const unsigned char *key, size_t key_len, const unsigned char *raw, size_t raw_len) {
  if (raw_len < 32 || raw_len % 16 != 0) fail("decryption", "the ciphertext is not a whole number of blocks");
  const EVP_CIPHER *cipher = nullptr;
  if (key_len == 16) cipher = EVP_aes_128_cbc();
  else if (key_len == 24) cipher = EVP_aes_192_cbc();
  else if (key_len == 32) cipher = EVP_aes_256_cbc();
  else fail("decryption", "the content could not be decrypted");
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  size_t ct_len = raw_len - 16;
  std::vector<unsigned char> out(ct_len + 16);
  int len = 0;
  int final_len = 0;
  bool ok = ctx && EVP_DecryptInit_ex(ctx, cipher, nullptr, key, raw) == 1 &&
            EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
            EVP_DecryptUpdate(ctx, out.data(), &len, raw + 16, static_cast<int>(ct_len)) == 1 &&
            EVP_DecryptFinal_ex(ctx, out.data() + len, &final_len) == 1;
  if (ctx) EVP_CIPHER_CTX_free(ctx);
  if (!ok) fail("decryption", "the content could not be decrypted");
  size_t total = static_cast<size_t>(len + final_len);
  if (total == 0) fail("decryption", "the decrypted content is not padded as XML Encryption pads it");
  unsigned pad = out[total - 1];
  if (pad < 1 || pad > 16) fail("decryption", "the decrypted content is not padded as XML Encryption pads it");
  return std::string(reinterpret_cast<char *>(out.data()), total - pad);
}

EVP_PKEY *jwk_public(const Json &jwk) {
  std::string kty = string_of(jwk.get("kty"));
  std::string kid = string_of(jwk.get("kid"));
  try {
    if (kty == "RSA") {
      auto nraw = b64_decode(string_of(jwk.get("n")), true);
      auto eraw = b64_decode(string_of(jwk.get("e")), true);
      BIGNUM *n = BN_bin2bn(nraw.data(), static_cast<int>(nraw.size()), nullptr);
      BIGNUM *e = BN_bin2bn(eraw.data(), static_cast<int>(eraw.size()), nullptr);
      OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
      OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n);
      OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e);
      OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
      EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
      EVP_PKEY *pkey = nullptr;
      if (!ctx || EVP_PKEY_fromdata_init(ctx) <= 0 ||
          EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
        BN_free(n);
        BN_free(e);
        return nullptr;
      }
      EVP_PKEY_CTX_free(ctx);
      OSSL_PARAM_free(params);
      OSSL_PARAM_BLD_free(bld);
      BN_free(n);
      BN_free(e);
      return pkey;
    }
    if (kty == "EC") {
      std::string crv = string_of(jwk.get("crv"));
      const char *group = crv == "P-256" ? "P-256" : crv == "P-384" ? "P-384" : crv == "P-521" ? "P-521" : nullptr;
      if (!group) fail("signature", "the transmitter's key " + kid + " cannot be read: unsupported curve");
      auto x = b64_decode(string_of(jwk.get("x")), true);
      auto y = b64_decode(string_of(jwk.get("y")), true);
      BIGNUM *bx = BN_bin2bn(x.data(), static_cast<int>(x.size()), nullptr);
      BIGNUM *by = BN_bin2bn(y.data(), static_cast<int>(y.size()), nullptr);
      OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
      OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, group, 0);
      OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_PUB_X, bx);
      OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_PUB_Y, by);
      OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
      EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
      EVP_PKEY *pkey = nullptr;
      bool ok = ctx && EVP_PKEY_fromdata_init(ctx) > 0 && EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) > 0;
      if (ctx) EVP_PKEY_CTX_free(ctx);
      OSSL_PARAM_free(params);
      OSSL_PARAM_BLD_free(bld);
      BN_free(bx);
      BN_free(by);
      if (!ok) return nullptr;
      return pkey;
    }
    if (kty == "OKP") {
      auto x = b64_decode(string_of(jwk.get("x")), true);
      if (x.size() != 32) fail("signature", "the transmitter's key " + kid + " cannot be read: bad OKP length");
      OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
      OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "Ed25519", 0);
      OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, x.data(), x.size());
      OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
      EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, "ED25519", nullptr);
      EVP_PKEY *pkey = nullptr;
      bool ok = ctx && EVP_PKEY_fromdata_init(ctx) > 0 && EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) > 0;
      if (ctx) EVP_PKEY_CTX_free(ctx);
      OSSL_PARAM_free(params);
      OSSL_PARAM_BLD_free(bld);
      if (!ok) return nullptr;
      return pkey;
    }
    fail("signature", "the transmitter's key " + kid + " cannot be read: unsupported kty " + kty);
  } catch (const failure &) {
    throw;
  }
  return nullptr;
}

bool jws_verify_key(EVP_PKEY *key, const std::string &alg, const std::string &data,
                    const std::vector<unsigned char> &sig) {
  const EVP_MD *md = nullptr;
  bool pss = false;
  bool ed = false;
  bool ec = false;
  if (alg == "RS256" || alg == "PS256") md = EVP_sha256();
  else if (alg == "RS384" || alg == "PS384") md = EVP_sha384();
  else if (alg == "RS512" || alg == "PS512") md = EVP_sha512();
  else if (alg == "ES256") {
    md = EVP_sha256();
    ec = true;
  } else if (alg == "ES384") {
    md = EVP_sha384();
    ec = true;
  } else if (alg == "ES512") {
    md = EVP_sha512();
    ec = true;
  } else if (alg == "EdDSA" || alg == "Ed25519") {
    ed = true;
  } else {
    return false;
  }
  if (alg.size() >= 2 && alg[0] == 'P') pss = true;
  if (ed) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    bool ok = ctx && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, key) == 1 &&
              EVP_DigestVerify(ctx, sig.data(), sig.size(), reinterpret_cast<const unsigned char *>(data.data()),
                               data.size()) == 1;
    if (ctx) EVP_MD_CTX_free(ctx);
    return ok;
  }
  auto digest = hash_data(md, data);
  if (ec) {
    if (sig.size() % 2 != 0) return false;
    size_t half = sig.size() / 2;
    BIGNUM *r = BN_bin2bn(sig.data(), static_cast<int>(half), nullptr);
    BIGNUM *s = BN_bin2bn(sig.data() + half, static_cast<int>(half), nullptr);
    ECDSA_SIG *es = ECDSA_SIG_new();
    ECDSA_SIG_set0(es, r, s);
    unsigned char *der = nullptr;
    int derlen = i2d_ECDSA_SIG(es, &der);
    ECDSA_SIG_free(es);
    if (derlen <= 0) return false;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    bool ok = ctx && EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, key) == 1 &&
              EVP_DigestVerify(ctx, der, static_cast<size_t>(derlen),
                               reinterpret_cast<const unsigned char *>(data.data()), data.size()) == 1;
    OPENSSL_free(der);
    if (ctx) EVP_MD_CTX_free(ctx);
    (void)digest;
    return ok;
  }
  if (pss) return rsa_verify_pss(key, md, digest.data(), digest.size(), sig.data(), sig.size());
  return rsa_verify_pkcs1(key, md, digest.data(), digest.size(), sig.data(), sig.size());
}

}  // namespace iya::wsfed
