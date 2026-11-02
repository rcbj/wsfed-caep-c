// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "detail.hpp"

namespace iya::wsfed {
namespace {

struct CipherSpec {
  const char *name;
  bool gcm;
  int key_length;
};

CipherSpec cipher_of(const std::string &alg) {
  if (alg == "http://www.w3.org/2009/xmlenc11#aes128-gcm") return {"aes-128-gcm", true, 16};
  if (alg == "http://www.w3.org/2009/xmlenc11#aes192-gcm") return {"aes-192-gcm", true, 24};
  if (alg == "http://www.w3.org/2009/xmlenc11#aes256-gcm") return {"aes-256-gcm", true, 32};
  if (alg == "http://www.w3.org/2001/04/xmlenc#aes128-cbc") return {"aes-128-cbc", false, 16};
  if (alg == "http://www.w3.org/2001/04/xmlenc#aes192-cbc") return {"aes-192-cbc", false, 24};
  if (alg == "http://www.w3.org/2001/04/xmlenc#aes256-cbc") return {"aes-256-cbc", false, 32};
  return {nullptr, false, 0};
}

std::string oaep_digest_name(const std::string &alg, bool &ok) {
  ok = true;
  if (alg == "http://www.w3.org/2000/09/xmldsig#sha1") return "sha1";
  if (alg == "http://www.w3.org/2001/04/xmlenc#sha256") return "sha256";
  if (alg == "http://www.w3.org/2001/04/xmldsig-more#sha384") return "sha384";
  if (alg == "http://www.w3.org/2001/04/xmlenc#sha512") return "sha512";
  ok = false;
  return "";
}

std::string mgf_name(const std::string &alg, bool &ok) {
  ok = true;
  if (alg == "http://www.w3.org/2009/xmlenc11#mgf1sha1") return "sha1";
  if (alg == "http://www.w3.org/2009/xmlenc11#mgf1sha256") return "sha256";
  if (alg == "http://www.w3.org/2009/xmlenc11#mgf1sha384") return "sha384";
  if (alg == "http://www.w3.org/2009/xmlenc11#mgf1sha512") return "sha512";
  ok = false;
  return "";
}

std::vector<unsigned char> b64_text(const std::string &value) {
  std::string compact;
  for (char c : value) {
    if (!std::isspace(static_cast<unsigned char>(c))) compact.push_back(c);
  }
  if (compact.empty()) return {};
  try {
    return b64_decode(compact, false);
  } catch (const failure &ex) {
    fail("decryption", std::string("the content key could not be unwrapped with this relying party's key"));
  }
}

std::vector<unsigned char> unwrap_key(xmlNodePtr encrypted_key, EVP_PKEY *key) {
  xmlNodePtr method = one_child(encrypted_key, NS_XENC, "EncryptionMethod");
  std::string alg = method ? attr_or(method, "Algorithm") : "";
  const std::string oaep_mgf1p = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
  const std::string oaep11 = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
  if (alg != oaep_mgf1p && alg != oaep11) {
    std::string shown = alg.empty() ? "(none)" : alg;
    fail("decryption", "the content key is wrapped with " + shown + "; only RSA-OAEP is accepted");
  }
  xmlNodePtr digest_method = method ? one_child(method, NS_DS, "DigestMethod") : nullptr;
  std::string digest_name = "sha1";
  if (digest_method) {
    std::string digest_alg = attr_or(digest_method, "Algorithm");
    if (!digest_alg.empty()) {
      bool ok = false;
      digest_name = oaep_digest_name(digest_alg, ok);
      if (!ok) fail("decryption", "the OAEP digest " + digest_alg + " is not supported");
    }
  }
  std::string mgf = "sha1";
  if (alg == oaep11 && method) {
    xmlNodePtr mgf_el = one_child(method, NS_XENC11, "MGF");
    if (mgf_el) {
      std::string mgf_alg = attr_or(mgf_el, "Algorithm");
      if (!mgf_alg.empty()) {
        bool ok = false;
        mgf = mgf_name(mgf_alg, ok);
        if (!ok) fail("decryption", "the OAEP mask generation function " + mgf_alg + " is not supported");
      }
    }
  }
  if (mgf != digest_name) {
    fail("decryption", "OAEP with digest " + digest_name + " and MGF1 " + mgf +
                           " is not supported; node:crypto uses one hash for both");
  }
  std::vector<xmlNodePtr> values;
  descendants(encrypted_key, NS_XENC, "CipherValue", values);
  std::string raw = values.empty() ? "" : text_of(values[0]);
  std::vector<unsigned char> blob;
  try {
    blob = b64_text(raw);
  } catch (const failure &) {
    fail("decryption", "the content key could not be unwrapped with this relying party's key");
  }
  try {
    return rsa_oaep_decrypt(key, digest_name, blob.data(), blob.size());
  } catch (const failure &) {
    fail("decryption", "the content key could not be unwrapped with this relying party's key");
  }
}

}  // namespace

std::string decrypt_element(xmlNodePtr encrypted, EVP_PKEY *key) {
  xmlNodePtr data = encrypted;
  if (!is_el(encrypted, NS_XENC, "EncryptedData")) data = one_child(encrypted, NS_XENC, "EncryptedData");
  std::string tag = encrypted && encrypted->name ? reinterpret_cast<const char *>(encrypted->name) : "";
  if (!data) fail("decryption", "<" + tag + "> has no EncryptedData");
  xmlNodePtr method = one_child(data, NS_XENC, "EncryptionMethod");
  std::string alg = method ? attr_or(method, "Algorithm") : "";
  CipherSpec spec = cipher_of(alg);
  if (!spec.name) {
    std::string shown = alg.empty() ? "(none)" : alg;
    fail("decryption", "the content is encrypted with " + shown + ", which is not supported");
  }
  std::vector<xmlNodePtr> keys;
  descendants(encrypted, NS_XENC, "EncryptedKey", keys);
  if (keys.empty()) fail("decryption", "<" + tag + "> carries no EncryptedKey");
  auto content_key = unwrap_key(keys[0], key);
  if (static_cast<int>(content_key.size()) != spec.key_length) {
    fail("decryption", "the content key is " + itoa_i(static_cast<long long>(content_key.size())) + " bytes; " + spec.name +
                           " needs " + itoa_i(spec.key_length));
  }
  xmlNodePtr cipher_data = one_child(data, NS_XENC, "CipherData");
  xmlNodePtr value_el = cipher_data ? one_child(cipher_data, NS_XENC, "CipherValue") : nullptr;
  std::string raw_text = value_el ? text_of(value_el) : "";
  std::vector<unsigned char> raw;
  try {
    raw = b64_text(raw_text);
  } catch (const failure &) {
    fail("decryption", "the content could not be decrypted");
  }
  if (spec.gcm) return aes_gcm_decrypt(content_key.data(), content_key.size(), raw.data(), raw.size());
  return aes_cbc_decrypt(content_key.data(), content_key.size(), raw.data(), raw.size());
}

}  // namespace iya::wsfed
