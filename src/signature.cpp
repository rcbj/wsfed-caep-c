// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "detail.hpp"

#include <openssl/evp.h>

namespace iya::wsfed {
namespace {

bool is_transform(const std::string &alg) {
  return alg == ENVELOPED || alg == EXC_C14N || alg == EXC_C14N_COMMENTS || alg == C14N10 || alg == C14N10_COMMENTS;
}

bool is_c14n(const std::string &alg) {
  return alg == EXC_C14N || alg == EXC_C14N_COMMENTS || alg == C14N10 || alg == C14N10_COMMENTS;
}

const EVP_MD *sig_md(const std::string &alg) {
  if (alg == kRsaSha256) return EVP_sha256();
  if (alg == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384") return EVP_sha384();
  if (alg == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512") return EVP_sha512();
  return nullptr;
}

const EVP_MD *digest_md(const std::string &alg) {
  if (alg == "http://www.w3.org/2001/04/xmlenc#sha256") return EVP_sha256();
  if (alg == "http://www.w3.org/2001/04/xmldsig-more#sha384") return EVP_sha384();
  if (alg == "http://www.w3.org/2001/04/xmlenc#sha512") return EVP_sha512();
  return nullptr;
}

std::string algorithm_of(xmlNodePtr parent, const char *local) {
  xmlNodePtr el = one_child(parent, NS_DS, local);
  if (!el) return "";
  return attr_or(el, "Algorithm");
}

std::vector<unsigned char> b64_el(xmlNodePtr el) {
  std::string raw = text_content(el);
  std::string compact;
  for (char c : raw) {
    if (!std::isspace(static_cast<unsigned char>(c))) compact.push_back(c);
  }
  if (compact.empty()) return {};
  try {
    return b64_decode(compact, false);
  } catch (const failure &) {
    while (compact.size() % 4) compact.pop_back();
    return b64_decode(compact, false);
  }
}

std::string reference_c14n(xmlNodePtr element, const std::vector<xmlNodePtr> &transforms) {
  std::string algorithm = EXC_C14N;
  std::string prefixes;
  bool enveloped = false;
  for (xmlNodePtr transform : transforms) {
    std::string alg = attr_or(transform, "Algorithm");
    if (alg == ENVELOPED) {
      enveloped = true;
      continue;
    }
    if (is_c14n(alg)) {
      algorithm = alg;
      prefixes = prefixes_of(transform);
    }
  }
  return canonicalize(element, algorithm, prefixes, enveloped || true);
}

bool bytes_equal(const std::vector<unsigned char> &a, const std::vector<unsigned char> &b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

std::string dump_doc(xmlDocPtr doc) {
  xmlChar *out = nullptr;
  int len = 0;
  xmlDocDumpMemory(doc, &out, &len);
  std::string text;
  if (out && len > 0) text.assign(reinterpret_cast<char *>(out), static_cast<size_t>(len));
  if (out) xmlFree(out);
  if (text.compare(0, 5, "<?xml") == 0) {
    auto end = text.find("?>");
    if (end != std::string::npos) {
      end += 2;
      if (end < text.size() && text[end] == '\r') end++;
      if (end < text.size() && text[end] == '\n') end++;
      text.erase(0, end);
    }
  }
  return text;
}

void insert_after(xmlNodePtr parent, xmlNodePtr after, xmlNodePtr child) {
  if (!parent || !child) return;
  if (!after) {
    xmlAddChild(parent, child);
    return;
  }
  xmlAddNextSibling(after, child);
}

}  // namespace

std::vector<unsigned char> hash_data_md(const EVP_MD *md, const std::string &data) {
  std::vector<unsigned char> out(EVP_MD_size(md));
  unsigned int len = 0;
  EVP_Digest(data.data(), data.size(), out.data(), &len, md, nullptr);
  out.resize(len);
  return out;
}

std::string verify_signed(xmlNodePtr el, const std::vector<std::shared_ptr<Cert>> &certs, const std::string &what) {
  xmlNodePtr sig = one_child(el, NS_DS, "Signature");
  if (!sig) return "";
  std::string element_id = attr_or(el, "ID");
  if (element_id.empty()) fail("signature", what + " is signed but has no ID for the signature to refer to");
  xmlNodePtr signed_info = one_child(sig, NS_DS, "SignedInfo");
  if (!signed_info) fail("signature", what + "'s signature has no SignedInfo");
  std::string c14n_alg = algorithm_of(signed_info, "CanonicalizationMethod");
  if (!is_c14n(c14n_alg)) {
    std::string shown = c14n_alg.empty() ? "(none)" : c14n_alg;
    fail("signature", what + "'s signature uses the canonicalization " + shown + ", which is refused");
  }
  std::string sig_alg = algorithm_of(signed_info, "SignatureMethod");
  const EVP_MD *md = sig_md(sig_alg);
  if (!md) {
    std::string shown = sig_alg.empty() ? "(none)" : sig_alg;
    fail("signature", what + "'s signature uses " + shown + ", which is refused (SHA-1 and non-RSA algorithms are not accepted)");
  }
  auto refs = children(signed_info, NS_DS, "Reference");
  if (refs.size() != 1) {
    fail("signature", what + "'s signature has " + itoa_i(static_cast<long long>(refs.size())) + " references; exactly one is accepted");
  }
  xmlNodePtr ref = refs[0];
  std::string uri = attr_or(ref, "URI");
  if (uri != "#" + element_id) {
    std::string shown = uri.empty() ? "(nothing)" : uri;
    fail("signature", what + "'s signature refers to " + shown + ", not to " + what + " itself (#" + element_id + ")");
  }
  std::string digest_alg = algorithm_of(ref, "DigestMethod");
  const EVP_MD *dmd = digest_md(digest_alg);
  if (!dmd) {
    std::string shown = digest_alg.empty() ? "(none)" : digest_alg;
    fail("signature", what + "'s signature digests with " + shown + ", which is refused");
  }
  xmlNodePtr transforms_el = one_child(ref, NS_DS, "Transforms");
  std::vector<xmlNodePtr> transform_els;
  if (transforms_el) transform_els = children(transforms_el, NS_DS, "Transform");
  for (xmlNodePtr transform : transform_els) {
    std::string alg = attr_or(transform, "Algorithm");
    if (!is_transform(alg)) {
      std::string shown = alg.empty() ? "(none)" : alg;
      fail("signature", what + "'s signature uses the transform " + shown + ", which is refused");
    }
  }
  if (certs.empty()) {
    fail("signature", "no signing certificate is known for the identity provider, so " + what + " cannot be verified");
  }
  std::string ref_c14n = reference_c14n(el, transform_els);
  auto got = hash_data_md(dmd, ref_c14n);
  xmlNodePtr digest_value = one_child(ref, NS_DS, "DigestValue");
  std::vector<unsigned char> want;
  bool dec_ok = true;
  try {
    want = b64_el(digest_value);
  } catch (const failure &) {
    dec_ok = false;
  }
  if (!dec_ok || !bytes_equal(got, want)) {
    fail("signature", what + "'s signature does not verify against the identity provider's certificate: the signature does not verify");
  }
  xmlNodePtr c14n_method = one_child(signed_info, NS_DS, "CanonicalizationMethod");
  std::string info = canonicalize(signed_info, c14n_alg, prefixes_of(c14n_method), false);
  auto hashed = hash_data_md(md, info);
  xmlNodePtr sig_value = one_child(sig, NS_DS, "SignatureValue");
  std::vector<unsigned char> sig_bytes;
  try {
    sig_bytes = b64_el(sig_value);
  } catch (const failure &ex) {
    fail("signature", what + "'s signature does not verify against the identity provider's certificate: " + ex.what());
  }
  std::string reason = "the signature does not verify";
  for (const auto &cert : certs) {
    EVP_PKEY *pub = X509_get_pubkey(cert->cert);
    if (!pub || !EVP_PKEY_is_a(pub, "RSA")) {
      if (pub) EVP_PKEY_free(pub);
      reason = "the certificate key is not RSA";
      continue;
    }
    bool ok = rsa_verify_pkcs1(pub, md, hashed.data(), hashed.size(), sig_bytes.data(), sig_bytes.size());
    EVP_PKEY_free(pub);
    if (!ok) {
      reason = "the signature does not verify";
      continue;
    }
    return ref_c14n;
  }
  fail("signature", what + "'s signature does not verify against the identity provider's certificate: " + reason);
}

std::string sign_enveloped(const std::string &xml, const std::string &element_id, const std::string &key_pem,
                           const std::string &cert_pem) {
  Xml doc = parse_xml(xml, "the signed element");
  xmlNodePtr target = find_id(doc.root(), element_id);
  if (!target) fail("signature", "no element ID " + element_id);
  std::string ref_c14n = canonicalize(target, EXC_C14N, "", false);
  auto sum = sha256_bytes(ref_c14n);
  std::string digest = b64_encode(sum.data(), sum.size());
  std::string sig_xml =
      "<ds:Signature xmlns:ds=\"" + std::string(NS_DS) + "\"><ds:SignedInfo>"
      "<ds:CanonicalizationMethod Algorithm=\"" +
      std::string(EXC_C14N) + "\"/>"
      "<ds:SignatureMethod Algorithm=\"" +
      std::string(kRsaSha256) + "\"/>"
      "<ds:Reference URI=\"#" +
      escape_xml(element_id) + "\"><ds:Transforms>"
      "<ds:Transform Algorithm=\"" +
      std::string(ENVELOPED) + "\"/>"
      "<ds:Transform Algorithm=\"" +
      std::string(EXC_C14N) + "\"/>"
      "</ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>"
      "<ds:DigestValue>" +
      digest + "</ds:DigestValue></ds:Reference></ds:SignedInfo>"
      "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>" +
      pem_body(cert_pem) + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo><ds:SignatureValue></ds:SignatureValue></ds:Signature>";
  Xml sig_doc = parse_xml(sig_xml, "the signature");
  xmlNodePtr sig = xmlDocCopyNode(sig_doc.root(), doc.doc, 1);
  xmlNodePtr issuer = one_child(target, NS_SAML, "Issuer");
  insert_after(target, issuer, sig);
  xmlNodePtr signed_info = one_child(sig, NS_DS, "SignedInfo");
  if (!signed_info) fail("signature", "SignedInfo was not built");
  std::string info = canonicalize(signed_info, EXC_C14N, "", false);
  auto hashed = sha256_bytes(info);
  auto key = load_private_key(key_pem);
  auto raw = rsa_sign_pkcs1(key->key, EVP_sha256(), hashed.data(), hashed.size());
  xmlNodePtr value = one_child(sig, NS_DS, "SignatureValue");
  xmlNodeSetContent(value, BAD_CAST b64_encode(raw.data(), raw.size()).c_str());
  return dump_doc(doc.doc);
}

std::string SignEnveloped(const std::string &xml, const std::string &element_id, const std::string &key_pem,
                          const std::string &cert_pem) {
  return sign_enveloped(xml, element_id, key_pem, cert_pem);
}

}  // namespace iya::wsfed
