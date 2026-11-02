// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "crypto.hpp"
#include "json.hpp"
#include "xml.hpp"

#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace iya::wsfed {

struct TlsMaterial {
  std::string ca;
  std::string cert;
  std::string key;
};

struct HttpResult {
  int status = 0;
  std::string content_type;
  std::string body;
  std::vector<std::pair<std::string, std::string>> headers;
};

HttpResult http_send(const std::string &method, const std::string &url,
                     const std::vector<std::pair<std::string, std::string>> &headers, const std::string *body,
                     const TlsMaterial *tls, const std::string &code);

std::string itoa_i(long long n);
int64_t now_ms();
bool parse_instant(const std::string &value, const std::string &what, int64_t &ms_out);
std::string iso_time(int64_t ms);
std::string random_hex(size_t nbytes);
std::string read_file(const std::string &path);
void write_file_mode(const std::string &path, const std::string &body, int mode);
bool file_exists(const std::string &path);
std::string abs_path(const std::string &path);
std::string join_path(const std::string &dir, const std::string &rel);
std::string cwd_path();
std::string clip_runes(const std::string &value, int n);

struct FullConfig {
  Resolved view;
  std::string private_key_pem;
  std::string certificate_pem;
  std::shared_ptr<PKey> private_key;
  std::shared_ptr<Cert> certificate;
};

FullConfig resolve_config_json(const Json &config, const std::string &base_dir);
FullConfig read_config_file(const std::string &path, const Json *overrides);

struct IdpInfo {
  std::string entity_id;
  std::string passive;
  std::vector<std::string> token_types;
  std::vector<std::shared_ptr<Cert>> certs;
};

IdpInfo read_idp_metadata(const std::string &xml, const std::string &entity_id);
std::string write_rp_metadata(const std::string &realm, const std::string &reply, const std::string &cert_pem);

class ReplayCache {
 public:
  explicit ReplayCache(int max_entries = 10000);
  bool check_and_record(const std::string &id, int64_t expires_ms);

 private:
  std::mutex mu_;
  std::map<std::string, int64_t> entries_;
  int max_;
};

struct TokenIn {
  std::string realm;
  std::string reply_url;
  std::string idp_entity;
  std::vector<std::shared_ptr<Cert>> certs;
  std::shared_ptr<PKey> decryption_key;
  int clock_skew_ms = 60000;
  bool want_encrypted = false;
  ReplayCache *replay = nullptr;
};

RelyingParty::LoginResult validate_token(const std::string &wresult, TokenIn ctx);

std::string sign_enveloped(const std::string &xml, const std::string &element_id, const std::string &key_pem,
                           const std::string &cert_pem);
std::string verify_signed(xmlNodePtr el, const std::vector<std::shared_ptr<Cert>> &certs, const std::string &what);
std::string decrypt_element(xmlNodePtr encrypted, EVP_PKEY *key);
std::vector<unsigned char> hash_data_md(const EVP_MD *md, const std::string &data);

}  // namespace iya::wsfed
