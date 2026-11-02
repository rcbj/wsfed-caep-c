// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "detail.hpp"

#include <cstdlib>

namespace iya::wsfed {
namespace {

bool is_pem(const std::string &value) { return value.find("-----BEGIN ") != std::string::npos; }

std::string material(std::string value, const std::string &base_dir, const std::string &what) {
  if (value.compare(0, 4, "env:") == 0) {
    std::string name = value.substr(4);
    const char *got = std::getenv(name.c_str());
    if (!got || !*got) fail("config", what + " environment variable " + name + " is not set");
    value = got;
  }
  if (value.compare(0, 5, "file:") == 0) value = value.substr(5);
  if (is_pem(value)) return value;
  std::string path = value;
  if (path.empty() || path[0] != '/') path = join_path(base_dir, value);
  std::string raw = read_file(path);
  if (raw.empty() && !file_exists(path)) {
    fail("config", what + " is neither a PEM nor a readable file (" + path + ")");
  }
  return raw;
}

std::string absolute_url(const Json *value, const std::string &what) {
  if (!value || value->type != Json::String || trim_copy(value->text).empty()) fail("config", what + " is required");
  const std::string &text = value->text;
  if (text.compare(0, 8, "https://") != 0 && text.compare(0, 7, "http://") != 0) {
    fail("config", what + " must be an absolute http(s) URL, not " + text);
  }
  std::string rest = text.compare(0, 8, "https://") == 0 ? text.substr(8) : text.substr(7);
  if (rest.empty() || rest[0] == '/') fail("config", what + " must be an absolute http(s) URL, not " + text);
  return text;
}

bool flag_value(const Json *value, bool present, bool fallback, const std::string &what) {
  if (!present || !value || value->type == Json::Null) return fallback;
  if (value->type != Json::Bool) fail("config", what + " must be true or false");
  return value->b;
}

std::string idp_metadata_ref(std::string value, const std::string &base_dir) {
  value = trim_copy(value);
  if (value.compare(0, 4, "env:") == 0) {
    std::string name = value.substr(4);
    const char *got = std::getenv(name.c_str());
    if (!got || !*got) fail("config", "idpMetadata environment variable " + name + " is not set");
    value = trim_copy(got);
  }
  if (value.compare(0, 5, "file:") == 0) value = value.substr(5);
  if (value.compare(0, 7, "http://") == 0 || value.compare(0, 8, "https://") == 0 || (!value.empty() && value[0] == '<')) {
    return value;
  }
  if (!value.empty() && value[0] == '/') return value;
  return join_path(base_dir, value);
}

}  // namespace

FullConfig resolve_config_json(const Json &config, const std::string &base_in) {
  if (config.type != Json::Object) fail("config", "the configuration must be an object");
  std::string base_dir = base_in.empty() ? cwd_path() : base_in;
  const Json *realm_j = config.get("realm");
  std::string realm = realm_j && realm_j->type == Json::String ? realm_j->text : "";
  if (trim_copy(realm).empty()) fail("config", "realm is required");
  std::string reply = absolute_url(config.get("replyUrl"), "replyUrl");
  const Json *meta_j = config.get("idpMetadata");
  if (!meta_j || meta_j->type != Json::String || trim_copy(meta_j->text).empty()) fail("config", "idpMetadata is required");
  std::string meta = idp_metadata_ref(meta_j->text, base_dir);
  double skew = 60.0;
  const Json *skew_j = config.get("clockSkewSeconds");
  bool skew_present = config.has("clockSkewSeconds");
  if (skew_present && skew_j && skew_j->type != Json::Null) {
    double parsed = 0;
    if (!json_as_float(*skew_j, parsed) || parsed < 0 || parsed > 600) {
      fail("config", "clockSkewSeconds must be a number from 0 to 600");
    }
    skew = parsed;
  }
  int skew_ms = static_cast<int>(skew) * 1000;
  if (skew_j && skew_j->type != Json::Null && !json_whole(*skew_j)) skew_ms = static_cast<int>(skew * 1000);
  if (!skew_present || !skew_j || skew_j->type == Json::Null) skew_ms = 60 * 1000;
  bool signals = flag_value(config.get("signals"), config.has("signals"), true, "signals");
  bool want = flag_value(config.get("wantAssertionsEncrypted"), config.has("wantAssertionsEncrypted"), false,
                         "wantAssertionsEncrypted");
  bool allow = flag_value(config.get("allowUnsolicited"), config.has("allowUnsolicited"), false, "allowUnsolicited");
  bool request_type = flag_value(config.get("requestTokenType"), config.has("requestTokenType"), true, "requestTokenType");
  FullConfig out;
  out.view.realm = realm;
  out.view.reply_url = reply;
  out.view.idp_metadata = meta;
  out.view.clock_skew_ms = skew_ms;
  out.view.want_assertions_encrypted = want;
  out.view.allow_unsolicited = allow;
  out.view.request_token_type = request_type;
  if (!signals) {
    out.view.signals_set = true;
    out.view.signals = false;
  }
  const Json *key_j = config.get("privateKey");
  const Json *cert_j = config.get("certificate");
  bool key_present = config.has("privateKey") && key_j && key_j->type != Json::Null;
  bool cert_present = config.has("certificate") && cert_j && cert_j->type != Json::Null;
  if (key_present != cert_present) fail("config", "privateKey and certificate go together: give both or neither");
  if (key_present && cert_present) {
    if (key_j->type != Json::String || cert_j->type != Json::String) {
      fail("config", "the private key or certificate cannot be read: not a string");
    }
    out.private_key_pem = material(key_j->text, base_dir, "privateKey");
    out.certificate_pem = material(cert_j->text, base_dir, "certificate");
    out.private_key = load_private_key(out.private_key_pem);
    out.certificate = load_certificate(out.certificate_pem);
    if (!key_matches(*out.private_key, *out.certificate)) fail("config", "the certificate is not for the private key");
    out.view.has_private_key = true;
  } else if (out.view.want_assertions_encrypted) {
    fail("config", "wantAssertionsEncrypted needs privateKey and certificate: the assertion is encrypted to them");
  }
  const Json *ca = config.get("idpCa");
  if (ca && ca->type == Json::String && !ca->text.empty()) {
    out.view.idp_ca = material(ca->text, base_dir, "idpCa");
  }
  const Json *id = config.get("idpEntityId");
  if (id && id->type == Json::String && !id->text.empty()) out.view.idp_entity_id = id->text;
  return out;
}

FullConfig read_config_file(const std::string &path, const Json *overrides) {
  std::string raw = read_file(path);
  if (raw.empty() && !file_exists(path)) fail("config", path + " cannot be read as JSON: no such file");
  Json parsed = parse_json(raw);
  if (parsed.type != Json::Object) fail("config", path + " cannot be read as JSON: not an object");
  if (overrides && overrides->type == Json::Object) {
    for (const auto &kv : overrides->obj) {
      if (kv.second.type == Json::Null) continue;
      bool found = false;
      for (auto &existing : parsed.obj) {
        if (existing.first == kv.first) {
          existing.second = kv.second;
          found = true;
          break;
        }
      }
      if (!found) parsed.obj.push_back(kv);
    }
  }
  std::string abs = abs_path(path);
  auto slash = abs.find_last_of('/');
  std::string dir = slash == std::string::npos ? cwd_path() : abs.substr(0, slash);
  return resolve_config_json(parsed, dir);
}

Resolved ResolveConfig(const std::string &json, const std::string &base_dir) {
  Json parsed = parse_json(json);
  return resolve_config_json(parsed, base_dir).view;
}

KeyPairPem CreateSelfSignedKeyPair(const std::string &common_name, int days, int bits) {
  return create_self_signed(common_name, days, bits);
}

}  // namespace iya::wsfed
