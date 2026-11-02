// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "detail.hpp"

#include <cstdio>
#include <ctime>

namespace iya::wsfed {
namespace {

const char *kProtocol[] = {"wa", "wtrealm", "wreply", "wctx", "wct", "wreq", "wreqptr", "wfresh", "wauth", "whr"};

bool protocol_param(const std::string &key) {
  for (const char *name : kProtocol) {
    if (key == name) return true;
  }
  return false;
}

std::string join_query(const std::string &endpoint, const std::string &query) {
  std::string joiner = endpoint.find('?') == std::string::npos ? "?" : "&";
  return endpoint + joiner + query;
}

std::string utc_wct() {
  time_t now = time(nullptr);
  std::tm tm{};
  gmtime_r(&now, &tm);
  char buf[32];
  std::snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02dZ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
                tm.tm_min, tm.tm_sec);
  return buf;
}

IdpInfo load_idp(const FullConfig &config) {
  const std::string &source = config.view.idp_metadata;
  std::string xml;
  if (!source.empty() && source[0] == '<') {
    xml = source;
  } else if (source.compare(0, 7, "http://") == 0 || source.compare(0, 8, "https://") == 0) {
    TlsMaterial tls;
    const TlsMaterial *use = nullptr;
    if (!config.view.idp_ca.empty()) {
      tls.ca = config.view.idp_ca;
      use = &tls;
    }
    std::vector<std::pair<std::string, std::string>> headers = {
        {"accept", "application/samlmetadata+xml, application/xml, text/xml"}};
    HttpResult answer = http_send("GET", source, headers, nullptr, use, "metadata");
    if (answer.status != 200) fail("metadata", source + " answered HTTP " + itoa_i(answer.status));
    xml = answer.body;
  } else {
    if (!file_exists(source)) fail("metadata", "the identity provider metadata file " + source + " cannot be read");
    xml = read_file(source);
  }
  return read_idp_metadata(xml, config.view.idp_entity_id);
}

std::map<std::string, std::string> query_of(const std::string &url) {
  auto q = url.find('?');
  if (q == std::string::npos) return {};
  std::string query = url.substr(q + 1);
  auto hash = query.find('#');
  if (hash != std::string::npos) query = query.substr(0, hash);
  return parse_query(query);
}

}  // namespace

struct RelyingParty::Impl {
  FullConfig config;
  IdpInfo idp;
  ReplayCache replay{10000};
};

RelyingParty::RelyingParty(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
RelyingParty::RelyingParty(RelyingParty &&) noexcept = default;
RelyingParty &RelyingParty::operator=(RelyingParty &&) noexcept = default;
RelyingParty::~RelyingParty() = default;

RelyingParty RelyingParty::Create(const std::string &json, const std::string &base_dir) {
  Json parsed = parse_json(json);
  auto impl = std::make_unique<Impl>();
  impl->config = resolve_config_json(parsed, base_dir);
  impl->idp = load_idp(impl->config);
  return RelyingParty(std::move(impl));
}

RelyingParty RelyingParty::FromFile(const std::string &path, const std::string &overrides_json) {
  const Json *overrides = nullptr;
  Json parsed;
  if (!overrides_json.empty()) {
    parsed = parse_json(overrides_json);
    overrides = &parsed;
  }
  auto impl = std::make_unique<Impl>();
  impl->config = read_config_file(path, overrides);
  impl->idp = load_idp(impl->config);
  return RelyingParty(std::move(impl));
}

RelyingParty::LoginRequest RelyingParty::Login(const LoginOptions &opts) {
  if (opts.relay_state && opts.relay_state->size() > 1024) fail("config", "relayState is longer than 1024 bytes");
  std::string request_id = random_hex(20);
  std::string wctx = "id=" + query_escape(request_id);
  if (opts.relay_state) wctx += "&ru=" + query_escape(*opts.relay_state);
  std::vector<std::pair<std::string, std::string>> pairs = {
      {"wa", "wsignin1.0"},
      {"wtrealm", impl_->config.view.realm},
      {"wreply", impl_->config.view.reply_url},
      {"wctx", wctx},
      {"wct", utc_wct()},
  };
  if (impl_->config.view.request_token_type) {
    pairs.emplace_back("wreq", "<wst:RequestSecurityToken xmlns:wst=\"" + std::string(NS_TRUST13) + "\"><wst:TokenType>" +
                                   NS_SAML + "</wst:TokenType></wst:RequestSecurityToken>");
  }
  if (opts.force_authn) {
    pairs.emplace_back("wfresh", "0");
  } else if (opts.freshness) {
    if (*opts.freshness < 0) fail("config", "freshness is a whole number of minutes");
    pairs.emplace_back("wfresh", itoa_i(*opts.freshness));
  }
  if (!opts.authentication_method.empty()) pairs.emplace_back("wauth", opts.authentication_method);
  if (!opts.home_realm.empty()) pairs.emplace_back("whr", opts.home_realm);
  for (const auto &param : opts.params) {
    if (protocol_param(param.first)) fail("config", "params cannot set " + param.first + "; it is the protocol's own");
    pairs.push_back(param);
  }
  LoginRequest req;
  req.id = request_id;
  req.wctx = wctx;
  req.url = join_query(impl_->idp.passive, encode_query(pairs));
  return req;
}

RelyingParty::LoginResult RelyingParty::HandleReply(const std::string &method, const std::string &url, const std::string &body,
                                                    const std::vector<std::string> &request_ids) {
  auto query = query_of(url);
  std::map<std::string, std::string> form;
  std::string upper = method;
  for (char &c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  if (upper == "POST") form = parse_query(body);
  std::string wa;
  if (form.count("wa")) wa = form["wa"];
  else if (query.count("wa")) wa = query["wa"];
  if (wa == "wsignoutcleanup1.0" || wa == "wsignout1.0") {
    fail("message", "the request is " + wa + ", a sign-out, not a sign-in response; see isSignOutCleanup()");
  }
  if (upper != "POST") fail("message", "a sign-in response is POSTed (WS-Federation 13.2.2); this request is a GET");
  if (wa != "wsignin1.0") {
    std::string shown = wa.empty() ? "(none)" : wa;
    fail("message", "the request's wa is " + shown + ", not wsignin1.0");
  }
  if (form.count("wresultptr")) {
    fail("message", "the response is by reference (wresultptr), which is never dereferenced; only wresult is accepted");
  }
  std::string wresult = form.count("wresult") ? form["wresult"] : "";
  if (wresult.empty()) fail("message", "the request carries no wresult");
  std::string wctx_raw = form.count("wctx") ? form["wctx"] : "";
  auto wctx = parse_query(wctx_raw);
  bool has_id = wctx.count("id") > 0;
  TokenIn ctx;
  ctx.realm = impl_->config.view.realm;
  ctx.reply_url = impl_->config.view.reply_url;
  ctx.idp_entity = impl_->idp.entity_id;
  ctx.certs = impl_->idp.certs;
  ctx.decryption_key = impl_->config.private_key;
  ctx.clock_skew_ms = impl_->config.view.clock_skew_ms;
  ctx.want_encrypted = impl_->config.view.want_assertions_encrypted;
  ctx.replay = &impl_->replay;
  if (has_id) {
    bool ok = false;
    for (const auto &id : request_ids) {
      if (id == wctx["id"]) ok = true;
    }
    if (!ok) fail("validation", "the response answers " + wctx["id"] + ", which is not a sign-in this browser has outstanding");
  } else if (!impl_->config.view.allow_unsolicited) {
    fail("validation", "the response is unsolicited (its wctx names no request), and unsolicited responses are not accepted");
  }
  LoginResult token = validate_token(wresult, ctx);
  if (has_id) token.request_id = wctx["id"];
  if (wctx.count("ru")) token.relay_state = wctx["ru"];
  return token;
}

std::string RelyingParty::Logout(const std::string &reply) {
  std::vector<std::pair<std::string, std::string>> pairs = {{"wa", "wsignout1.0"}, {"wtrealm", impl_->config.view.realm}};
  if (!reply.empty()) pairs.emplace_back("wreply", reply);
  return join_query(impl_->idp.passive, encode_query(pairs));
}

bool RelyingParty::IsSignOutCleanup(const std::string &method, const std::string &url, const std::string &body) const {
  auto query = query_of(url);
  std::map<std::string, std::string> form;
  std::string upper = method;
  for (char &c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  if (upper == "POST") form = parse_query(body);
  std::string wa;
  if (form.count("wa")) wa = form["wa"];
  else if (query.count("wa")) wa = query["wa"];
  return wa == "wsignoutcleanup1.0" || wa == "wsignout1.0";
}

std::string RelyingParty::Metadata() const {
  return write_rp_metadata(impl_->config.view.realm, impl_->config.view.reply_url, impl_->config.certificate_pem);
}

const Resolved &RelyingParty::config() const { return impl_->config.view; }
std::string RelyingParty::IdpEntityId() const { return impl_->idp.entity_id; }
std::string RelyingParty::PassiveEndpoint() const { return impl_->idp.passive; }
std::vector<std::string> RelyingParty::TokenTypesOffered() const { return impl_->idp.token_types; }
int RelyingParty::SigningCertificateCount() const { return static_cast<int>(impl_->idp.certs.size()); }

}  // namespace iya::wsfed
